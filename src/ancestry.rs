//! Is a given block part of the history a proof verified?
//!
//! A node serves only its current HistoryStep terminal, so an older height
//! cannot be verified by fetching an older proof. It does not need one. The
//! verified proof already covers every block back to its recursion root, and
//! what joins those blocks is their parent links, each of which is fixed:
//!
//!   * the tip's own `prev_block_hash` is absorbed into its semantic
//!     projection, which the proof binds;
//!   * every older link, `child.prev_block_hash == hash_block_header(parent)`
//!     with the parent's nonce included, is sealed in-circuit by the child
//!     step's parent-seal replay (`ParentSealTrace` in jetsam_recursive's
//!     `block_slots.rs`; `accumulator.rs` states the same invariant).
//!
//! So a run of headers that hashes, link by link, up to the tip's parent is
//! the run the proof verified, block for block, down to the recursion root.
//! Below the root the links still hash, but those blocks were proved under an
//! earlier relation, which this crate does not carry; callers keep the walk
//! at or above it.
//!
//! Shared by the page (through `lib.rs`) and `verify_terminal`, so the native
//! acceptance test exercises the same code the browser runs.
use jetsam_chain::block_header::block_id;
use jetsam_chain::BlockHeader;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// Only blocks strictly below the verified tip can be walked to.
    NotBelowTip { target: u64, tip: u64 },
    /// The headers are not exactly the blocks from the target to the tip.
    Count { expected: u64, actual: usize },
    /// A header sits at a height other than the one its position implies.
    Height { expected: u64, actual: u64 },
    /// The header at this height does not hash to its child's parent link.
    Link { height: u64 },
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::NotBelowTip { target, tip } => {
                write!(f, "block {target} is not below the verified tip {tip}")
            }
            Self::Count { expected, actual } => {
                write!(f, "expected {expected} headers, got {actual}")
            }
            Self::Height { expected, actual } => {
                write!(f, "expected the header for block {expected}, got block {actual}")
            }
            Self::Link { height } => write!(
                f,
                "block {height} does not hash to the parent link of block {}",
                height + 1
            ),
        }
    }
}

/// Walk from the verified tip down to `target`.
///
/// `headers` are the blocks `target..tip_height` in ascending order: every
/// block strictly below the tip, down to and including the target.
/// `tip_parent` is the verified tip's `prev_block_hash`. Returns the target's
/// header, every field of which, nonce included, is then fixed by the proof.
pub fn walk<'a>(
    tip_height: u64,
    tip_parent: &[u8; 32],
    target: u64,
    headers: &'a [BlockHeader],
) -> Result<&'a BlockHeader, WalkError> {
    if target >= tip_height {
        return Err(WalkError::NotBelowTip { target, tip: tip_height });
    }
    let expected = tip_height - target;
    if headers.len() as u64 != expected {
        return Err(WalkError::Count { expected, actual: headers.len() });
    }
    for (offset, header) in headers.iter().enumerate() {
        let height = target + offset as u64;
        if header.height != height {
            return Err(WalkError::Height { expected: height, actual: header.height });
        }
    }
    // Top down, starting from the one link the proof binds directly.
    let mut link = *tip_parent;
    for header in headers.iter().rev() {
        if block_id(header) != link {
            return Err(WalkError::Link { height: header.height });
        }
        link = header.prev_block_hash;
    }
    Ok(&headers[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetsam_poseidon2b::primitives::Address;

    fn header(height: u64, prev_block_hash: [u8; 32]) -> BlockHeader {
        BlockHeader {
            prev_block_hash,
            state_root: [height as u8; 32],
            tx_root: [0x11; 32],
            timestamp: 1_790_000_000 + height * 90,
            height,
            miner_address: Address([0x22; 32]),
            nonce: u128::from(height) * 7919,
            difficulty_target: [0xff; 32],
            log_slots: 20,
            active_slot_count: 1000 + height,
            alloc_counter: height,
        }
    }

    /// Blocks `from..to`, properly linked, and the id of the last one, which
    /// is what the block at `to` (the tip) carries as its parent.
    fn chain(from: u64, to: u64) -> (Vec<BlockHeader>, [u8; 32]) {
        let mut prev = [0x99; 32];
        let headers: Vec<BlockHeader> = (from..to)
            .map(|h| {
                let hdr = header(h, prev);
                prev = block_id(&hdr);
                hdr
            })
            .collect();
        (headers, prev)
    }

    #[test]
    fn a_linked_run_reaches_its_target() {
        let (headers, tip_parent) = chain(100, 110);
        let found = walk(110, &tip_parent, 100, &headers).unwrap();
        assert_eq!(*found, headers[0]);
        let one = walk(110, &tip_parent, 109, &headers[9..]).unwrap();
        assert_eq!(one.height, 109);
    }

    /// The nonce is inside the block id, so a header that differs only in its
    /// nonce is a different block and breaks the link above it.
    #[test]
    fn a_changed_nonce_breaks_the_link_above_it() {
        let (mut headers, tip_parent) = chain(100, 110);
        headers[4].nonce ^= 1;
        assert_eq!(walk(110, &tip_parent, 100, &headers), Err(WalkError::Link { height: 104 }));
    }

    #[test]
    fn the_top_header_must_hash_to_the_tips_parent() {
        let (headers, mut tip_parent) = chain(100, 110);
        tip_parent[0] ^= 1;
        assert_eq!(walk(110, &tip_parent, 100, &headers), Err(WalkError::Link { height: 109 }));
    }

    /// A consistent chain that ends somewhere else is not this chain.
    #[test]
    fn a_self_consistent_chain_elsewhere_is_refused() {
        let (_, tip_parent) = chain(100, 110);
        let mut other = chain(100, 110).0;
        other[0].tx_root = [0x33; 32];
        let mut prev = block_id(&other[0]);
        for hdr in other.iter_mut().skip(1) {
            hdr.prev_block_hash = prev;
            prev = block_id(hdr);
        }
        assert_eq!(walk(110, &tip_parent, 100, &other), Err(WalkError::Link { height: 109 }));
    }

    #[test]
    fn a_gap_or_a_misplaced_header_is_refused() {
        let (headers, tip_parent) = chain(100, 110);
        assert_eq!(
            walk(110, &tip_parent, 100, &headers[1..]),
            Err(WalkError::Count { expected: 10, actual: 9 })
        );
        let mut swapped = headers.clone();
        swapped.swap(3, 4);
        assert_eq!(
            walk(110, &tip_parent, 100, &swapped),
            Err(WalkError::Height { expected: 103, actual: 104 })
        );
    }

    #[test]
    fn only_blocks_below_the_tip_can_be_walked_to() {
        let (headers, tip_parent) = chain(100, 110);
        assert_eq!(
            walk(110, &tip_parent, 110, &headers),
            Err(WalkError::NotBelowTip { target: 110, tip: 110 })
        );
    }
}
