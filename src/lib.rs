//! Verify the Jetsam chain in a browser tab, trusting nobody.
//!
//! Trust chain, end to end:
//!   1. the runtime metadata authenticates itself against its own trailing
//!      poseidon2b digest, which the caller pins to a known release value;
//!   2. each canonical matrix goes through the SAFE loader, which re-derives
//!      the structural digest and compares it to the one the metadata pins;
//!   3. the terminal and headers come off an RPC we do not trust, so any wrong
//!      byte makes the proof replay reject.
//!
//! Nothing here trusts the server that served any of it.
#![cfg(target_arch = "wasm32")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use jetsam_chain::block_header::block_id;
use jetsam_chain::consensus::params::{HistoryStepPackGeneration, V1_3_ACTIVATION_HEIGHT};
use jetsam_chain::consensus::{
    previous_tx_epoch_anchor_height_for_child, tx_epoch_anchor_height_for_child,
};
use jetsam_chain::BlockHeader;
use jetsam_ivc_core::field_r1cs::CompactFieldR1cs;
use jetsam_ivc_core::proof::FieldShape;
use jetsam_poseidon2b::native::poseidon2b_hash_byte_slices;
use jetsam_recursive::{
    decode_verify_history_step_terminal_rooted, pin_history_step_class_bank, ChainAccumulator,
    CanonicalHistoryStepClassId, HistoryStepError, HistoryStepMatrixLease,
    HistoryStepMatrixSource, HistoryStepMatrixSourceError, HistoryStepRuntime,
    HistoryStepRuntimeParts, RecursionRoot, HISTORY_STEP_CLASS_COUNT,
};
use wasm_bindgen::prelude::*;

/// Spin up the rayon worker pool. JS must await this before anything else, or
/// the matrix scan runs single-threaded (measured 3.1x slower).
pub use wasm_bindgen_rayon::init_thread_pool;

/// How many threads rayon actually has, so the page cannot claim parallelism
/// it does not have.
#[wasm_bindgen]
pub fn thread_count() -> usize {
    rayon::current_num_threads()
}

// --- metadata frame -------------------------------------------------------
// Reimplemented from jetsam_miner::history_step_artifacts, which cannot target
// wasm (tokio + libc). The frame is:
//   MAGIC(16) | VERSION u16le(2) | body_len u64le(8) | body | digest(32)
// The body is [matrix digests; CLASS_COUNT] followed by the compact runtime
// parts. The digest covers the BODY ONLY.
const MAGIC: [u8; 16] = *b"JETSAM/HSTEP/V1\0";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 16 + 2 + 8;
const TRAILER_BYTES: usize = 32;
const MATRIX_DIGEST_BYTES: usize = 32 * HISTORY_STEP_CLASS_COUNT;
const DIGEST_DOMAIN: &[u8] = b"JTM/HISTORY-STEP/RUNTIME-METADATA/V1";

struct Metadata {
    bank: jetsam_recursive::PinnedHistoryStepClassBank,
    parts: HistoryStepRuntimeParts,
}

fn decode_metadata(encoded: &[u8], pinned: [u8; 32]) -> Result<Metadata, String> {
    if encoded.len() < HEADER_BYTES + MATRIX_DIGEST_BYTES + TRAILER_BYTES {
        return Err("metadata too short".into());
    }
    if encoded[..16] != MAGIC {
        return Err("bad magic".into());
    }
    let version = u16::from_le_bytes(encoded[16..18].try_into().unwrap());
    if version != VERSION {
        return Err(format!("unsupported metadata version {version}"));
    }
    let body_len = u64::from_le_bytes(encoded[18..26].try_into().unwrap()) as usize;
    let expected_len = HEADER_BYTES
        .checked_add(body_len)
        .and_then(|n| n.checked_add(TRAILER_BYTES))
        .ok_or("body length overflow")?;
    if expected_len != encoded.len() || body_len <= MATRIX_DIGEST_BYTES {
        return Err("body length mismatch".into());
    }

    let body = &encoded[HEADER_BYTES..HEADER_BYTES + body_len];
    let advertised: [u8; 32] = encoded[HEADER_BYTES + body_len..].try_into().unwrap();
    let actual = poseidon2b_hash_byte_slices(DIGEST_DOMAIN, &[body]);
    if advertised != actual {
        return Err("metadata digest does not match its own trailer".into());
    }
    if actual != pinned {
        return Err("metadata does not match the pinned release digest".into());
    }

    let matrix_digests: [[u8; 32]; HISTORY_STEP_CLASS_COUNT] = core::array::from_fn(|i| {
        body[i * 32..i * 32 + 32].try_into().expect("32-byte digest")
    });
    let parts = HistoryStepRuntimeParts::decode_compact(&body[MATRIX_DIGEST_BYTES..])
        .map_err(|e| format!("runtime parts: {e:?}"))?;
    let bank = pin_history_step_class_bank(matrix_digests, &parts)
        .map_err(|e| format!("class bank: {e:?}"))?;
    // These parameters name the relation they belong to, and a relation says
    // where its recursion starts. v1.3 proves forward from the activation
    // boundary rather than from genesis, and the bank has to carry that
    // height for two separate reasons: the terminal decoder reads it to tell
    // "a frame of the other generation" apart from "a malformed frame", and
    // the root check in `verify` compares the carried root against it.
    let bank = bank.rooted_at_height(recursion_root_height(parts.generation())?);
    Ok(Metadata { bank, parts })
}

/// Height of the boundary this generation's recursion starts from.
///
/// Zero for the relation the chain launched with, whose base is genesis; the
/// block before the activation height for v1.3. Both are schedule constants
/// compiled into this build, read exactly the way a node reads them.
fn recursion_root_height(generation: HistoryStepPackGeneration) -> Result<u64, String> {
    match generation {
        HistoryStepPackGeneration::V1 => Ok(0),
        HistoryStepPackGeneration::V1_3 => V1_3_ACTIVATION_HEIGHT
            .and_then(|height| height.checked_sub(1))
            .ok_or_else(|| {
                "these are the v1.3 parameters, but this build carries no v1.3 activation \
                 height to root them at"
                    .to_string()
            }),
    }
}

/// Decode one 212-byte block header, naming which one when it will not.
fn decode_header(label: &str, bytes: Option<&[u8]>) -> Result<BlockHeader, JsValue> {
    let bytes = bytes.ok_or_else(|| JsValue::from_str(&format!("{label} was not supplied")))?;
    BlockHeader::from_bytes(bytes).map_err(|e| JsValue::from_str(&format!("{label}: {e:?}")))
}

/// Quote a Rust debug string so it can sit inside a JSON string literal.
fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// The relation a bank belongs to and the boundary its recursion starts from.
fn schedule_json(bank: &jetsam_recursive::PinnedHistoryStepClassBank) -> String {
    format!(
        "{{\"generation\":\"{}\",\"root_height\":{},\"binds_two_epoch_anchors\":{}}}",
        generation_name(bank.generation()),
        bank.recursion_root_height(),
        bank.generation().binds_two_epoch_anchors()
    )
}

/// Name a generation the way the page prints it.
fn generation_name(generation: HistoryStepPackGeneration) -> &'static str {
    match generation {
        HistoryStepPackGeneration::V1 => "v1",
        HistoryStepPackGeneration::V1_3 => "v1.3",
    }
}

/// A failed verification is one of two very different things, and the page
/// must not blur them.
///
/// The split is WHERE it failed, not how bad it sounds. Everything below is
/// raised while the frame is still being read: the bytes are not a terminal of
/// the relation these parameters are for, so no cryptography ever ran on them.
/// Everything else is a proof that parsed as ours and then did not check out,
/// and that stays loud.
///
/// `ForeignIoLayout` is upstream naming the case outright, but it is not the
/// only shape the case takes, and measuring that was worth doing: offering a
/// post-fork terminal to the pre-fork parameters gives `WireEncoding`, not
/// `ForeignIoLayout`, because the older encoding accepts a *range* of lengths
/// and the newer frame fits inside it, is read at the wrong IO width, and
/// desynchronises. A page that only looked for `ForeignIoLayout` would have
/// cried wolf on exactly the upgrade it was built to survive.
///
/// This is a wider net than "the page is out of date", and the page says so:
/// bytes that do not parse as a terminal are also what a broken or hostile
/// server returns. Neither of those is "the chain produced a bad proof", which
/// is the one claim this page must not make wrongly.
fn is_unreadable_frame(error: &HistoryStepError) -> bool {
    matches!(
        error,
        HistoryStepError::ForeignIoLayout { .. }
            | HistoryStepError::WireVersion
            | HistoryStepError::WireLength { .. }
            | HistoryStepError::WireEncoding
            | HistoryStepError::InvalidClass
            | HistoryStepError::RootlessGeneration
    )
}

// --- matrix source --------------------------------------------------------

/// Holds matrices that already passed the SAFE loader. Returning one for a
/// class it was not minted for is harmless: `HistoryStepRuntime::load_matrix`
/// re-authenticates every lease against that class's pinned digest.
struct LoadedMatrices(Mutex<HashMap<usize, Arc<CompactFieldR1cs>>>);

impl HistoryStepMatrixSource for LoadedMatrices {
    fn load(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError> {
        self.0
            .lock()
            .map_err(|_| HistoryStepMatrixSourceError)?
            .get(&class.index())
            .map(|m| HistoryStepMatrixLease::Compact(Arc::clone(m)))
            .ok_or(HistoryStepMatrixSourceError)
    }
}

// --- public API -----------------------------------------------------------

/// Authenticate one canonical matrix. This is the expensive step (measured
/// ~340 s for class 0 on six browser threads), so JS calls it once per class
/// and caches the outcome.
#[wasm_bindgen]
pub struct ScannedMatrix {
    class: usize,
    canonical_bytes: usize,
    matrix: Arc<CompactFieldR1cs>,
}

#[wasm_bindgen]
impl ScannedMatrix {
    #[wasm_bindgen(getter)]
    pub fn useful_rows(&self) -> usize {
        self.matrix.useful_rows()
    }

    #[wasm_bindgen(getter)]
    pub fn class(&self) -> usize {
        self.class
    }

    /// Length of the canonical artifact this was authenticated from. The page
    /// must store it beside the cached image: the seal is bound to it.
    #[wasm_bindgen(getter)]
    pub fn canonical_bytes(&self) -> usize {
        self.canonical_bytes
    }

    /// Serialise this ALREADY-AUTHENTICATED relation so the page can cache it
    /// and skip the multi-minute rescan next visit. Pair with
    /// [`load_cached_matrix`].
    pub fn packed_image(&self) -> Result<Vec<u8>, JsValue> {
        self.matrix
            .encode_startup_packed_image()
            .map(|b| b.into_vec())
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))
    }
}

/// Restore a matrix this browser itself authenticated on an earlier visit.
///
/// # What this does and does not trust
///
/// This skips the structural rescan. It is sound only because `image` is the
/// exact output of [`ScannedMatrix::packed_image`] from a previous successful
/// [`scan_matrix`] in THIS browser, under the same `shape` and `digest`. Those
/// still come from metadata that self-authenticates against the pinned release
/// digest, never from the cached blob.
///
/// The residual assumption is that same-origin IndexedDB returned what we put
/// there. That is strictly weaker than trusting a server, but it is NOT the
/// same as a full rescan, and a page using this must say so.
#[wasm_bindgen]
pub fn load_cached_matrix(
    class: usize,
    image: &[u8],
    m: usize,
    k_log: usize,
    k_skip: usize,
    const_pin: i32,
    digest: &[u8],
    canonical_bytes: usize,
) -> Result<ScannedMatrix, JsValue> {
    let expected: [u8; 32] = digest
        .try_into()
        .map_err(|_| JsValue::from_str("structural digest must be 32 bytes"))?;
    let shape = FieldShape {
        m,
        k_log,
        k_skip,
        const_pin: if const_pin < 0 { None } else { Some(const_pin as usize) },
    };
    // SAFETY: caller contract documented above. `image` is our own prior
    // `encode_startup_packed_image` output for a relation this browser already
    // put through the full `open_packed` scan under exactly this shape+digest.
    let seal = unsafe {
        jetsam_ivc_core::field_r1cs::BuildAuthenticatedFieldR1csSeal::from_release_build(
            shape,
            expected,
            canonical_bytes,
        )
    };
    let matrix = unsafe {
        CompactFieldR1cs::open_build_authenticated_packed_image(image, seal)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?
    };
    Ok(ScannedMatrix { class, canonical_bytes, matrix: Arc::new(matrix) })
}

/// Run the SAFE loader over already-decompressed canonical bytes for one class.
///
/// `shape` and `digest` must come from metadata that already passed the
/// digest check, never from the same source as `bytes`.
#[wasm_bindgen]
pub fn scan_matrix(
    class: usize,
    canonical: Vec<u8>,
    m: usize,
    k_log: usize,
    k_skip: usize,
    const_pin: i32,
    digest: &[u8],
) -> Result<ScannedMatrix, JsValue> {
    let expected: [u8; 32] = digest
        .try_into()
        .map_err(|_| JsValue::from_str("structural digest must be 32 bytes"))?;
    let shape = FieldShape {
        m,
        k_log,
        k_skip,
        const_pin: if const_pin < 0 { None } else { Some(const_pin as usize) },
    };
    let canonical_bytes = canonical.len();
    let matrix = CompactFieldR1cs::open_packed(canonical.into_boxed_slice(), shape, expected)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(ScannedMatrix { class, canonical_bytes, matrix: Arc::new(matrix) })
}

/// Authenticated runtime parameters.
///
/// Decoding costs a ~2.2 MB Poseidon hash (measured ~22 s in wasm), so it is
/// done ONCE and reused: the page reads the per-class shapes from here to drive
/// the scans, then consumes the same value into a [`Verifier`]. Decoding twice
/// wasted 22 s on every visit.
#[wasm_bindgen]
pub struct Parameters {
    bank: jetsam_recursive::PinnedHistoryStepClassBank,
    parts: HistoryStepRuntimeParts,
}

#[wasm_bindgen]
impl Parameters {
    /// Decode and authenticate against the pinned release digest.
    #[wasm_bindgen(constructor)]
    pub fn new(metadata: &[u8], pinned: &[u8]) -> Result<Parameters, JsValue> {
        let pin: [u8; 32] = pinned
            .try_into()
            .map_err(|_| JsValue::from_str("pinned digest must be 32 bytes"))?;
        let md = decode_metadata(metadata, pin).map_err(|e| JsValue::from_str(&e))?;
        Ok(Parameters { bank: md.bank, parts: md.parts })
    }

    /// What each class pins: shape plus the structural digest a matrix must
    /// match. The page needs this before scanning.
    #[wasm_bindgen(getter)]
    pub fn classes_json(&self) -> String {
        let mut classes = Vec::new();
        for i in 0..HISTORY_STEP_CLASS_COUNT {
            let id = match CanonicalHistoryStepClassId::from_index(i) {
                Some(id) => id,
                None => continue,
            };
            let entry = self.bank.entry(id);
            let shape = entry.shape();
            classes.push(format!(
                "{{\"class\":{},\"m\":{},\"k_log\":{},\"k_skip\":{},\"const_pin\":{},\"digest\":\"{}\"}}",
                i, shape.m, shape.k_log, shape.k_skip,
                shape.const_pin.map(|c| c as i64).unwrap_or(-1),
                entry.matrix_digest().iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
        }
        format!("{{\"classes\":[{}]}}", classes.join(","))
    }

    /// Which relation these parameters are, and where its recursion starts.
    /// The page reads this before anything is scanned, so it can say which
    /// generation it is about to check against.
    #[wasm_bindgen(getter)]
    pub fn schedule_json(&self) -> String {
        schedule_json(&self.bank)
    }

    /// Consume these parameters and the scanned matrices into a verifier.
    pub fn into_verifier(self, matrices: Vec<ScannedMatrix>) -> Result<Verifier, JsValue> {
        let mut map = HashMap::new();
        for scanned in matrices {
            map.insert(scanned.class, scanned.matrix);
        }
        let runtime = HistoryStepRuntime::new(
            self.bank,
            Box::new(LoadedMatrices(Mutex::new(map))),
            self.parts,
        )
        .map_err(|e| JsValue::from_str(&format!("runtime: {e:?}")))?;
        Ok(Verifier { runtime })
    }
}

/// A ready verifier. Verifying a chain state after this is the only repeated
/// cost (measured ~3 min in wasm, 5.27 s natively).
#[wasm_bindgen]
pub struct Verifier {
    runtime: HistoryStepRuntime,
}

#[wasm_bindgen]
impl Verifier {

    /// Which relation these parameters are, and where its recursion starts.
    #[wasm_bindgen(getter)]
    pub fn schedule_json(&self) -> String {
        schedule_json(self.runtime.bank())
    }

    /// The heights this verifier needs headers for, given a terminal's own
    /// height.
    ///
    /// The page fetches these over the untrusted RPC and hands the bytes back
    /// to [`Verifier::verify`]. The arithmetic lives here, beside the relation
    /// that defines it, so the page and the relation cannot drift apart: a
    /// generation that binds two epoch anchors asks for two, and one that
    /// pins its own base asks for no boundary headers at all.
    pub fn required_heights_json(&self, terminal_height: u64) -> String {
        let bank = self.runtime.bank();
        let binds_two = bank.generation().binds_two_epoch_anchors();
        let anchors = |height: u64| {
            let previous = binds_two
                .then(|| previous_tx_epoch_anchor_height_for_child(height).to_string())
                .unwrap_or_else(|| "null".to_string());
            format!(
                "\"epoch_anchor\":{},\"previous_epoch_anchor\":{previous}",
                tx_epoch_anchor_height_for_child(height)
            )
        };
        // Root height zero is genesis, which the relation pins itself: there
        // is no boundary to read off the chain and nothing to fetch.
        let root_height = bank.recursion_root_height();
        let root = if root_height == 0 {
            "null".to_string()
        } else {
            format!("{{\"height\":{root_height},{}}}", anchors(root_height))
        };
        format!(
            "{{\"terminal\":{{\"height\":{terminal_height},{}}},\"root\":{root}}}",
            anchors(terminal_height)
        )
    }

    /// Verify a HistoryStep terminal against the branch it belongs to.
    ///
    /// `header` and `epoch_header` are for the terminal's OWN height (parse it
    /// off the wire: byte 0 is the version, bytes 1..9 the height, little
    /// endian), not the chain tip, which typically runs several blocks ahead.
    /// Everything else is generation-dependent and named by
    /// [`Verifier::required_heights_json`]: v1.3 binds a second, older epoch
    /// anchor, and proves forward from the activation boundary rather than
    /// genesis, so the three headers at that boundary are needed to rebuild
    /// the recursion root the proof claims to start from.
    ///
    /// # What the root check is and is not
    ///
    /// Comparing the carried root to one rebuilt from headers establishes
    /// that this proof continues the branch those headers describe, and
    /// rejects a valid proof of a different branch at the same height. It does
    /// NOT re-prove the history before the boundary: that history was proved
    /// under the previous relation, whose parameters this page does not carry.
    ///
    /// Returns JSON carrying a `status` of `verified`, `stale` or `failed`.
    /// Anything that is not `verified` is not a verification, and a caller
    /// that does not check the field is wrong.
    pub fn verify(
        &self,
        terminal: &[u8],
        header: &[u8],
        epoch_header: &[u8],
        previous_epoch_header: Option<Vec<u8>>,
        root_header: Option<Vec<u8>>,
        root_epoch_header: Option<Vec<u8>>,
        root_previous_epoch_header: Option<Vec<u8>>,
    ) -> Result<String, JsValue> {
        console_error_panic_hook::set_once();
        // Natively the verifier runs on its own rayon lane with a 64 MiB stack.
        // wasm cannot spawn such a pool (rayon::ThreadPoolBuilder::build fails
        // under wasm-bindgen-rayon), so we declare this thread as the budgeted
        // large-stack worker and run the recursion in place. The 64 MiB stack
        // is supplied by -zstack-size in .cargo/config.toml. The contract on
        // this hook is that the caller really does have one.
        jetsam_ivc_core::verifier::set_budgeted_large_stack_worker(true);

        let generation = self.runtime.bank().generation();

        // The unambiguous mismatch, checked before anything expensive: this
        // build's own activation schedule says which relation governs the
        // terminal's height, and it is not the one these parameters are. That
        // happens when a node serves a pre-fork proof to a post-fork page. It
        // cannot catch a fork this build has never heard of, which is why the
        // frame-level net above exists as well.
        if terminal.len() >= 9 {
            let height = u64::from_le_bytes(terminal[1..9].try_into().unwrap());
            let governing = HistoryStepPackGeneration::at_height(height);
            if governing != generation {
                return Ok(format!(
                    "{{\"status\":\"stale\",\"certain\":true,\"reason\":\"the proof is for block \
                     {height}, which this build's schedule says is governed by the {} relation, not the \
                     {} parameters this page carries\",\"generation\":\"{}\"}}",
                    generation_name(governing),
                    generation_name(generation),
                    generation_name(generation),
                ));
            }
        }

        let header = decode_header("header", Some(header))?;
        let epoch = decode_header("epoch header", Some(epoch_header))?;
        let previous_epoch = match previous_epoch_header.as_deref() {
            Some(bytes) => Some(decode_header("previous epoch header", Some(bytes))?),
            None if generation.binds_two_epoch_anchors() => {
                return Err(JsValue::from_str(
                    "this relation binds two epoch anchors; the previous one was not supplied",
                ))
            }
            None => None,
        };

        // Rebuild the boundary this branch starts from, exactly as a node
        // does: arithmetic over permanent headers, never a shipped constant.
        let root_height = self.runtime.bank().recursion_root_height();
        let root = if root_height == 0 {
            None
        } else {
            let boundary = decode_header("boundary header", root_header.as_deref())?;
            if boundary.height != root_height {
                return Err(JsValue::from_str(&format!(
                    "boundary header is height {}, expected {root_height}",
                    boundary.height
                )));
            }
            let boundary_epoch = decode_header("boundary epoch header", root_epoch_header.as_deref())?;
            let boundary_previous = match root_previous_epoch_header.as_deref() {
                Some(bytes) => Some(decode_header("boundary previous epoch header", Some(bytes))?),
                None if generation.binds_two_epoch_anchors() => {
                    return Err(JsValue::from_str(
                        "this relation binds two epoch anchors; the boundary's previous anchor \
                         was not supplied",
                    ))
                }
                None => None,
            };
            Some(RecursionRoot::new(
                ChainAccumulator::from_canonical_headers(
                    generation,
                    &boundary,
                    &boundary_epoch,
                    boundary_previous.as_ref(),
                ),
                block_id(&boundary),
            ))
        };

        match decode_verify_history_step_terminal_rooted(
            &self.runtime,
            terminal,
            &header,
            &epoch,
            previous_epoch.as_ref(),
            root.as_ref(),
        ) {
            Ok(accepted) => Ok(format!(
                "{{\"status\":\"verified\",\"height\":{},\"semantic_id\":\"{}\",\"class\":{},\
                 \"generation\":\"{}\",\"root_height\":{root_height}}}",
                accepted.height(),
                accepted
                    .semantic_id()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                accepted.class_id().index(),
                generation_name(generation),
            )),
            Err(error) => {
                // `certain` is false here on purpose. A frame that will not
                // parse is what an upgraded chain looks like, and also what a
                // broken or hostile server looks like; the page must not claim
                // to know which.
                let status = if is_unreadable_frame(&error) { "stale" } else { "failed" };
                Ok(format!(
                    "{{\"status\":\"{status}\",\"certain\":false,\"reason\":\"{}\",\"generation\":\"{}\"}}",
                    json_escape(&format!("{error:?}")),
                    generation_name(generation),
                ))
            }
        }
    }

}



