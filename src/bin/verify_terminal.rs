//! End-to-end Jetsam chain verification, trusting nobody.
//!
//! This is the native twin of the browser page: same relation, same headers,
//! same checks, without the wasm penalty. It is the acceptance test for a
//! re-point — if this passes against a live node, the parameters in `assets/`
//! are the ones the chain is running.
//!
//! Every input is either self-authenticating or checked locally:
//!   * the runtime metadata carries its own pinned poseidon2b digest;
//!   * each canonical matrix goes through the SAFE loader, which re-derives the
//!     structural digest and compares it to the one the metadata pins;
//!   * the terminal and every header come off an RPC we do not trust -- if any
//!     byte were wrong the proof replay below would reject it.
//!
//!     cargo run --release --bin verify_terminal [rpc-url]
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use jetsam_chain::block_header::block_id;
use jetsam_chain::consensus::{
    previous_tx_epoch_anchor_height_for_child, tx_epoch_anchor_height_for_child,
};
use jetsam_chain::BlockHeader;
use jetsam_ivc_core::field_r1cs::CompactFieldR1cs;
use jetsam_ivc_core::proof::FieldShape;
use jetsam_miner::history_step_artifacts::decode_history_step_runtime_metadata_pinned;
use jetsam_recursive::{
    decode_verify_history_step_terminal_rooted, CanonicalHistoryStepClassId, ChainAccumulator,
    HistoryStepMatrixLease, HistoryStepMatrixSource, HistoryStepMatrixSourceError,
    HistoryStepPackGeneration, HistoryStepRuntime, RecursionRoot, HISTORY_STEP_CLASS_COUNT,
};

const DEFAULT_RPC: &str = "http://127.0.0.1:3097/rpc";

/// Loads a class's canonical matrix on first use and authenticates it with the
/// SAFE loader. Lazy on purpose: it shows which classes a given terminal
/// actually needs, and what each one costs.
struct LazyMatrices {
    pins: Vec<(FieldShape, [u8; 32])>,
    cache: Mutex<HashMap<usize, Arc<CompactFieldR1cs>>>,
}

impl HistoryStepMatrixSource for LazyMatrices {
    fn load(
        &self,
        class: CanonicalHistoryStepClassId,
    ) -> Result<HistoryStepMatrixLease, HistoryStepMatrixSourceError> {
        let idx = class.index();
        let mut cache = self.cache.lock().unwrap();
        if let Some(existing) = cache.get(&idx) {
            return Ok(HistoryStepMatrixLease::Compact(Arc::clone(existing)));
        }
        let (shape, digest) = *self.pins.get(idx).ok_or(HistoryStepMatrixSourceError)?;
        let path = format!("assets/canonical-c{idx:02}-mainnet.zst");
        let comp = std::fs::read(&path).map_err(|_| HistoryStepMatrixSourceError)?;
        let t = Instant::now();
        let canonical =
            zstd::stream::decode_all(comp.as_slice()).map_err(|_| HistoryStepMatrixSourceError)?;
        let matrix = CompactFieldR1cs::open_packed(canonical.into_boxed_slice(), shape, digest)
            .map_err(|_| HistoryStepMatrixSourceError)?;
        println!(
            "   class {idx}: {:.2} MB shipped -> SAFE scan OK in {:?}  ({:?})",
            comp.len() as f64 / 1048576.0,
            t.elapsed(),
            shape
        );
        let matrix = Arc::new(matrix);
        cache.insert(idx, Arc::clone(&matrix));
        Ok(HistoryStepMatrixLease::Compact(matrix))
    }
}

/// One JSON-RPC call over curl, returning the `result` string.
///
/// The response shape is `{"jsonrpc":"2.0","id":1,"result":"<hex>"}` and only
/// the hex is wanted, so this lifts it out rather than pulling a JSON parser
/// into a crate that otherwise has none. Nothing here is trusted: a wrong byte
/// makes the replay reject.
fn rpc(url: &str, method: &str, params: &str) -> Option<String> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let out = Command::new("curl")
        .args(["-s", "-m", "60", "-X", "POST", url, "-H", "content-type: application/json", "-d", &body])
        .output()
        .expect("curl");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if let Some(at) = text.find("\"error\"") {
        panic!("{method} failed: {}", &text[at..text.len().min(at + 200)]);
    }
    let at = text.find("\"result\":")? + "\"result\":".len();
    let rest = text[at..].trim_start();
    if rest.starts_with("null") {
        return None;
    }
    let rest = rest.strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

fn header_at(url: &str, height: u64) -> BlockHeader {
    let hex = rpc(url, "jetsam_getHeaderByHeight", &format!("[{height}]"))
        .unwrap_or_else(|| panic!("no header at height {height}"));
    BlockHeader::from_bytes(&hex::decode(hex).expect("header hex"))
        .unwrap_or_else(|e| panic!("header {height}: {e:?}"))
}

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_RPC.to_string());

    // 1. Runtime metadata, pinned by its own trailing poseidon2b digest.
    // Overridable so the "wrong generation" path can be exercised on purpose:
    // point this at the pre-fork pack and a post-fork terminal must come back
    // as ForeignIoLayout, not as a verification failure.
    let meta_path = std::env::var("JETSAM_VERIFY_METADATA")
        .unwrap_or_else(|_| "assets/history-step.runtime.mainnet".to_string());
    let meta = std::fs::read(&meta_path).unwrap_or_else(|e| panic!("{meta_path}: {e}"));
    let pinned: [u8; 32] = meta[meta.len() - 32..].try_into().unwrap();
    let md = decode_history_step_runtime_metadata_pinned(&meta, pinned)
        .expect("metadata decodes against its own pinned digest");
    let pins: Vec<(FieldShape, [u8; 32])> = (0..HISTORY_STEP_CLASS_COUNT)
        .map(|i| {
            let e = md.bank().entry(CanonicalHistoryStepClassId::from_index(i).unwrap());
            (e.shape(), e.matrix_digest())
        })
        .collect();
    println!("1. metadata   OK  pinned {}", hex::encode(pinned));
    for (i, (shape, _)) in pins.iter().enumerate() {
        println!("              class {i}: {shape:?}");
    }

    // 2. Runtime, rooted where this relation's recursion starts. The launch
    //    relation starts at genesis and pins that itself; v1.3 starts at the
    //    block before the activation height and carries the boundary in its
    //    public IO, so the bank has to know which height that is.
    let (bank, parts) = md.into_parts();
    let generation = parts.generation();
    let root_height = match generation {
        HistoryStepPackGeneration::V1 => 0,
        HistoryStepPackGeneration::V1_3 => jetsam_chain::consensus::params::V1_3_ACTIVATION_HEIGHT
            .expect("v1.3 parameters need a v1.3 activation height")
            - 1,
    };
    let source = LazyMatrices { pins, cache: Mutex::new(HashMap::new()) };
    let runtime = HistoryStepRuntime::new(bank.rooted_at_height(root_height), Box::new(source), parts)
        .expect("runtime parts match the pinned bank");
    println!("2. runtime    OK  generation {generation:?}, rooted at height {root_height}");

    // 3. Live chain state, straight off an RPC we do not trust.
    let terminal_hex = rpc(&url, "jetsam_getHistoryStepTerminal", "[]")
        .expect("this node has no finalized HistoryStep terminal");
    let terminal = hex::decode(terminal_hex).expect("terminal hex");
    let height = u64::from_le_bytes(terminal[1..9].try_into().unwrap());
    let binds_two = generation.binds_two_epoch_anchors();
    let anchors = |h: u64| {
        (
            tx_epoch_anchor_height_for_child(h),
            binds_two.then(|| previous_tx_epoch_anchor_height_for_child(h)),
        )
    };
    let (epoch_height, previous_epoch_height) = anchors(height);
    let header = header_at(&url, height);
    let epoch = header_at(&url, epoch_height);
    let previous_epoch = previous_epoch_height.map(|h| header_at(&url, h));
    println!(
        "3. inputs     terminal {} bytes for height {height}, wire version {}",
        terminal.len(),
        terminal[0]
    );
    println!("              epoch anchor {epoch_height}{}",
        previous_epoch_height.map(|h| format!(", previous {h}")).unwrap_or_default());

    // 4. The boundary this branch starts from, rebuilt from permanent headers
    //    exactly as a node rebuilds it -- never a shipped constant. The engine
    //    compares it against the root the proof carries in its public IO, so a
    //    valid proof of a DIFFERENT branch at the same height is rejected.
    let root = if root_height == 0 {
        None
    } else {
        let (root_epoch_height, root_previous_epoch_height) = anchors(root_height);
        let boundary = header_at(&url, root_height);
        let boundary_epoch = header_at(&url, root_epoch_height);
        let boundary_previous = root_previous_epoch_height.map(|h| header_at(&url, h));
        println!(
            "              recursion root {root_height} (epoch {root_epoch_height}{})",
            root_previous_epoch_height.map(|h| format!(", previous {h}")).unwrap_or_default()
        );
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

    println!("5. verifying (matrices load on demand):");
    let t = Instant::now();
    match decode_verify_history_step_terminal_rooted(
        &runtime,
        &terminal,
        &header,
        &epoch,
        previous_epoch.as_ref(),
        root.as_ref(),
    ) {
        Ok(accepted) => {
            println!("\n=== CHAIN VERIFIED in {:?} (incl. matrix scans) ===", t.elapsed());
            println!("   height      {}", accepted.height());
            println!("   semantic id {}", hex::encode(accepted.semantic_id()));
            println!("   class       {}", accepted.class_id().index());
            println!("   generation  {generation:?}, rooted at {root_height}");
        }
        // Same split the page makes: a frame that never parsed as a terminal
        // of this relation is not a proof that failed, and must not be
        // reported as one. See `is_unreadable_frame` in src/lib.rs.
        Err(e) => {
            let unreadable = matches!(
                e,
                jetsam_recursive::HistoryStepError::ForeignIoLayout { .. }
                    | jetsam_recursive::HistoryStepError::WireVersion
                    | jetsam_recursive::HistoryStepError::WireLength { .. }
                    | jetsam_recursive::HistoryStepError::WireEncoding
                    | jetsam_recursive::HistoryStepError::InvalidClass
                    | jetsam_recursive::HistoryStepError::RootlessGeneration
            );
            let governs = HistoryStepPackGeneration::at_height(height);
            if governs != generation {
                println!(
                    "\n=== WRONG PARAMETERS after {:?}: block {height} is governed by \
                     {governs:?}, these are the {generation:?} parameters ({e:?}) ===",
                    t.elapsed()
                );
            } else if unreadable {
                println!(
                    "\n=== UNREADABLE FRAME after {:?}: {e:?} ===\n   \
                     These bytes are not a terminal of the {generation:?} relation. Nothing was \
                     verified, so this is not a proof that failed.",
                    t.elapsed()
                );
            } else {
                println!("\n=== VERIFY FAILED after {:?}: {e:?} ===", t.elapsed());
            }
        }
    }
}
