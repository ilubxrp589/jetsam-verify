//! End-to-end Jetsam chain verification, trusting nobody.
//!
//! Every input is either self-authenticating or checked locally:
//!   * the runtime metadata carries its own pinned poseidon2b digest;
//!   * each canonical matrix goes through the SAFE loader, which re-derives the
//!     structural digest and compares it to the one the metadata pins;
//!   * the terminal/headers come off an RPC we do not trust -- if any byte were
//!     wrong the proof replay below would reject it.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use jetsam_chain::BlockHeader;
use jetsam_ivc_core::field_r1cs::CompactFieldR1cs;
use jetsam_ivc_core::proof::FieldShape;
use jetsam_miner::history_step_artifacts::decode_history_step_runtime_metadata_pinned;
use jetsam_recursive::{
    decode_verify_history_step_terminal, CanonicalHistoryStepClassId, HistoryStepMatrixLease,
    HistoryStepMatrixSource, HistoryStepMatrixSourceError, HistoryStepRuntime,
    HISTORY_STEP_CLASS_COUNT,
};

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
        let canonical = zstd::stream::decode_all(comp.as_slice())
            .map_err(|_| HistoryStepMatrixSourceError)?;
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

fn read_hex(path: &str) -> Vec<u8> {
    hex::decode(std::fs::read_to_string(path).expect(path).trim()).expect("hex")
}

fn main() {
    // 1. Runtime metadata, pinned by its own trailing poseidon2b digest.
    let meta = std::fs::read("assets/history-step.runtime.mainnet").expect("metadata");
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

    // 2. Runtime, with matrices authenticated lazily on first use.
    let (bank, parts) = md.into_parts();
    let source = LazyMatrices { pins, cache: Mutex::new(HashMap::new()) };
    let runtime = HistoryStepRuntime::new(bank, Box::new(source), parts)
        .expect("runtime parts match the pinned bank");
    println!("2. runtime    OK");

    // 3. The actual chain verification.
    let terminal = read_hex("assets/terminal.mainnet.hex");
    let header = BlockHeader::from_bytes(&read_hex("assets/header.mainnet.hex")).expect("header");
    let epoch =
        BlockHeader::from_bytes(&read_hex("assets/epoch_header.mainnet.hex")).expect("epoch header");
    println!("3. inputs     terminal {} bytes, 2 headers", terminal.len());
    println!("4. verifying (matrices load on demand):");

    let t = Instant::now();
    match decode_verify_history_step_terminal(&runtime, &terminal, &header, &epoch) {
        Ok(accepted) => {
            println!("\n=== CHAIN VERIFIED in {:?} (incl. matrix scans) ===", t.elapsed());
            println!("   height      {}", accepted.height());
            println!("   semantic id {}", hex::encode(accepted.semantic_id()));
            println!("   class       {}", accepted.class_id().index());
        }
        Err(e) => println!("\n=== VERIFY FAILED after {:?}: {e:?} ===", t.elapsed()),
    }
}
