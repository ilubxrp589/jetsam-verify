//! Prove the SAFE loader accepts the canonical matrix extracted from the
//! dev-published testnet binary. No unsafe, no seal, no trust in the server
//! that served the bytes -- open_packed does the full structural Poseidon scan
//! and rejects anything that does not match the shape+digest from the metadata.
use std::time::Instant;
use jetsam_ivc_core::field_r1cs::CompactFieldR1cs;
use jetsam_miner::history_step_artifacts::decode_history_step_runtime_metadata_pinned;
use jetsam_recursive::CanonicalHistoryStepClassId;

fn main() {
    // --- metadata: its own trailer is the pinned poseidon2b digest ---
    let meta = std::fs::read("assets/history-step.runtime.testnet").expect("metadata");
    let digest: [u8; 32] = meta[meta.len() - 32..].try_into().unwrap();
    let md = decode_history_step_runtime_metadata_pinned(&meta, digest)
        .expect("testnet metadata decodes against its own pinned digest");
    let class = CanonicalHistoryStepClassId::from_index(0).unwrap();
    let entry = md.bank().entry(class);
    println!("metadata OK  class0 shape={:?}", entry.shape());
    println!("  expected structural digest = {}", hex::encode(entry.matrix_digest()));

    // --- matrix: ship compressed, expand, verify structurally ---
    let t = Instant::now();
    let comp = std::fs::read("assets/canonical-c00.zst").expect("matrix");
    let canonical = zstd::stream::decode_all(comp.as_slice()).expect("zstd");
    println!("  shipped {:.2} MB -> expanded {:.1} MB in {:?}",
             comp.len() as f64 / 1048576.0, canonical.len() as f64 / 1048576.0, t.elapsed());

    let t = Instant::now();
    match CompactFieldR1cs::open_packed(
        canonical.into_boxed_slice(), entry.shape(), entry.matrix_digest(),
    ) {
        Ok(m) => {
            let m: CompactFieldR1cs = m;
            println!("\nSAFE open_packed ACCEPTED in {:?}\n  shape={:?} useful_rows={}",
                     t.elapsed(), m.shape(), m.useful_rows());
        }
        Err(e) => println!("\nopen_packed REJECTED: {e:?}"),
    }
}
