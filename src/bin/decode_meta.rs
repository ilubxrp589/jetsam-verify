//! Step 1: does the metadata extracted from the official binary decode?
//! The digest is the name of the node's history-step-cache directory, so a
//! successful decode proves the extraction is byte-exact.
use jetsam_miner::history_step_artifacts::decode_history_step_runtime_metadata_pinned;

fn main() {
    let bytes = std::fs::read("assets/history-step.runtime").expect("metadata");
    let digest: [u8; 32] = hex::decode(
        "148986844146fe0a4d498bd75f9938c63d1a56dfb5c9265341203c7aa7edb5c2",
    ).unwrap().try_into().unwrap();
    println!("metadata: {} bytes", bytes.len());
    match decode_history_step_runtime_metadata_pinned(&bytes, digest) {
        Ok(md) => {
            println!("DECODED OK — extraction is byte-exact and digest-pinned");
            let bank = md.bank();
            for i in 0..2 {
                if let Some(c) = jetsam_recursive::CanonicalHistoryStepClassId::from_index(i) {
                    let e = bank.entry(c);
                    println!("  class {i}: shape={:?} digest={}", e.shape(), hex::encode(e.matrix_digest()));
                }
            }
        }
        Err(e) => println!("DECODE FAILED: {e}"),
    }
}
