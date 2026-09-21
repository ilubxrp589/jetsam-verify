//! Print the shape + structural digest each class pins, for the web page.
use jetsam_miner::history_step_artifacts::decode_history_step_runtime_metadata_pinned;
use jetsam_recursive::{CanonicalHistoryStepClassId, HISTORY_STEP_CLASS_COUNT};

fn main() {
    let meta = std::fs::read("assets/history-step.runtime.mainnet").expect("metadata");
    let pinned: [u8; 32] = meta[meta.len() - 32..].try_into().unwrap();
    let md = decode_history_step_runtime_metadata_pinned(&meta, pinned).expect("metadata");
    println!("{{");
    println!("  \"metadata_digest\": \"{}\",", hex::encode(pinned));
    println!("  \"classes\": [");
    for i in 0..HISTORY_STEP_CLASS_COUNT {
        let e = md.bank().entry(CanonicalHistoryStepClassId::from_index(i).unwrap());
        let s = e.shape();
        let comma = if i + 1 == HISTORY_STEP_CLASS_COUNT { "" } else { "," };
        println!(
            "    {{ \"class\": {i}, \"m\": {}, \"k_log\": {}, \"k_skip\": {}, \"const_pin\": {}, \"digest\": \"{}\" }}{comma}",
            s.m, s.k_log, s.k_skip,
            s.const_pin.map(|c| c as i64).unwrap_or(-1),
            hex::encode(e.matrix_digest())
        );
    }
    println!("  ]");
    println!("}}");
}
