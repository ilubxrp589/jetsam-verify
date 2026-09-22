//! What one parameter pack pins: its relation, its boundary, and the shape and
//! structural digest of every class. This is what the web page is pinned to.
//!
//!     print_pins [metadata-path]          describe one pack
//!     print_pins --generation-at HEIGHT   which relation governs a height
//!
//! A v1.3 node binary carries two packs, because it verifies blocks on both
//! sides of the fork. `--generation-at` is how a re-point decides which of
//! them the page should ship: it reads the activation schedule compiled into
//! this build, exactly as a node reads it.
use jetsam_chain::consensus::params::HistoryStepPackGeneration;
use jetsam_miner::history_step_artifacts::decode_history_step_runtime_metadata_pinned;
use jetsam_recursive::{CanonicalHistoryStepClassId, HISTORY_STEP_CLASS_COUNT};

const DEFAULT_METADATA: &str = "assets/history-step.runtime.mainnet";

fn name(generation: HistoryStepPackGeneration) -> &'static str {
    match generation {
        HistoryStepPackGeneration::V1 => "v1",
        HistoryStepPackGeneration::V1_3 => "v1.3",
    }
}

fn root_height(generation: HistoryStepPackGeneration) -> u64 {
    match generation {
        HistoryStepPackGeneration::V1 => 0,
        HistoryStepPackGeneration::V1_3 => jetsam_chain::consensus::params::V1_3_ACTIVATION_HEIGHT
            .expect("a build carrying v1.3 parameters has a v1.3 activation height")
            - 1,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--generation-at") {
        let height: u64 = args
            .get(1)
            .expect("--generation-at needs a height")
            .parse()
            .expect("height must be a number");
        println!("{}", name(HistoryStepPackGeneration::at_height(height)));
        return;
    }

    let path = args.first().map(String::as_str).unwrap_or(DEFAULT_METADATA);
    let meta = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let pinned: [u8; 32] = meta[meta.len() - 32..].try_into().unwrap();
    let md = decode_history_step_runtime_metadata_pinned(&meta, pinned)
        .unwrap_or_else(|e| panic!("{path} does not decode against its own pinned digest: {e}"));
    let generation = md.runtime_parts().generation();
    println!("{{");
    println!("  \"metadata_digest\": \"{}\",", hex::encode(pinned));
    println!("  \"generation\": \"{}\",", name(generation));
    println!("  \"root_height\": {},", root_height(generation));
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
