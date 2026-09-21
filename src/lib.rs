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

use jetsam_chain::BlockHeader;
use jetsam_ivc_core::field_r1cs::CompactFieldR1cs;
use jetsam_ivc_core::proof::FieldShape;
use jetsam_poseidon2b::native::poseidon2b_hash_byte_slices;
use jetsam_recursive::{
    decode_verify_history_step_terminal, pin_history_step_class_bank, CanonicalHistoryStepClassId,
    HistoryStepMatrixLease, HistoryStepMatrixSource, HistoryStepMatrixSourceError,
    HistoryStepRuntime, HistoryStepRuntimeParts, HISTORY_STEP_CLASS_COUNT,
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
    Ok(Metadata { bank, parts })
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

    /// Verify a HistoryStep terminal against its block header and epoch anchor.
    ///
    /// The headers must be for the terminal's OWN height (parse it off the
    /// wire: byte 0 is the version, bytes 1..9 the height, little endian), not
    /// the chain tip, which typically runs several blocks ahead of it.
    pub fn verify(
        &self,
        terminal: &[u8],
        header: &[u8],
        epoch_header: &[u8],
    ) -> Result<String, JsValue> {
        console_error_panic_hook::set_once();
        // Natively the verifier runs on its own rayon lane with a 64 MiB stack.
        // wasm cannot spawn such a pool (rayon::ThreadPoolBuilder::build fails
        // under wasm-bindgen-rayon), so we declare this thread as the budgeted
        // large-stack worker and run the recursion in place. The 64 MiB stack
        // is supplied by -zstack-size in .cargo/config.toml. The contract on
        // this hook is that the caller really does have one.
        jetsam_ivc_core::verifier::set_budgeted_large_stack_worker(true);
        let header = BlockHeader::from_bytes(header)
            .map_err(|e| JsValue::from_str(&format!("header: {e:?}")))?;
        let epoch = BlockHeader::from_bytes(epoch_header)
            .map_err(|e| JsValue::from_str(&format!("epoch header: {e:?}")))?;
        let accepted = decode_verify_history_step_terminal(&self.runtime, terminal, &header, &epoch)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
        Ok(format!(
            "{{\"height\":{},\"semantic_id\":\"{}\",\"class\":{}}}",
            accepted.height(),
            accepted
                .semantic_id()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            accepted.class_id().index()
        ))
    }
}



