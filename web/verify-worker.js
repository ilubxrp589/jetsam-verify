// Engine worker. Everything that touches wasm lives here so a multi-minute
// verification cannot freeze the page: thread pool, matrix authentication,
// IndexedDB cache, live chain fetch, and the proof replay.
//
// The handler is registered BEFORE any top-level await on purpose: during an
// await the worker event loop already runs, so a queued message would be
// dispatched with no listener and silently lost.
import init, { initThreadPool, thread_count, Parameters,
                scan_matrix, load_cached_matrix } from "./pkg-web/jetsam_verify.js";

// The single constant a user checks against the published release. It is the
// poseidon2b digest of the runtime metadata embedded in jetsam-node v1.2.0,
// whose SHA256 is published on the project's GitHub releases page.
const PIN = "148986844146fe0a4d498bd75f9938c63d1a56dfb5c9265341203c7aa7edb5c2";
const TX_EPOCH_BLOCKS = 32n;
// The HistoryStep wire version these parameters were extracted for. A protocol
// upgrade that changes how proofs are constructed will bump this, and the
// honest response is "this page is out of date", NOT "verification failed".
const KNOWN_WIRE_VERSION = 5;

const send  = (m) => self.postMessage(m);
const hex   = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const bytes = async (u) => new Uint8Array(await (await fetch(u)).arrayBuffer());

async function rpc(method, params = []) {
  const r = await fetch("rpc", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

let dbPromise = null;
const openDb = () => (dbPromise ??= new Promise((res, rej) => {
  const r = indexedDB.open("jetsam-verify", 1);
  r.onupgradeneeded = () => r.result.createObjectStore("matrices");
  r.onsuccess = () => res(r.result);
  r.onerror   = () => rej(r.error);
}));
const kv = async (mode, fn) => {
  const db = await openDb();
  return new Promise((res, rej) => {
    const rq = fn(db.transaction("matrices", mode).objectStore("matrices"));
    rq.onsuccess = () => res(rq.result);
    rq.onerror   = () => rej(rq.error);
  });
};

// Does this device already hold verified parameters? Drives cold vs warm UI.
async function cacheState() {
  try {
    const db = await openDb();
    const keys = await new Promise((res, rej) => {
      const rq = db.transaction("matrices", "readonly").objectStore("matrices").getAllKeys();
      rq.onsuccess = () => res(rq.result); rq.onerror = () => rej(rq.error);
    });
    return keys.filter((k) => String(k).startsWith(PIN)).length;
  } catch { return 0; }
}

self.onmessage = async (e) => {
  const cmd = e.data?.type;
  if (cmd === "probe") {
    send({ type: "probe", cached: await cacheState(), isolated: self.crossOriginIsolated,
           cores: navigator.hardwareConcurrency || 0 });
    return;
  }
  if (cmd !== "run") return;
  const tamper = e.data?.tamper === true;

  let trust = "full";
  try {
    send({ type: "stage", stage: "engine" });
    await init();
    await initThreadPool(navigator.hardwareConcurrency);
    send({ type: "engine", threads: thread_count(), isolated: self.crossOriginIsolated });

    // 1. Parameters: metadata authenticates itself against the pinned digest.
    send({ type: "stage", stage: "metadata" });
    const meta = await bytes("assets/history-step.runtime.mainnet");
    // Decoded ONCE and reused below; the 2.2 MB Poseidon costs ~22 s in wasm.
    const params = new Parameters(meta, hex(PIN));
    const info = JSON.parse(params.classes_json);
    send({ type: "metadata", classes: info.classes.length, pin: PIN });

    // 2. Each class: restore what this device already authenticated, else scan.
    const matrices = [];
    for (const c of info.classes) {
      const key = `${PIN}:c${c.class}`;
      const hit = await kv("readonly", (s) => s.get(key));
      if (hit) {
        trust = "cached";
        const t = performance.now();
        matrices.push(load_cached_matrix(c.class, hit.image, c.m, c.k_log, c.k_skip,
                                         c.const_pin, hex(c.digest), hit.canonical_bytes));
        send({ type: "matrix", cls: c.class, mode: "cached", ms: performance.now() - t });
      } else {
        send({ type: "matrix", cls: c.class, mode: "scanning", m: c.m });
        const raw = await bytes(`assets/canonical-c${String(c.class).padStart(2, "0")}-mainnet.zst`);
        const t = performance.now();
        const scanned = scan_matrix(c.class, raw, c.m, c.k_log, c.k_skip, c.const_pin, hex(c.digest));
        const ms = performance.now() - t;
        const image = scanned.packed_image();
        await kv("readwrite", (s) => s.put({ image, canonical_bytes: scanned.canonical_bytes }, key));
        send({ type: "matrix", cls: c.class, mode: "scanned", ms,
               rows: scanned.useful_rows, cachedMb: image.length / 1048576 });
        matrices.push(scanned);
      }
    }

    const verifier = params.into_verifier(matrices);

    // 3. Live chain state, straight off the RPC. Untrusted by construction:
    //    a wrong byte anywhere makes the replay below reject.
    send({ type: "stage", stage: "fetch" });
    const terminalHex = await rpc("jetsam_getHistoryStepTerminal");
    const terminal = hex(terminalHex);
    // Deliberate corruption, for the "watch it reject a bad proof" demo. One
    // byte deep in the proof body, past the header, so this is the
    // cryptography rejecting it rather than a framing check.
    let tamperAt = -1;
    if (tamper) {
      tamperAt = Math.floor(terminal.length * 0.55);
      terminal[tamperAt] ^= 0x01;
      send({ type: "tampered", at: tamperAt, total: terminal.length });
    }
    // byte 0 = wire version, bytes 1..9 = height LE. Headers must match the
    // terminal's OWN height, not the chain tip (the tip runs ahead of it).
    const view = new DataView(terminal.buffer, terminal.byteOffset);
    const wireVersion = terminal[0];
    if (wireVersion !== KNOWN_WIRE_VERSION) {
      send({ type: "stale", saw: wireVersion, expected: KNOWN_WIRE_VERSION });
      return;
    }
    const height = view.getBigUint64(1, true);
    const anchor = height === 0n ? 0n : ((height - 1n) / TX_EPOCH_BLOCKS) * TX_EPOCH_BLOCKS;
    const [headerHex, epochHex, chain] = await Promise.all([
      rpc("jetsam_getHeaderByHeight", [Number(height)]),
      rpc("jetsam_getHeaderByHeight", [Number(anchor)]),
      rpc("jetsam_getChainInfo"),
    ]);
    send({ type: "chain", height: Number(height), anchor: Number(anchor),
           tip: chain.height, bytes: terminal.length });

    // 4. Replay the proof.
    send({ type: "stage", stage: "verify" });
    const t = performance.now();
    const out = JSON.parse(verifier.verify(terminal, hex(headerHex), hex(epochHex)));
    send({ type: "verified", ...out, seconds: (performance.now() - t) / 1000, trust,
           tamper, tamperAt });
  } catch (err) {
    send({ type: "failed", message: String(err && err.message ? err.message : err), tamper });
  }
};
