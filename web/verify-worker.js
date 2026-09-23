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
// poseidon2b digest of the v1.3 runtime metadata embedded in jetsam-node
// v1.3.1, whose SHA256 is published on the project's GitHub releases page.
//
// A v1.3 node carries two parameter packs, because one binary verifies blocks
// on both sides of the fork. This is the digest of the second one: the
// relation that governs blocks from the activation height on, which is every
// block this page will ever be shown.
const PIN = "99c447656912c9030b2cf893f5bab78b360ad8cfdad73bf668a90d270c54e3c9";
// The release that digest was extracted from. It travels with the pin because
// the two only ever change together, and naming the wrong release beside a
// right digest is as misleading as getting the digest wrong.
const RELEASE = "v1.3.1";

const send  = (m) => self.postMessage(m);
const hex   = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const bytes = async (u) => new Uint8Array(await (await fetch(u)).arrayBuffer());

// Where the proof and headers are fetched from. Same-origin by default; a
// visitor can point this anywhere, because nothing here is trusted: every byte
// that arrives is checked by the replay, and a wrong one makes it reject.
let rpcUrl = "rpc";

async function rpc(method, params = []) {
  let r;
  try {
    r = await fetch(rpcUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
  } catch {
    // A network-level failure here is almost always CORS, and the usual cause
    // is pointing this at a node rather than at a gateway.
    throw new Error(`could not reach ${rpcUrl}. A browser can only talk to a ` +
      `CORS-enabled read-only gateway: a Jetsam node refuses every request ` +
      `that carries an Origin header.`);
  }
  if (!r.ok) {
    throw new Error(r.status === 403
      ? `${rpcUrl} returned 403, which is what a Jetsam node returns to any ` +
        `browser request. Point this at a read-only gateway instead.`
      : `${rpcUrl} returned HTTP ${r.status}`);
  }
  const j = await r.json();
  if (j.error) {
    const err = new Error(`${method}: ${j.error.message}`);
    err.code = j.error.code;
    throw err;
  }
  return j.result;
}

// "Is block h in this chain" walks parent links from the verified tip down to
// h, one header per block, so it is capped: about a day of blocks.
const MAX_WALK = 1000;
// Headers per range request; rpc-proxy.mjs refuses more.
const RANGE_MAX = 250;
// A source without the range method is asked one header at a time, and that
// only makes sense for a short walk.
const MAX_WALK_SINGLE = 100;

// The raw headers of blocks from..to (exclusive), concatenated, ascending.
// Nothing here is trusted: VerifiedTip.walk_to hashes every one of them.
async function headersBetween(from, to) {
  const hexes = [];
  for (let start = from; start < to; start += RANGE_MAX) {
    const count = Math.min(RANGE_MAX, to - start);
    let batch, rest = false;
    try {
      batch = await rpc("jetsam_getHeadersByHeightRange", [start, count]);
    } catch (err) {
      if (err.code !== -32601) throw err;
      if (to - from > MAX_WALK_SINGLE)
        throw new Error(`this source has no header ranges, so it can only walk ${MAX_WALK_SINGLE} ` +
                        `blocks below the tip`);
      batch = [];
      for (let h = start; h < to; h++) batch.push(await rpc("jetsam_getHeaderByHeight", [h]));
      rest = true;
    }
    const want = rest ? to - start : count;
    if (!Array.isArray(batch) || batch.length !== want)
      throw new Error(`the source returned ${Array.isArray(batch) ? batch.length : "no"} of ` +
                      `${want} headers from block ${start}`);
    hexes.push(...batch);
    if (rest) break;
  }
  const out = new Uint8Array(hexes.length * 212);
  hexes.forEach((h, i) => {
    if (typeof h !== "string" || h.length !== 424)
      throw new Error(`the header for block ${from + i} is not 212 bytes`);
    out.set(hex(h), i * 212);
  });
  return out;
}

// The tip the last verification accepted: the only place a walk can start.
let verifiedTip = null;
// The lowest block a walk may reach: the cap below the tip, and never under
// the recursion root, whose earlier blocks another relation proved.
const walkFrom = (tip) => Math.max(Number(tip.root_height), Number(tip.height) - MAX_WALK);

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

// Started once and reused. rayon's global pool can only be built once, so a
// second initThreadPool panics inside wasm-bindgen-rayon and surfaces as
// "called `Result::unwrap_throw()` on an `Err` value" -- which reads like a
// verification failure and is not one. Every button on the page that starts a
// second run reached that, because each successful run so far had been a fresh
// page load.
let engine = null;
const startEngine = () => (engine ??= (async () => {
  await init();
  await initThreadPool(navigator.hardwareConcurrency);
  return thread_count();
})());

self.onmessage = async (e) => {
  const cmd = e.data?.type;
  if (cmd === "probe") {
    // The page renders the digest plate from this, rather than from a copy of
    // the hash pasted into the HTML. A second copy is a second thing to forget
    // at a re-point, and the plate is the one value a visitor is told to check
    // against the published release.
    send({ type: "probe", cached: await cacheState(), isolated: self.crossOriginIsolated,
           cores: navigator.hardwareConcurrency || 0, pin: PIN, release: RELEASE });
    return;
  }
  if (cmd === "walk") {
    const target = Number(e.data?.height);
    try {
      if (!verifiedTip)
        throw new Error("verify the chain first: a walk starts from the block the proof accepted");
      const tip = Number(verifiedTip.height);
      const lowest = walkFrom(verifiedTip);
      if (!Number.isSafeInteger(target) || target < lowest || target >= tip)
        throw new Error(`choose a block from ${lowest} to ${tip - 1}`);
      send({ type: "walking", target, tip, links: tip - target });
      const t = performance.now();
      const bytes = await headersBetween(target, tip);
      const out = JSON.parse(verifiedTip.walk_to(BigInt(target), bytes));
      send({ type: "walked", ...out, target, tip, ms: performance.now() - t });
    } catch (err) {
      send({ type: "walk-failed", target, message: String(err && err.message ? err.message : err) });
    }
    return;
  }
  if (cmd !== "run") return;
  // A new run supersedes whatever the last one accepted.
  verifiedTip?.free();
  verifiedTip = null;
  const tamper = e.data?.tamper === true;
  // Only http(s) absolute urls, or the same-origin default. Nothing here is
  // trusted, but the page should not be talked into a javascript: or data: url.
  const asked = typeof e.data?.rpcUrl === "string" ? e.data.rpcUrl.trim() : "";
  rpcUrl = "rpc";
  if (asked) {
    try {
      const u = new URL(asked, self.location.href);
      if (u.protocol !== "http:" && u.protocol !== "https:")
        throw new Error("only http and https endpoints are accepted");
      rpcUrl = u.href;
    } catch (err) {
      send({ type: "failed", message: `proof source: ${err.message || err}`, tamper });
      return;
    }
  }
  send({ type: "source", url: rpcUrl, own: rpcUrl !== "rpc" });
  // Reach the endpoint before committing to ninety seconds of Poseidon. A
  // typo, a node instead of a gateway, or a gateway without CORS should cost
  // one request to discover, not a minute and a half.
  if (rpcUrl !== "rpc") {
    try {
      await rpc("jetsam_getChainInfo");
    } catch (err) {
      send({ type: "failed", message: String(err && err.message ? err.message : err), tamper });
      return;
    }
  }

  let trust = "full";
  // Freed explicitly when the run ends. It holds both matrices, close to a
  // gigabyte of wasm memory, and the FinalizationRegistry the bindings rely on
  // runs only after a JS garbage collection, which that memory never prompts.
  // Left to it, each "Verify again" stacked another copy under the 4 GB cap: a
  // second run measured an 84 s cache restore instead of 3 s.
  let verifier = null;
  try {
    send({ type: "stage", stage: "engine" });
    const threads = await startEngine();
    send({ type: "engine", threads, isolated: self.crossOriginIsolated });

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

    verifier = params.into_verifier(matrices);

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
    // byte 0 = wire version, bytes 1..9 = height LE. Which headers this
    // relation needs is the relation's business, not the page's, so the
    // engine is asked rather than guessed at: v1.3 binds a second, older
    // epoch anchor, and it proves forward from the fork boundary instead of
    // genesis, which needs three more headers to rebuild that boundary.
    const view = new DataView(terminal.buffer, terminal.byteOffset);
    const height = view.getBigUint64(1, true);
    const need = JSON.parse(verifier.required_heights_json(height));

    const header = (h) => (h === null || h === undefined)
      ? Promise.resolve(null)
      : rpc("jetsam_getHeaderByHeight", [Number(h)]);
    const [headerHex, epochHex, prevEpochHex, chain] = await Promise.all([
      header(need.terminal.height),
      header(need.terminal.epoch_anchor),
      header(need.terminal.previous_epoch_anchor),
      rpc("jetsam_getChainInfo"),
    ]);
    // The boundary the v1.3 recursion starts from, rebuilt here from
    // permanent headers exactly as a node rebuilds it. Nothing about it is
    // shipped or trusted: the engine compares what it derives against the
    // root the proof itself carries in its public IO.
    const [rootHex, rootEpochHex, rootPrevEpochHex] = need.root
      ? await Promise.all([
          header(need.root.height),
          header(need.root.epoch_anchor),
          header(need.root.previous_epoch_anchor),
        ])
      : [null, null, null];
    send({ type: "chain", height: Number(height), anchor: Number(need.terminal.epoch_anchor),
           tip: chain.height, bytes: terminal.length,
           root: need.root ? Number(need.root.height) : null });

    // 4. Replay the proof.
    send({ type: "stage", stage: "verify" });
    const t = performance.now();
    const b = (h) => (h === null || h === undefined) ? undefined : hex(h);
    const out = JSON.parse(verifier.verify(
      terminal, hex(headerHex), hex(epochHex), b(prevEpochHex),
      b(rootHex), b(rootEpochHex), b(rootPrevEpochHex)));
    const seconds = (performance.now() - t) / 1000;
    // Default deny. Only the exact word "verified" is a pass; a status this
    // page does not recognise is a failure, never a success.
    if (out.status === "verified") {
      verifiedTip = verifier.verified_tip() ?? null;
      send({ type: "verified", ...out, seconds, trust, tamper, tamperAt,
             walk_from: verifiedTip ? walkFrom(verifiedTip) : null });
    } else if (out.status === "stale") {
      send({ type: "stale", reason: out.reason, generation: out.generation,
             certain: out.certain === true, pin: PIN });
    } else {
      send({ type: "failed", message: out.reason || `unrecognised result: ${out.status}`,
             tamper });
    }
  } catch (err) {
    send({ type: "failed", message: String(err && err.message ? err.message : err), tamper });
  } finally {
    verifier?.free();
  }
};
