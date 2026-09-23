// Read-only JSON-RPC gateway for the public Jetsam verifier page.
//
// WHY THIS EXISTS: the only synced mainnet node available is the FAUCET node
// on this LAN, and its RPC surface includes `jetsam_walletSend`,
// `jetsam_walletConsolidate`, `jetsam_walletGetBalance` and friends. Proxying
// that node directly at a public hostname would expose the ability to drain
// the faucet wallet. This gateway is DEFAULT-DENY: anything not on the
// allowlist below is refused before it ever reaches the node.
import { createServer } from "node:http";

// Point this at a Jetsam node's RPC. Keep that node's RPC on loopback.
const UPSTREAM   = process.env.JTM_RPC_UPSTREAM || "http://127.0.0.1:9701";
const PORT       = Number(process.env.JTM_RPC_PORT || 3097);
const MAX_BODY   = 8 * 1024;          // requests are tiny; replies may be large
const RATE_MAX   = 30;                // requests per window per IP
const RATE_MS    = 60_000;

// Exactly what the verifier page needs. Read-only. Nothing else, ever.
const ALLOWED = new Set([
  "jetsam_getChainInfo",
  "jetsam_getHistoryStepTerminal",
  "jetsam_getHeaderByHeight",
  "jetsam_getHeaderByHash",
  "jetsam_getEpochAnchor",
]);

// One method is assembled here rather than forwarded. The page's "is this
// block in the chain" walk needs every header from a block up to the verified
// tip, a node has no range method, and one request per header would run a
// visitor into the limit above long before a day of blocks. It is built only
// from the node's own read-only jetsam_getHeaderByHeight, so the node's
// surface is unchanged; the caps keep one request from becoming a burst of
// hundreds against it.
const RANGE_METHOD   = "jetsam_getHeadersByHeightRange";
const RANGE_MAX      = 250;           // headers per request
const RANGE_BUDGET   = 2_000;         // headers per window per IP
const RANGE_PARALLEL = 8;             // upstream calls in flight per request

const buckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || now - b.start > RATE_MS) { buckets.set(ip, { start: now, n: 1, headers: 0 }); return false; }
  b.n += 1;
  return b.n > RATE_MAX;
}
function overHeaderBudget(ip, count) {
  const b = buckets.get(ip);
  b.headers += count;
  return b.headers > RANGE_BUDGET;
}

async function upstreamCall(method, params) {
  const r = await fetch(UPSTREAM, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

class PastTip extends Error {}

// Headers start..start+count, ascending, or an error naming the first height
// the node does not have (a range past the tip).
async function headerRange(start, count) {
  const out = new Array(count);
  let next = 0;
  const lane = async () => {
    while (next < count) {
      const i = next++;
      out[i] = await upstreamCall("jetsam_getHeaderByHeight", [start + i]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(RANGE_PARALLEL, count) }, lane));
  const missing = out.findIndex((h) => typeof h !== "string");
  if (missing >= 0) throw new PastTip(`no header at height ${start + missing}`);
  return out;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of buckets) if (now - b.start > RATE_MS) buckets.delete(ip);
}, RATE_MS).unref();

// A Jetsam node refuses every browser request outright: the RPC server
// returns a static 403 to anything carrying an Origin header, before JSON-RPC
// dispatch, so that a web page cannot reach a wallet through a loopback
// listener. That is the right call, and it means a browser can only ever
// reach the chain through a non-browser proxy like this one. So if this
// gateway is to be usable by a page served from somewhere else, it has to say
// so in CORS terms itself.
//
// Every method this gateway allows is read-only and already public, so the
// default is open. Set ALLOW_ORIGIN to pin it to one page instead.
const ALLOW_ORIGIN = process.env.ALLOW_ORIGIN || "*";
const cors = (res) => {
  res.setHeader("access-control-allow-origin", ALLOW_ORIGIN);
  res.setHeader("access-control-allow-headers", "content-type");
  res.setHeader("access-control-allow-methods", "POST, OPTIONS");
  res.setHeader("access-control-max-age", "86400");
  if (ALLOW_ORIGIN !== "*") res.setHeader("vary", "origin");
  // Deliberately no Cross-Origin-Resource-Policy. COEP: require-corp accepts a
  // cross-origin response either because CORP allows it or because the request
  // passed a CORS check, and this one did. Setting it as well produced a second,
  // conflicting CORP header where a reverse proxy already adds same-origin.
};

const deny = (res, code, message, id = null) => {
  cors(res);
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }));
};

createServer((req, res) => {
  // A JSON content-type makes this a preflighted request, so OPTIONS has to
  // be answered before the POST is ever sent.
  if (req.method === "OPTIONS") { cors(res); res.writeHead(204).end(); return; }
  if (req.method !== "POST") { cors(res); res.writeHead(405).end("POST only"); return; }
  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress;
  if (rateLimited(ip)) { deny(res, -32029, "rate limited"); return; }

  // Opt-in diagnostics (?diag=1 on the page). Plain progress lines only, so a
  // run on someone else's machine can be watched from here. Nothing is sent
  // unless the visitor asks for it.
  if ((req.url || "").startsWith("/log")) {
    let t = "";
    req.on("data", (c) => { t += c; if (t.length > 512) req.destroy(); });
    req.on("end", () => {
      console.log(`[diag ${ip}] ${t.replace(/[\r\n]+/g, " ").slice(0, 400)}`);
      cors(res);
      res.writeHead(204).end();
    });
    return;
  }

  let body = "";
  let over = false;
  req.on("data", (c) => {
    body += c;
    if (body.length > MAX_BODY) { over = true; req.destroy(); }
  });
  req.on("end", async () => {
    if (over) return;
    let rpc;
    try { rpc = JSON.parse(body); } catch { deny(res, -32700, "parse error"); return; }

    // Reject batches outright: an array could smuggle a denied method past a
    // naive single-method check.
    if (Array.isArray(rpc)) { deny(res, -32600, "batch requests are not accepted"); return; }
    if (!rpc || typeof rpc.method !== "string") { deny(res, -32600, "invalid request"); return; }
    if (rpc.method === RANGE_METHOD) {
      const [start, count] = Array.isArray(rpc.params) ? rpc.params : [];
      if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(count)
          || count < 1 || count > RANGE_MAX) {
        deny(res, -32602, `params are [start, count] with 1 <= count <= ${RANGE_MAX}`, rpc.id ?? null);
        return;
      }
      if (overHeaderBudget(ip, count)) { deny(res, -32029, "header budget exceeded", rpc.id ?? null); return; }
      try {
        const result = await headerRange(start, count);
        cors(res);
        res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: rpc.id ?? 1, result }));
      } catch (e) {
        if (e instanceof PastTip) { deny(res, -32602, e.message, rpc.id ?? null); return; }
        console.log(`[upstream error] ${RANGE_METHOD}: ${e.message}`);
        deny(res, -32603, "upstream unavailable", rpc.id ?? null);
      }
      return;
    }
    if (!ALLOWED.has(rpc.method)) {
      console.log(`[deny] ${ip} ${rpc.method}`);
      deny(res, -32601, "method not available through this gateway", rpc.id ?? null);
      return;
    }
    if (rpc.params !== undefined && (!Array.isArray(rpc.params) || rpc.params.length > 4)) {
      deny(res, -32602, "invalid params", rpc.id ?? null);
      return;
    }

    // Rebuild the request rather than forwarding the client's bytes/headers.
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: rpc.id ?? 1,
      method: rpc.method,
      params: rpc.params ?? [],
    });
    try {
      const upstream = await fetch(UPSTREAM, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: payload,
        signal: AbortSignal.timeout(60_000),
      });
      const text = await upstream.text();
      cors(res);
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(text);
    } catch (e) {
      console.log(`[upstream error] ${rpc.method}: ${e.message}`);
      deny(res, -32603, "upstream unavailable", rpc.id ?? null);
    }
  });
}).listen(PORT, "127.0.0.1", () =>
  console.log(`jtm read-only rpc gateway on 127.0.0.1:${PORT} -> ${UPSTREAM} ` +
              `(${ALLOWED.size} methods allowed, plus ${RANGE_METHOD})`));
