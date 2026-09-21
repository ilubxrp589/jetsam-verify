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

const buckets = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const b = buckets.get(ip);
  if (!b || now - b.start > RATE_MS) { buckets.set(ip, { start: now, n: 1 }); return false; }
  b.n += 1;
  return b.n > RATE_MAX;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of buckets) if (now - b.start > RATE_MS) buckets.delete(ip);
}, RATE_MS).unref();

const deny = (res, code, message, id = null) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }));
};

createServer((req, res) => {
  if (req.method !== "POST") { res.writeHead(405).end("POST only"); return; }
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
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(text);
    } catch (e) {
      console.log(`[upstream error] ${rpc.method}: ${e.message}`);
      deny(res, -32603, "upstream unavailable", rpc.id ?? null);
    }
  });
}).listen(PORT, "127.0.0.1", () =>
  console.log(`jtm read-only rpc gateway on 127.0.0.1:${PORT} -> ${UPSTREAM} (${ALLOWED.size} methods allowed)`));
