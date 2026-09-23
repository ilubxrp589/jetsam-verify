// Dev server for the verifier page, serving the same flat layout deploy.sh
// publishes: the page, worker and fonts from web/, pkg-web/ and assets/ from
// the repo root, all at one level.
//   * COOP/COEP so SharedArrayBuffer exists -> wasm threads work.
//   * .zst served with Content-Encoding: zstd so the BROWSER decompresses it.
//     Chrome 123+/Firefox 126+ do this natively, which saves shipping a JS
//     zstd decoder just to expand 471 MB of matrices.
import { createReadStream, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
// The page's default proof source is same-origin `rpc`. Forwarded to a
// read-only gateway, never to a node: see rpc-proxy.mjs for why.
const GATEWAY = process.env.JTM_GATEWAY || "http://127.0.0.1:3097/";
const TYPES = { ".html":"text/html", ".js":"text/javascript", ".wasm":"application/wasm",
                ".json":"application/json", ".hex":"text/plain", ".css":"text/css" };

createServer((req, res) => {
  if (req.method === "POST" && req.url === "/rpc") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", async () => {
      try {
        const r = await fetch(GATEWAY, { method: "POST", body,
          headers: { "content-type": "application/json" } });
        res.writeHead(r.status, { "content-type": "application/json" }).end(await r.text());
      } catch (e) {
        res.writeHead(502).end(`gateway ${GATEWAY} unreachable: ${e.message}`);
      }
    });
    return;
  }
  if (req.method === "POST" && req.url === "/log") {
    let body = "";
    req.on("data", c => body += c);
    req.on("end", () => { console.log("  [page] " + body); res.writeHead(204).end(); });
    return;
  }
  const rel = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^(\.\.[/\\])+/, "");
  // web/ first, so "/verify-worker.js" finds the source file, then the root.
  let path, st;
  for (const c of rel === "/" ? ["web/index.html"] : [join("web", rel), rel]) {
    try { path = join(ROOT, c); st = statSync(path); break; } catch { st = null; }
  }
  if (!st) { res.writeHead(404).end("not found"); return; }
  // wasm-bindgen-rayon's worker does `import('../../..')`, i.e. it imports the
  // package DIRECTORY. Bundlers resolve that through package.json; a plain
  // static server has to do it too, or the workers never load and
  // initThreadPool hangs forever waiting for 'wasm_bindgen_worker_ready'.
  if (st.isDirectory()) {
    try {
      const pkg = JSON.parse(readFileSync(join(path, "package.json"), "utf8"));
      const entry = pkg.module || pkg.main;
      if (entry) { path = join(path, entry); st = statSync(path); }
      else throw new Error("no entry");
    } catch {
      res.writeHead(404).end("not found");
      return;
    }
  }

  const headers = {
    // Required for SharedArrayBuffer.
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Content-Type": TYPES[extname(path)] || "application/octet-stream",
  };
  if (path.endsWith(".zst")) {
    headers["Content-Encoding"] = "zstd";       // browser inflates it for us
    delete headers["Content-Length"];
  } else {
    headers["Content-Length"] = st.size;
  }
  res.writeHead(200, headers);
  const stream = createReadStream(path);
  stream.on("error", (e) => { console.log("  [stream error] " + rel + ": " + e.code); res.end(); });
  stream.pipe(res);
}).listen(8099, "127.0.0.1", () => console.log("  serving http://127.0.0.1:8099"));
