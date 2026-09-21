// Time the SAFE loader (CompactFieldR1cs::open_packed) under wasm in V8.
// zstd is done in JS on purpose: it keeps the C zstd out of the wasm graph,
// and a real browser would do the same with a JS zstd (fzstd) or plain bytes.
import { readFileSync } from "node:fs";
import { zstdDecompressSync } from "node:zlib";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const wasm = require("./pkg-node/jetsam_verify.js");

// Taken natively from the chain's own runtime metadata (testnet class 0).
const SHAPE  = { m: 22, k_log: 22, k_skip: 6, const_pin: 0 };
const DIGEST = "5e605e49f5fbf5a85b8c779a0e8ba2824d55aa4b08f7266b9c8962197647bebd";

const comp = readFileSync("assets/canonical-c00.zst");

let t = process.hrtime.bigint();
const canonical = zstdDecompressSync(comp, { maxOutputLength: 512 * 1024 * 1024 });
const tDecomp = Number(process.hrtime.bigint() - t) / 1e6;
console.log(`  shipped ${(comp.length / 1048576).toFixed(2)} MB -> expanded ` +
            `${(canonical.length / 1048576).toFixed(1)} MB in ${tDecomp.toFixed(1)} ms (JS zstd)`);

t = process.hrtime.bigint();
try {
  const desc = wasm.open_canonical(
    canonical, SHAPE.m, SHAPE.k_log, SHAPE.k_skip, SHAPE.const_pin,
    Buffer.from(DIGEST, "hex"),
  );
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  console.log(`\nWASM open_packed ACCEPTED in ${(ms / 1000).toFixed(2)} s`);
  console.log(`  ${desc}`);
} catch (e) {
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  console.log(`\nWASM open_packed REJECTED after ${(ms / 1000).toFixed(2)} s: ${e}`);
  process.exitCode = 1;
}
