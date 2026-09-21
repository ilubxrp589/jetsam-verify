# jetsam-verify

Verify the Jetsam (JTM) chain in a browser tab, trusting nothing but one
published hash.

**Live: https://jtmverify.halcyon-names.io**

    height 16501 · proof 853 KB · verified in 3:03 in a browser tab

A recursive `HistoryStep` proof means one ~872 KB blob proves the whole chain at
any height, and the size does not grow as the chain grows. This page fetches
that blob from an RPC it does not trust, re-derives the proving parameters
locally, and replays the proof in WebAssembly. Bitcoin SPV trusts miners for
state; Ethereum light clients trust a sync committee; this trusts the SHA256 of
the published `jetsam-node` release, which anyone can check on the project's
releases page.

There is a button on the page that flips one bit of the proof before checking
it. That is rejected in about four seconds with `Verify(Auxiliary)`, so the
rejection comes from the cryptography rather than from a parse check.

## What it costs

| | |
|---|---|
| first visit, re-deriving the parameters | about 29 minutes, once |
| stored afterwards (IndexedDB) | about 913 MB |
| every verification after that | 853 KB and about 3 minutes, at any height |
| the same work on a native node | 5.3 seconds |

Desktop only. The first run peaks near 4.3 GB of memory and needs
`SharedArrayBuffer`, so it will not complete on a phone.

It is slow for one reason: Jetsam's cryptography leans on CPU instructions that
WebAssembly does not have. Profiling with `JETSAM_CPU_BACKEND=scalar` separates
the two causes:

| verify path | time | |
|---|---|---|
| native, AVX2/PCLMULQDQ | 5.27 s | 1x |
| native, scalar | 298.62 s | 56.7x |
| wasm, in a worker | 318.99 s | 60.6x |

WebAssembly's own overhead is only 1.07x. The whole gap is the absence of
PCLMULQDQ, AES, GFNI and AVX2.

## Build

You need the upstream source at `./jetsam` with the four patches in `patches/`
applied. Those patches are what make the verifier cross-compile, and one of
them is a 3.2x speedup to the matrix scan that helps a native node too.

    git clone --branch v1.3.0 https://github.com/jetsam-chain/jetsam.git jetsam
    cd jetsam && git apply ../patches/000*.patch && cd ..

Wasm threads need nightly, `build-std`, and the linker flags already in
`.cargo/config.toml`:

    rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly
    rustup target add wasm32-unknown-unknown --toolchain nightly
    RUSTUP_TOOLCHAIN=nightly CARGO_UNSTABLE_BUILD_STD="panic_abort,std" \
      wasm-pack build --release --target web --out-dir pkg-web

Note that `[unstable] build-std` in `.cargo/config.toml` is silently ignored by
cargo; it only works passed on the command line or through
`CARGO_UNSTABLE_BUILD_STD`, and without it you get a confusing
"failed to find `__wasm_init_tls`" much later.

## Assets

The page needs three files extracted from the official release binary, which is
why nothing here has to be trusted:

    mainnet/extract.py       metadata + the class-0 canonical matrix
    mainnet/extract_c01.py   the class-1 canonical matrix
    mainnet/fetch_chain.py   a live proof and its matching headers

Download `jetsam-node-linux-x86_64`, check it against the published
`SHA256SUMS`, then run those. They are deliberately not committed: deriving them
yourself from the verified binary is the point.

## Serving it

`deploy.sh` publishes to `/var/www/jtmverify`. The vhost must set:

- `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`, or there is no
  `SharedArrayBuffer`, the engine silently drops to one thread, and the first
  run takes about 95 minutes instead of 29
- `Content-Encoding: zstd` on `*.zst`, so the browser inflates the matrices
  natively (3.68 MB to 81.9 MB in about 114 ms) and no JS zstd decoder is needed
- a rewrite from `/pkg-web/` to `/pkg-web/jetsam_verify.js`, because
  wasm-bindgen-rayon's worker imports the package *directory*. Without it the
  thread pool waits forever for `wasm_bindgen_worker_ready` and nothing loads.

`rpc-proxy.mjs` is a read-only JSON-RPC gateway with a **default-deny
allowlist** of five methods. Do not point a public page straight at a node:
a node's RPC surface includes `jetsam_walletSend` and `jetsam_walletConsolidate`.
Batch requests are refused outright, since an array could otherwise smuggle a
denied method past a naive single-method check.

## Trust, stated precisely

Two levels, and the page labels which one produced a result:

- **FULL** re-derives the parameters from the canonical artifacts on this
  machine. Trusts only the published release hash.
- **CACHED** reuses parameters this browser authenticated on an earlier visit.
  Still trusts no server, but it does trust the browser's own IndexedDB, which
  is a weaker claim and is shown as such.

## Licence

The patches in `patches/` are against `jetsam-chain/jetsam` and carry that
project's licence (MIT OR Apache-2.0). Everything else here is MIT.
