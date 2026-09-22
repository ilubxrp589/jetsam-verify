# jetsam-verify

Verify the Jetsam (JTM) chain in a browser tab, trusting nothing but one
published hash.

**Live: https://jtmverify.halcyon-names.io**

    height 17973 · proof ~853 KB · verified in 2:08 in a browser tab, 64 s natively

A recursive `HistoryStep` proof means one ~853 KB blob proves the chain at any
height, and the size does not grow as the chain grows. This page fetches that
blob from an RPC it does not trust, re-derives the proving parameters locally,
and replays the proof in WebAssembly. Bitcoin SPV trusts miners for
state; Ethereum light clients trust a sync committee; this trusts the SHA256 of
the published `jetsam-node` release, which anyone can check on the project's
releases page.

There is a button on the page that flips one bit of the proof before checking
it. That is rejected in about four seconds with `Verify(Auxiliary)`, so the
rejection comes from the cryptography rather than from a parse check.

## Which chain history this covers

Jetsam changed relation at block 17750. A v1.3 proof does not recurse back to
genesis: it proves forward from the boundary at block 17749, and carries that
boundary in its public IO. The page rebuilds the boundary from the three
permanent headers that define it and compares the two, exactly as a node does,
so a valid proof of a *different* branch at that height is rejected as
`ForeignRecursionRoot`.

What that does not do is re-prove the history before 17750. That history was
proved under the previous relation, whose parameters this page does not carry.
The result stamp says so rather than leaving it implied.

## What it costs

| | |
|---|---|
| first visit, re-deriving the parameters | about 36 minutes at six threads, once |
| stored afterwards (IndexedDB) | 913 MB, as 171 + 742 |
| every verification after that | ~853 KB and about two minutes, at any height |
| the same work natively, one class | 64 seconds including the matrix scan |

Measured at six worker threads on a machine that was also busy, so the scans
read high if anything; the replay figure is the mean of three runs. The
pre-fork numbers are not carried over, since the relation and the matrices
both changed and the old replay estimate was out by more than a factor of two.

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

    git clone --branch v1.3.1 https://github.com/jetsam-chain/jetsam.git jetsam
    cd jetsam && git apply ../patches/000*.patch && cd ..
    cargo build --release        # the patches must BUILD, not merely apply

That last line is not a formality. `git apply --check` passes on a patch that
deletes a file without creating its replacement, because `git diff` omits
untracked files; only a build against a clean checkout catches it.

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

The page needs the runtime metadata and one canonical matrix per proof class,
all extracted from the official release binary, which is why nothing here has
to be trusted. `./repoint.sh <tag>` does the whole job: download, check against
the published `SHA256SUMS`, extract, choose, compress, and print the new pin.

A v1.3 binary carries **two** parameter packs, one relation for blocks before
the activation height and one for blocks after it, so "extract the parameters"
has two answers. `mainnet/extract.py` writes every pack it finds by scanning for
the shape header rather than a file offset, and `repoint.sh` then picks the one
whose generation governs the current tip, asking the build the same question a
node asks:

    ./target/release/print_pins --generation-at 17896      # -> v1.3
    ./target/release/print_pins mainnet/gen0-history-step.runtime

Assets are deliberately not committed: deriving them yourself from the verified
binary is the point.

    ./target/release/verify_terminal [rpc-url]

is the acceptance test. It is the native twin of the page (same relation, same
headers, same checks) and it verifies against a live node, so a pack that is
merely well-formed but wrong cannot pass it.

## Serving it

`deploy.sh` publishes to `/var/www/jtmverify`. The vhost must set:

- `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`, or there is no
  `SharedArrayBuffer`, the engine silently drops to one thread, and the first
  run takes about 95 minutes instead of 29
- `Content-Encoding: zstd` on `*.zst`, so the browser inflates the matrices
  natively (3.66 MB to 81.5 MB in about 114 ms) and no JS zstd decoder is needed
- a rewrite from `/pkg-web/` to `/pkg-web/jetsam_verify.js`, because
  wasm-bindgen-rayon's worker imports the package *directory*. Without it the
  thread pool waits forever for `wasm_bindgen_worker_ready` and nothing loads.

`rpc-proxy.mjs` is a read-only JSON-RPC gateway with a **default-deny
allowlist** of five methods. Do not point a public page straight at a node:
a node's RPC surface includes `jetsam_walletSend` and `jetsam_walletConsolidate`.
Batch requests are refused outright, since an array could otherwise smuggle a
denied method past a naive single-method check.

It answers cross-origin callers, so the page can be pointed at someone else's
copy of it. `ALLOW_ORIGIN` pins that to one page; the default is open, since
every method it allows is read-only and already public. It sets no
`Cross-Origin-Resource-Policy`: a CORS-approved fetch already satisfies
`COEP: require-corp`, and adding one produced a second, conflicting header
wherever a reverse proxy sets `same-origin` already.

## Bringing your own proof source

The page takes an endpoint, because "we do not trust the server" is easier to
believe when you pick the server. It changes nothing about the result: a wrong
byte from any source makes the replay reject, which is the entire design.

It has to be a **gateway, not a node**. A Jetsam node returns a static `403` to
any request carrying an `Origin` header, before JSON-RPC dispatch, so that a
web page cannot reach a wallet through a loopback listener
(`jetsam_rpc/src/server.rs`). That is the right call, and it means no browser
will ever talk to a node directly, whoever runs it. The page says so, and a
custom endpoint is probed with one request before the ninety-second digest
starts, so a typo costs a second rather than a minute and a half.

## Trust, stated precisely

Two levels, and the page labels which one produced a result:

- **FULL** re-derives the parameters from the canonical artifacts on this
  machine. Trusts only the published release hash.
- **CACHED** reuses parameters this browser authenticated on an earlier visit.
  Still trusts no server, but it does trust the browser's own IndexedDB, which
  is a weaker claim and is shown as such.

The cache is keyed by the pinned digest, so a re-point invalidates it rather
than silently verifying new proofs against old parameters.

A page pinned to one release will eventually meet a chain that has moved past
it, and "verification failed" would be a false alarm on the one page that must
not cry wolf. The split is **where** it failed:

- the bytes never parsed as a terminal of this relation, so no cryptography ran
  on them. Reported amber. Nothing was verified and nothing failed a check.
- the frame parsed as ours and then did not check out. Reported crimson, loudly.
  The tamper button lands here, as `Verify(Auxiliary)`.

Two things this got wrong on the first pass, both caught by measuring instead of
reasoning. The signal was originally the terminal's wire-version byte, and v1.3
changed the relation while leaving that byte at 5, so the page would have shown
a crimson failure on the one upgrade it was built to survive. The replacement
keyed on `ForeignIoLayout`, which is upstream's own name for "a well-formed
terminal of another relation" but is not the only shape the case takes: feeding
the pre-fork parameters a post-fork terminal actually yields `WireEncoding`,
because the older encoding accepts a *range* of frame lengths and the newer
frame fits inside it, is read at the wrong IO width, and desynchronises. The
net is now every frame-level variant, which is wider than "out of date" and the
page words it accordingly: bytes that will not parse are also what a broken or
hostile server returns, and the page does not claim to know which.

There is one case it can name exactly. This build's own activation schedule
says which relation governs any given height, so a terminal for a block on the
other side of a fork this build knows about is reported as a definite version
mismatch rather than an unreadable frame. That covers a node serving a pre-fork
proof; it cannot cover a fork this build has never heard of, which is why the
wider net exists too.

## Licence

The patches in `patches/` are against `jetsam-chain/jetsam` and carry that
project's licence (MIT OR Apache-2.0). Everything else here is MIT.
