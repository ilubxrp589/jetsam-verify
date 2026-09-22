# Four changes that let the Jetsam verifier run in a browser

> **Status: not an open proposal.** This was written as a patch submission.
> The Jetsam maintainers have since said they will implement these changes
> themselves, so it is kept as the technical record of what had to move, why,
> and what was measured. The patches in `../patches/` apply to `v1.3.1` and
> build; they are a reference, not a request.

This page verifies Jetsam mainnet state entirely client-side in WebAssembly,
trusting nothing but the SHA256 of the published `jetsam-node-linux-x86_64`
release. It works against live mainnet, and it crossed the v1.3 fork:

    height 17910 · proof ~853 KB · v1.3 relation, rooted at 17749

Live: https://jtmverify.halcyon-names.io
Source and patches: https://github.com/ilubxrp589/jetsam-verify

This targets the public network because, when I started, the only published
testnet build was `testnet-v1.1.2`, which could not sync the live test chain
(`unsupported HistoryStep version 5`). The `*-testnet-*` binaries in v1.3.0
look like they resolve that; I have not retried.

**Against:** `381f35d` (tag `v1.3.1`). Verified against a pristine clone of
that tag: `git reset --hard v1.3.1 && git clean -fd`, all four apply, and the
workspace then BUILDS, native and wasm32. I check by building rather than by
`git apply --check`, because that check passes on a patch that deletes a file
without creating its replacement (`git diff` omits untracked files) and it
let exactly that through once. Apply with
`git apply 0001-*.patch 0002-*.patch 0003-*.patch 0004-*.patch`.

The measurements below were taken on v1.2.0 and I have not re-run them all.
v1.3's changes are in `consensus/` and the relation, which these patches do
not touch, and the class shapes are unchanged (m=22 and m=24, k_skip=6 in
both generations). The one number I did re-measure post-fork is the class-0
matrix scan, which patch 0003 speeds up: 61.6 s natively and 7:03 in a
browser on six threads.

Four changes were needed. **Three are useful to you regardless of browsers.**
Nothing here touches consensus, the wire format, the proof system, or any
cryptographic constant.

An earlier draft claimed 0003 speeds up node startup. It does not, and you
were right to correct it: `open_canonical` goes through
`open_build_authenticated` against a seal your pack preflight already
produced, so a node never runs that scan. It helps your release build and
anyone re-deriving from scratch, which is this page on a first visit.
`cargo check --workspace` is clean with all four applied.

---

## 0003. Parallel span hashing in the streaming matrix scan (start here)

**This is a straight speedup for your node, not a favour to my browser.**

`CompactFieldR1cs::open` walks the canonical matrix one span at a time and
hashes each span inline. The resident path (`matrix_span_digests`) already does
this with `into_par_iter()`. The streaming path does not, and that is the path
any third-party or cold-start loader uses.

Spans are independent for *hashing*, which is exactly what the two-level digest
was designed for. They are **not** independent for *decoding*: the stream
carries `previous_first` (zigzag first-column delta), `next_dictionary_index`
(global monotone rule) and variable-length group framing across span
boundaries. So the patch keeps decode strictly sequential and batches only the
Poseidon work:

- decode spans into bounded buffers (16 MB cap, so peak memory is independent
  of matrix size)
- hash the batch with `par_iter()`
- absorb digests **in order** (`par_iter().collect()` is an indexed parallel
  iterator, so the statement digest is bit-identical)

Measured, 6 cores:

| | before | after | |
|---|---|---|---|
| class 0 (m=22) | 148.70 s | 45.41 s | 3.27× |
| class 1 (m=24) | 644.16 s | 198.78 s | 3.24× |

Amdahl fit: ~17% sequential (decode), ~83% parallel. This is self-testing,
because the scan compares against the digest pinned in your metadata and would
reject any deviation. It did not.

I kept `StreamingOnePieceByteHash` with the same domain and `span_payload_len`
rather than switching to the resident hash function, so bit-exactness is
verifiable by inspection, and used `try_reserve_exact` with the existing
`Allocation` error rather than `with_capacity`, since the length comes from
untrusted artifact data.

## 0002. 4-bit comb carry-less multiply for targets without a clmul instruction

`clmul_gcm` dispatches to PCLMULQDQ / PMULL, and everything else falls to
`soft_clmul`, which was bit-serial: one iteration per set bit of `b` (~32),
each doing a full 128-bit multiply. wasm32 has no carry-less multiply at all,
not even in SIMD128, so it always takes that path.

Replaced with a 4-bit comb (Lopez-Dahab): precompute `a·u` for all 4-bit `u`,
then fold `b` a nibble at a time with Horner, so every shift is by a
compile-time constant and **no 128-bit multiply is emitted**. At least 2× on
the wasm scan; helps any non-x86/ARM target.

To be precise about scope: this **does** change the software fallback on every
target, including an x86 machine whose runtime check finds no PCLMULQDQ. The
output is bit-identical, and the patch ships the test that proves it: 50k
random pairs plus edge cases against a naive bit-by-bit reference, and 50k
random 128-bit pairs where `soft_clmul::clmul_block128` must equal `clmul_gcm`.
That second test is **the software path checked against real hardware
PCLMULQDQ**, which is the one that matters.

## 0004. `timing::Instant` shim for targets with no clock

`std::time::Instant::now()` panics on `wasm32-unknown-unknown`
(`std::sys::time::unsupported`), aborting the verifier. There are 192
unconditional call sites across 29 files in `jetsam_ivc_core`,
`jetsam_recursive`, `jetsam_fri_binius` and `jetsam_gkr`, all of it
instrumentation gated behind `NOIDH_C1_VERIFY_TIMING`.

Rather than touch 192 sites, each crate gets a `timing` module that is
`pub(crate) use std::time::Instant` on every normal target, and a zero-sized
stub returning `Duration::ZERO` on wasm. On anything but wasm this is a
re-export, so the compiled result is exactly what you have today. Usage
surface checked first: 209 `.elapsed()`, 6 `.duration_since()`, a few struct
fields.

## 0001. Make `jetsam_chain`'s storage (libmdbx) optional

`libmdbx`'s build.rs cannot cross-compile, so `jetsam_chain` cannot target
wasm at all. But `jetsam_recursive` only needs pure things from it:
`TX_EPOCH_BLOCKS`, `hash_block_header`, `block_reward`, `semantic_header_id`,
`BLOCK_PAGE_CLASS_TIERS`, `StateHash`, `BlockHeader`, `genesis_header`,
`TX_TREE_DEPTH`, `sparse_merkle`, `pressure_multiplier`, `SlotValue`. No
database.

Moves `storage/meta.rs` → `src/meta.rs` (`FinalizedCheckpoint`/`ConsensusMeta`
are plain data and were the only thing outside `storage/` needing it), gates
`pub mod storage` behind a default-on `storage` feature, and has
`jetsam_recursive` use `default-features = false`. Top-level re-exports keep
`jetsam_chain::FinalizedCheckpoint` identical. Default builds are unchanged.

---

## Evidence the verification is real, not reported

The page has a button that corrupts the proof before checking it. One bit
flipped at byte 478,291 of 869,620:

    FAILED: Verify(Auxiliary)   after 4 seconds

One bit in roughly seven million, caught by the cryptography rather than by a
framing or parse check. The proof was structurally well-formed and the maths
still rejected it.

## Two things I did NOT need to patch, for the record

- **The verifier's thread lanes.** `verifier.rs` builds its own rayon pools with
  64 MiB stacks; `ThreadPoolBuilder::build()` fails under wasm, where threads
  cannot be spawned that way. No patch was needed, because
  `set_budgeted_large_stack_worker(true)` is already public and is exactly the
  right hook. I supply the stack with `-C link-arg=-zstack-size=67108864` to
  honour its contract.
- **Matrix caching.** `encode_startup_packed_image` +
  `open_build_authenticated_packed_image` let a browser persist a matrix it
  authenticated itself and restore it in ~430 ms instead of rescanning.

## One ask, and it is the big one

**Please publish a digest for the packed matrix images alongside releases.**

Today a third-party verifier must re-derive the parameters from the canonical
artifacts, because there is no independently-checkable digest for the packed
form. That is a **~29 minute** first run in a browser. `load_cached_matrix`
already restores a packed image in **430 ms**, so a published packed digest
would replace 29 minutes of computation with a download, **with the trust model
unchanged**: still only the published hash, still no trust in whoever served
the bytes.

To be fair about the trade rather than overselling it: the packed images are
171 MB and 742 MB uncompressed against 3.68 MB and 12.42 MB for the canonical
artifacts, and I have not measured what they compress to. So this swaps a long
computation for a considerably larger transfer. On a desktop that is plainly the
better deal; I am less sure it helps a phone.

Smaller asks in the same area:
- **A chunked or streaming packed-image loader.** This is what would actually
  make a phone viable. Materialising a 742 MB image whole is why this is
  desktop-only: the cold run peaks near 4.3 GB and even a cached restore peaks
  near 3.7 GB, because the image is read out of browser storage and then copied
  into the wasm heap. Fed in pieces, neither peak would exist.
- `open_packed` is one atomic call, so a long scan cannot be resumed or report
  progress. The span batching in 0003 could expose a cursor.
- A documented third-party verifier entry point would help generally.

## Performance data you may find useful regardless

Profiled with `JETSAM_CPU_BACKEND=scalar` to separate "lost the SIMD" from
"wasm is slow":

| verify path | time | |
|---|---|---|
| native, AVX2/PCLMULQDQ | 5.27 s | 1× |
| native, **scalar** | 298.62 s | **56.7×** |
| wasm, in a worker | 318.99 s | 60.6× |

**wasm overhead is only 1.07×**. A browser runs your verifier at essentially
native speed. The entire gap is the absence of PCLMULQDQ/AES/GFNI/AVX2, which
wasm does not have. Worth knowing before anyone blames WebAssembly.

One softer observation, offered with its caveat: the 389 MB class-1 scan looks
memory-bandwidth bound rather than compute bound. Doubling logical cores gained
only 1.04× on it, while the proof replay gained 1.66× on the same jump. That
comparison is across two different machines, not a clean thread sweep on one,
so treat it as a hint rather than a result.

## Scope, honestly stated

Desktop only, and the page enforces it rather than warning about it: a phone
or tablet is offered no start button, because the first run peaks near 4.3 GB
and needs real worker threads. Cached parameters occupy roughly 913 MB of
browser storage, as 171 MB and 742 MB. Every verification after the first is
~853 KB and about two minutes, at any chain height, since proof size does not
grow with height.

James Turner
