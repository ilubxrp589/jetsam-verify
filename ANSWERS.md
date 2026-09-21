# Likely questions from the Jetsam devs, and the answers

Short answers you can give directly. If they go deeper than this, say so and
come back to me rather than guessing.

## "How do you know the parallel span hashing preserves order?"

`par_iter().collect()` in Rayon is an *indexed* parallel iterator, so collecting
into a `Vec` returns results in input order regardless of which thread finished
first. The digests are then absorbed into the top hash in that order, exactly as
the sequential version did.

It is also self-checking rather than something you have to take on faith: the
scan compares the digest it derives against the one pinned in your own runtime
metadata. If the order were wrong by a single span the digest would differ and
the load would reject. It does not, on both matrix classes.

## "Why not switch to the resident hash function while you're in there?"

Deliberately not. I kept `StreamingOnePieceByteHash` with the same domain string
and the same `span_payload_len`, so the construction is identical to what the
sequential path did and bit-exactness can be confirmed by reading it. Swapping
in `matrix_span_digests`'s hash would have been a second change to reason about.

## "Is the batching memory-safe? This reads untrusted artifact data."

Batches are capped at 16 MB, so peak memory is independent of matrix size.
Buffers use `try_reserve_exact` and map failure onto the existing
`FieldR1csArtifactError::Allocation`, rather than `with_capacity`, because the
length is derived from the artifact and an artifact is attacker-controlled.

## "Does the comb change behaviour on x86?"

Yes, and I say so in the writeup. It replaces the software fallback on every
target, which an x86 machine reaches if its runtime check finds no PCLMULQDQ.
The output is bit-identical and the patch ships the test that proves it: 50k
random 128-bit pairs where the software path must equal `clmul_gcm`, which on
that machine is hardware PCLMULQDQ.

## "You use the unsafe packed-image loader. Aren't you bypassing authentication?"

Only to restore a matrix that this same browser authenticated earlier with the
safe `open_packed` path, then serialised with `encode_startup_packed_image`.
The shape and structural digest passed to the seal come from the runtime
metadata, which authenticates against the pinned release digest. They never come
from the cached blob.

That is still weaker than a full re-derivation, because it trusts the browser's
own IndexedDB, and the page labels it as such: a result from cached parameters
is badged CACHED, not FULL, with the difference spelled out.

## "Has it actually verified anything?"

Live mainnet at heights 16478, 16480, 16501 and 16511, with the proof between
849 and 854 KB each time and the replay around three minutes. The page also has
a button that flips one bit of the proof before checking; that is rejected in
about four seconds with `Verify(Auxiliary)`, so the rejection is cryptographic
rather than a parse failure.

## "What Rust toolchain does the browser build need?"

Nightly, because wasm threads need `-Z build-std` to rebuild `std` with atomics.
Note that `[unstable] build-std` in `.cargo/config.toml` is silently ignored;
it only takes effect on the command line or via `CARGO_UNSTABLE_BUILD_STD`.
None of that affects your builds, only mine.

## If they ask something I have not covered

Say you had AI assistance on the implementation and you would rather check than
guess. That is a better answer than a confident wrong one, and it is the same
thing you already told them.
