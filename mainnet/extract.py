"""Pull the verifier's trust anchors out of a release node binary.

A v1.3 node carries **two** parameter packs, because one binary has to verify
blocks on both sides of the fork: the pre-fork pack that the chain ran on
since block one, and the v1.3 pack that governs blocks at and above the
activation height. Each pack is a run of canonical R1CS matrices followed by
the runtime metadata blob that names them, staged in that order by
jetsam_node/build.rs.

So this walks the binary in offset order, closes a pack every time it meets a
metadata blob, and writes each pack out separately. Nothing here decides which
pack the page should ship -- choose_pack.py does that against a digest, and
the whole thing is re-checked by actually verifying a live proof.
"""
import struct, subprocess, sys, pathlib

BIN = pathlib.Path("jetsam-node-linux-x86_64")
blob = BIN.read_bytes()
print(f"  binary {len(blob):,} bytes")

META_MAGIC = b"JETSAM/HSTEP/V1\x00"
ZMAGIC = b"\x28\xb5\x2f\xfd"
PEEK = 1 << 20          # enough input for zstd to emit the 32-byte header
LEAVES_PER_PACK = 2     # HISTORY_STEP_PACK_LEAF_COUNT


def unzstd(payload):
    # zstd exits non-zero on a truncated frame; the bytes it did emit are
    # still on stdout, which is all the header probe needs.
    return subprocess.run(["zstd", "-d", "-c"], input=payload,
                          capture_output=True).stdout


def find_all(needle):
    out, start = [], 0
    while True:
        i = blob.find(needle, start)
        if i < 0:
            return out
        out.append(i)
        start = i + 1


# ---------- locate every metadata blob ----------
metas = []
for i in find_all(META_MAGIC):
    version = struct.unpack_from("<H", blob, i + 16)[0]
    if version != 1:
        print(f"   metadata magic @0x{i:08x} version={version} (code literal, skipping)")
        continue
    body_len = struct.unpack_from("<Q", blob, i + 18)[0]
    total = 26 + body_len + 32
    if i + total > len(blob) or body_len > 8 << 20:
        continue
    metas.append((i, total))
    print(f"   metadata @0x{i:08x} version=1 total={total:,}")

# ---------- locate every canonical matrix ----------
mats = []
for i in find_all(ZMAGIC):
    head = unzstd(blob[i:i + PEEK])[:32]
    if head[:8] != b"NOIDR1CS":
        continue
    total_bytes = struct.unpack_from("<Q", head, 12)[0]
    m, k_log, k_skip = struct.unpack_from("<III", head, 20)
    mats.append((i, m, k_log, k_skip, total_bytes))
    print(f"   matrix   @0x{i:08x} m={m} k_log={k_log} k_skip={k_skip} "
          f"total_bytes={total_bytes:,}")

if not metas or not mats:
    sys.exit("!! this binary carries no embedded pack — nothing to extract")

# ---------- group into packs: matrices, then the metadata that names them ----------
packs, pending = [], []
for item in sorted(mats + [(off, "META", total) for off, total in metas],
                   key=lambda t: t[0]):
    if item[1] == "META":
        packs.append({"meta": (item[0], item[2]), "mats": pending})
        pending = []
    else:
        pending.append(item)
if pending:
    sys.exit(f"!! {len(pending)} matrices trail the last metadata blob — layout changed")

print(f"\n  {len(packs)} pack(s) in this binary")
for g, pack in enumerate(packs):
    if len(pack["mats"]) != LEAVES_PER_PACK:
        sys.exit(f"!! pack {g} has {len(pack['mats'])} matrices, expected {LEAVES_PER_PACK}")
    off, total = pack["meta"]
    meta = blob[off:off + total]
    pin = meta[-32:].hex()
    pathlib.Path(f"gen{g}-history-step.runtime").write_bytes(meta)
    print(f"  pack {g}: metadata {total:,} bytes  pin={pin}")
    # Ascending m is the class ladder HISTORY_STEP_CURRENT_CLASS_MS declares.
    for cls, (moff, m, k_log, k_skip, nbytes) in enumerate(
            sorted(pack["mats"], key=lambda t: t[1])):
        canonical = unzstd(blob[moff:])[:nbytes]   # zstd runs past the frame
        if len(canonical) != nbytes:
            sys.exit(f"!! short decode pack {g} class {cls}: {len(canonical)} != {nbytes}")
        out = pathlib.Path(f"gen{g}-canonical-c{cls:02d}.raw")
        out.write_bytes(canonical)
        print(f"           class {cls} m={m} k_log={k_log} k_skip={k_skip} -> {out} ({nbytes:,} bytes)")
