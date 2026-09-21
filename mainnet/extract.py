import struct, subprocess, sys, pathlib

blob = pathlib.Path("jetsam-node-linux-x86_64").read_bytes()
print(f"  binary {len(blob):,} bytes")

# ---------- 1. HistoryStep runtime metadata ----------
MAGIC = b"JETSAM/HSTEP/V1\x00"
found = None
start = 0
while True:
    i = blob.find(MAGIC, start)
    if i < 0:
        break
    start = i + 1
    version = struct.unpack_from("<H", blob, i + 16)[0]
    if version != 1:
        print(f"   magic @0x{i:08x} version={version} (code literal, skipping)")
        continue
    body_len = struct.unpack_from("<Q", blob, i + 18)[0]
    total = 26 + body_len + 32
    if i + total > len(blob) or body_len > 8 << 20:
        continue
    print(f"   magic @0x{i:08x} version=1 body_len={body_len:,} total={total:,}")
    found = blob[i:i + total]
pathlib.Path("../assets/history-step.runtime.mainnet").write_bytes(found)
print(f"  metadata -> assets/history-step.runtime.mainnet ({len(found):,} bytes)")

# ---------- 2. canonical matrices (zstd frames whose payload is NOIDR1CS) ----------
ZMAGIC = b"\x28\xb5\x2f\xfd"
def peek(off, n=64):
    p = subprocess.run(["zstd", "-d", "-c"], input=blob[off:],
                       capture_output=True)
    return p.stdout[:n] if p.stdout else b""

start = 0
hits = []
while True:
    i = blob.find(ZMAGIC, start)
    if i < 0:
        break
    start = i + 1
    head = peek(i)
    if head[:8] != b"NOIDR1CS":
        continue
    total_bytes = struct.unpack_from("<Q", head, 12)[0]
    m = struct.unpack_from("<I", head, 20)[0]
    k_log = struct.unpack_from("<I", head, 24)[0]
    k_skip = struct.unpack_from("<I", head, 28)[0]
    print(f"   zstd frame @0x{i:08x}  m={m} k_log={k_log} k_skip={k_skip} total_bytes={total_bytes:,}")
    hits.append((i, m, total_bytes))

for off, m, total_bytes in hits:
    if m != 22:
        continue
    p = subprocess.run(["zstd", "-d", "-c"], input=blob[off:], capture_output=True)
    canonical = p.stdout[:total_bytes]          # zstd runs past the frame; truncate
    assert len(canonical) == total_bytes, f"short decode {len(canonical)} != {total_bytes}"
    out = pathlib.Path("canonical-c00-mainnet.raw")
    out.write_bytes(canonical)
    print(f"  c00 canonical -> {out} ({total_bytes:,} bytes)")
