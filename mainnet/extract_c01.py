import struct, subprocess, pathlib
blob = pathlib.Path("jetsam-node-linux-x86_64").read_bytes()
off = 0x0054303a
p = subprocess.run(["zstd","-d","-c"], input=blob[off:], capture_output=True)
head = p.stdout[:32]
assert head[:8] == b"NOIDR1CS", head[:8]
total = struct.unpack_from("<Q", head, 12)[0]
m, k_log, k_skip = struct.unpack_from("<III", head, 20)
print(f"   c01 m={m} k_log={k_log} k_skip={k_skip} total_bytes={total:,}")
pathlib.Path("canonical-c01-mainnet.raw").write_bytes(p.stdout[:total])
print(f"   wrote canonical-c01-mainnet.raw ({total:,} bytes)")
