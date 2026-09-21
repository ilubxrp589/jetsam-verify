#!/bin/bash
# Re-point the verifier at a new Jetsam release after a protocol upgrade.
#
#   ./repoint.sh v1.4.0
#
# Downloads the release binary, checks it against the published SHA256SUMS,
# extracts the runtime metadata and every canonical matrix, prints the new
# pinned digest, and tells you the one line to change. It does not deploy:
# read the output first, because a fork can change the class count too.
set -euo pipefail
TAG="${1:?usage: ./repoint.sh <release-tag>}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
WORK="$ROOT/mainnet"
BASE="https://github.com/jetsam-chain/jetsam/releases/download/$TAG"

mkdir -p "$WORK" && cd "$WORK"
echo "== fetching $TAG"
curl -sSL --retry 3 -o jetsam-node-linux-x86_64 "$BASE/jetsam-node-linux-x86_64"
curl -sSL --retry 3 -o SHA256SUMS "$BASE/SHA256SUMS"

echo "== verifying the binary against the published hash"
if ! sha256sum --ignore-missing -c SHA256SUMS 2>/dev/null | grep -q "jetsam-node-linux-x86_64: OK"; then
  echo "!! SHA256 MISMATCH. Stop here. Everything downstream trusts this check."
  exit 1
fi
echo "   OK"

echo "== extracting metadata and matrices"
python3 extract.py
python3 extract_c01.py

echo "== compressing for the browser"
for raw in canonical-c*-mainnet.raw; do
  out="$ROOT/assets/$(basename "$raw" .raw).zst"
  zstd -19 -q -f "$raw" -o "$out"
  printf "   %-34s %s\n" "$(basename "$out")" "$(du -h "$out" | cut -f1)"
done

echo "== the new pin"
cd "$ROOT"
cargo build --release --bin print_pins >/dev/null 2>&1
./target/release/print_pins | tee web_pins.json

NEWPIN=$(python3 -c "import json,io;print(json.load(io.open('web_pins.json'))['metadata_digest'])")
OLDPIN=$(grep -oE '"[0-9a-f]{64}"' web/verify-worker.js | head -1 | tr -d '"')
echo
echo "== what to change"
if [ "$NEWPIN" = "$OLDPIN" ]; then
  echo "   pin UNCHANGED ($NEWPIN). Parameters did not move in this release."
else
  echo "   old pin: $OLDPIN"
  echo "   new pin: $NEWPIN"
  echo
  echo "   1. set PIN in web/verify-worker.js to the new value"
  echo "   2. set KNOWN_WIRE_VERSION to the wire version the new chain emits"
  echo "      (byte 0 of jetsam_getHistoryStepTerminal; check it before guessing)"
  echo "   3. confirm the class count in web_pins.json still matches the page"
  echo "   4. ./deploy.sh"
  echo
  echo "   Visitors' cached parameters are keyed by the pin, so they will"
  echo "   re-derive against the new one rather than silently misverify."
fi
