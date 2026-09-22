#!/bin/bash
# Re-point the verifier at a new Jetsam release after a protocol upgrade.
#
#   ./repoint.sh v1.3.1
#
# Downloads the release binary, checks it against the published SHA256SUMS,
# extracts every parameter pack it carries, picks the one that governs the
# chain right now, and prints the one line to change. It does not deploy: read
# the output first, because a fork can change the class count too.
#
# A post-fork binary carries TWO packs -- one relation for blocks before the
# activation height and one for blocks after it -- so "extract the parameters"
# is no longer a single answer. The pack is chosen by asking this build which
# generation governs the current tip, the same question a node asks.
set -euo pipefail
TAG="${1:?usage: ./repoint.sh <release-tag>}"
RPC="${RPC:-http://127.0.0.1:3097/rpc}"
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

echo "== extracting every pack this binary carries"
python3 extract.py

# The source tree under ./jetsam must be the SAME release, or the question
# "which generation governs this height" is answered by the wrong schedule.
cd "$ROOT"
cargo build --release --bin print_pins >/dev/null
TIP=$(curl -s -m 30 -X POST "$RPC" -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"jetsam_getChainInfo","params":[]}' \
      | grep -oE '"height":[0-9]+' | head -1 | cut -d: -f2)
[ -n "$TIP" ] || { echo "!! could not read the chain tip from $RPC"; exit 1; }
WANT=$(./target/release/print_pins --generation-at "$TIP")
echo "== tip $TIP is governed by the $WANT relation"

echo "== packs found"
CHOSEN=""
for meta in "$WORK"/gen*-history-step.runtime; do
  GEN=$(./target/release/print_pins "$meta" | grep -oE '"generation": "[^"]+"' | cut -d'"' -f4)
  PIN=$(./target/release/print_pins "$meta" | grep -oE '"metadata_digest": "[^"]+"' | cut -d'"' -f4)
  MARK=" "
  if [ "$GEN" = "$WANT" ]; then MARK="*"; CHOSEN="$meta"; fi
  printf "  %s %-40s %-5s %s\n" "$MARK" "$(basename "$meta")" "$GEN" "$PIN"
done
[ -n "$CHOSEN" ] || { echo "!! no pack in this binary is the $WANT relation"; exit 1; }
PREFIX="${CHOSEN%-history-step.runtime}"

echo "== promoting $(basename "$PREFIX") to the shipped names"
cp "$CHOSEN" "$ROOT/assets/history-step.runtime.mainnet"
for raw in "$PREFIX"-canonical-c*.raw; do
  cls=$(basename "$raw" .raw); cls="${cls##*-canonical-}"
  ln -f "$raw" "$WORK/canonical-$cls-mainnet.raw"
  out="$ROOT/assets/canonical-$cls-mainnet.zst"
  zstd -19 -q -f -T0 "$raw" -o "$out"
  printf "   %-34s %s\n" "$(basename "$out")" "$(du -h "$out" | cut -f1)"
done

echo "== the new pin"
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
  echo "   2. confirm the class count in web_pins.json still matches the page"
  echo "   3. if the RELATION changed (a different generation above), rebuild the"
  echo "      wasm as well -- new parameters under old relation code verify nothing:"
  echo "        git -C jetsam reset --hard $TAG && git -C jetsam clean -fd"
  echo "        for p in patches/*.patch; do git -C jetsam apply \"\$p\"; done"
  echo "        cargo build --release          # patches must BUILD, not just apply"
  echo "        RUSTUP_TOOLCHAIN=nightly CARGO_UNSTABLE_BUILD_STD=\"panic_abort,std\" \\"
  echo "          wasm-pack build --release --target web --out-dir pkg-web"
  echo "   4. ./target/release/verify_terminal      # acceptance test, against the live chain"
  echo "   5. ./deploy.sh"
  echo
  echo "   Visitors' cached parameters are keyed by the pin, so they will"
  echo "   re-derive against the new one rather than silently misverify."
fi
