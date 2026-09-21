#!/bin/bash
# Serve the page and drive it with headless Chrome. Kills only by exact process
# name -- a -f pattern match would match this script's own command line.
cd "$(dirname "$0")/.."
SCRATCH="${1:-/tmp/chrome-verify-profile}"
PAGEQ="${2:-}"
: > /tmp/verify-server.log
node web/server.mjs > /tmp/verify-server.log 2>&1 &
SERVER=$!
sleep 2
# Third arg "keep" preserves the profile -- IndexedDB lives in it, so wiping
# would destroy the very cache we want to test restoring from.
[ "${3:-}" = "keep" ] || rm -rf "$SCRATCH"
timeout 5400 google-chrome --headless=new --no-sandbox --disable-gpu \
  --disable-dev-shm-usage --user-data-dir="$SCRATCH" \
  http://127.0.0.1:8099/web/index.html${PAGEQ} > /tmp/chrome-verify.log 2>&1 &
CHROME=$!
# Wait for the page to signal completion, then tear both down.
for i in $(seq 1 5400); do
  grep -q "__DONE__" /tmp/verify-server.log && break
  sleep 1
done
kill $CHROME 2>/dev/null; kill $SERVER 2>/dev/null
grep "\[page\]" /tmp/verify-server.log
