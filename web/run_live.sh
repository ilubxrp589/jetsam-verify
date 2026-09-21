#!/bin/bash
# Drive the LIVE site in headless Chrome and capture console output.
SCRATCH="${1:-/tmp/chrome-live-profile}"
rm -rf "$SCRATCH"
timeout 5400 google-chrome --headless=new --no-sandbox --disable-gpu \
  --disable-dev-shm-usage --user-data-dir="$SCRATCH" \
  --enable-logging=stderr --v=0 \
  --virtual-time-budget=1 \
  https://jtmverify.halcyon-names.io/ > /tmp/chrome-live.log 2>&1
