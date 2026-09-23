#!/bin/bash
# Run the page end to end in headless Chrome and report the verdict, how long
# it took, and Chrome's peak memory.
#
# Heavy: near 4 GB and every core for half an hour on a first visit. Run it
# where that costs nothing else, not beside a service that needs its memory.
#
#   web/browser-test.sh live  [profile-dir]   the deployed page, as a visitor gets it
#   web/browser-test.sh local [profile-dir]   web/server.mjs on :8099, same layout
#
# A new profile is a first visit: the full re-derivation, about half an hour at
# six threads. Pass the same profile again to test the cached path, a couple of
# minutes, since the parameters live in that profile's IndexedDB.
#
# THEN lists further phases to run in the same page load, in order, each of
# which must pass: "again" (verify again), "walk" (is a block about 300 below
# the tip in the chain) and "tamper" (the page's own tampered-proof run, which
# must end FAILED). For a release: THEN="again walk tamper". See drive.mjs.
#
# Chrome needs two flags here and, on the serving box, a third. Missing any of
# them looks like a bug in the page. --enable-features=SharedArrayBuffer, and
# --remote-debugging-port, which is how drive.mjs reads the transcript. Then
# for "live" on the box that serves it, a resolver rule sending the public
# name to loopback: Chrome's own resolver fails on it from there, and the page
# then reports "not cross-origin isolated", which reads like a header problem
# and is not one.
#
# Peak memory is the summed RSS of this profile's Chrome processes, the same
# measure behind the README's ~4.3 GB. It over-counts pages they share.
set -uo pipefail
cd "$(dirname "$0")/.."
MODE="${1:-}"
PROFILE="${2:-$(mktemp -d /tmp/jetsam-verify-chrome.XXXXXX)}"
OUT="${OUT:-/tmp/jetsam-verify-result}"
PORT="${PORT:-9223}"
HOST=jtmverify.halcyon-names.io
EXTRA=()
SERVER=

case "$MODE" in
  live)
    URL="https://$HOST/?auto=1"
    if curl -s -m 5 -o /dev/null --resolve "$HOST:443:127.0.0.1" "https://$HOST/"; then
      EXTRA=(--host-resolver-rules="MAP $HOST 127.0.0.1")
    fi ;;
  local)
    node web/server.mjs > /tmp/jetsam-verify-server.log 2>&1 & SERVER=$!
    URL="http://127.0.0.1:8099/?auto=1" ;;
  *) echo "usage: $0 live|local [profile-dir]"; exit 2 ;;
esac

# Niced, so a half-hour run yields to whatever else the machine is doing.
nice -n 15 google-chrome --headless=new --user-data-dir="$PROFILE" \
  --remote-debugging-port="$PORT" --enable-features=SharedArrayBuffer \
  --no-first-run --no-default-browser-check "${EXTRA[@]}" about:blank \
  > /tmp/jetsam-verify-chrome.log 2>&1 &
CHROME=$!

rm -f "$OUT.peak_kb"
( peak=0
  while kill -0 "$CHROME" 2>/dev/null; do
    kb=0
    for pid in $(pgrep -f -- "--user-data-dir=$PROFILE"); do
      r=$(awk '/^VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null)
      kb=$((kb + ${r:-0}))
    done
    if [ "$kb" -gt "$peak" ]; then peak=$kb; echo "$peak" > "$OUT.peak_kb"; fi
    sleep 5
  done ) &
SAMPLER=$!

START=$(date +%s)
timeout 5400 node web/drive.mjs "$PORT" "$URL" "$OUT" ${THEN:-}
RC=$?
ELAPSED=$(( $(date +%s) - START ))

# By PID only. A pattern kill would match this script's own command line.
kill "$SAMPLER" "$CHROME" $SERVER 2>/dev/null
sleep 2
kill -9 "$CHROME" 2>/dev/null

PEAK_MB=$(( $(cat "$OUT.peak_kb" 2>/dev/null || echo 0) / 1024 ))
echo "$([ "$RC" = 0 ] && echo VERIFIED || echo "NOT VERIFIED (exit $RC)") after" \
     "$((ELAPSED / 60))m$((ELAPSED % 60))s · chrome peak ${PEAK_MB} MB · profile $PROFILE" \
     "· $OUT.png / $OUT.json"
exit "$RC"
