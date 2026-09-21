#!/bin/bash
# Publish the verifier to /var/www/jtmverify.
#
# The page lives in web/ during development and references ../pkg-web and
# ../assets. The served layout is flat, so those prefixes are rewritten here
# rather than being maintained as a second copy of the source.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST=/var/www/jtmverify
SUDO="sudo"

$SUDO mkdir -p "$DEST/assets"
$SUDO rsync -a --delete "$ROOT/pkg-web" "$DEST/"
for f in canonical-c00-mainnet.zst canonical-c01-mainnet.zst history-step.runtime.mainnet; do
  $SUDO cp "$ROOT/assets/$f" "$DEST/assets/"
done
$SUDO rsync -a --delete "$ROOT/web/fonts" "$DEST/"
$SUDO cp "$ROOT/web/fonts.css" "$DEST/"
for f in index.html verify-worker.js; do
  sed -e 's#\.\./pkg-web/#pkg-web/#g' -e 's#\.\./assets/#assets/#g' "$ROOT/web/$f" \
    | $SUDO tee "$DEST/$f" > /dev/null
done
$SUDO chown -R caddy:caddy "$DEST" 2>/dev/null || $SUDO chown -R www-data:www-data "$DEST" 2>/dev/null || true
echo "deployed to $DEST ($($SUDO du -sh "$DEST" | cut -f1))"
