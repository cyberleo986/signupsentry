#!/bin/bash
# Refresh disposable-domains.txt from upstream public sources
# Runs daily via cron

set -e
DATA_DIR="$(dirname "$0")/../data"
TMP="$(mktemp)"

echo "[$(date -u)] Refreshing disposable domain list..."

# Primary source: disposable-email-domains on GitHub
curl -sL --max-time 30 \
  "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf" \
  -o "$TMP" || {
    echo "ERROR: failed to download primary list" >&2
    exit 1
  }

# Sort, dedupe, write
sort -u "$TMP" > "$DATA_DIR/disposable-domains.txt"
LINES=$(wc -l < "$DATA_DIR/disposable-domains.txt")

echo "[$(date -u)] Wrote $LINES disposable domains to $DATA_DIR/disposable-domains.txt"
rm "$TMP"