#!/usr/bin/env bash
# Start FileGuard's dedicated clamd (skip if already running). Non-zero only if we
# tried and failed; callers may fall back to clamscan.
export PATH="$PATH:/usr/sbin"
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p run
CONF_IN="clamav/clamd.conf.in"
CONF="clamav/clamd.conf"
if [ -f "$CONF_IN" ]; then
  sed "s|@FILEGUARD_DIR@|$ROOT|g" "$CONF_IN" > "$CONF.tmp"
  mv "$CONF.tmp" "$CONF"
fi
SOCK=run/clamd.sock
if [ -S "$SOCK" ] && clamdscan --config-file="$CONF" --ping 1 >/dev/null 2>&1; then
  echo "clamd already running"; exit 0
fi
if ! command -v clamd >/dev/null 2>&1 && [ ! -x /usr/sbin/clamd ]; then
  echo "clamd not installed; will use clamscan if available" >&2
  exit 1
fi
rm -f "$SOCK"
/usr/sbin/clamd --config-file="$CONF"
for i in $(seq 1 120); do
  if clamdscan --config-file="$CONF" --ping 1 >/dev/null 2>&1; then echo "clamd ready"; exit 0; fi
  sleep 1
done
echo "clamd failed to start, see run/clamd.log" >&2
exit 1
