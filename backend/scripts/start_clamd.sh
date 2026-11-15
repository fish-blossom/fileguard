#!/usr/bin/env bash
# Start FileGuard's dedicated clamd (skip if already running). Non-zero only if we
# tried and failed; callers may fall back to clamscan.
#   - Uses the pinned official ClamAV build in vendor/clamav when present.
#   - Restarts a running FileGuard clamd whose version differs from the vendored one.
#   - A non-default install reuses the default install's clamd instead of starting a
#     second ~1 GB daemon (set FILEGUARD_NO_SHARED_CLAMD=1 to disable).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p run
DATA="${FILEGUARD_DATA:-$ROOT/data}"
VC="$ROOT/vendor/clamav"
if [ -x "$VC/sbin/clamd" ]; then
  export LD_LIBRARY_PATH="$VC/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  CLAMD="$VC/sbin/clamd"; CLAMDSCAN="$VC/bin/clamdscan"
else
  export PATH="$PATH:/usr/sbin"
  CLAMD="$(command -v clamd || echo /usr/sbin/clamd)"; CLAMDSCAN="$(command -v clamdscan || echo clamdscan)"
fi
if [ -n "${FILEGUARD_CLAMAV_DB:-}" ]; then DB="$FILEGUARD_CLAMAV_DB"
elif ls "$DATA/clamav-db"/main.c?d >/dev/null 2>&1; then DB="$DATA/clamav-db"
else DB=/var/lib/clamav; fi
CONF_IN="clamav/clamd.conf.in"
CONF="clamav/clamd.conf"
if [ -f "$CONF_IN" ]; then
  sed -e "s|@FILEGUARD_DIR@|$ROOT|g" -e "s|@CLAMAV_DB@|$DB|g" "$CONF_IN" > "$CONF.tmp"
  mv "$CONF.tmp" "$CONF"
fi
SOCK=run/clamd.sock
want="$("$CLAMD" --config-file="$CONF" --version 2>/dev/null | sed -E 's|^ClamAV ([0-9.]+).*|\1|' | head -n1)"
if [ -S "$SOCK" ] && "$CLAMDSCAN" --config-file="$CONF" --ping 1 >/dev/null 2>&1; then
  have="$("$CLAMDSCAN" --config-file="$CONF" --version 2>/dev/null | sed -E 's|^ClamAV ([0-9.]+).*|\1|' | head -n1)"
  if [ -z "$want" ] || [ "$have" = "$want" ]; then
    echo "clamd already running ($have)"; exit 0
  fi
  echo "restarting clamd $have -> $want" >&2
  if [ -f run/clamd.pid ]; then kill "$(cat run/clamd.pid)" 2>/dev/null || true; fi
  for i in $(seq 1 30); do "$CLAMDSCAN" --config-file="$CONF" --ping 1 >/dev/null 2>&1 || break; sleep 1; done
fi
DEFAULT_CONF=/workspace/fileguard/clamav/clamd.conf
if [ "${FILEGUARD_NO_SHARED_CLAMD:-0}" != 1 ] && [ "$(realpath -m "$CONF")" != "$(realpath -m "$DEFAULT_CONF")" ] \
   && [ -f "$DEFAULT_CONF" ] && "$CLAMDSCAN" --config-file="$DEFAULT_CONF" --ping 1 >/dev/null 2>&1; then
  echo "reusing the default FileGuard clamd"; exit 0
fi
if [ ! -x "$CLAMD" ]; then
  echo "clamd not installed; will use clamscan if available" >&2
  exit 1
fi
rm -f "$SOCK"
"$CLAMD" --config-file="$CONF"
for i in $(seq 1 120); do
  if "$CLAMDSCAN" --config-file="$CONF" --ping 1 >/dev/null 2>&1; then echo "clamd ready"; exit 0; fi
  sleep 1
done
echo "clamd failed to start, see run/clamd.log" >&2
exit 1
