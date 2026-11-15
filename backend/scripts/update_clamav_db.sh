#!/usr/bin/env bash
# Refresh FileGuard's ClamAV signature DB (data/clamav-db) with the pinned freshclam and
# tell clamd to reload. Seeds from an existing local DB first so a fresh install does
# not re-download ~110 MB when the box already has one. Never needs root.
#   update_clamav_db.sh [--if-older-than HOURS]
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${FILEGUARD_DATA:-$ROOT/data}"
DB="${FILEGUARD_CLAMAV_DB:-$DATA/clamav-db}"
MAX_H=0
[ "${1:-}" = "--if-older-than" ] && MAX_H="${2:-24}"
mkdir -p "$DB" "$ROOT/run"
STAMP="$DATA/clamav_db_checked"
if [ "$MAX_H" != 0 ] && [ -f "$STAMP" ] && ls "$DB"/main.c?d >/dev/null 2>&1; then
  age=$(( $(date +%s) - $(stat -c %Y "$STAMP") ))
  [ "$age" -lt $(( MAX_H * 3600 )) ] && { echo "clamav db fresh"; exit 0; }
fi
if ! ls "$DB"/main.c?d >/dev/null 2>&1; then
  for src in /workspace/fileguard/data/clamav-db /var/lib/clamav; do
    if [ "$(realpath -m "$src")" != "$(realpath -m "$DB")" ] && ls "$src"/main.c?d >/dev/null 2>&1; then
      cp -p "$src"/*.c?d "$DB"/ 2>/dev/null && { echo "seeded clamav db from $src" >&2; break; }
    fi
  done
fi
VC="$ROOT/vendor/clamav"
if [ -x "$VC/bin/freshclam" ]; then
  export LD_LIBRARY_PATH="$VC/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  FRESHCLAM="$VC/bin/freshclam"
else
  FRESHCLAM="$(command -v freshclam || true)"
fi
[ -n "$FRESHCLAM" ] || { echo "freshclam not available" >&2; exit 1; }
sed -e "s|@FILEGUARD_DIR@|$ROOT|g" -e "s|@CLAMAV_DB@|$DB|g" "$ROOT/clamav/freshclam.conf.in" > "$ROOT/clamav/freshclam.conf"
if "$FRESHCLAM" --config-file="$ROOT/clamav/freshclam.conf" --datadir="$DB" --stdout >"$ROOT/run/freshclam.last" 2>&1; then
  touch "$STAMP"
  # reload a running FileGuard clamd so it picks up the new signatures
  CONF="$ROOT/clamav/clamd.conf"
  if [ -S "$ROOT/run/clamd.sock" ] && [ -f "$CONF" ]; then
    CLAMDSCAN="$VC/bin/clamdscan"; [ -x "$CLAMDSCAN" ] || CLAMDSCAN=clamdscan
    "$CLAMDSCAN" --config-file="$CONF" --reload >/dev/null 2>&1 || true
  fi
  echo "clamav db updated"
  exit 0
fi
echo "freshclam failed (see run/freshclam.last)" >&2
exit 1
