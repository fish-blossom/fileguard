#!/usr/bin/env bash
# Start FileGuard's dedicated clamd (skip if already running). Non-zero only if we
# tried and failed; callers may fall back to clamscan.
#   - Uses the pinned official ClamAV build in vendor/clamav when present.
#   - Restarts a running FileGuard clamd whose version differs from the vendored one, or
#     whose binary is not the current vendor/clamav/sbin/clamd (still running from an old
#     .prev-* tree, or from a deleted file, after an update - including a same-version one).
#   - Only ever stops a clamd verified as THIS install's own: its pid is the one in
#     run/clamd.pid AND its binary is this install's vendor clamd (current tree, an old
#     .prev-<ts> tree, or the deleted variant of either). A system/shared clamd is never touched.
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
ROOT_P="$(pwd -P)"
WANT_EXE="$(readlink -f "$CLAMD" 2>/dev/null || true)"
own_clamd_exe() {  # exe path -> 0 if it is this install's vendor clamd (current, .prev-<ts>, deleted)
  local exe="${1% (deleted)}" ts
  case "$exe" in
    "$ROOT_P/vendor/clamav/sbin/clamd") return 0 ;;
    "$ROOT_P"/.prev-*/vendor/clamav/sbin/clamd)
      ts="${exe#"$ROOT_P"/.prev-}"; ts="${ts%/vendor/clamav/sbin/clamd}"
      case "$ts" in ''|*[!0-9]*) return 1 ;; esac; return 0 ;;
  esac
  return 1
}
own_clamd_pid() {  # prints the pid of THIS install's clamd, or nothing
  local pid exe
  [ -f run/clamd.pid ] || return 0
  pid="$(tr -d ' \n' < run/clamd.pid)"
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || return 0
  if own_clamd_exe "$exe"; then echo "$pid"; fi
  return 0
}
stop_own_clamd() {  # pid (verified by own_clamd_pid): SIGTERM, wait up to 30 s, SIGKILL only if still ours
  local pid="$1" i
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 30); do [ -e "/proc/$pid" ] && [ "$(own_clamd_pid)" = "$pid" ] || break; sleep 1; done
  if [ -e "/proc/$pid" ] && [ "$(own_clamd_pid)" = "$pid" ]; then kill -KILL "$pid" 2>/dev/null || true; sleep 1; fi
  rm -f "$SOCK"
}
want="$("$CLAMD" --config-file="$CONF" --version 2>/dev/null | sed -E 's|^ClamAV ([0-9.]+).*|\1|' | head -n1)"
OWN="$(own_clamd_pid)"
OWN_EXE=""; [ -z "$OWN" ] || OWN_EXE="$(readlink "/proc/$OWN/exe" 2>/dev/null || true)"
STALE=0; [ -n "$OWN" ] && [ -n "$WANT_EXE" ] && [ "$OWN_EXE" != "$WANT_EXE" ] && STALE=1
if [ -S "$SOCK" ] && "$CLAMDSCAN" --config-file="$CONF" --ping 1 >/dev/null 2>&1; then
  have="$("$CLAMDSCAN" --config-file="$CONF" --version 2>/dev/null | sed -E 's|^ClamAV ([0-9.]+).*|\1|' | head -n1)"
  reason=""
  if [ -n "$want" ] && [ "$have" != "$want" ]; then reason="version $have -> $want"
  elif [ "$STALE" = 1 ]; then reason="binary $OWN_EXE -> $WANT_EXE"; fi
  if [ -z "$reason" ]; then echo "clamd already running ($have)"; exit 0; fi
  if [ -z "$OWN" ]; then
    echo "clamd on $SOCK needs a restart ($reason) but is not this install's own clamd; leaving it" >&2
    exit 0
  fi
  echo "restarting clamd ($reason)" >&2
  stop_own_clamd "$OWN"
elif [ "$STALE" = 1 ]; then
  echo "stopping stale clamd ($OWN_EXE)" >&2   # not answering and from an old/deleted tree
  stop_own_clamd "$OWN"
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
# Start clamd with only stdin/stdout/stderr: it is long-lived and must not keep any
# inherited descriptor open (e.g. an installer's lock fd, which would block later updates).
(
  for fd in /proc/self/fd/*; do
    n="${fd##*/}"
    case "$n" in 0|1|2) ;; *) eval "exec $n>&-" 2>/dev/null ;; esac
  done
  exec "$CLAMD" --config-file="$CONF"
)
for i in $(seq 1 120); do
  if "$CLAMDSCAN" --config-file="$CONF" --ping 1 >/dev/null 2>&1; then echo "clamd ready"; exit 0; fi
  sleep 1
done
echo "clamd failed to start, see run/clamd.log" >&2
exit 1
