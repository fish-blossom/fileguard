#!/usr/bin/env bash
# FileGuard bootstrap: the stable entry point for first install and every update.
# Keep this file small and rarely changed; all real install logic lives in the release's
# own install.sh, which this script runs ONLY after verifying that release.
#
#   bootstrap.sh [--dir D] [--force-check]   install, or update at most once per 24 h
#   bootstrap.sh --estimate [--dir D]        no changes; print the init time estimate JSON
#
# Each run:
#   1. take the install lock ($DATA/.install.lock). If it is held only by THIS install's own
#      clamd (fd leak from installers <= 0.5.2), restart that clamd and take the lock.
#   2. download manifest.json + manifest.json.sig of the latest GitHub Release and verify the
#      signature with the pinned key: $DATA/trust/release-signers (TOFU: pinned from the
#      installed release-signers, or on a first install from the key shipped next to this file).
#   3. download fileguard.tar.gz to a file; SHA-256 must equal the manifest. If `gh` can reach
#      the attestation API, `gh attestation verify` must also pass (skipped when gh is absent
#      or logged out; signature + SHA-256 are always mandatory).
#   4. run the NEW release's install.sh --from-tree --verified (staged swap, self-check,
#      rollback to the old version on failure). No curl|bash: everything is a verified file.
# Prints ONE JSON object on stdout (same shape as install.sh); progress goes to stderr.
set -uo pipefail
umask 022

main() {
REPO=fish-blossom/fileguard
SIGNER_ID="fileguard-release@fish-blossom"; SIG_NS="fileguard-release"
BASE="${FILEGUARD_RELEASE_BASE:-https://github.com/$REPO/releases/latest/download}"
INTERVAL="${FILEGUARD_UPDATE_INTERVAL_S:-86400}"
DIR="${FILEGUARD_DIR:-/workspace/fileguard}"; FORCE=0; ESTIMATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR="${2:-}"; shift 2 ;;
    --force-check) FORCE=1; shift ;;
    --auto) shift ;;
    --estimate) ESTIMATE=1; shift ;;
    *) echo "unknown argument: $1" >&2; return 2 ;;
  esac
done
DIR="$(realpath -m "$DIR")"; DATA="${FILEGUARD_DATA:-$DIR/data}"
SELF_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
if [ "$ESTIMATE" = 1 ]; then
  FILEGUARD_DATA="$DATA" bash "$SELF_DIR/install.sh" --estimate --dir "$DIR" 9>&-; return $?
fi
TMP="$(mktemp -d /tmp/fileguard-boot.XXXXXX)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$DATA"
RESTART_CLAMD=0

log() { printf '%s\n' "$*" >&2; }
dl() { curl -fsSL --retry 2 --connect-timeout 20 --max-time "${3:-600}" "$1" -o "$2"; }
installed_version() { [ -f "$DIR/VERSION" ] && head -n1 "$DIR/VERSION" | tr -d ' \t\r' || true; }
usable() { [ -x "$DIR/scripts/fg" ] && FILEGUARD_HOME="$DIR" FILEGUARD_DATA="$DATA" "$DIR/scripts/fg" version --json >/dev/null 2>&1; }
jget() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2]) or "")' "$1" "$2"; }
newer() { python3 - "$1" "$2" << 'PY'
import re, sys
def k(v):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", (v or "").strip())
    if not m: return (-1, -1, -1, 0, ())
    pre = m.group(4)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1,
            tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in (pre or "").split(".") if p))
sys.exit(0 if k(sys.argv[1]) > k(sys.argv[2]) else 1)
PY
}
state() {  # key=value pairs into update_state.json
  python3 - "$DATA/update_state.json" "$@" << 'PY'
import json, os, sys, time
p = sys.argv[1]
try: st = json.load(open(p))
except Exception: st = {}
for kv in sys.argv[2:]:
    k, v = kv.split("=", 1); st[k] = v
st["last_check"] = time.time()
json.dump(st, open(p + ".tmp", "w"), indent=1); os.replace(p + ".tmp", p)
PY
}
due() {
  [ "$FORCE" = 1 ] && return 0
  python3 - "$DATA/update_state.json" "$INTERVAL" << 'PY'
import json, sys, time
try: sys.exit(0 if time.time() - float(json.load(open(sys.argv[1])).get("last_check", 0)) >= float(sys.argv[2]) else 1)
except Exception: sys.exit(0)
PY
}
restart_clamd_if_needed() {
  if [ "$RESTART_CLAMD" = 1 ] && [ -f "$DIR/scripts/start_clamd.sh" ]; then
    FILEGUARD_DATA="$DATA" bash "$DIR/scripts/start_clamd.sh" 9>&- >/dev/null 2>&1 || log "clamd restart failed (clamscan fallback)"
    RESTART_CLAMD=0
  fi
}
emit() {  # action ok
  restart_clamd_if_needed
  local u=0; usable && u=1
  python3 -c 'import json,sys; a,v,d,dd,ok,u=sys.argv[1:]; print(json.dumps({"action":a,"version":v,"dir":d,"data_dir":dd,"ok":ok=="1","usable":u=="1","rolled_back":False,"missing_components":[]}))' \
    "$1" "$(installed_version)" "$DIR" "$DATA" "$2" "$u"
}
finish_fail() {  # keep the old version; non-zero only when the engine is not usable
  emit "$1" 0; usable && return 0 || return 1
}

# ---- 1. lock (with self-heal for a lock leaked into our own clamd) ----
lock_holders() {
  local p fd
  for p in /proc/[0-9]*; do
    for fd in "$p"/fd/*; do
      [ "$(readlink "$fd" 2>/dev/null)" = "$1" ] && { echo "${p#/proc/}"; break; }
    done
  done 2>/dev/null
}
own_clamd() {
  local exe; exe="$(readlink "/proc/$1/exe" 2>/dev/null)" || return 1
  case "$exe" in "$DIR"/*/clamd|"$DIR"/*"/clamd (deleted)") return 0 ;; */clamd|*"/clamd (deleted)") ;; *) return 1 ;; esac
  [ -f "$DIR/run/clamd.pid" ] && [ "$(tr -d ' \n' < "$DIR/run/clamd.pid")" = "$1" ]
}
exec 9>"$DATA/.install.lock"
if ! flock -n 9; then
  exec 9>&-
  pids="$(lock_holders "$(realpath -m "$DATA/.install.lock")")"
  heal=1; [ -n "$pids" ] || heal=0
  for p in $pids; do own_clamd "$p" || heal=0; done
  got=0
  if [ "$heal" = 1 ]; then
    log "install lock held only by this install's clamd (old installer fd leak); restarting clamd"
    for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
    RESTART_CLAMD=1
  fi
  for _ in $(seq 1 30); do
    exec 9>"$DATA/.install.lock"; flock -n 9 && { got=1; break; }
    exec 9>&-; [ "$heal" = 1 ] || [ -z "$pids" ] || break; sleep 1
  done
  if [ "$got" != 1 ]; then log "another FileGuard install/update is running"; emit busy 1; return 0; fi
fi

OLD="$(installed_version)"; HAVE=0; usable && [ -n "$OLD" ] && HAVE=1
if [ "$HAVE" = 1 ]; then   # daily ClamAV signature refresh (cheap when fresh)
  FILEGUARD_DATA="$DATA" bash "$DIR/scripts/update_clamav_db.sh" --if-older-than 24 9>&- >/dev/null 2>&1 || true
  if ! due; then emit up_to_date 1; return 0; fi
fi

# ---- 2. pinned key + signed manifest ----
mkdir -p "$DATA/trust"; KEY="$DATA/trust/release-signers"
if [ ! -s "$KEY" ]; then
  if [ -s "$DIR/release-signers" ]; then cp "$DIR/release-signers" "$KEY"
  elif [ -s "$SELF_DIR/release-signers" ]; then cp "$SELF_DIR/release-signers" "$KEY"
  else log "no pinned release key"; finish_fail refused; return; fi
fi
if ! dl "$BASE/manifest.json" "$TMP/manifest.json" 60 || ! dl "$BASE/manifest.json.sig" "$TMP/manifest.json.sig" 60; then
  state last_result=manifest_failed; log "cannot download release manifest"; finish_fail check_failed; return
fi
if ! ssh-keygen -Y verify -f "$KEY" -I "$SIGNER_ID" -n "$SIG_NS" -s "$TMP/manifest.json.sig" < "$TMP/manifest.json" >/dev/null 2>&1; then
  state last_result=signature_invalid; log "release manifest signature INVALID - refusing"; finish_fail refused; return
fi
NEW="$(jget "$TMP/manifest.json" version)"
if [ "$HAVE" = 1 ] && ! newer "$NEW" "$OLD"; then
  state latest_seen="$NEW" last_result=up_to_date; emit up_to_date 1; return 0
fi

# ---- 3. tarball: SHA-256 (+ optional attestation) ----
if [ -n "${FILEGUARD_RELEASE_BASE:-}" ]; then TURL="$BASE/fileguard.tar.gz"
else
  TURL="$(jget "$TMP/manifest.json" tarball_url)"
  case "$TURL" in "https://github.com/$REPO/releases/download/"*) ;; *) log "unexpected tarball URL"; finish_fail refused; return ;; esac
fi
dl "$TURL" "$TMP/fileguard.tar.gz" 600 || { state last_result=download_failed; finish_fail download_failed; return; }
if [ "$(sha256sum "$TMP/fileguard.tar.gz" | awk '{print $1}')" != "$(jget "$TMP/manifest.json" sha256)" ]; then
  state last_result=sha256_mismatch; log "tarball SHA-256 mismatch - refusing"; finish_fail refused; return
fi
if command -v gh >/dev/null 2>&1; then
  if ! GH_PROMPT_DISABLED=1 gh attestation verify "$TMP/fileguard.tar.gz" --repo "$REPO" --deny-self-hosted-runners >/dev/null 2>"$TMP/att.err"; then
    if grep -qiE 'HTTP[_ ]?(401|403)|GH_TOKEN|gh auth login|not logged in|authentication|credentials|error connecting|dial tcp|Could not resolve host|network' "$TMP/att.err"; then
      log "gh cannot reach the attestation API; skipping (signature + SHA-256 verified)"
    else
      state last_result=attestation_failed; log "artifact attestation INVALID or missing - refusing"; finish_fail refused; return
    fi
  fi
fi
mkdir -p "$TMP/x" && tar -xzf "$TMP/fileguard.tar.gz" -C "$TMP/x" --no-same-owner \
  && [ "$(head -n1 "$TMP/x/fileguard/VERSION" | tr -d ' \t\r')" = "$NEW" ] && [ -f "$TMP/x/fileguard/install.sh" ] \
  || { log "release tarball malformed"; finish_fail refused; return; }

# ---- 4. the NEW release's installer does the staged install / rollback ----
log "installing FileGuard $NEW"
FILEGUARD_DATA="$DATA" bash "$TMP/x/fileguard/install.sh" --from-tree --verified --dir "$DIR" 9>&- > "$TMP/inner.json"
rc=$?
state latest_seen="$NEW" last_result="$([ $rc -eq 0 ] && echo installed || echo failed)"
restart_clamd_if_needed
cat "$TMP/inner.json"
return $rc
}
main "$@"; exit $?
