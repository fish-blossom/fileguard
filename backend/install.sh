#!/usr/bin/env bash
# FileGuard engine installer / updater for a Grok Bot box (Debian/Ubuntu, /workspace writable,
# sudo optional). Installs ONLY verified GitHub Release builds:
#   manifest.json (+ manifest.json.sig, ssh-keygen signature by the pinned release key)
#   -> fileguard.tar.gz whose SHA-256 must match the manifest
#   -> if `gh` is on PATH, also `gh attestation verify` the tarball against this repo
#      (SLSA provenance from GitHub Actions). Missing/invalid attestation refuses install.
#      If `gh` is not installed, skip attestation and rely on signature + SHA-256.
#   -> extract -> install.
# Signature + SHA-256 are mandatory and work without `gh` or a GitHub login.
#
# Usage:
#   install.sh                     install, or update to the latest release (verified)
#   install.sh --estimate          no changes; print {action, version, estimated_seconds, estimate_text_*}
#   install.sh --auto              silent daily maintenance: at most one release check per 24 h,
#                                  update if a newer release exists, refresh ClamAV signatures
#   install.sh --tarball F         install a downloaded release tarball (still verified against
#                                  the signed manifest of the same version)
#   --dir D                        install dir (default /workspace/fileguard, or $FILEGUARD_DIR)
#   --force-check                  ignore the 24 h throttle
# Dev only: --from-tree (install this source tree as-is, unverified).
#
# Prints ONE JSON object on stdout; progress goes to stderr. The bot must not describe the
# install to the user. Updates are atomic: the new tree + venv + tools are staged next to
# the old one, swapped in, self-checked, and rolled back on failure. data/ is never touched.
set -euo pipefail
log() { printf '%s\n' "$*" >&2; }

REPO="${FILEGUARD_REPO:-fish-blossom/fileguard}"
MANIFEST_URL="${FILEGUARD_MANIFEST_URL:-https://github.com/$REPO/releases/latest/download/manifest.json}"
SIGNER_ID="fileguard-release@fish-blossom"
SIG_NAMESPACE="fileguard-release"
CHECK_INTERVAL_S="${FILEGUARD_UPDATE_INTERVAL_S:-86400}"

# Pinned third-party parsers (official builds; SHA-256 verified before use).
SEVENZIP_VER="26.06"
SEVENZIP_URL="https://github.com/ip7z/7zip/releases/download/26.06/7z2606-linux-x64.tar.xz"
SEVENZIP_SHA256="2b539cf067b2ad48e1baa5093dbaa8818b73542d1222a0ffde9dc5f2922ea62e"
CLAMAV_VER="1.4.6"
CLAMAV_URL="https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.4.6/clamav-1.4.6.linux.x86_64.deb"
CLAMAV_SHA256="d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2"

DIR="${FILEGUARD_DIR:-/workspace/fileguard}"
MODE="install"; TARBALL=""; FROM_TREE=0; VERIFIED=0; FORCE_CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --estimate) MODE="estimate"; shift ;;
    --auto) MODE="auto"; shift ;;
    --tarball|--from-tarball) TARBALL="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --force-check) FORCE_CHECK=1; shift ;;
    --from-tree) FROM_TREE=1; shift ;;
    --verified) VERIFIED=1; shift ;;   # internal: re-exec of a verified release tree
    -h|--help) sed -n '2,24p' "$0" >&2; exit 0 ;;
    *) log "unknown argument: $1"; exit 2 ;;
  esac
done
umask 022
# Updates (and plain installs) go through bootstrap.sh, which verifies the latest release and
# then runs THAT release's installer. Only --tarball / --estimate / --from-tree stay here.
if [ "$FROM_TREE" -eq 0 ] && [ -z "$TARBALL" ] && [ "$MODE" != "estimate" ] \
   && [ -f "$(dirname "$(readlink -f "$0")")/bootstrap.sh" ]; then
  args=(--dir "$DIR"); [ "$FORCE_CHECK" -eq 1 ] && args+=(--force-check)
  exec bash "$(dirname "$(readlink -f "$0")")/bootstrap.sh" "${args[@]}"
fi
DIR="$(realpath -m "$DIR")"
DATA="${FILEGUARD_DATA:-$DIR/data}"
SRC_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
TMP="$(mktemp -d /tmp/fileguard-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

have_sudo=0
if [ "$(id -u)" -eq 0 ]; then have_sudo=2; SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then have_sudo=1; SUDO="sudo"
else SUDO=""; fi

dl() { curl -fsSL --retry 2 --connect-timeout 20 --max-time "${3:-600}" "$1" -o "$2"; }
sha256() { sha256sum "$1" | awk '{print $1}'; }
installed_version() { [ -f "$DIR/VERSION" ] && head -n1 "$DIR/VERSION" | tr -d ' \t\r' || true; }
engine_present() { [ -d "$DIR/fileguard" ] && [ -x "$DIR/scripts/fg" ]; }
fg_usable() {
  engine_present || return 1
  FILEGUARD_HOME="$DIR" FILEGUARD_DATA="$DATA" "$DIR/scripts/fg" version --json >/dev/null 2>&1
}
# semver compare: prints -1 / 0 / 1
vercmp() {
  python3 - "$1" "$2" << 'PY'
import re, sys
def key(v):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", (v or "").strip())
    if not m:
        return (-1, -1, -1, 0, ())
    pre = m.group(4)
    # a release sorts after its pre-releases
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1,
            tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in (pre or "").split(".") if p))
a, b = key(sys.argv[1]), key(sys.argv[2])
print((a > b) - (a < b))
PY
}
json_get() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get(sys.argv[2]) or "")' "$1" "$2"; }

state_file() { echo "$DATA/update_state.json"; }
check_due() {
  [ "$FORCE_CHECK" -eq 1 ] && return 0
  python3 - "$(state_file)" "$CHECK_INTERVAL_S" << 'PY'
import json, sys, time
try:
    st = json.load(open(sys.argv[1]))
    sys.exit(0 if time.time() - float(st.get("last_check", 0)) >= float(sys.argv[2]) else 1)
except Exception:
    sys.exit(0)
PY
}
record_check() {
  mkdir -p "$DATA"
  python3 - "$(state_file)" "$1" "$2" << 'PY'
import json, os, sys, time
p, latest, result = sys.argv[1:]
try:
    st = json.load(open(p))
except Exception:
    st = {}
st.update(last_check=time.time(), latest_seen=latest or st.get("latest_seen"), last_result=result)
tmp = p + ".tmp"
json.dump(st, open(tmp, "w"), indent=1)
os.replace(tmp, p)
PY
}

# ---------- release manifest + signature ----------
# Signer list: the INSTALLED copy's pinned key wins (an attacker who can publish a release
# cannot also change what existing installs trust); a first install uses the key shipped in
# the bootstrap tree.
signers_file() {
  if [ -f "$DIR/release-signers" ]; then echo "$DIR/release-signers"
  elif [ -f "$SRC_DIR/release-signers" ]; then echo "$SRC_DIR/release-signers"
  else echo ""; fi
}
fetch_manifest() {   # $1 = url -> $TMP/manifest.json (+ .sig) ; verifies signature
  local url="$1" sf
  dl "$url" "$TMP/manifest.json" 60 || { log "cannot download release manifest"; return 1; }
  dl "$url.sig" "$TMP/manifest.json.sig" 60 || { log "release manifest signature missing"; return 1; }
  sf="$(signers_file)"
  if [ -z "$sf" ]; then log "no pinned release key"; return 1; fi
  if ! command -v ssh-keygen >/dev/null 2>&1 && [ "$have_sudo" -ge 1 ]; then
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq openssh-client >/dev/null 2>&1 || true
  fi
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    log "ssh-keygen not available; cannot verify the release signature"; return 1
  fi
  if ! ssh-keygen -Y verify -f "$sf" -I "$SIGNER_ID" -n "$SIG_NAMESPACE" \
        -s "$TMP/manifest.json.sig" < "$TMP/manifest.json" >/dev/null 2>&1; then
    log "release manifest signature INVALID - refusing"; return 1
  fi
  return 0
}
verify_tarball() {   # $1 tarball ; manifest already verified
  local want got
  want="$(json_get "$TMP/manifest.json" sha256)"
  got="$(sha256 "$1")"
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    log "tarball SHA-256 mismatch (manifest $want, got $got) - refusing"; return 1
  fi
}

# Optional GitHub Artifact Attestation (SLSA build provenance) produced by
# .github/workflows/release.yml. Signature + SHA-256 above remain mandatory
# and are sufficient when `gh` is not installed.
#
# If `gh` is on PATH, verify the exact tarball against $REPO and refuse to
# install when the attestation is missing, the digest does not match, or the
# signer is wrong. Transport / authentication errors (gh present but unable
# to query the API) are skipped, not treated as a failed verification, so a
# signed+hashed release still installs on a box whose `gh` is logged out.
verify_attestation() {  # $1 tarball
  local tb="$1" err="$TMP/attest.err"
  if ! command -v gh >/dev/null 2>&1; then
    log "gh not found; skipping artifact attestation (signature + SHA-256 already verified)"
    return 0
  fi
  if GH_PROMPT_DISABLED=1 GIT_TERMINAL_PROMPT=0 gh attestation verify "$tb" --repo "$REPO" \
        --deny-self-hosted-runners >"$TMP/attest.out" 2>"$err"; then
    return 0
  fi
  if grep -qiE 'HTTP[_ ]?(401|403)|GH_TOKEN|not logged in|authentication required|Must be authenticated|no.*credentials|to re-authenticate|error connecting|network error|dial tcp|temporary failure in name resolution|Could not resolve host' "$err"; then
    log "gh cannot fetch artifact attestations; skipping (signature + SHA-256 already verified)"
    return 0
  fi
  log "artifact attestation INVALID or missing - refusing"
  return 1
}
extract_and_reexec() {   # $1 verified tarball
  mkdir -p "$TMP/x"
  tar -xzf "$1" -C "$TMP/x" --no-same-owner
  [ -f "$TMP/x/fileguard/install.sh" ] || { log "release tarball has no fileguard/install.sh"; return 1; }
  # 9>&-: the inner installer starts clamd; it must not inherit the install lock fd.
  FILEGUARD_DATA="$DATA" bash "$TMP/x/fileguard/install.sh" --from-tree --verified --dir "$DIR" 9>&-
}

# ---------- install lock ----------
# The lock is an flock on $DATA/.install.lock held on fd 9 by the outer installer only.
# Long-lived children (clamd) must never inherit fd 9, or the lock outlives the installer
# and every later update reports "busy". Installers <= 0.5.2 leaked it into clamd; when the
# lock is held ONLY by this install's own clamd, stop that clamd, take the lock, and start
# clamd again without the fd. Any other holder means a real install is running.
lock_holders() {  # pids that have the lock file open
  local lf="$1" p fd
  for p in /proc/[0-9]*; do
    for fd in "$p"/fd/*; do
      [ "$(readlink "$fd" 2>/dev/null)" = "$lf" ] && { echo "${p#/proc/}"; break; }
    done
  done 2>/dev/null
}
is_own_clamd() {  # pid -> 0 only for the clamd of THIS install dir
  # Must be a clamd binary AND either this install's pinned build or the pid recorded in
  # this install's run/clamd.pid (clamd chdirs to /, so cwd cannot be used).
  local pid="$1" exe
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || return 1
  case "$exe" in "$DIR"/*/clamd|"$DIR"/*"/clamd (deleted)") return 0 ;; */clamd|*"/clamd (deleted)") ;; *) return 1 ;; esac
  [ -f "$DIR/run/clamd.pid" ] && [ "$(tr -d ' \n' < "$DIR/run/clamd.pid")" = "$pid" ] && return 0
  return 1
}
take_lock() {
  mkdir -p "$DATA"
  exec 9>"$DATA/.install.lock"
  flock -n 9 && return 0
  # Close our own fd before looking, so only foreign holders are listed.
  exec 9>&-
  local lf pids p
  lf="$(realpath -m "$DATA/.install.lock")"
  pids="$(lock_holders "$lf")"
  [ -n "$pids" ] || { exec 9>"$DATA/.install.lock"; flock -n 9; return; }
  for p in $pids; do is_own_clamd "$p" || return 1; done
  log "install lock held only by this install's clamd (old installer fd leak); restarting clamd"
  for p in $pids; do kill -TERM "$p" 2>/dev/null || true; done
  for _ in $(seq 1 30); do
    exec 9>"$DATA/.install.lock"
    flock -n 9 && { RESTART_CLAMD=1; return 0; }
    exec 9>&-
    sleep 1
  done
  return 1
}
RESTART_CLAMD=0

emit() {  # action version ok usable rolled_back [missing...]
  python3 - "$@" << 'PY'
import json, sys
action, version, d, data, ok, usable, rolled, *missing = sys.argv[1:]
out = {"action": action, "version": version, "dir": d, "data_dir": data, "ok": ok == "1",
       "usable": usable == "1", "rolled_back": rolled == "1", "missing_components": missing}
if action == "installed" and usable == "1":
    # first install only (never on silent updates): the bot appends the engine's example list after the ready line
    out["after_ready"] = "fg examples --lang <zh|en>"
print(json.dumps(out, ensure_ascii=False))
PY
}

# ---------- estimate ----------
estimate_seconds() {
  python3 - "$1" "$DIR" "$DATA" << 'PY'
import os, subprocess, sys, glob
action, dest, data = sys.argv[1:]
if action == "up_to_date":
    print(0); raise SystemExit
def pkg_ok(names):
    for n in names:
        try:
            r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", n], capture_output=True, text=True, timeout=5)
            if "install ok installed" in (r.stdout or ""):
                return True
        except Exception:
            pass
    return False
apt = [("python3-venv",), ("libmagic1", "libmagic1t64"), ("rpm",), ("msitools",), ("innoextract",),
       ("osslsigncode",), ("gnupg",), ("xz-utils",), ("openssh-client",)]
need_apt = sum(1 for a in apt if not pkg_ok(a))
venv = os.path.isfile(os.path.join(dest, ".venv", "bin", "python"))
vendor = os.path.isfile(os.path.join(dest, "vendor", "clamav", "sbin", "clamd"))
db = any(glob.glob(p) for p in (os.path.join(data, "clamav-db", "main.c?d"), "/var/lib/clamav/main.c?d",
                                 "/workspace/fileguard/data/clamav-db/main.c?d"))
clamd_up = os.path.exists("/workspace/fileguard/run/clamd.sock")
s = 10
s += (40 + 8 * need_apt) if need_apt else 0     # apt packages (only when missing)
s += 20                                          # venv + hash-locked wheels
s += 0 if vendor else 10                         # pinned ClamAV + 7-Zip downloads
s += 5 if db else 30                             # signature DB (seed + freshclam, or full download)
s += 5 if clamd_up and dest != "/workspace/fileguard" else 30   # clamd start / DB load
s += 10                                          # silent verification scan
if action == "updated":
    s = max(20, s - 20)
print(int(s))
PY
}
estimate_texts() {
  python3 - "$1" << 'PY'
import sys
s = int(sys.argv[1])
if s <= 0:
    print(""); print(""); raise SystemExit
if s < 90:
    print(f"约 {s} 秒"); print(f"about {s} seconds")
else:
    m = max(2, int(round(s / 60)))
    print(f"约 {m} 分钟"); print(f"about {m} minutes")
PY
}

latest_version() {   # verified manifest version or empty
  if fetch_manifest "$MANIFEST_URL"; then json_get "$TMP/manifest.json" version; fi
}

if [ "$MODE" = "estimate" ]; then
  OLD="$(installed_version)"
  NEW=""; ACTION="up_to_date"
  if ! engine_present || [ -z "$OLD" ]; then
    ACTION="installed"; NEW="$(latest_version || true)"
    [ -n "$NEW" ] || NEW="$(head -n1 "$SRC_DIR/VERSION" 2>/dev/null | tr -d ' \t\r')"
  elif check_due; then
    NEW="$(latest_version || true)"
    if [ -n "$NEW" ] && [ "$(vercmp "$NEW" "$OLD")" = 1 ]; then ACTION="updated"
    else record_check "$NEW" "up_to_date"; NEW="${NEW:-$OLD}"; fi
  else
    NEW="$OLD"
  fi
  SECS="$(estimate_seconds "$ACTION")"
  mapfile -t TX < <(estimate_texts "$SECS")
  python3 - "$ACTION" "$NEW" "$OLD" "$DIR" "$DATA" "$SECS" "${TX[0]:-}" "${TX[1]:-}" << 'PY'
import json, sys
a, v, old, d, data, secs, zh, en = sys.argv[1:]
print(json.dumps({"action": a, "version": v, "installed_version": old or None, "dir": d, "data_dir": data,
                  "estimated_seconds": int(secs), "estimate_text_zh": zh, "estimate_text_en": en}, ensure_ascii=False))
PY
  exit 0
fi

# ---------- outer modes: obtain a verified release, then re-exec its installer ----------
if [ "$FROM_TREE" -eq 0 ]; then
  if ! take_lock; then log "another FileGuard install/update is running"; emit busy "$(installed_version)" "$DIR" "$DATA" 1 "$(fg_usable && echo 1 || echo 0)" 0; exit 0; fi
  if [ "$RESTART_CLAMD" = 1 ] && [ -x "$DIR/scripts/start_clamd.sh" ]; then
    FILEGUARD_DATA="$DATA" bash "$DIR/scripts/start_clamd.sh" 9>&- >/dev/null 2>&1 || log "clamd restart failed (scans fall back to clamscan)"
  fi
  OLD="$(installed_version)"
  if [ "$MODE" = "auto" ]; then
    # daily ClamAV signature refresh (cheap no-op when fresh)
    if engine_present && [ -x "$DIR/scripts/update_clamav_db.sh" ]; then
      FILEGUARD_DATA="$DATA" bash "$DIR/scripts/update_clamav_db.sh" --if-older-than 24 9>&- >/dev/null 2>&1 || true
    fi
    if engine_present && ! check_due; then
      emit up_to_date "$OLD" "$DIR" "$DATA" 1 "$(fg_usable && echo 1 || echo 0)" 0; exit 0
    fi
  fi
  if [ -n "$TARBALL" ]; then
    [ -f "$TARBALL" ] || { log "tarball not found: $TARBALL"; exit 1; }
    TV="$(tar -xzOf "$TARBALL" fileguard/VERSION 2>/dev/null | head -n1 | tr -d ' \t\r')"
    [ -n "$TV" ] || { log "not a FileGuard release tarball"; exit 1; }
    murl="${FILEGUARD_MANIFEST_URL:-https://github.com/$REPO/releases/download/v$TV/manifest.json}"
    if ! fetch_manifest "$murl" || [ "$(json_get "$TMP/manifest.json" version)" != "$TV" ] || ! verify_tarball "$TARBALL" || ! verify_attestation "$TARBALL"; then
      emit refused "$OLD" "$DIR" "$DATA" 0 "$(fg_usable && echo 1 || echo 0)" 0; exit 1
    fi
    cp "$TARBALL" "$TMP/release.tar.gz"
  else
    if ! fetch_manifest "$MANIFEST_URL"; then
      record_check "" "manifest_failed" 2>/dev/null || true
      emit check_failed "$OLD" "$DIR" "$DATA" 0 "$(fg_usable && echo 1 || echo 0)" 0
      engine_present && exit 0 || exit 1
    fi
    NEW="$(json_get "$TMP/manifest.json" version)"
    if engine_present && [ -n "$OLD" ] && [ "$(vercmp "$NEW" "$OLD")" != 1 ]; then
      record_check "$NEW" "up_to_date"
      emit up_to_date "$OLD" "$DIR" "$DATA" 1 "$(fg_usable && echo 1 || echo 0)" 0; exit 0
    fi
    TURL="$(json_get "$TMP/manifest.json" tarball_url)"
    case "$TURL" in https://github.com/"$REPO"/releases/download/*) ;; *) log "unexpected tarball URL: $TURL"; exit 1 ;; esac
    log "downloading FileGuard $NEW"
    dl "$TURL" "$TMP/release.tar.gz" 600 || { emit download_failed "$OLD" "$DIR" "$DATA" 0 "$(fg_usable && echo 1 || echo 0)" 0; exit 1; }
    if ! verify_tarball "$TMP/release.tar.gz"; then
      record_check "$NEW" "sha256_mismatch"
      emit refused "$OLD" "$DIR" "$DATA" 0 "$(fg_usable && echo 1 || echo 0)" 0
      engine_present && exit 0 || exit 1
    fi
    if ! verify_attestation "$TMP/release.tar.gz"; then
      record_check "$NEW" "attestation_failed"
      emit refused "$OLD" "$DIR" "$DATA" 0 "$(fg_usable && echo 1 || echo 0)" 0
      engine_present && exit 0 || exit 1
    fi
  fi
  set +e
  extract_and_reexec "$TMP/release.tar.gz"
  rc=$?
  set -e
  record_check "$(json_get "$TMP/manifest.json" version)" "$([ $rc -eq 0 ] && echo installed || echo failed)"
  exit $rc
fi

# =====================================================================================
# Inner mode (--from-tree): install THIS tree into $DIR. Reached via a verified re-exec
# (--verified) or explicitly for development.
# =====================================================================================
set +e
exec 9>&- 2>/dev/null   # never let clamd (started below) inherit an outer installer's lock fd
[ "$VERIFIED" -eq 1 ] || log "WARNING: installing an unverified source tree (development mode)"
NEW_VER="$(head -n1 "$SRC_DIR/VERSION" | tr -d ' \t\r')"
OLD_VER="$(installed_version)"
if engine_present && [ -n "$OLD_VER" ]; then ACTION="updated"; else ACTION="installed"; fi
[ "$ACTION" = "updated" ] && [ "$OLD_VER" = "$NEW_VER" ] && ACTION="reinstalled"
log "$ACTION FileGuard ${OLD_VER:+$OLD_VER -> }$NEW_VER at $DIR (data: $DATA)"
mkdir -p "$DIR" "$DATA" "$DIR/run"
MANAGED=(fileguard scripts bin rules intel clamav examples vendor .venv install.sh bootstrap.sh VERSION README.md LICENSE
         requirements.txt requirements.lock release-signers)
STAGE="$DIR/.stage"
rm -rf "$STAGE" "$DIR"/.prev-* 2>/dev/null || true
mkdir -p "$STAGE"
MISSING=()

# ---- 1. system packages (one apt call, per-package fallback) ----
APT_PKGS=(python3-venv libmagic1 rpm msitools innoextract osslsigncode gnupg xz-utils openssh-client ca-certificates)
pkg_ok() { local n; for n in "$1" $([ "$1" = libmagic1 ] && echo libmagic1t64); do
  dpkg-query -W -f='${Status}' "$n" 2>/dev/null | grep -q "install ok installed" && return 0; done; return 1; }
need=(); for p in "${APT_PKGS[@]}"; do pkg_ok "$p" || need+=("$p"); done
if [ "${#need[@]}" -gt 0 ]; then
  if [ "$have_sudo" -eq 0 ]; then
    log "no sudo; cannot apt-install: ${need[*]}"; MISSING+=("${need[@]}")
  else
    $SUDO apt-get update -qq >/dev/null 2>&1 || log "apt-get update failed (continuing)"
    if ! DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq --no-install-recommends "${need[@]}" >/dev/null 2>&1; then
      for p in "${need[@]}"; do
        DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq --no-install-recommends "$p" >/dev/null 2>&1 \
          || { [ "$p" = libmagic1 ] && DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq libmagic1t64 >/dev/null 2>&1; } \
          || { log "  apt: $p unavailable"; MISSING+=("$p"); }
      done
    fi
  fi
fi

# ---- 2. stage the code tree ----
for item in "${MANAGED[@]}"; do
  case "$item" in vendor|.venv) continue ;; esac
  [ -e "$SRC_DIR/$item" ] && cp -a "$SRC_DIR/$item" "$STAGE/$item"
done
find "$STAGE" -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "$STAGE/clamav/clamd.conf" "$STAGE/clamav/freshclam.conf"
chmod +x "$STAGE/install.sh" "$STAGE/bootstrap.sh" "$STAGE/scripts/"* "$STAGE/bin/fg" 2>/dev/null || true

# ---- 3. venv from the hash-locked requirements (wheels only) ----
FAIL=0
LOCK_SHA="$(sha256 "$STAGE/requirements.lock")"
if [ -f "$DIR/.venv/.fileguard-lock" ] && [ "$(cat "$DIR/.venv/.fileguard-lock")" = "$LOCK_SHA" ] \
   && "$DIR/.venv/bin/python" -c 'import httpx, yara, magic' >/dev/null 2>&1; then
  log "reusing Python environment (lock unchanged)"
  cp -al "$DIR/.venv" "$STAGE/.venv" 2>/dev/null || cp -a "$DIR/.venv" "$STAGE/.venv" || FAIL=1
else
  log "building Python environment"
  if python3 -m venv "$STAGE/.venv" >/dev/null 2>&1; then
    if "$STAGE/.venv/bin/python" -m pip install -q --disable-pip-version-check --no-input \
         --require-hashes --only-binary=:all: --no-deps -r "$STAGE/requirements.lock" >&2; then
      echo "$LOCK_SHA" > "$STAGE/.venv/.fileguard-lock"
    else
      log "pip install (hash-locked) failed"; FAIL=1; MISSING+=("python-requirements")
    fi
  else
    log "python3 -m venv failed"; FAIL=1; MISSING+=("venv")
  fi
fi

# ---- 4. pinned parsers: official 7-Zip and ClamAV builds ----
mkdir -p "$STAGE/vendor"
CACHE="$DATA/.downloads"; mkdir -p "$CACHE"
fetch_pinned() {  # url sha dest
  if [ -f "$3" ] && [ "$(sha256 "$3")" = "$2" ]; then return 0; fi
  dl "$1" "$3.part" 900 || { rm -f "$3.part"; return 1; }
  if [ "$(sha256 "$3.part")" != "$2" ]; then log "SHA-256 mismatch for $1"; rm -f "$3.part"; return 1; fi
  mv "$3.part" "$3"
}
reuse_vendor() {  # name sha
  [ -f "$DIR/vendor/$1/.sha256" ] && [ "$(cat "$DIR/vendor/$1/.sha256")" = "$2" ] && cp -al "$DIR/vendor/$1" "$STAGE/vendor/$1" 2>/dev/null
}
if [ "$(uname -m)" = "x86_64" ]; then
  if ! reuse_vendor 7zip "$SEVENZIP_SHA256"; then
    if fetch_pinned "$SEVENZIP_URL" "$SEVENZIP_SHA256" "$CACHE/7zip.tar.xz"; then
      mkdir -p "$STAGE/vendor/7zip" && tar -xJf "$CACHE/7zip.tar.xz" -C "$STAGE/vendor/7zip" 7zzs License.txt readme.txt \
        && echo "$SEVENZIP_SHA256" > "$STAGE/vendor/7zip/.sha256" || { rm -rf "$STAGE/vendor/7zip"; MISSING+=("7zip"); }
    else MISSING+=("7zip"); fi
  fi
  if ! reuse_vendor clamav "$CLAMAV_SHA256"; then
    if fetch_pinned "$CLAMAV_URL" "$CLAMAV_SHA256" "$CACHE/clamav.deb"; then
      X="$TMP/clamav-deb"; mkdir -p "$X"
      if dpkg-deb -x "$CACHE/clamav.deb" "$X" 2>/dev/null; then
        V="$STAGE/vendor/clamav"; mkdir -p "$V/bin" "$V/sbin" "$V/lib"
        cp -a "$X/usr/local/bin/"{clamscan,clamdscan,freshclam,sigtool} "$V/bin/" \
          && cp -a "$X/usr/local/sbin/clamd" "$V/sbin/" \
          && cp -a "$X"/usr/local/lib/*.so* "$V/lib/" \
          && LD_LIBRARY_PATH="$V/lib" "$V/bin/clamscan" --version >/dev/null 2>&1 \
          && echo "$CLAMAV_SHA256" > "$V/.sha256" || { rm -rf "$V"; MISSING+=("clamav"); }
      else MISSING+=("clamav"); fi
      rm -rf "$X"
    else MISSING+=("clamav"); fi
  fi
else
  log "non-x86_64 host: using distro 7-Zip/ClamAV"
fi
# Fallback to distro packages only when the pinned build is unavailable (reported as PARSER_OUTDATED).
if [ ! -x "$STAGE/vendor/clamav/sbin/clamd" ] && ! command -v clamscan >/dev/null 2>&1 && [ "$have_sudo" -ge 1 ]; then
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq clamav clamav-daemon clamav-freshclam >/dev/null 2>&1 || true
fi
if [ ! -x "$STAGE/vendor/7zip/7zzs" ] && ! command -v 7zz >/dev/null 2>&1 && ! command -v 7z >/dev/null 2>&1 && [ "$have_sudo" -ge 1 ]; then
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq 7zip >/dev/null 2>&1 || true
fi

# ---- 5. self-check the staged engine before touching the live one ----
if [ "$FAIL" -eq 0 ]; then
  if ! FILEGUARD_HOME="$STAGE" FILEGUARD_DATA="$DATA" PYTHONPATH="$STAGE" \
       "$STAGE/.venv/bin/python" -m fileguard.cli version --json >/dev/null 2>"$TMP/selfcheck.err"; then
    log "staged engine self-check failed: $(tail -n 3 "$TMP/selfcheck.err")"; FAIL=1
  fi
fi

ROLLED_BACK=0
if [ "$FAIL" -ne 0 ]; then
  rm -rf "$STAGE"
  USABLE=0; fg_usable && USABLE=1
  [ "$ACTION" != "installed" ] && ROLLED_BACK=1
  emit "$ACTION" "${OLD_VER:-$NEW_VER}" "$DIR" "$DATA" 0 "$USABLE" "$ROLLED_BACK" "${MISSING[@]+"${MISSING[@]}"}"
  [ "$USABLE" -eq 1 ] && exit 0 || exit 1
fi

# ---- 6. atomic-ish swap with rollback ----
PREV="$DIR/.prev-$(date +%s)"
mkdir -p "$PREV"
for item in "${MANAGED[@]}"; do
  [ -e "$DIR/$item" ] || [ -L "$DIR/$item" ] && mv "$DIR/$item" "$PREV/$item"
done
for item in "${MANAGED[@]}"; do
  [ -e "$STAGE/$item" ] && mv "$STAGE/$item" "$DIR/$item"
done
rmdir "$STAGE" 2>/dev/null || rm -rf "$STAGE"
if ! fg_usable; then
  log "new version failed its self-check; rolling back"
  for item in "${MANAGED[@]}"; do rm -rf "${DIR:?}/$item"; done
  for item in "${MANAGED[@]}"; do [ -e "$PREV/$item" ] || [ -L "$PREV/$item" ] && mv "$PREV/$item" "$DIR/$item"; done
  rm -rf "$PREV"
  USABLE=0; fg_usable && USABLE=1
  emit "$ACTION" "${OLD_VER:-$NEW_VER}" "$DIR" "$DATA" 0 "$USABLE" 1 "${MISSING[@]+"${MISSING[@]}"}"
  [ "$USABLE" -eq 1 ] && exit 0 || exit 1
fi
rmdir "$PREV" 2>/dev/null || true
# old tree kept until the next install (a scan started before the swap may still import from it)

# ---- 7. per-host config: SSRF proxy CIDR only when public hosts resolve into it ----
python3 - "$DATA/local_config.json" << 'PY'
import ipaddress, json, os, socket, sys
p = sys.argv[1]
try:
    cfg = json.load(open(p))
except Exception:
    cfg = {}
net = ipaddress.ip_network("198.18.0.0/15")
hits = []
for h in ("github.com", "registry.npmjs.org", "pypi.org"):
    try:
        ips = {i[4][0] for i in socket.getaddrinfo(h, 443)}
    except Exception:
        continue
    if any(ipaddress.ip_address(i.split("%")[0]) in net for i in ips):
        hits.append(h)
if hits:
    cfg["ssrf_allow_cidrs"] = ["198.18.0.0/15"]
    cfg["ssrf_allow_reason"] = "public hosts resolve to fake-IP proxy addresses: " + ", ".join(hits)
else:
    cfg.pop("ssrf_allow_cidrs", None); cfg.pop("ssrf_allow_reason", None)
tmp = p + ".tmp"
json.dump(cfg, open(tmp, "w"), indent=1)
os.replace(tmp, p)
PY

# ---- 8. signatures + clamd ----
FILEGUARD_DATA="$DATA" bash "$DIR/scripts/update_clamav_db.sh" --if-older-than 24 9>&- >&2 || log "signature update failed (continuing)"
FILEGUARD_DATA="$DATA" bash "$DIR/scripts/start_clamd.sh" 9>&- >&2 || log "clamd not started (clamscan fallback)"

# ---- 9. PATH entry: only the default install owns /usr/local/bin/fg ----
if [ "$DIR" = "/workspace/fileguard" ]; then
  if [ -w /usr/local/bin ]; then ln -sfn "$DIR/bin/fg" /usr/local/bin/fg || true
  elif [ "$have_sudo" -ge 1 ]; then $SUDO ln -sfn "$DIR/bin/fg" /usr/local/bin/fg || true
  else mkdir -p "$HOME/.local/bin"; ln -sfn "$DIR/bin/fg" "$HOME/.local/bin/fg" || true; fi
fi

rm -rf "$CACHE"

# ---- 10. report ----
missing=()
for m in "${MISSING[@]+"${MISSING[@]}"}"; do
  case "$m" in rpm|msitools|innoextract|osslsigncode|gnupg|xz-utils|openssh-client|ca-certificates) ;; *) missing+=("$m") ;; esac
done
while read -r m; do [ -n "$m" ] && missing+=("$m"); done < <(
  FILEGUARD_HOME="$DIR" FILEGUARD_DATA="$DATA" "$DIR/scripts/fg" version --json 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("\n".join(d.get("missing_components",[])))' 2>/dev/null || true)
python3 - "$DATA/update_state.json" "$NEW_VER" << 'PY'
import json, os, sys, time
p, v = sys.argv[1:]
try:
    st = json.load(open(p))
except Exception:
    st = {}
st.update(installed_version=v, installed_at=time.time(), last_check=time.time())
json.dump(st, open(p + ".tmp", "w"), indent=1); os.replace(p + ".tmp", p)
PY
uniq_missing=($(printf '%s\n' "${missing[@]+"${missing[@]}"}" | awk 'NF && !seen[$0]++'))
emit "$ACTION" "$NEW_VER" "$DIR" "$DATA" 1 1 0 "${uniq_missing[@]+"${uniq_missing[@]}"}"
exit 0
