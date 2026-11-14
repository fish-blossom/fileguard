#!/usr/bin/env bash
# Idempotent FileGuard engine installer / updater for a Grok Bot box
# (Debian/Ubuntu, user `box`, /workspace writable, sudo likely available).
#
# Usage:
#   ./install.sh
#   ./install.sh --estimate          # no changes; print action + estimated_seconds
#   ./install.sh --tarball /path/to/fileguard.tar.gz
#   FILEGUARD_SOURCE_URL=https://github.com/fish-blossom/fileguard/archive/refs/heads/main.tar.gz \
#     ./install.sh
#   # or from a git checkout: git clone https://github.com/fish-blossom/fileguard.git && bash fileguard/backend/install.sh
#   FILEGUARD_DIR=/workspace/fileguard FILEGUARD_DATA=/workspace/fileguard/data ./install.sh
#
# Default source is GitHub's auto archive of main (not a Release asset):
#   https://github.com/fish-blossom/fileguard/archive/refs/heads/main.tar.gz
# Version checks (silent updates) use:
#   https://raw.githubusercontent.com/fish-blossom/fileguard/main/backend/VERSION
# The GitHub archive unpacks as fileguard-main/backend/ (engine root).
#
# Prints ONE JSON object to stdout (progress / errors go to stderr).
#   install:  {action, version, dir, data_dir, ok, usable, rolled_back, missing_components}
#   --estimate: {action, version, estimated_seconds, estimate_text_zh, estimate_text_en, ...}
# action is installed | updated | up_to_date.
# The bot must not list components or describe the install to the user.
# Updates are silent; if an update fails the previous version is restored when possible.
set -euo pipefail

log() { printf '%s\n' "$*" >&2; }

DIR="${FILEGUARD_DIR:-/workspace/fileguard}"
TARBALL=""
SOURCE_URL="${FILEGUARD_SOURCE_URL:-}"
ESTIMATE=0
DEFAULT_SOURCE_URL="https://github.com/fish-blossom/fileguard/archive/refs/heads/main.tar.gz"
DEFAULT_VERSION_URL="https://raw.githubusercontent.com/fish-blossom/fileguard/main/backend/VERSION"

while [ $# -gt 0 ]; do
  case "$1" in
    --tarball|--from-tarball) TARBALL="${2:-}"; shift 2 ;;
    --source-url) SOURCE_URL="${2:-}"; shift 2 ;;
    --dir) DIR="${2:-}"; shift 2 ;;
    --estimate) ESTIMATE=1; shift ;;
    -h|--help)
      sed -n '2,22p' "$0" >&2
      exit 0
      ;;
    *) log "unknown argument: $1"; exit 2 ;;
  esac
done

umask 022
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
TMP=""
BACKUP=""
ROLLED_BACK=0
OK=1
cleanup() {
  [ -n "${TMP:-}" ] && rm -rf "$TMP"
  # keep BACKUP only if we still need it; successful runs drop it
  if [ "${OK}" -eq 1 ] && [ -n "${BACKUP:-}" ] && [ -d "${BACKUP:-}" ]; then
    rm -rf "$BACKUP"
  fi
}
trap cleanup EXIT

installed_version() {
  if [ -f "$DIR/VERSION" ]; then
    head -n1 "$DIR/VERSION" | tr -d ' \t\r'
  else
    echo ""
  fi
}

peek_version_from_tar() {
  local t="$1" member
  member="$(tar -tzf "$t" 2>/dev/null | grep -E '(^|/)VERSION$' | head -n1 || true)"
  if [ -n "$member" ]; then
    tar -xOf "$t" "$member" 2>/dev/null | head -n1 | tr -d ' \t\r'
  fi
}

fg_usable() {
  local fgbin=""
  if [ -x "$DIR/scripts/fg" ]; then
    fgbin="$DIR/scripts/fg"
  elif [ -x "$DIR/bin/fg" ]; then
    fgbin="$DIR/bin/fg"
  else
    return 1
  fi
  FILEGUARD_HOME="$DIR" FILEGUARD_DATA="${FILEGUARD_DATA:-$DIR/data}" \
    "$fgbin" --version >/dev/null 2>&1
}

# ---------- resolve source (estimate never extracts or downloads an archive) ----------
find_engine_root() {
  python3 - "$1" << 'PY'
import os, sys
root = sys.argv[1]
for dirpath, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in {".git", ".venv", "data", "run", "__pycache__", "node_modules"}]
    if "fileguard" in dirs and ("install.sh" in files or "VERSION" in files):
        if os.path.isfile(os.path.join(dirpath, "fileguard", "__init__.py")):
            print(dirpath)
            raise SystemExit(0)
raise SystemExit(1)
PY
}

fetch_remote_version() {
  local url="${FILEGUARD_SOURCE_VERSION_URL:-$DEFAULT_VERSION_URL}"
  local v=""
  if command -v curl >/dev/null 2>&1; then
    v="$(curl -fsSL --max-time 15 "$url" 2>/dev/null | head -n1 | tr -d ' \t\r' || true)"
  elif command -v wget >/dev/null 2>&1; then
    v="$(wget -q -O - --timeout=15 "$url" 2>/dev/null | head -n1 | tr -d ' \t\r' || true)"
  fi
  case "$v" in
    [0-9]*) printf '%s\n' "$v" ;;
    *) printf '%s\n' "" ;;
  esac
}

is_git_url() {
  local u="$1"
  case "$u" in
    *.git) return 0 ;;
    *github.com/*/*) 
      case "$u" in
        */archive/*|*.tar.gz|*.tgz|*.zip) return 1 ;;
        *) return 0 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

fetch_source() {
  local url="$1"
  TMP="$(mktemp -d /tmp/fileguard-install.XXXXXX)"
  if is_git_url "$url"; then
    log "cloning $url"
    if ! git clone --depth 1 --branch main "$url" "$TMP/src" >&2; then
      git clone --depth 1 "$url" "$TMP/src" >&2
    fi
    SRC_DIR="$(find_engine_root "$TMP/src" || true)"
  else
    log "downloading $url"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$url" -o "$TMP/src.tar.gz"
    else
      wget -q -O "$TMP/src.tar.gz" "$url"
    fi
    tar -xzf "$TMP/src.tar.gz" -C "$TMP"
    SRC_DIR="$(find_engine_root "$TMP" || true)"
  fi
  if [ -z "${SRC_DIR:-}" ] || [ ! -d "$SRC_DIR/fileguard" ]; then
    log "could not find the FileGuard engine in the downloaded source"
    exit 1
  fi
}

ESTIMATE_VER=""
if [ -n "$TARBALL" ]; then
  if [ ! -f "$TARBALL" ]; then
    log "tarball not found: $TARBALL"
    exit 1
  fi
  if [ "$ESTIMATE" -eq 1 ]; then
    ESTIMATE_VER="$(peek_version_from_tar "$TARBALL")"
  else
    log "extracting $TARBALL"
    TMP="$(mktemp -d /tmp/fileguard-install.XXXXXX)"
    tar -xzf "$TARBALL" -C "$TMP"
    SRC_DIR="$(find_engine_root "$TMP" || true)"
    if [ -z "${SRC_DIR:-}" ]; then
      log "could not find the FileGuard engine in $TARBALL"
      exit 1
    fi
  fi
elif [ "$ESTIMATE" -eq 0 ] && [ -n "$SOURCE_URL" ]; then
  fetch_source "$SOURCE_URL"
fi

LOCAL_VER=""
if [ -f "$SRC_DIR/VERSION" ]; then
  LOCAL_VER="$(head -n1 "$SRC_DIR/VERSION" | tr -d ' \t\r')"
fi
REMOTE_VER=""
# For --estimate (no tarball) and in-place updates, prefer the published VERSION on main.
if [ -z "$TARBALL" ]; then
  REMOTE_VER="$(fetch_remote_version || true)"
fi

if [ -n "$ESTIMATE_VER" ]; then
  NEW_VER="$ESTIMATE_VER"
elif [ -n "$REMOTE_VER" ]; then
  # If we are running from a full unpacked/checkout tree that is *not* the live
  # install dir, use that tree's version (bootstrap / git clone).
  if [ -n "$LOCAL_VER" ] && [ -d "$SRC_DIR/fileguard" ]; then
    src_real="$(realpath "$SRC_DIR" 2>/dev/null || echo "$SRC_DIR")"
    dir_real="$(realpath "$DIR" 2>/dev/null || echo "$DIR")"
    if [ "$src_real" != "$dir_real" ]; then
      NEW_VER="$LOCAL_VER"
    else
      NEW_VER="$REMOTE_VER"
    fi
  else
    NEW_VER="$REMOTE_VER"
  fi
else
  NEW_VER="${LOCAL_VER:-0.0.0}"
fi

OLD_VER="$(installed_version)"
DATA="${FILEGUARD_DATA:-$DIR/data}"

classify_action() {
  if [ -z "$OLD_VER" ] || [ ! -d "$DIR/fileguard" ] || { [ ! -x "$DIR/scripts/fg" ] && [ ! -x "$DIR/bin/fg" ]; }; then
    ACTION="installed"
  elif [ "$OLD_VER" = "$NEW_VER" ]; then
    ACTION="up_to_date"
  else
    ACTION="updated"
  fi
}

estimate_seconds() {
  python3 - "$ACTION" "$DIR" << 'PY'
import os, subprocess, sys
action, dest = sys.argv[1], sys.argv[2]
if action == "up_to_date":
    print(0)
    raise SystemExit

def pkg_ok(name):
    aliases = {"libmagic1": ("libmagic1", "libmagic1t64"),
               "python3-pip": ("python3-pip", "python3-pip-whl")}
    names = aliases.get(name, (name,))
    for n in names:
        try:
            r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", n],
                               capture_output=True, text=True, timeout=5)
            if "install ok installed" in (r.stdout or ""):
                return True
        except Exception:
            pass
    return False

required = ["clamav", "clamav-daemon", "clamav-freshclam", "yara", "python3-venv", "python3-pip", "libmagic1"]
need_apt = sum(1 for p in required if not pkg_ok(p))
venv = os.path.isfile(os.path.join(dest, ".venv", "bin", "python"))
warm = False
if venv:
    try:
        r = subprocess.run([os.path.join(dest, ".venv", "bin", "python"), "-c", "import httpx,yara"],
                           capture_output=True, timeout=10)
        warm = r.returncode == 0
    except Exception:
        warm = False
sigs = any(os.path.exists(p) for p in ("/var/lib/clamav/main.cvd", "/var/lib/clamav/main.cld"))
seconds = 8
if need_apt:
    seconds += 90 + 25 * min(need_apt, 6)
if not venv:
    seconds += 70
elif not warm:
    seconds += 40
else:
    seconds += 8
if not sigs:
    seconds += 90
if action == "installed":
    seconds = max(seconds, 60)
    if need_apt or not venv or not sigs:
        seconds = max(seconds, 120)
elif action == "updated":
    if need_apt:
        seconds = max(seconds, 90)
    else:
        seconds = max(20, min(seconds, 60))
print(int(seconds))
PY
}

estimate_texts() {
  python3 - "$1" << 'PY'
import sys
s = int(sys.argv[1])
if s <= 0:
    print("")
    print("")
    raise SystemExit
if s < 90:
    print(f"约 {s} 秒")
    print(f"about {s} seconds")
else:
    m = max(1, int(round(s / 60)))
    if m == 1:
        print("约 1 分钟")
        print("about 1 minute")
    else:
        print(f"约 {m} 分钟")
        print(f"about {m} minutes")
PY
}

classify_action

if [ "$ESTIMATE" -eq 1 ]; then
  SECS="$(estimate_seconds)"
  mapfile -t _TX < <(estimate_texts "$SECS")
  ZH="${_TX[0]:-}"
  EN="${_TX[1]:-}"
  python3 - "$ACTION" "$NEW_VER" "$OLD_VER" "$DIR" "$DATA" "$SECS" "$ZH" "$EN" << 'PY'
import json, sys
action, version, old, d, data, secs, zh, en = sys.argv[1:]
print(json.dumps({
    "action": action,
    "version": version,
    "installed_version": old or None,
    "dir": d,
    "data_dir": data,
    "estimated_seconds": int(secs),
    "estimate_text_zh": zh,
    "estimate_text_en": en,
}, ensure_ascii=False))
PY
  exit 0
fi

# In-place update of an already-installed copy: pull the latest tree from GitHub
# (or FILEGUARD_SOURCE_URL) so we are not copying the old install onto itself.
if [ "$ACTION" = "updated" ] && [ -z "$TARBALL" ] && [ -z "$SOURCE_URL" ]; then
  src_real="$(realpath "$SRC_DIR" 2>/dev/null || echo "$SRC_DIR")"
  dir_real="$(realpath "$DIR" 2>/dev/null || echo "$DIR")"
  if [ "$src_real" = "$dir_real" ] || [ ! -d "$SRC_DIR/fileguard" ]; then
    fetch_source "${FILEGUARD_SOURCE_URL:-$DEFAULT_SOURCE_URL}"
  fi
fi

mkdir -p "$DIR" "$DATA"

copy_tree() {
  python3 - "$SRC_DIR" "$DIR" << 'PY'
import os, shutil, sys
src, dest = sys.argv[1], sys.argv[2]
if os.path.realpath(src) == os.path.realpath(dest):
    sys.exit(0)
for root, dirs, files in os.walk(src):
    rel = os.path.relpath(root, src)
    dirs[:] = [d for d in dirs if d not in {".venv", "data", "run", "__pycache__", ".git"} and not d.endswith(".tmp")]
    if rel.replace("\\", "/").startswith("tests/out"):
        dirs[:] = []
        continue
    target = dest if rel == "." else os.path.join(dest, rel)
    os.makedirs(target, exist_ok=True)
    for f in files:
        if f.endswith((".pyc", ".pid", ".sock")) or f == "too_big.bin":
            continue
        s = os.path.join(root, f)
        d = os.path.join(target, f)
        shutil.copy2(s, d)
        if f in ("fg", "install.sh", "start_clamd.sh") or f.endswith(".sh"):
            os.chmod(d, 0o755)
PY
}

backup_existing() {
  BACKUP="$(mktemp -d /tmp/fileguard-prev.XXXXXX)"
  python3 - "$DIR" "$BACKUP" << 'PY'
import os, shutil, sys
src, dest = sys.argv[1], sys.argv[2]
for name in ("fileguard", "scripts", "bin", "rules", "intel", "clamav", "requirements.txt", "VERSION", "install.sh", "README.md"):
    s = os.path.join(src, name)
    if not os.path.exists(s):
        continue
    d = os.path.join(dest, name)
    if os.path.isdir(s):
        shutil.copytree(s, d, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    else:
        shutil.copy2(s, d)
PY
}

restore_backup() {
  [ -n "${BACKUP:-}" ] && [ -d "$BACKUP" ] || return 1
  log "update failed; restoring the previous FileGuard version"
  python3 - "$BACKUP" "$DIR" << 'PY'
import os, shutil, sys
src, dest = sys.argv[1], sys.argv[2]
for name in os.listdir(src):
    s = os.path.join(src, name)
    d = os.path.join(dest, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    elif os.path.lexists(d):
        os.remove(d)
    if os.path.isdir(s):
        shutil.copytree(s, d, symlinks=True)
    else:
        shutil.copy2(s, d)
PY
  ROLLED_BACK=1
}

if [ -z "$OLD_VER" ]; then
  ACTION="installed"
  log "installing FileGuard $NEW_VER into $DIR"
elif [ "$OLD_VER" = "$NEW_VER" ] && [ -d "$DIR/fileguard" ] && { [ -x "$DIR/scripts/fg" ] || [ -x "$DIR/bin/fg" ]; }; then
  ACTION="up_to_date"
  log "FileGuard $NEW_VER already installed at $DIR — refreshing dependencies if needed"
else
  ACTION="updated"
  log "updating FileGuard $OLD_VER → $NEW_VER at $DIR (data dir preserved: $DATA)"
  backup_existing
fi

# From here, failures during an update should roll back rather than leave a half-written tree.
set +e
FAIL=0

copy_tree || FAIL=1
mkdir -p "$DIR/run" "$DATA" "$DIR/bin"
if [ -f "$SRC_DIR/VERSION" ]; then
  src_v="$(realpath "$SRC_DIR/VERSION" 2>/dev/null || echo "$SRC_DIR/VERSION")"
  dst_v="$(realpath "$DIR/VERSION" 2>/dev/null || echo "")"
  if [ "$src_v" != "$dst_v" ]; then
    cp -f "$SRC_DIR/VERSION" "$DIR/VERSION" || FAIL=1
  fi
fi

APT_PKGS=(clamav clamav-daemon clamav-freshclam yara python3-venv python3-pip python3-dev
          libmagic1 libyara-dev gcc p7zip-full 7zip unrar-free unar libarchive-tools
          rpm msitools innoextract osslsigncode gnupg)
missing_apt=()
have_sudo=0
if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  have_sudo=1
elif [ "$(id -u)" -eq 0 ]; then
  have_sudo=2
fi

pkg_ok() {
  local n
  for n in "$1" $([ "$1" = libmagic1 ] && echo libmagic1t64); do
    dpkg-query -W -f='${Status}' "$n" 2>/dev/null | grep -q "install ok installed" && return 0
  done
  return 1
}

need_apt=()
for p in "${APT_PKGS[@]}"; do
  pkg_ok "$p" || need_apt+=("$p")
done

if [ "${#need_apt[@]}" -gt 0 ]; then
  if [ "$have_sudo" -eq 0 ]; then
    log "sudo not available; skipping apt install of: ${need_apt[*]}"
    missing_apt+=("${need_apt[@]}")
  else
    log "installing apt packages (missing: ${need_apt[*]})"
    SUDO="sudo"
    [ "$have_sudo" -eq 2 ] && SUDO=""
    $SUDO apt-get update -qq || log "apt-get update failed (continuing)"
    for p in "${need_apt[@]}"; do
      if $SUDO apt-get install -y -qq "$p" >/dev/null 2>&1; then
        log "  installed $p"
      else
        log "  skipped $p (not available or failed)"
        missing_apt+=("$p")
      fi
    done
  fi
fi

PY=python3
if [ ! -x "$DIR/.venv/bin/python" ]; then
  log "creating Python venv at $DIR/.venv"
  "$PY" -m venv "$DIR/.venv" || FAIL=1
fi
if [ -x "$DIR/.venv/bin/pip" ]; then
  log "installing Python requirements"
  if ! "$DIR/.venv/bin/pip" install -q -r "$DIR/requirements.txt"; then
    log "pip install failed"
    missing_apt+=("python-requirements")
    FAIL=1
  fi
else
  FAIL=1
fi

if command -v freshclam >/dev/null 2>&1 || [ -x /usr/bin/freshclam ]; then
  if [ ! -e /var/lib/clamav/main.cvd ] && [ ! -e /var/lib/clamav/main.cld ]; then
    log "running freshclam (non-fatal if it fails)"
    if [ "$have_sudo" -ge 1 ]; then
      SUDO="sudo"; [ "$have_sudo" -eq 2 ] && SUDO=""
      $SUDO freshclam || log "freshclam failed (continuing; ClamAV may be incomplete)"
    else
      freshclam || log "freshclam failed (continuing)"
    fi
  else
    log "ClamAV signatures already present; skipping freshclam"
  fi
fi

if [ -x "$DIR/scripts/start_clamd.sh" ]; then
  bash "$DIR/scripts/start_clamd.sh" || log "clamd not started (clamscan fallback will be used if available)"
fi

chmod +x "$DIR/scripts/fg" "$DIR/install.sh" 2>/dev/null || true
[ -e "$DIR/bin/fg" ] || ln -sfn ../scripts/fg "$DIR/bin/fg"
chmod +x "$DIR/bin/fg" 2>/dev/null || true
if [ -w /usr/local/bin ] || { [ "$have_sudo" -ge 1 ] && [ -d /usr/local/bin ]; }; then
  if [ -w /usr/local/bin ]; then
    ln -sfn "$DIR/bin/fg" /usr/local/bin/fg || true
  elif [ "$have_sudo" -ge 1 ]; then
    SUDO="sudo"; [ "$have_sudo" -eq 2 ] && SUDO=""
    $SUDO ln -sfn "$DIR/bin/fg" /usr/local/bin/fg || true
  fi
else
  mkdir -p "$HOME/.local/bin"
  ln -sfn "$DIR/bin/fg" "$HOME/.local/bin/fg" || true
fi

missing=()
command -v clamd >/dev/null 2>&1 || [ -x /usr/sbin/clamd ] || command -v clamscan >/dev/null 2>&1 || missing+=("clamav")
command -v yara >/dev/null 2>&1 || { [ -x "$DIR/.venv/bin/python" ] && "$DIR/.venv/bin/python" -c 'import yara' 2>/dev/null; } || missing+=("yara")
[ -x "$DIR/.venv/bin/python" ] || missing+=("venv")
[ -x "$DIR/scripts/fg" ] || missing+=("fg")
for p in "${missing_apt[@]}"; do
  case "$p" in
    7zip|p7zip-full|unrar-free|unar|libarchive-tools|rpm|msitools|innoextract|osslsigncode|gnupg|libyara-dev|python3-dev|gcc) ;;
    *)
      case " ${missing[*]} " in
        *" $p "*) ;;
        *) missing+=("$p") ;;
      esac
      ;;
  esac
done

if [ "$ACTION" = "up_to_date" ] && [ ! -d "$DIR/fileguard" ]; then
  ACTION="installed"
fi

if [ "$FAIL" -ne 0 ] && [ "$ACTION" = "updated" ]; then
  restore_backup || true
fi

USABLE=0
if fg_usable; then
  USABLE=1
fi

# A failed first-time install is not usable; a failed update should still be usable after rollback.
if [ "$FAIL" -ne 0 ]; then
  OK=0
  if [ "$ACTION" = "updated" ] && [ "$USABLE" -eq 1 ]; then
    # Keep the previous version. The bot stays silent.
    :
  fi
else
  OK=1
fi

python3 - "$ACTION" "$NEW_VER" "$DIR" "$DATA" "$OK" "$USABLE" "$ROLLED_BACK" "${missing[@]+"${missing[@]}"}" << 'PY'
import json, sys
action, version, d, data, ok, usable, rolled, *missing = sys.argv[1:]
print(json.dumps({
    "action": action,
    "version": version,
    "dir": d,
    "data_dir": data,
    "ok": ok == "1",
    "usable": usable == "1",
    "rolled_back": rolled == "1",
    "missing_components": missing,
}, ensure_ascii=False))
PY

if [ "$OK" -eq 1 ] || { [ "$ACTION" = "updated" ] && [ "$USABLE" -eq 1 ]; }; then
  exit 0
fi
exit 1
