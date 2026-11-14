#!/usr/bin/env bash
# Build the FileGuard engine release tarball (no .venv, no data, no 500 MB test fixture).
# Usage: scripts/build_release.sh [output-dir]
# Default output: $ROOT/dist/fileguard.tar.gz  and fileguard-<version>.tar.gz
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist}"
VER="$(head -n1 "$ROOT/VERSION" | tr -d ' \t\r')"
VER="${VER:-0.0.0}"
mkdir -p "$OUT_DIR"
STAGE="$(mktemp -d /tmp/fileguard-rel.XXXXXX)"
trap 'rm -rf "$STAGE"' EXIT

DEST="$STAGE/fileguard"
mkdir -p "$DEST"

# Copy a clean engine tree.
python3 - "$ROOT" "$DEST" << 'PY'
import os, shutil, sys
src, dest = sys.argv[1], sys.argv[2]
skip_top = {".venv", "data", "run", "__pycache__", ".git"}
for name in os.listdir(src):
    if name in skip_top:
        continue
    s = os.path.join(src, name)
    d = os.path.join(dest, name)
    if os.path.isdir(s):
        def ignore(dirpath, names):
            out = []
            rel = os.path.relpath(dirpath, s)
            for n in names:
                if n in {"__pycache__", ".git", ".venv", "data", "run"}:
                    out.append(n)
                elif n.endswith((".pyc", ".pid", ".sock")) or n == "too_big.bin":
                    out.append(n)
                elif rel.replace("\\", "/") == "out" and os.path.basename(s) == "tests":
                    out.append(n)
            return out
        shutil.copytree(s, d, ignore=ignore, dirs_exist_ok=True)
    else:
        if name.endswith((".pyc", ".zip")):
            continue
        shutil.copy2(s, d)

# Ensure tests/out is not present; drop stale MCP leftovers if any slipped in.
for rel in (
    "fileguard/mcp_server.py", "fileguard/db.py",
    "scripts/run_mcp_http.sh", "scripts/run_mcp_stdio.sh", "scripts/fg_client.py",
    "tests/out", "tests/samples/too_big.bin",
):
    p = os.path.join(dest, rel)
    if os.path.isdir(p):
        shutil.rmtree(p, ignore_errors=True)
    elif os.path.isfile(p):
        os.remove(p)
PY

chmod +x "$DEST/install.sh" "$DEST/scripts/fg" "$DEST/scripts/start_clamd.sh" "$DEST/scripts/build_release.sh" "$DEST/bin/fg" 2>/dev/null || true

TAR="$OUT_DIR/fileguard-${VER}.tar.gz"
TAR_LATEST="$OUT_DIR/fileguard.tar.gz"
tar -czf "$TAR" -C "$STAGE" fileguard
cp -f "$TAR" "$TAR_LATEST"
# a sibling VERSION file so getting-started can check latest without unpacking
cp -f "$ROOT/VERSION" "$OUT_DIR/fileguard-VERSION"
ls -lh "$TAR" "$TAR_LATEST"
echo "built $TAR"
