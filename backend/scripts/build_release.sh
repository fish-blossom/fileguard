#!/usr/bin/env bash
# Build a reproducible FileGuard release from a clean git checkout and (optionally) sign it.
#   scripts/build_release.sh [out-dir]
#   FILEGUARD_SIGNING_KEY=~/.config/fileguard-release/release_ed25519 scripts/build_release.sh dist
# Outputs: fileguard.tar.gz (top dir fileguard/), fileguard.tar.gz.sha256, manifest.json,
#          manifest.json.sig (ssh-keygen -Y sign, namespace fileguard-release) when a key is given.
# CI (.github/workflows/release.yml) also attests the tarball and manifest with GitHub Actions
# build provenance and publishes them as a GitHub Release; do not also publish from a laptop.
# The tarball is built from `git archive` of HEAD's backend/ so it contains exactly the committed
# files (no venv, data, tests or caches); file times are pinned to the commit time.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(git -C "$ROOT" rev-parse --show-toplevel)"
OUT="$(realpath -m "${1:-$ROOT/dist}")"
REPO="${FILEGUARD_REPO:-fish-blossom/fileguard}"
mkdir -p "$OUT"
if [ -n "$(git -C "$REPO_ROOT" status --porcelain -- backend)" ]; then
  echo "backend/ has uncommitted changes; commit first" >&2; exit 1
fi
VER="$(git -C "$REPO_ROOT" show HEAD:backend/VERSION | head -n1 | tr -d ' \t\r')"
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct HEAD)"
STAGE="$(mktemp -d /tmp/fileguard-rel.XXXXXX)"; trap 'rm -rf "$STAGE"' EXIT
git -C "$REPO_ROOT" archive --format=tar --prefix=fileguard/ HEAD:backend | tar -x -C "$STAGE"
cp "$REPO_ROOT/LICENSE" "$STAGE/fileguard/LICENSE" 2>/dev/null || true
tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner --mode='u+rwX,go+rX,go-w' \
    -C "$STAGE" -cf - fileguard | gzip -9n > "$OUT/fileguard.tar.gz"
SHA="$(sha256sum "$OUT/fileguard.tar.gz" | awk '{print $1}')"
echo "$SHA  fileguard.tar.gz" > "$OUT/fileguard.tar.gz.sha256"
python3 - "$OUT/manifest.json" "$VER" "$COMMIT" "$SHA" "$(stat -c %s "$OUT/fileguard.tar.gz")" "$REPO" "$EPOCH" << 'PY'
import json, sys, time
out, ver, commit, sha, size, repo, epoch = sys.argv[1:]
json.dump({
    "name": "fileguard",
    "version": ver,
    "tag": f"v{ver}",
    "commit": commit,
    "tarball": "fileguard.tar.gz",
    "tarball_url": f"https://github.com/{repo}/releases/download/v{ver}/fileguard.tar.gz",
    "sha256": sha,
    "size": int(size),
    "source_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(epoch))),
}, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY
if [ -n "${FILEGUARD_SIGNING_KEY:-}" ]; then
  rm -f "$OUT/manifest.json.sig"
  ssh-keygen -Y sign -f "$FILEGUARD_SIGNING_KEY" -n fileguard-release "$OUT/manifest.json" >/dev/null
  ssh-keygen -Y verify -f "$ROOT/release-signers" -I fileguard-release@fish-blossom -n fileguard-release \
    -s "$OUT/manifest.json.sig" < "$OUT/manifest.json"
fi
ls -l "$OUT"
