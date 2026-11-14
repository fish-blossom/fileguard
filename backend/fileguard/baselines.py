"""Version-baseline snapshots on disk, plus a registry fetch of the previous version
when no local baseline exists.

A baseline is a JSON profile (file list with hashes, install hooks, deps, network IOCs,
binaries, eval_count) stored at data/baselines/<ecosystem>/<name>/<version>.json.
Only complete NO_FINDINGS scans are written as local "scan" baselines. A registry
fetch is a best-effort profile of the previous published version (not a verdict) so
S4 can still diff on a first-seen package.
"""
from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path

import httpx

from . import config, store
from .model import ScanContext


def previous_registry_version(eco, name, version):
    """Return the published version immediately before `version`, or None."""
    try:
        if eco == "npm":
            return _npm_previous(name, version)
        if eco == "pypi":
            return _pypi_previous(name, version)
    except Exception:
        return None
    return None


def _npm_previous(name, version):
    import nodesemver
    url = f"{config.NPM_REGISTRY}/{name.replace('/', '%2f')}"
    r = httpx.get(url, timeout=config.NET_STALL_TIMEOUT, follow_redirects=True)
    r.raise_for_status()
    doc = r.json()
    versions = [v for v in (doc.get("versions") or {}) if v and v != version]
    # drop unpublished / yanked if marked
    time_map = doc.get("time") or {}
    versions = [v for v in versions if time_map.get(v) != "unpublished"]
    try:
        older = [v for v in versions if nodesemver.satisfies(v, "<" + version, loose=True)]
        if not older:
            return None
        return nodesemver.max_satisfying(older, "*", loose=True)
    except Exception:
        # last-resort string sort is worse; just pick the last listed before current if possible
        if version in (doc.get("versions") or {}) :
            keys = list((doc.get("versions") or {}).keys())
            if version in keys:
                i = keys.index(version)
                return keys[i - 1] if i > 0 else None
        return None


def _pypi_previous(name, version):
    from packaging.version import InvalidVersion, Version
    r = httpx.get(f"{config.PYPI_URL}/pypi/{name}/json", timeout=config.NET_STALL_TIMEOUT, follow_redirects=True)
    r.raise_for_status()
    doc = r.json()
    try:
        cur = Version(version)
    except InvalidVersion:
        return None
    older = []
    for v, files in (doc.get("releases") or {}).items():
        if not files or v == version:
            continue
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv < cur and not pv.is_prerelease:
            older.append(pv)
    if not older:
        return None
    return str(max(older))


def _tarball_url(eco, name, version):
    if eco == "npm":
        # official layout: /<name>/-/<basename>-<ver>.tgz ; scoped: @scope/name -> name-ver.tgz
        base = name.split("/")[-1]
        return f"{config.NPM_REGISTRY}/{name}/-/{base}-{version}.tgz"
    if eco == "pypi":
        r = httpx.get(f"{config.PYPI_URL}/pypi/{name}/{version}/json", timeout=config.NET_STALL_TIMEOUT, follow_redirects=True)
        r.raise_for_status()
        urls = r.json().get("urls") or []
        # prefer sdist
        for want in ("sdist", "bdist_wheel"):
            for u in urls:
                if u.get("packagetype") == want and u.get("url"):
                    return u["url"]
        if urls and urls[0].get("url"):
            return urls[0]["url"]
    return None


def profile_archive(path, filename):
    """Build a baseline profile from an already-downloaded archive. Never executes the sample."""
    import hashlib
    from .analyzers import Analyzer
    from .pipeline import _profile, _yara_on_bytes
    from .unpack import Unpacker

    ctx = ScanContext("baseline-fetch", "en")
    ctx.deadline = lambda: None
    work = Path(tempfile.mkdtemp(prefix="fg-base-", dir=str(config.WORK_DIR)))
    try:
        unp = Unpacker(ctx, work / "x")
        inv = unp.run(str(path), filename)
        an = Analyzer(ctx, _yara_on_bytes)
        for item in inv:
            try:
                an.analyze(item)
            except Exception:
                pass
            try:
                with open(item["abs"], "rb") as fh:
                    item["sha256"] = hashlib.sha256(fh.read()).hexdigest()
                if item.get("depth", 0) > 0 and not item.get("container"):
                    rel = item["rel"].split("!/", 1)
                    an.file_hashes[rel[-1]] = item["sha256"]
            except Exception:
                continue
        return _profile(an), _sha256(path)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_previous_profile(eco, name, version):
    """Download the previous published version and return a baseline row, or None."""
    prev = previous_registry_version(eco, name, version)
    if not prev:
        return None
    # already on disk?
    existing = store.baseline_get(eco, name, prev)
    if existing:
        return existing
    url = _tarball_url(eco, name, prev)
    if not url:
        return None
    from . import netutil
    dest_dir = Path(tempfile.mkdtemp(prefix="fg-base-dl-", dir=str(config.WORK_DIR)))
    dest = dest_dir / "pkg.bin"
    try:
        netutil.download(url, dest, config.MAX_FILE_BYTES, lambda: None)
        filename = Path(url).name or f"{name}-{prev}"
        profile, sha = profile_archive(dest, filename)
        rec = store.baseline_put(eco, name, prev, sha, profile, scan_id=None, source="registry")
        # API shape
        return {
            "ecosystem": eco,
            "name": name,
            "version": prev,
            "sha256": sha,
            "profile_json": __import__("json").dumps(profile, ensure_ascii=False),
            "scan_id": None,
            "created_at": rec.get("created_at"),
            "source": "registry",
        }
    except Exception:
        return None
    finally:
        shutil.rmtree(dest_dir, ignore_errors=True)


def resolve(eco, name, version):
    """Local baseline of another version, else a registry-fetched previous version, else None."""
    local = store.baseline_latest(eco, name, exclude_version=version)
    if local:
        return local
    return fetch_previous_profile(eco, name, version)
