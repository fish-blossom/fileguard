"""Scan-duration estimator (returned with scan_id) and remaining-time estimate while running.

Cheap features only (no full unpack): input size, type, zip entry count, package manifest peek
(ecosystem, declared dependency count, how many are already in the dependency cache, repository field),
and whether signature / repo-tag checks will run. Coefficients are calibrated on real runs on this box
(see README, "耗时预估"); the range is 0.6x-1.8x of the point estimate.
"""
import base64
import io
import json
import os
import re
import tarfile
import urllib.parse
import zipfile

from . import config, store

# seconds; calibrated on lodash/axios/express/typescript/esbuild/flask/requests/numpy/putty/node runs
C = {"base": 0.3, "per_file": 0.002, "per_unpacked_mb": 0.2, "per_new_dep": 0.02, "per_cached_dep": 0.003,
     "repo_diff": 0.4, "repo_per_mb": 0.25, "npm_sigs": 0.5, "pypi_sigs": 0.6, "pe_sig": 0.3, "installer": 1.5, "url_fetch": 0.5,
     "transitive_factor_npm": 2.2, "transitive_factor_pypi": 1.5}
STAGE_FRAC = {"S0": 0.03, "S1": 0.06, "S2": 0.10, "S3:unpack": 0.15, "S3:clamav": 0.25, "S3:yara+analyzers": 0.35,
              "S3:signatures": 0.55, "S3:lockfiles": 0.60, "S3:deps": 0.65, "S4": 0.85, "S5": 0.95, "S6": 0.98, "S7": 0.99}
STAGE_NAME = {"S0": ("输入受理", "intake"), "S1": ("来源检查", "source checks"), "S2": ("完整性/哈希", "integrity & hashes"),
              "S3:unpack": ("解包", "unpacking"), "S3:clamav": ("ClamAV 扫描", "ClamAV scan"), "S3:yara+analyzers": ("YARA 与格式分析", "YARA & format analysis"),
              "S3:signatures": ("签名与来源证明验证", "signature & provenance verification"), "S3:lockfiles": ("锁文件哈希比对", "lock-file hash comparison"),
              "S3:deps": ("依赖检查", "dependency checks"), "S4": ("版本/源码 tag 比对", "version / source-tag diff"), "S5": ("安装足迹预测", "install-footprint prediction"),
              "S6": ("裁决", "verdict"), "S7": ("生成报告", "report")}


def _archive_stats(data_or_path, size):
    """(entries, uncompressed_bytes) for zip (central directory: cheap) and tar.gz (streamed listing, only <=100 MB)."""
    try:
        f = open(data_or_path, "rb") if isinstance(data_or_path, str) else io.BytesIO(data_or_path)
        with f:
            head = f.read(4)
            f.seek(0)
            if head[:2] == b"PK":
                z = zipfile.ZipFile(f)
                infos = z.infolist()
                return len(infos), sum(i.file_size for i in infos)
            if head[:2] == b"\x1f\x8b" and size <= 100 * (1 << 20):
                n = u = 0
                with tarfile.open(fileobj=f, mode="r|gz") as tf:
                    for m in tf:
                        if m.isfile():
                            n += 1
                            u += m.size
                return n, u
    except Exception:
        pass
    return None, None


def _peek_manifest(data_or_path):
    """Return (ecosystem, deps dict, repository, n_entries) by peeking the archive head; None on failure."""
    try:
        f = open(data_or_path, "rb") if isinstance(data_or_path, str) else io.BytesIO(data_or_path)
        with f:
            head = f.read(4)
            f.seek(0)
            if head[:2] == b"PK":
                z = zipfile.ZipFile(f)
                names = z.namelist()
                for n in names:
                    b = n.rsplit("/", 1)[-1]
                    if b == "package.json" and n.count("/") <= 1:
                        pj = json.loads(z.read(n))
                        return "npm", pj.get("dependencies") or {}, pj.get("repository"), len(names)
                    if b in ("METADATA", "PKG-INFO") and n.count("/") <= 1:
                        t = z.read(n).decode("utf-8", "replace").split("\n\n", 1)[0]
                        return "pypi", {d: "" for d in re.findall(r"^Requires-Dist:\s*([A-Za-z0-9_.\-]+)(?![^\n]*extra ==)", t, re.M)}, \
                            "github.com" if "github.com" in t else None, len(names)
                return None, {}, None, len(names)
            if head[:2] == b"\x1f\x8b":
                with tarfile.open(fileobj=f, mode="r|gz") as tf:
                    for i, m in enumerate(tf):
                        if i > 20000:
                            break
                        b = m.name.rsplit("/", 1)[-1]
                        if m.isfile() and m.name.count("/") == 1 and b in ("package.json", "PKG-INFO"):
                            t = tf.extractfile(m).read(2_000_000).decode("utf-8", "replace")
                            if b == "package.json":
                                pj = json.loads(t)
                                return "npm", pj.get("dependencies") or {}, pj.get("repository"), None
                            hd = t.split("\n\n", 1)[0]
                            return "pypi", {d: "" for d in re.findall(r"^Requires-Dist:\s*([A-Za-z0-9_.\-]+)(?![^\n]*extra ==)", hd, re.M)}, \
                                "github.com" if "github.com" in hd else None, None
    except Exception:
        pass
    return None, {}, None, None


def _cached_count(eco, names):
    if not names:
        return 0
    try:
        return store.dep_cache_count(eco, names)
    except Exception:
        return 0


def features(source):
    f = {"kind": source["kind"], "size": None, "ext": "", "entries": None, "unpacked": None, "ecosystem": None, "deps": 0, "deps_cached": 0,
         "repo": False, "pe": False, "installer": False}
    name = source.get("filename") or os.path.basename(source.get("path", "")) or urllib.parse.urlsplit(source.get("url", "")).path.rsplit("/", 1)[-1]
    f["ext"] = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    peek = None
    if source["kind"] == "path" and os.path.isfile(source["path"]):
        f["size"] = os.path.getsize(source["path"])
        peek = source["path"]
    elif source["kind"] == "base64":
        f["size"] = len(source.get("data") or "") * 3 // 4
        if f["size"] < 50 * (1 << 20):
            try:
                peek = base64.b64decode(source["data"])
            except Exception:
                peek = None
    elif source["kind"] == "url":
        u = source.get("url", "")
        m = re.match(r"https://registry\.npmjs\.org/(?:@[^/]+/)?[^/]+/-/", u)
        if m:
            f["ecosystem"] = "npm"
        elif "files.pythonhosted.org" in u:
            f["ecosystem"] = "pypi"
    if peek is not None and f["ext"] in ("zip", "tgz", "gz", "whl", "jar", "nupkg", "crx", "xpi", "vsix"):
        eco, deps, repo, n = _peek_manifest(peek)
        n2, unpacked = _archive_stats(peek, f["size"] or 0)
        rs = json.dumps(repo) if repo else ""
        f.update(ecosystem=eco or f["ecosystem"], deps=len(deps), entries=n2 or n, unpacked=unpacked,
                 repo=bool(repo) and ("github" in rs or bool(re.fullmatch(r'"[\w.-]+/[\w.-]+"', rs))))
        if eco:
            f["deps_cached"] = _cached_count(eco, list(deps)[:500])
    if f["ext"] in ("exe", "dll", "msi", "sys"):
        f["pe"] = True
        f["installer"] = f["ext"] == "msi" or "setup" in name.lower() or "install" in name.lower()
    return f


def estimate(f):
    """Point estimate in seconds. Calibrated on this box (real packages, see README): ~0.002 s per file and
    ~0.2 s per uncompressed MB (ClamAV + YARA + analyzers), dependency resolution ~0.02 s per new dependency
    (16-way parallel, transitive fan-out ~2x for npm), repo-tag diff = tag tarball download + hashing."""
    if f["size"] and f["size"] > config.MAX_FILE_BYTES:
        return 0.5                         # rejected at intake
    size_mb = (f["size"] or 2 * (1 << 20)) / (1 << 20)
    unpacked_mb = (f.get("unpacked") or f["size"] or 2 * (1 << 20)) / (1 << 20)
    if unpacked_mb > size_mb * config.BOMB_RATIO:   # bomb-like entries are refused early, not unpacked
        unpacked_mb = size_mb * 2
    unpacked_mb = min(unpacked_mb, config.MAX_UNPACK_TOTAL_BYTES / (1 << 20))
    entries = f["entries"]
    if entries is None and f["ext"] in ("tgz", "gz", "tar", "xz", "bz2", "7z", "rar", "zip", "whl"):
        entries = int(size_mb * 300)       # unknown listing: ~300 files per compressed MB of source
    t = C["base"] + C["per_file"] * (entries or 1) + C["per_unpacked_mb"] * unpacked_mb
    if f["kind"] == "url":
        t += C["url_fetch"] + size_mb / 10.0
    if f["ecosystem"]:
        new = max(0, f["deps"] - f["deps_cached"])
        factor = C["transitive_factor_npm"] if f["ecosystem"] == "npm" else C["transitive_factor_pypi"]
        t += C["per_new_dep"] * min(new * factor, config.MAX_NEW_DEPS) + C["per_cached_dep"] * f["deps_cached"] * factor
        t += C["npm_sigs"] if f["ecosystem"] == "npm" else C["pypi_sigs"]
        if f["repo"] or f["ecosystem"] == "pypi":
            t += C["repo_diff"] + C["repo_per_mb"] * min(unpacked_mb, 30)
    if f["pe"]:
        t += C["pe_sig"]
    if f["installer"]:
        t += C["installer"]
    return round(max(0.5, t), 1)


def human(seconds, lang):
    lo, hi = max(1, round(seconds * 0.6)), max(2, round(seconds * 1.8))

    def fmt(s, zh):
        if s < 90:
            return f"{s} 秒" if zh else f"{s}s"
        m = round(s / 60)
        return f"{m} 分钟" if zh else f"{m} min"
    zh = lang != "en"
    if zh:
        return f"约 {fmt(round(seconds), True)}（通常 {fmt(lo, True)}–{fmt(hi, True)}）"
    return f"about {fmt(round(seconds), False)} (typically {fmt(lo, False)}–{fmt(hi, False)})"


def remaining(est, elapsed, stage):
    frac = STAGE_FRAC.get(stage, STAGE_FRAC.get((stage or "").split(":")[0], 0.1))
    projected = est
    if elapsed > est * 0.8 and frac >= 0.1:
        projected = max(est, elapsed / frac)
    return round(max(1.0, projected - elapsed), 1), round(frac * 100)


def stage_label(stage, lang):
    s = STAGE_NAME.get(stage) or STAGE_NAME.get((stage or "").split(":")[0])
    return (s[0] if lang != "en" else s[1]) if s else stage
