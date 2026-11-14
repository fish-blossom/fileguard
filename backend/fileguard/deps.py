"""S3 dependency analysis: breadth-first, depth <= MAX_DEP_DEPTH, <= MAX_NEW_DEPS newly checked
dependencies per scan; cache hits do not consume the quota. Metadata-level checks only
(registry metadata, known-malicious lists, OSV.dev, typosquatting, install hooks) - no install."""
import json
import os
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import nodesemver
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from . import ENGINE_VERSION, config, store
from .scanners import rules_version

_KNOWN = json.loads((config.INTEL_DIR / "known_malicious_packages.json").read_text())
_POPULAR = json.loads((config.INTEL_DIR / "popular_packages.json").read_text())


def _lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typosquat_of(eco, name):
    n = name.lower()
    pop = [p.lower() for p in _POPULAR.get(eco, [])]
    if eco == "pypi":   # PEP 503: names differing only in -, _ or . are the SAME project, not a typosquat
        n = re.sub(r"[-_.]+", "-", n)
        pop = [re.sub(r"[-_.]+", "-", p) for p in pop]
    if n in pop:
        return None
    norm = re.sub(r"[-_.]", "", n)
    # scope impersonation: @axios/core while the real package is unscoped "axios"
    m = re.match(r"^@([^/]+)/(.+)$", n)
    if m and m.group(1) in pop and n not in pop:
        return m.group(1)
    # prefix/suffix padding: axios-js, js-axios, axios2, python-requests, requests-py
    for p in pop:
        if len(p) >= 4 and re.fullmatch(rf"(js-|node-|python-|py-|py)?{re.escape(p)}(-?js|-node|-py|-python|\d|-dev|-latest|-core)?", n) and n != p:
            if n.replace(p, "") in ("-js", "js", "-node", "node-", "js-", "-py", "py-", "python-", "-python", "py", "-dev", "-latest", "-core") or re.fullmatch(r"\d", n.replace(p, "")):
                return p
    for p in pop:
        if norm == re.sub(r"[-_.]", "", p) and n != p:
            return p
        if len(p) >= 4 and (_lev(n, p) == 1 or _transposed(n, p)):
            return p
    return None


def known_malicious(eco, name, version):
    vs = _KNOWN.get(eco, {}).get(name) or _KNOWN.get(eco, {}).get(name.lower())
    return bool(vs) and ("*" in vs or version in vs)


class DepResolver:
    def __init__(self, ctx):
        self.ctx = ctx
        self.client = httpx.Client(timeout=config.NET_STALL_TIMEOUT, headers={"User-Agent": "FileGuard/0.1"}, follow_redirects=True)
        self._pack = {}

    # ---------- registry access ----------
    def _npm_packument(self, name):
        if name in self._pack:
            return self._pack[name]
        url = f"{config.NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}".replace("/@", "/@").replace("%40", "@")
        if name.startswith("@"):
            url = f"{config.NPM_REGISTRY}/{name.replace('/', '%2f')}"
        r = self.client.get(url, headers={"Accept": "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"})
        res = None if r.status_code == 404 else _json(r)
        self._pack[name] = res
        return res

    def _npm_version_doc(self, name, version):
        n = name.replace("/", "%2f") if name.startswith("@") else name
        r = self.client.get(f"{config.NPM_REGISTRY}/{n}/{version}")
        return r.json() if r.status_code == 200 else {}

    def _pypi_meta(self, name, version=None):
        key = ("pypi", name, version)
        if key in self._pack:
            return self._pack[key]
        url = f"{config.PYPI_URL}/pypi/{name}/{version}/json" if version else f"{config.PYPI_URL}/pypi/{name}/json"
        r = self.client.get(url)
        res = None if r.status_code == 404 else _json(r)
        self._pack[key] = res
        return res

    def resolve(self, eco, name, spec):
        """Return (version, meta) ; version None if package missing."""
        if eco == "npm":
            p = self._npm_packument(name)
            if p is None:
                return None, None
            versions = list((p.get("versions") or {}).keys())
            tags = p.get("dist-tags") or {}
            spec = (spec or "latest").strip()
            if spec in tags:
                v = tags[spec]
            elif re.match(r"^(git|http|file:|link:|github:|[\w-]+/[\w.-]+$)", spec):
                self.ctx.add("medium", "S3", "DEP_NON_REGISTRY_SOURCE", f"依赖 {name} 来自非注册表来源：{spec}",
                             f"Dependency {name} comes from a non-registry source: {spec}", None, spec[:120])
                return "non-registry", {}
            else:
                try:
                    v = nodesemver.max_satisfying(versions, spec, loose=True)
                except Exception:
                    v = None
                v = v or tags.get("latest")
            return v, (p.get("versions") or {}).get(v, {})
        if eco == "pypi":
            p = self._pypi_meta(name)
            if p is None:
                return None, None
            rels = [k for k, files in (p.get("releases") or {}).items() if files]
            v = None
            try:
                ss = SpecifierSet(spec if spec and spec[0] in "<>=!~" else (f"=={spec}" if spec else ""))
                cands = sorted((Version(x) for x in rels if _valid(x) and Version(x) in ss and not Version(x).is_prerelease), reverse=True)
                v = str(cands[0]) if cands else None
            except Exception:
                v = None
            v = v or (p.get("info") or {}).get("version")
            meta = self._pypi_meta(name, v) or {}
            return v, meta
        return None, None

    @staticmethod
    def children(eco, meta):
        if eco == "npm":
            d = dict(meta.get("dependencies") or {})
            d.update(meta.get("optionalDependencies") or {})
            return d
        if eco == "pypi":
            out = {}
            for r in (meta.get("info") or {}).get("requires_dist") or []:
                if ";" in r and "extra" in r.split(";", 1)[1]:
                    continue
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)", r)
                if m:
                    out[m.group(1).lower()] = ""
            return out
        return {}

    # ---------- per-dependency security check ----------
    def check_one(self, eco, name, version, meta, direct):
        f = []   # list of (severity, code, zh, en, evidence)
        if version is None:
            f.append(("medium", "DEP_NOT_IN_REGISTRY", f"依赖 {name} 在公共注册表中不存在（依赖混淆风险）",
                      f"Dependency {name} does not exist in the public registry (dependency-confusion risk)", name))
            return {"findings": f, "children": {}, "osv": []}
        if known_malicious(eco, name, version):
            f.append(("critical", "DEP_KNOWN_MALICIOUS", f"已知恶意依赖：{name}@{version}",
                      f"Known malicious dependency: {name}@{version}", f"{name}@{version}"))
        t = typosquat_of(eco, name)
        if t:
            f.append(("high" if direct else "medium", "DEP_TYPOSQUAT", f"依赖名 {name} 与热门包 {t} 极相似（疑似仿冒）",
                      f"Dependency name {name} closely resembles popular package {t} (possible typosquat)", name))
        if eco == "npm" and meta and (meta.get("hasInstallScript") or (meta.get("scripts") or {})):
            doc = meta if meta.get("scripts") else self._npm_version_doc(name, version)
            sc = doc.get("scripts") or {}
            for hook in ("preinstall", "install", "postinstall"):
                cmd = sc.get(hook)
                if not cmd:
                    continue
                if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh|node\s+-e|base64|eval|powershell", cmd, re.I):
                    f.append(("high", "DEP_HOOK_SUSPICIOUS", f"依赖 {name}@{version} 的 {hook} 钩子下载/解码并执行代码",
                              f"Dependency {name}@{version} {hook} hook downloads/decodes and executes code", cmd[:120]))
                else:
                    f.append(("info", "DEP_HAS_INSTALL_HOOK", f"依赖 {name}@{version} 含安装钩子 {hook}",
                              f"Dependency {name}@{version} has install hook {hook}", cmd[:120]))
        mv = re.match(r"^(\d+)", str(version))
        mj = int(mv.group(1)) if mv else 0
        if 90 <= mj < 1990 or 2100 < mj < 19000000:
            f.append(("medium", "DEP_ABNORMAL_VERSION", f"依赖 {name} 版本号异常高（{version}），依赖混淆常用手法",
                      f"Dependency {name} has an abnormally high version ({version}), a dependency-confusion trick", f"{name}@{version}"))
        scopes = [x.strip() for x in os.environ.get("FILEGUARD_INTERNAL_PREFIXES", "").split(",") if x.strip()]
        if any(name.startswith(sc) for sc in scopes):
            f.append(("high", "DEP_CONFUSION_INTERNAL_NAME", f"依赖 {name} 与内部包同名但解析到了公共注册表（依赖混淆）",
                      f"Dependency {name} matches an internal package name but resolved from the public registry (dependency confusion)", name))
        if eco == "npm" and meta and meta.get("deprecated"):
            f.append(("info", "DEP_DEPRECATED", f"依赖 {name}@{version} 已被弃用", f"Dependency {name}@{version} is deprecated",
                      str(meta.get("deprecated"))[:120]))
        return {"findings": f, "children": self.children(eco, meta or {}), "osv": []}

    def osv_batch(self, items):
        """items: list of (eco, name, version). Returns list of vuln-id lists. Raises on failure."""
        if not items:
            return []
        eco_map = {"npm": "npm", "pypi": "PyPI"}
        out = []
        for i in range(0, len(items), 500):
            chunk = items[i:i + 500]
            q = {"queries": [{"package": {"name": n, "ecosystem": eco_map[e]}, "version": v} for e, n, v in chunk]}
            r = self.client.post(f"{config.OSV_API}/v1/querybatch", json=q)
            r.raise_for_status()
            out += [[v["id"] for v in (res.get("vulns") or [])] for res in r.json().get("results", [])]
        return out

    # ---------- BFS driver ----------
    def run(self, manifests):
        ev, rv = ENGINE_VERSION, rules_version()
        stats = {"total_unique": 0, "new_checked": 0, "cache_hits": 0, "skipped_quota": 0, "skipped_depth": 0,
                 "light_checked": 0, "light_skipped": 0, "failed": 0, "max_depth_seen": 0, "ecosystems": []}
        skipped, checked, light = [], [], []
        roots = [m for m in manifests if m.get("top") and m.get("deps")]
        if not roots:
            return {"stats": stats, "skipped": [], "checked": [], "light_checked": [], "applicable": False}
        frontier = []
        for m in roots:
            for n, spec in m["deps"].items():
                frontier.append((m["ecosystem"], n, spec, 1, m["name"] or "(root)"))
        stats["ecosystems"] = sorted({m["ecosystem"] for m in roots})
        seen = set()
        depth = 1
        while frontier:
            if self.ctx.deadline:
                self.ctx.deadline()
            is_light = depth > config.MAX_DEP_DEPTH   # beyond depth 5: light checks only (no INCOMPLETE)
            # dedupe this level by (eco,name) for resolution
            level, keys = [], set()
            for e, n, spec, d, parent in frontier:
                if (e, n) in seen or (e, n, spec) in keys:
                    continue
                keys.add((e, n, spec))
                level.append((e, n, spec, d, parent))
            level.sort(key=lambda x: (x[0], x[1].lower()))
            # resolve versions concurrently (metadata only)
            def _res(x):
                try:
                    return self.resolve(x[0], x[1], x[2]), None
                except Exception as exc:
                    return (None, None), exc
            with ThreadPoolExecutor(max_workers=16) as pool:
                resolved = list(pool.map(_res, level))
            to_check, next_frontier = [], []
            for (e, n, spec, d, parent), ((ver, meta), exc) in zip(level, resolved):
                if (e, n) in seen:
                    continue
                seen.add((e, n))
                stats["total_unique"] += 1
                stats["max_depth_seen"] = max(stats["max_depth_seen"], d)
                if exc is not None:
                    stats["failed"] += 1
                    skipped.append({"ecosystem": e, "name": n, "spec": spec, "depth": d, "parent": parent,
                                    "reason": f"registry_error:{type(exc).__name__}"})
                    continue
                cached = store.dep_cache_get(e, n, ver or "MISSING", ev, rv)
                if is_light and cached is None:
                    if stats["light_checked"] >= config.MAX_LIGHT_DEPS:
                        stats["light_skipped"] += 1
                        skipped.append({"ecosystem": e, "name": n, "spec": spec, "version": ver, "depth": d, "parent": parent, "reason": "light_quota"})
                        continue
                    stats["light_checked"] += 1
                    res = self.light_check(e, n, ver, meta)
                    to_check.append((e, n, ver, res, meta))
                    light.append({"ecosystem": e, "name": n, "version": ver, "depth": d, "parent": parent})
                elif cached is not None:
                    stats["cache_hits"] += 1
                    res = cached
                    (light if is_light else checked).append({"ecosystem": e, "name": n, "version": ver, "depth": d, "cache": True})
                elif stats["new_checked"] >= config.MAX_NEW_DEPS:
                    stats["skipped_quota"] += 1
                    skipped.append({"ecosystem": e, "name": n, "spec": spec, "version": ver, "depth": d, "parent": parent, "reason": "quota"})
                    continue
                else:
                    stats["new_checked"] += 1
                    res = self.check_one(e, n, ver, meta, d == 1)
                    to_check.append((e, n, ver, res, meta))
                    checked.append({"ecosystem": e, "name": n, "version": ver, "depth": d, "cache": False})
                self._emit(e, n, ver, res, d)
                for cn, cs in (res.get("children") or {}).items():
                    next_frontier.append((e, cn, cs, d + 1, f"{n}@{ver}"))
            # OSV for newly checked deps
            osv_items = [(e, n, v) for e, n, v, r, m in to_check if v and v != "non-registry" and e in ("npm", "pypi")]
            if osv_items and config.OSV_ENABLED:
                try:
                    vulns = self.osv_batch(osv_items)
                    vmap = {(e, n, v): ids for (e, n, v), ids in zip(osv_items, vulns)}
                except Exception as exc:
                    vmap = None
                    self.ctx.miss("S3", "OSV_UNAVAILABLE", f"OSV 漏洞/恶意包情报查询失败（{type(exc).__name__}）",
                                  f"OSV vulnerability/malicious-package lookup failed ({type(exc).__name__})")
            else:
                vmap = {}
                if osv_items and not config.OSV_ENABLED:
                    self.ctx.limit("OSV 在线情报已关闭，仅使用本地恶意包列表", "OSV online intel disabled; only the local malicious list was used")
            for e, n, v, res, meta in to_check:
                ids = (vmap or {}).get((e, n, v), [])
                if res.get("light"):
                    mal = [i for i in ids if i.startswith("MAL-")]
                    if mal:
                        res["findings"].append(("critical", "DEP_OSV_MALICIOUS", f"OSV 将依赖 {n}@{v} 标记为恶意包：{', '.join(mal[:3])}",
                                                f"OSV flags dependency {n}@{v} as malicious: {', '.join(mal[:3])}", ",".join(mal[:3])))
                        self._emit(e, n, v, {"findings": res["findings"][-1:]}, 0)
                    continue
                res["osv"] = ids
                mal = [i for i in ids if i.startswith("MAL-")]
                if mal:
                    res["findings"].append(("critical", "DEP_OSV_MALICIOUS", f"OSV 将依赖 {n}@{v} 标记为恶意包：{', '.join(mal[:3])}",
                                            f"OSV flags dependency {n}@{v} as malicious: {', '.join(mal[:3])}", ",".join(mal[:3])))
                    self._emit(e, n, v, {"findings": res["findings"][-1:]}, 0)
                elif ids:
                    res["findings"].append(("low", "DEP_KNOWN_VULNS", f"依赖 {n}@{v} 有 {len(ids)} 个已知漏洞（{', '.join(ids[:3])}）",
                                            f"Dependency {n}@{v} has {len(ids)} known vulnerabilities ({', '.join(ids[:3])})", ",".join(ids[:3])))
                    self._emit(e, n, v, {"findings": res["findings"][-1:]}, 0)
                if vmap is not None:
                    store.dep_cache_put(e, n, v or "MISSING", None, ev, rv, res)
            frontier = next_frontier
            depth += 1
        if stats["skipped_quota"]:
            self.ctx.miss("S3", "DEP_QUOTA_EXCEEDED",
                          f"新检测依赖超过 {config.MAX_NEW_DEPS} 个上限，{stats['skipped_quota']} 个依赖未检测",
                          f"More than {config.MAX_NEW_DEPS} new dependencies; {stats['skipped_quota']} not checked")
        if stats["light_checked"] or len(light):
            self.ctx.limit(f"第 {config.MAX_DEP_DEPTH} 层以下的 {len(light)} 个依赖仅做轻量检查（已知恶意包列表 + OSV 恶意包 + 安装钩子），未做完整检查",
                           f"{len(light)} dependencies beyond depth {config.MAX_DEP_DEPTH} were light-checked only (known-malicious list + OSV malicious + install hooks)")
        if stats["light_skipped"]:
            self.ctx.miss("S3", "DEP_LIGHT_QUOTA_EXCEEDED",
                          f"第 {config.MAX_DEP_DEPTH} 层以下依赖超过轻量检查上限 {config.MAX_LIGHT_DEPS} 个，{stats['light_skipped']} 个未检查",
                          f"Dependencies beyond depth {config.MAX_DEP_DEPTH} exceed the light-check cap {config.MAX_LIGHT_DEPS}; {stats['light_skipped']} unchecked")
        if stats["failed"]:
            self.ctx.miss("S3", "DEP_REGISTRY_ERROR", f"{stats['failed']} 个依赖的注册表元数据获取失败",
                          f"Registry metadata fetch failed for {stats['failed']} dependencies")
        return {"stats": stats, "skipped": skipped, "checked": checked, "light_checked": light, "applicable": True}

    def light_check(self, eco, name, version, meta):
        """Beyond depth 5: known-malicious list, OSV MAL- (in the batch above) and install hooks only."""
        f = []
        if version is None:
            return {"findings": f, "children": {}, "osv": [], "light": True}
        if known_malicious(eco, name, version):
            f.append(("critical", "DEP_KNOWN_MALICIOUS", f"已知恶意依赖（第 {config.MAX_DEP_DEPTH} 层以下，轻量检查发现）：{name}@{version}",
                      f"Known malicious dependency (beyond depth {config.MAX_DEP_DEPTH}, light check): {name}@{version}", f"{name}@{version}"))
        if eco == "npm" and meta and (meta.get("hasInstallScript") or (meta.get("scripts") or {})):
            doc = meta if meta.get("scripts") else self._npm_version_doc(name, version)
            for hook in ("preinstall", "install", "postinstall"):
                cmd = (doc.get("scripts") or {}).get(hook)
                if not cmd:
                    continue
                if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh|node\s+-e|base64|eval|powershell", cmd, re.I):
                    f.append(("high", "DEP_HOOK_SUSPICIOUS", f"深层依赖 {name}@{version} 的 {hook} 钩子下载/解码并执行代码",
                              f"Deep dependency {name}@{version} {hook} hook downloads/decodes and executes code", cmd[:120]))
                else:
                    f.append(("info", "DEP_HAS_INSTALL_HOOK", f"深层依赖 {name}@{version} 含安装钩子 {hook}",
                              f"Deep dependency {name}@{version} has install hook {hook}", cmd[:120]))
        return {"findings": f, "children": self.children(eco, meta or {}), "osv": [], "light": True}

    def _emit(self, eco, name, ver, res, depth):
        for sev, code, zh, en, evid in res.get("findings", []):
            if depth == 0 and code not in ("DEP_OSV_MALICIOUS", "DEP_KNOWN_VULNS"):
                continue
            self.ctx.add(sev, "S3", code, zh, en, f"dep:{eco}:{name}@{ver}", evid)


def _valid(v):
    try:
        Version(v)
        return True
    except InvalidVersion:
        return False


def _json(r):
    r.raise_for_status()
    return r.json()


def _transposed(a, b):
    if len(a) != len(b) or a == b:
        return False
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
