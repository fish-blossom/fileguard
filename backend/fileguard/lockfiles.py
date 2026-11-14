"""S2b: lock-file hash verification. Compares locked integrity/hashes with registry metadata and with any
vendored artifacts in the sample. Mismatch -> HIGH. Registry unreachable -> failed (missing check).
Supported: package-lock.json / npm-shrinkwrap.json (v1-v3), yarn.lock (v1; berry checksums are yarn-internal),
pnpm-lock.yaml, poetry.lock, Pipfile.lock, requirements*.txt with --hash."""
import base64
import hashlib
import json
import re
import tomllib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import yaml

from . import config

LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock"}


def is_lockfile(name):
    return name in LOCK_NAMES or (re.match(r"requirements.*\.txt$", name) is not None)


def _sri_to_hex(sri):
    """sha512-<b64> -> ('sha512', hex)."""
    if not sri or "-" not in sri:
        return None, None
    algo, b64 = sri.split(" ")[0].split("-", 1)
    try:
        return algo, base64.b64decode(b64).hex()
    except Exception:
        return None, None


def parse(name, text):
    """Return list of entries {eco, name, version, hashes:{algo:set(hex)}, resolved}."""
    out = []
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        d = json.loads(text)
        if "packages" in d:
            for k, v in d["packages"].items():
                if not k or v.get("link") or "node_modules/" not in k:
                    continue
                n = v.get("name") or k.rsplit("node_modules/", 1)[1]
                out.append(_npm_entry(n, v))
        else:
            def walk(deps):
                for n, v in (deps or {}).items():
                    out.append(_npm_entry(n, v))
                    walk(v.get("dependencies"))
            walk(d.get("dependencies"))
    elif name == "yarn.lock":
        if "__metadata:" in text:
            return [{"eco": "npm", "unsupported": "yarn berry checksum (yarn-internal zip hash)"}]
        for block in re.split(r"\n(?=\S)", text):
            head = block.split("\n", 1)[0]
            m = re.match(r'^"?((?:@[^/@"]+/)?[^@"]+)@', head)
            v = re.search(r'^\s+version "([^"]+)"', block, re.M)
            i = re.search(r'^\s+integrity (\S+)', block, re.M)
            r = re.search(r'^\s+resolved "([^"]+)"', block, re.M)
            if m and v:
                hs = {}
                if i:
                    a, h = _sri_to_hex(i.group(1))
                    if a:
                        hs[a] = {h}
                if r and "#" in r.group(1) and re.fullmatch(r"[0-9a-f]{40}", r.group(1).rsplit("#", 1)[1]):
                    hs.setdefault("sha1", set()).add(r.group(1).rsplit("#", 1)[1])
                out.append({"eco": "npm", "name": m.group(1), "version": v.group(1), "hashes": hs, "resolved": r.group(1) if r else None})
    elif name == "pnpm-lock.yaml":
        d = yaml.safe_load(text) or {}
        for k, v in (d.get("packages") or {}).items():
            k2 = k.lstrip("/")
            m = re.match(r"^((?:@[^/]+/)?[^@/]+)[@/]([^(@/]+)", k2)
            if not m:
                continue
            integ = ((v or {}).get("resolution") or {}).get("integrity")
            a, h = _sri_to_hex(integ)
            out.append({"eco": "npm", "name": m.group(1), "version": m.group(2), "hashes": {a: {h}} if a else {}, "resolved": ((v or {}).get("resolution") or {}).get("tarball")})
    elif name == "poetry.lock":
        d = tomllib.loads(text)
        for p in d.get("package", []):
            hs = {}
            for f in p.get("files", []):
                a, _, h = (f.get("hash") or "").partition(":")
                if h:
                    hs.setdefault(a, set()).add(h.lower())
            src = (p.get("source") or {}).get("type")
            out.append({"eco": "pypi", "name": p["name"].lower(), "version": p["version"], "hashes": hs, "resolved": src})
    elif name == "Pipfile.lock":
        d = json.loads(text)
        for sec in ("default", "develop"):
            for n, v in (d.get(sec) or {}).items():
                ver = (v.get("version") or "").lstrip("=")
                hs = {}
                for h in v.get("hashes", []):
                    a, _, x = h.partition(":")
                    hs.setdefault(a, set()).add(x.lower())
                if ver:
                    out.append({"eco": "pypi", "name": n.lower(), "version": ver, "hashes": hs, "resolved": None})
    else:  # requirements with --hash
        joined = re.sub(r"\\\n", " ", text)
        for line in joined.splitlines():
            line = line.split("#", 1)[0].strip() if " #" in line or line.startswith("#") else line.strip()
            if "--hash" not in line:
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([\w.+!\-]+)", line)
            if not m:
                continue
            hs = {}
            for a, x in re.findall(r"--hash[=\s]+(\w+):([0-9a-fA-F]+)", line):
                hs.setdefault(a, set()).add(x.lower())
            out.append({"eco": "pypi", "name": m.group(1).lower(), "version": m.group(2), "hashes": hs, "resolved": None})
    return out


def _npm_entry(n, v):
    a, h = _sri_to_hex(v.get("integrity"))
    return {"eco": "npm", "name": n, "version": v.get("version"), "hashes": {a: {h}} if a else {}, "resolved": v.get("resolved")}


class LockChecker:
    def __init__(self, ctx):
        self.ctx = ctx
        self.client = httpx.Client(timeout=config.NET_STALL_TIMEOUT, follow_redirects=True)

    def _npm_hashes(self, name, version):
        n = name.replace("/", "%2f") if name.startswith("@") else name
        r = self.client.get(f"{config.NPM_REGISTRY}/{n}", headers={"Accept": "application/vnd.npm.install-v1+json"})
        if r.status_code == 404:
            return None
        r.raise_for_status()
        v = (r.json().get("versions") or {}).get(version)
        if not v:
            return None
        d = v.get("dist") or {}
        hs = {}
        a, h = _sri_to_hex(d.get("integrity"))
        if a:
            hs[a] = {h}
        if d.get("shasum"):
            hs.setdefault("sha1", set()).add(d["shasum"])
        return hs

    def _pypi_hashes(self, name, version):
        r = self.client.get(f"{config.PYPI_URL}/pypi/{name}/{version}/json")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        hs = {}
        for f in r.json().get("urls", []):
            for a, x in (f.get("digests") or {}).items():
                hs.setdefault(a, set()).add(x.lower())
        return hs

    def run(self, lockfiles, vendored):
        """lockfiles: list of (rel, name, text). vendored: {rel: {algo: hex}} of archives bundled in the sample."""
        res = {"check": "lockfile_hashes", "status": "not_applicable", "files": [], "entries": 0, "verified": 0,
               "mismatches": [], "not_in_registry": [], "unsupported": [], "vendored_matched": 0}
        if not lockfiles:
            res.update(detail_zh="样本中没有锁文件", detail_en="No lock file in the sample")
            return res
        entries = []
        for rel, name, text in lockfiles:
            try:
                es = parse(name, text)
            except Exception as e:
                self.ctx.miss("S2", "LOCKFILE_PARSE_FAILED", f"锁文件解析失败：{rel}（{type(e).__name__}）", f"Lock file parse failed: {rel} ({type(e).__name__})", rel)
                continue
            res["files"].append(rel)
            for e in es:
                if e.get("unsupported"):
                    res["unsupported"].append(f"{rel}: {e['unsupported']}")
                    continue
                e["lock"] = rel
                entries.append(e)
        # dedupe
        uniq = {}
        for e in entries:
            if e.get("name") and e.get("version") and e["hashes"]:
                uniq.setdefault((e["eco"], e["name"], e["version"], e["lock"]), e)
        items = list(uniq.values())
        res["entries"] = len(items)
        if len(items) > config.MAX_LOCK_ENTRIES:
            self.ctx.miss("S2", "LOCKFILE_TOO_MANY_ENTRIES", f"锁文件条目 {len(items)} 个，超过 {config.MAX_LOCK_ENTRIES} 上限，部分未比对",
                          f"{len(items)} lock entries exceed the {config.MAX_LOCK_ENTRIES} limit; some not compared")
            items = items[: config.MAX_LOCK_ENTRIES]
        for e in items:
            if e.get("resolved") and isinstance(e["resolved"], str) and e["resolved"].startswith("http://"):
                self.ctx.add("medium", "S2", "LOCKFILE_INSECURE_RESOLVED", f"锁文件中 {e['name']}@{e['version']} 通过明文 HTTP 下载",
                             f"Lock entry {e['name']}@{e['version']} resolves over plaintext HTTP", e["lock"], e["resolved"][:100])
            elif e.get("resolved") and isinstance(e["resolved"], str) and e["eco"] == "npm" and e["resolved"].startswith("https://") \
                    and "registry.npmjs.org" not in e["resolved"] and "registry.yarnpkg.com" not in e["resolved"] and not e["resolved"].startswith(config.NPM_REGISTRY):
                self.ctx.add("low", "S2", "LOCKFILE_NONSTANDARD_REGISTRY", f"锁文件中 {e['name']} 来自非官方 registry：{e['resolved'][:80]}",
                             f"Lock entry {e['name']} resolves from a non-default registry: {e['resolved'][:80]}", e["lock"])

        def work(e):
            try:
                return e, (self._npm_hashes if e["eco"] == "npm" else self._pypi_hashes)(e["name"], e["version"]), None
            except Exception as exc:
                return e, None, exc
        failed = 0
        with ThreadPoolExecutor(max_workers=16) as pool:
            for e, reg, exc in pool.map(work, items):
                if exc is not None:
                    failed += 1
                    continue
                # vendored artifacts bundled in the sample (e.g. vendor/foo-1.2.3.tgz, wheels/)
                short = e["name"].split("/")[-1].replace("-", "[-_]")
                for vrel, vh in vendored.items():
                    base = vrel.split("!/")[-1].rsplit("/", 1)[-1]
                    if re.match(rf"^{short}-{re.escape(e['version'])}([-.]|$)", base, re.I):
                        if any(h == vh.get(a) for a, hs in e["hashes"].items() for h in hs):
                            res["vendored_matched"] += 1
                        else:
                            res["mismatches"].append(f"vendored {base} vs {e['lock']}")
                            self.ctx.add("high", "S2", "LOCKFILE_VENDORED_MISMATCH",
                                         f"样本内附带的制品 {base} 与锁文件锁定的哈希不一致（内嵌制品被替换）",
                                         f"Bundled artifact {base} does not match the hash locked in {e['lock']} (vendored artifact swapped)", vrel, base)
                if reg is None:
                    res["not_in_registry"].append(f"{e['eco']}:{e['name']}@{e['version']}")
                    continue
                common = [a for a in e["hashes"] if a in reg]
                if not common:
                    continue
                if e["eco"] == "npm":
                    ok = all(e["hashes"][a] <= reg[a] for a in common)
                else:  # every locked file hash must be a published file hash
                    ok = all(e["hashes"][a] <= reg[a] for a in common)
                if ok:
                    res["verified"] += 1
                else:
                    res["mismatches"].append(f"{e['eco']}:{e['name']}@{e['version']} ({e['lock']})")
                    self.ctx.add("high", "S2", "LOCKFILE_HASH_MISMATCH",
                                 f"锁文件锁定的 {e['name']}@{e['version']} 哈希与注册表发布的不一致（锁文件被篡改或指向替换过的制品）",
                                 f"Locked hash for {e['name']}@{e['version']} differs from the registry-published hash (tampered lock file or swapped artifact)",
                                 e["lock"], f"{e['name']}@{e['version']}")
        if failed:
            self.ctx.miss("S2", "LOCKFILE_REGISTRY_UNAVAILABLE", f"{failed} 个锁文件条目无法从注册表获取哈希进行比对",
                          f"{failed} lock entries could not be compared (registry unavailable)")
        if res["not_in_registry"]:
            self.ctx.add("medium", "S2", "LOCKFILE_ENTRY_NOT_IN_REGISTRY", f"锁文件中 {len(res['not_in_registry'])} 个条目在公共注册表中不存在：{', '.join(res['not_in_registry'][:5])}",
                         f"{len(res['not_in_registry'])} lock entries do not exist in the public registry: {', '.join(res['not_in_registry'][:5])}")
        res["status"] = "failed" if failed else "done"
        res["detail_zh"] = (f"比对 {res['entries']} 个锁定条目：{res['verified']} 个与注册表一致，{len(res['mismatches'])} 个不一致，"
                            f"{len(res['not_in_registry'])} 个注册表中不存在，{failed} 个无法比对；内嵌制品匹配 {res['vendored_matched']} 个")
        res["detail_en"] = (f"Compared {res['entries']} locked entries: {res['verified']} match the registry, {len(res['mismatches'])} mismatch, "
                            f"{len(res['not_in_registry'])} not in registry, {failed} not comparable; vendored artifacts matched {res['vendored_matched']}")
        return res


def vendored_hashes(inventory):
    """sha1/sha256/sha512 of archive-like artifacts bundled in the sample (e.g. .tgz/.whl/.tar.gz)."""
    out = {}
    for i in inventory:
        if i["depth"] == 0:
            continue
        n = i["rel"].split("!/")[-1]
        if re.search(r"\.(tgz|whl|tar\.gz|zip)$", n) and i["size"] < 200 * (1 << 20):
            data = Path(i["abs"]).read_bytes()
            out[i["rel"]] = {a: hashlib.new(a, data).hexdigest() for a in ("sha1", "sha256", "sha512")}
    return out
