"""FileGuard S0-S7 pipeline. Stages always run in this fixed order; the model/bot cannot skip any.

S0 intake & validation   S1 source reputation   S2 integrity & hash cache
S3 static analysis (unpack, ClamAV, YARA, format analyzers, dependencies)
S4 version diff vs baseline   S5 install-footprint prediction   S6 verdict   S7 delivery/report
"""
import base64
import hashlib
import json
import os
import re
import shutil
import time
import urllib.parse
from pathlib import Path

from . import ENGINE_VERSION, config, netutil, scanners, store, tools
from .analyzers import Analyzer, ecosystem_of, file_type
from .deps import DepResolver, typosquat_of
from .model import SEVERITY_ORDER, ScanContext
from .unpack import Unpacker

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly", "t.ly", "shorturl.at"}
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "country", "work", "su", "ru", "pw"}
OFFICIAL_HOSTS = ("registry.npmjs.org", "files.pythonhosted.org", "pypi.org", "github.com", "objects.githubusercontent.com",
                  "codeload.github.com", "deb.debian.org", "download.microsoft.com", "releases.ubuntu.com", "nodejs.org", "python.org")


def _known_bad_hashes():
    out = {}
    p = config.INTEL_DIR / "known_bad_hashes.txt"
    for line in p.read_text().splitlines() if p.exists() else []:
        h, _, c = line.partition("#")
        h = h.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", h):
            out[h] = c.strip()
    return out


def _hashes(path):
    s2, s1, m5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            s2.update(chunk); s1.update(chunk); m5.update(chunk)
    return {"sha256": s2.hexdigest(), "sha1": s1.hexdigest(), "md5": m5.hexdigest()}


class InputRejected(Exception):
    def __init__(self, code, zh, en):
        super().__init__(en)
        self.code, self.zh, self.en = code, zh, en


def run_scan(scan_id, source, lang="zh", progress=None, expected_sha256=None, force_rescan=False):
    """source: {"kind": "url", "url": ...} | {"kind": "path", "path": ..., "filename": ...} |
               {"kind": "base64", "data": ..., "filename": ...}"""
    ctx = ScanContext(scan_id, lang)
    t0 = time.time()
    # No overall scan timeout (user decision). ctx.deadline is only a progress heartbeat; hang protection is
    # per step (each network request: NET_STALL_TIMEOUT without progress; each tool process: its own limit),
    # and a stalled step is recorded as a failed/missing check instead of aborting the scan.
    ctx.deadline = lambda: None
    work = config.WORK_DIR / scan_id
    work.mkdir(parents=True, exist_ok=True)
    prog = progress or (lambda s: None)
    error = None
    reused = None
    try:
        sample = _s0_intake(ctx, source, work, prog)
        _s1_source(ctx, source, prog)
        reused = _s2_integrity(ctx, sample, source, expected_sha256, force_rescan, prog)
        if reused is None:
            an, unp = _s3_static(ctx, sample, work, prog)
            _s4_diff(ctx, an, prog)
            _s5_footprint(ctx, prog)
        else:
            for s in ("S3", "S4", "S5"):
                ctx.stage(s, "done", f"复用缓存的检测结果（{reused['scan_id']}）", f"Reused cached result ({reused['scan_id']})")
    except InputRejected as e:
        error = {"code": e.code, "zh": e.zh, "en": e.en}
    except netutil.DownloadError as e:
        error = {"code": e.code, "zh": e.zh, "en": e.en}
    except Exception as e:  # engine fault -> ERROR, never NO_FINDINGS
        error = {"code": "ENGINE_FAILURE", "zh": f"检测引擎故障：{type(e).__name__}: {str(e)[:200]}",
                 "en": f"Engine failure: {type(e).__name__}: {str(e)[:200]}"}
    finally:
        # sample retention policy: delete every sample byte, keep only report + hashes
        shutil.rmtree(work, ignore_errors=True)
        ctx.meta["sample_deleted"] = not work.exists()
    from .verdict import decide
    from .report import build_report
    verdict = decide(ctx, error, reused)
    ctx.stage("S6", "done", f"规则引擎裁决：{verdict['verdict']}", f"Rule-engine verdict: {verdict['verdict']}")
    report = build_report(ctx, verdict, error, reused, time.time() - t0)
    _s7_followup(ctx, report, verdict)
    return report


# ---------------------------------------------------------------- S0
def _s0_intake(ctx, source, work, prog):
    prog("S0")
    dest = work / "sample.bin"
    kind = source["kind"]
    if kind == "url":
        ctx.meta["original_url"] = source["url"]
        info = netutil.download(source["url"], dest, config.MAX_FILE_BYTES, ctx.deadline)
        ctx.meta.update(final_url=info["final_url"], redirects=info["redirects"], resolved_ips=info["resolved_ips"],
                        content_type=info["content_type"])
        fname = None
        m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', info.get("content_disposition") or "")
        if m:
            fname = urllib.parse.unquote(m.group(1))
        fname = fname or Path(urllib.parse.urlsplit(info["final_url"]).path).name or "download.bin"
    elif kind == "path":
        p = Path(source["path"])
        if not p.is_file():
            raise InputRejected("FILE_NOT_FOUND", f"找不到文件：{p}", f"File not found: {p}")
        size = p.stat().st_size
        if size > config.MAX_FILE_BYTES:
            raise InputRejected("FILE_TOO_LARGE", f"文件大小 {size} 字节超过上限 {config.MAX_FILE_BYTES} 字节（{config.MAX_FILE_BYTES >> 20} MB），未进行检测",
                                f"File size {size} bytes exceeds the {config.MAX_FILE_BYTES >> 20} MB limit; not scanned")
        shutil.copyfile(p, dest)          # the user's original file is never modified or deleted
        fname = source.get("filename") or p.name
    elif kind == "base64":
        raw = source["data"]
        if len(raw) * 3 // 4 > config.MAX_FILE_BYTES:
            raise InputRejected("FILE_TOO_LARGE", f"文件超过上限 {config.MAX_FILE_BYTES >> 20} MB，未进行检测",
                                f"File exceeds the {config.MAX_FILE_BYTES >> 20} MB limit; not scanned")
        try:
            dest.write_bytes(base64.b64decode(raw, validate=False))
        except Exception:
            raise InputRejected("BAD_BASE64", "上传内容不是合法的 Base64", "Uploaded content is not valid Base64")
        fname = source.get("filename") or "upload.bin"
    else:
        raise InputRejected("BAD_INPUT", "不支持的输入方式", "Unsupported input kind")
    size = dest.stat().st_size
    if size > config.MAX_FILE_BYTES:
        raise InputRejected("FILE_TOO_LARGE", f"文件超过上限 {config.MAX_FILE_BYTES >> 20} MB，未进行检测",
                            f"File exceeds the {config.MAX_FILE_BYTES >> 20} MB limit; not scanned")
    fname = re.sub(r"[\x00-\x1f/\\]", "_", fname)[:200]
    desc, mime = file_type(str(dest))
    ctx.meta.update(file_name=fname, file_size=size, file_type=desc, mime=mime)
    ctx.stage("S0", "done", "输入已受理：类型识别、大小校验" + ("、URL 归一化与 SSRF 检查" if kind == "url" else ""),
              "Input accepted: type identified, size checked" + (", URL normalized & SSRF-checked" if kind == "url" else ""))
    return dest


def _ext_mismatch(fname, mime):
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    exe = mime in ("application/x-dosexec", "application/vnd.microsoft.portable-executable", "application/x-executable")
    if ext in ("pdf", "jpg", "jpeg", "png", "gif", "txt", "doc", "docx", "xls", "xlsx", "mp3", "mp4") and exe:
        return True
    return False


# ---------------------------------------------------------------- S1
def _s1_source(ctx, source, prog):
    prog("S1")
    if source["kind"] != "url":
        ctx.stage("S1", "not_applicable", "用户直接上传，无下载来源；包名仿冒检查在 S3 进行",
                  "Direct upload, no download source; package-name typosquat check runs in S3")
        return
    from .analyzers import NETWORK_IOCS
    hosts = [urllib.parse.urlsplit(u).hostname or "" for u in
             [ctx.meta.get("original_url", "")] + [r["to"] for r in ctx.meta.get("redirects", [])]]
    for h in set(hosts):
        if any(h == i or h.endswith("." + i) for i in NETWORK_IOCS):
            ctx.add("critical", "S1", "SOURCE_IOC", f"下载来源命中恶意网络 IOC：{h}", f"Download source matches malicious IOC: {h}", None, h)
        if re.fullmatch(r"[\d.]+|\[[0-9a-f:]+\]", h):
            ctx.add("medium", "S1", "SOURCE_IP_LITERAL", f"直接使用 IP 地址下载：{h}", f"Downloaded directly from an IP address: {h}", None, h)
        if h in SHORTENERS:
            ctx.add("medium", "S1", "SOURCE_SHORTENER", f"经过短链接跳转：{h}", f"Passed through a URL shortener: {h}", None, h)
        if h.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            ctx.add("low", "S1", "SOURCE_SUSPICIOUS_TLD", f"来源域名使用高风险顶级域：{h}", f"Source uses a high-abuse TLD: {h}", None, h)
        if h.startswith("xn--") or ".xn--" in h:
            ctx.add("medium", "S1", "SOURCE_PUNYCODE", f"来源域名为 Punycode（可能是同形异义仿冒）：{h}",
                    f"Source host is punycode (possible homograph): {h}", None, h)
    from . import source as src_mod
    for u in [ctx.meta.get("original_url", "")] + [r["to"] for r in ctx.meta.get("redirects", [])]:
        src_mod.host_checks(ctx, u)
    if ctx.meta.get("redirects"):
        hs = [urllib.parse.urlsplit(r["to"]).hostname for r in ctx.meta["redirects"]]
        if any(src_mod.reg_domain(h or "") != src_mod.reg_domain(urllib.parse.urlsplit(ctx.meta["original_url"]).hostname or "") for h in hs):
            ctx.add("low", "S1", "CROSS_DOMAIN_REDIRECT", f"跨域名重定向：{' -> '.join([urllib.parse.urlsplit(ctx.meta['original_url']).hostname or ''] + [h or '' for h in hs])}",
                    f"Cross-domain redirect: {' -> '.join([urllib.parse.urlsplit(ctx.meta['original_url']).hostname or ''] + [h or '' for h in hs])}")
    src_mod.domain_age(ctx, urllib.parse.urlsplit(ctx.meta.get("final_url", "")).hostname)
    if urllib.parse.urlsplit(ctx.meta.get("final_url", "")).scheme == "http":
        ctx.add("medium", "S1", "SOURCE_PLAINTEXT_HTTP", "通过明文 HTTP 下载，传输过程可能被篡改",
                "Downloaded over plaintext HTTP; content could be tampered in transit")
    if len({h for h in hosts if h}) > 1:
        ctx.meta["cross_domain_redirect"] = True
    final_host = urllib.parse.urlsplit(ctx.meta.get("final_url", "")).hostname or ""
    ctx.meta["official_source"] = any(final_host == o or final_host.endswith("." + o) for o in OFFICIAL_HOSTS)
    if config.ABUSECH_AUTH_KEY:
        _urlhaus(ctx, ctx.meta.get("final_url"))
    else:
        ctx.limit("未配置 URLhaus/MalwareBazaar API Key，在线 URL/Hash 威胁情报未查询（仅使用本地 IOC 列表）",
                  "No URLhaus/MalwareBazaar API key configured; online URL/hash intel not queried (local IOC list only)")
    ctx.stage("S1", "done", "来源检查：IOC、IP 直连、短链、可疑顶级域、Punycode、重定向链、官方来源识别",
              "Source checks: IOC, IP literal, shortener, TLD, punycode, redirect chain, official-source")


def _urlhaus(ctx, url):
    import httpx
    try:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                       headers={"Auth-Key": config.ABUSECH_AUTH_KEY}, timeout=15)
        j = r.json()
        if j.get("query_status") == "ok" and j.get("url_status") in ("online", "offline"):
            ctx.add("critical", "S1", "URLHAUS_HIT", "URLhaus 收录该 URL 为恶意软件分发地址", "URLhaus lists this URL as malware distribution", None, url)
    except Exception as e:
        ctx.limit(f"URLhaus 查询失败：{type(e).__name__}", f"URLhaus lookup failed: {type(e).__name__}")


# ---------------------------------------------------------------- S2
def _s2_integrity(ctx, sample, source, expected_sha256, force_rescan, prog):
    prog("S2")
    h = _hashes(sample)
    ctx.meta.update(h)
    bad = _known_bad_hashes()
    if h["sha256"] in bad:
        ctx.add("critical", "S2", "KNOWN_BAD_HASH", f"文件 SHA-256 命中已知恶意 Hash 列表（{bad[h['sha256']]}）",
                f"File SHA-256 is on the known-bad hash list ({bad[h['sha256']]})", None, h["sha256"])
    checks = []
    if expected_sha256:
        checks.append("user_expected_sha256")
        if expected_sha256.lower().strip() != h["sha256"]:
            ctx.add("high", "S2", "HASH_MISMATCH_EXPECTED", "文件 SHA-256 与提供的期望值不一致（可能被篡改或替换）",
                    "File SHA-256 does not match the expected value (possibly tampered/replaced)", None, expected_sha256)
    if source["kind"] == "url":
        from . import source as src_mod
        reg = _registry_digest(ctx, ctx.meta.get("final_url", ""), sample, h)
        if not reg and src_mod.checksum_sidecars(ctx, ctx.meta.get("final_url", ""), h["sha256"], ctx.meta.get("file_name", "")):
            reg = "published checksum file"
        if not reg:
            src_mod.signature_sidecars(ctx, ctx.meta.get("final_url", ""), sample)
        if reg:
            checks.append(reg)
        else:
            ctx.meta["integrity_unavailable"] = True
            ctx.limit("未能校验：该下载来源没有公布可核对的官方校验值（SHA256SUMS/.sha256/注册表摘要）", "Not verified: this source publishes no official checksum (SHA256SUMS/.sha256/registry digest)")
    ctx.meta["integrity_checks"] = checks
    ctx.stage("S2", "done", f"已计算 SHA-256/SHA-1/MD5；已比对已知恶意 Hash；官方校验：{', '.join(checks) or '无可用'}",
              f"SHA-256/SHA-1/MD5 computed; known-bad hash list checked; official digests: {', '.join(checks) or 'none available'}")
    if force_rescan:
        return None
    sv = scanners.sigs_version()
    c = store.cache_get_hash(h["sha256"], ENGINE_VERSION, scanners.rules_version(), sv)
    if c and c["verdict"] in ("BLOCK", "HIGH_RISK", "NO_FINDINGS"):
        prev = store.get_scan(c["scan_id"])
        if prev and prev.get("report_json"):
            ctx.meta["cache_hit"] = {"scan_id": c["scan_id"], "verdict": c["verdict"]}
            return json.loads(prev["report_json"]) | {"scan_id": c["scan_id"]}
    return None


def _registry_digest(ctx, url, sample, h):
    """npm / PyPI: compare against registry-published digests (dist.integrity / sha256)."""
    import httpx
    try:
        m = re.match(r"https://registry\.npmjs\.org/((?:@[^/]+/)?[^/]+)/-/[^/]+-(\d[^/]*)\.tgz$", url)
        if m:
            name, ver = m.group(1), m.group(2)
            rr = httpx.get(f"https://registry.npmjs.org/{name.replace('/', '%2f')}/{ver}", timeout=config.NET_STALL_TIMEOUT)
            rr.raise_for_status()
            doc = rr.json()
            dist = doc.get("dist") or {}
            integ = dist.get("integrity", "")
            if integ.startswith("sha512-"):
                d = hashlib.sha512(sample.read_bytes()).digest()
                ok = base64.b64encode(d).decode() == integ[7:]
            else:
                ok = dist.get("shasum") == h["sha1"]
            if not ok:
                ctx.add("critical", "S2", "REGISTRY_DIGEST_MISMATCH", "下载文件与 npm 注册表公布的完整性摘要不一致",
                        "Downloaded file does not match the npm registry integrity digest", None, integ[:40])
            ctx.meta["package_hint"] = {"ecosystem": "npm", "name": name, "version": ver}
            return "npm dist.integrity"
        m = re.match(r"https://files\.pythonhosted\.org/packages/.+/([^/]+)$", url)
        if m:
            fn = m.group(1)
            pm = re.match(r"([A-Za-z0-9_.\-]+?)-(\d[\w.]*?)(?:-|\.tar|\.zip)", fn)
            if pm:
                rr = httpx.get(f"https://pypi.org/pypi/{pm.group(1)}/{pm.group(2)}/json", timeout=config.NET_STALL_TIMEOUT)
                rr.raise_for_status()
                j = rr.json()
                for f in j.get("urls", []):
                    if f.get("filename") == fn:
                        if f["digests"]["sha256"] != h["sha256"]:
                            ctx.add("critical", "S2", "REGISTRY_DIGEST_MISMATCH", "下载文件与 PyPI 公布的 SHA-256 不一致",
                                    "Downloaded file does not match the PyPI-published SHA-256", None, f["digests"]["sha256"])
                        ctx.meta["package_hint"] = {"ecosystem": "pypi", "name": pm.group(1), "version": pm.group(2)}
                        return "PyPI sha256"
    except Exception as e:
        ctx.miss("S2", "REGISTRY_DIGEST_UNAVAILABLE", f"注册表完整性摘要获取失败（{type(e).__name__}），关键校验未完成",
                 f"Registry integrity digest fetch failed ({type(e).__name__}); key integrity check not completed")
    return None


# ---------------------------------------------------------------- S3
def _yara_on_bytes(data, display):
    import yara  # noqa
    name = Path(display.split("!/")[-1].split("#")[0]).name.lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    out = []
    for m in scanners._compiled().match(data=data, externals={"fg_ext": ext, "fg_name": name}, timeout=30):
        out.append({"rule": m.rule, "severity": m.meta.get("severity", "medium"), "zh": m.meta.get("desc_zh", m.rule),
                    "en": m.meta.get("desc_en", m.rule),
                    "strings": [i.matched_data[:80].decode("latin-1") for s in m.strings[:2] for i in s.instances[:1]]})
    return out


def _s3_static(ctx, sample, work, prog):
    prog("S3:unpack")
    unp = Unpacker(ctx, work / "x")
    inv = unp.run(str(sample), ctx.meta["file_name"])
    ctx.meta["unpack"] = unp.stats | {"total_unpacked_bytes": unp.total, "files": len(inv)}
    ctx.deadline()
    # ClamAV over original + every extracted file
    prog("S3:clamav")
    ok, det, engine, err = scanners.clamav_scan([i["abs"] for i in inv])
    ctx.tools["clamav"] = f"{scanners.clamav_version()} ({engine})"
    dbi = scanners.db_info()
    ctx.tools["clamav_db"] = dbi.get("date") or "N/A"
    if dbi.get("stale"):
        ctx.miss("S3", "CLAMAV_DB_STALE",
                 f"ClamAV 病毒库过旧（最后更新 {dbi.get('date') or '未知'}，超过 {config.CLAMAV_DB_STALE_DAYS} 天），新出现的恶意软件可能认不出",
                 f"ClamAV signature database is stale (last updated {dbi.get('date') or 'unknown'}, older than {config.CLAMAV_DB_STALE_DAYS} days)")
    _exe7, _v7 = tools.sevenzip_version()
    ctx.tools["unpacker"] = f"7-Zip {_v7}" if _v7 else "N/A"
    for t in tools.parser_status():
        if t["version"] and not t["ok"]:
            ctx.miss("S3", "PARSER_OUTDATED",
                     f"解析工具 {t['tool']} {t['version']} 低于已修复漏洞的版本 {t['min']}，解析不可信文件存在风险",
                     f"Parser {t['tool']} {t['version']} is older than the patched version {t['min']}")
    abs2rel = {i["abs"]: i["rel"] for i in inv}
    for p, sig in det.items():
        if sig.startswith(("Heuristics.Encrypted", "Heuristics.Limits", "Heuristics.Broken")) or ".Limits.Exceeded" in sig:
            ctx.miss("S3", "CLAMAV_" + sig.split(".")[1].upper(), f"ClamAV 无法完整检查（{sig}）", f"ClamAV could not fully inspect ({sig})", abs2rel.get(p, p))
            continue
        ctx.add("critical", "S3", f"CLAMAV:{sig}", f"ClamAV 检出：{sig}", f"ClamAV detection: {sig}", abs2rel.get(p, p), sig)
    if not ok:
        ctx.miss("S3", "CLAMAV_FAILED", f"ClamAV 扫描未完成：{err}", f"ClamAV scan did not complete: {err}")
    ctx.deadline()
    # format analyzers + YARA (manifests first so install-hook files are known)
    prog("S3:yara+analyzers")
    an = Analyzer(ctx, _yara_on_bytes)
    ctx.tools["yara"] = scanners.yara_version()
    order = sorted(inv, key=lambda i: (0 if Path(i["rel"].split("!/")[-1]).name in ("package.json", "setup.py") else 1, i["depth"]))
    yara_hits = {}
    for item in order:
        ctx.deadline()
        try:
            an.analyze(item)
        except Exception as e:
            ctx.miss("S3", "ANALYZER_FAILED", f"格式分析失败（{type(e).__name__}）", f"Format analyzer failed ({type(e).__name__})", item["rel"])
        try:
            hits = scanners.yara_scan(item["abs"], item["rel"])
        except Exception as e:
            ctx.miss("S3", "YARA_FAILED", f"YARA 扫描失败（{type(e).__name__}）", f"YARA scan failed ({type(e).__name__})", item["rel"])
            continue
        yara_hits[item["rel"]] = hits
        for hh in hits:
            ctx.add(hh["severity"], "S3", f"YARA:{hh['rule']}", hh["zh"], hh["en"], item["rel"], (hh["strings"] or [""])[0])
        with open(item["abs"], "rb") as fh:
            item["sha256"] = hashlib.sha256(fh.read()).hexdigest()
        if item["depth"] > 0 and not item.get("container"):
            an.file_hashes[item["rel"].split("!/", 1)[1]] = item["sha256"]
    # escalation: an install-hook script that itself matches a high rule => critical
    for rel, hits in yara_hits.items():
        base = Path(rel.split("!/")[-1]).name
        if base in an.hook_files and any(SEVERITY_ORDER[h["severity"]] >= 3 for h in hits):
            ctx.add("critical", "S3", "INSTALL_HOOK_MALICIOUS_CODE",
                    f"安装钩子会自动执行的脚本 {base} 含高危恶意特征（{', '.join(h['rule'] for h in hits)}）",
                    f"Script {base} auto-run by an install hook carries high-risk malicious traits ({', '.join(h['rule'] for h in hits)})", rel)
    # context weighting: inside a package, heuristic hits in docs/CI/tests/examples that no install hook
    # references are downgraded one level (still reported). Critical evidence is never downgraded.
    if ecosystem_of(inv) or len(inv) > 1:
        nonrt = re.compile(r"(^|/)(docs?|ci|\.github|\.gitlab|tests?|testing|examples?|samples?|benchmarks?|vendored-[^/]+/[^/]+/ci)/", re.I)
        down = {"high": "medium", "medium": "low"}
        for f in ctx.findings:
            inner = (f.path or "").split("!/")[-1]
            if f.stage == "S3" and f.severity in down and nonrt.search(inner) and Path(inner).name not in an.hook_files \
                    and not f.code.startswith(("CLAMAV", "KNOWN", "NETWORK_IOC", "INSTALL_HOOK", "ARCHIVE_")):
                f.severity = down[f.severity]
                f.downgraded = True
                f.zh += "（位于文档/CI/测试目录且不在安装路径上，已降一级）"
                f.en += " (in docs/CI/tests, not on the install path; downgraded one level)"
    # unsupported / unknown formats are reported explicitly
    ctx.files = [{"rel": i["rel"], "size": i["size"], "type": i.get("type", ""), "sha256": i.get("sha256"), "depth": i["depth"]} for i in inv]
    eco = ecosystem_of(inv) or (ctx.meta.get("package_hint") or {}).get("ecosystem")
    ctx.meta["ecosystem"] = eco
    top = next((m for m in an.manifests if m.get("pkginfo") and m.get("name")), None) or \
        next((m for m in an.manifests if m.get("top") and m.get("name")), None)
    if top:
        ctx.meta["package"] = {"ecosystem": top["ecosystem"], "name": top["name"], "version": top["version"]}
        t = typosquat_of(top["ecosystem"], top["name"])
        if t:
            ctx.add("high", "S3", "PACKAGE_TYPOSQUAT", f"包名 {top['name']} 与热门包 {t} 极相似（疑似仿冒）",
                    f"Package name {top['name']} closely resembles popular package {t} (possible typosquat)", top["path"], top["name"])
        from .deps import known_malicious
        if known_malicious(top["ecosystem"], top["name"], top["version"]):
            ctx.add("critical", "S3", "PACKAGE_KNOWN_MALICIOUS", f"该包版本为已知恶意版本：{top['name']}@{top['version']}",
                    f"This package version is known malicious: {top['name']}@{top['version']}", top["path"])
    # published-artifact identity: registry signatures / provenance / PEP 740 (S2 evidence, run once the package is known)
    prog("S3:signatures")
    _package_signatures(ctx, sample, inv, an, top)
    # lock files: locked hashes vs registry metadata and vendored artifacts
    prog("S3:lockfiles")
    _lockfiles(ctx, inv)
    # dependencies
    prog("S3:deps")
    ctx.deadline()
    res = DepResolver(ctx).run(an.manifests)
    ctx.deps = res
    an.finalize(res)
    ctx._top = top
    ctx.meta["network_indicators"] = sorted(an.network)[:100]
    ctx.meta["hooks"] = an.hooks
    ctx._an_profile = _profile(an)
    parts = ["解包", "ClamAV", "YARA", "格式分析", "混淆/编码分析", "网络与凭据特征", "依赖" if res.get("applicable") else "依赖(无清单)"]
    status = "partial" if any(m.stage == "S3" for m in ctx.missing) else "done"
    ctx.stage("S3", status, "、".join(parts), ", ".join(["unpack", "ClamAV", "YARA", "format analyzers", "obfuscation", "network/credential", "dependencies"]))
    return an, unp


def _profile(an):
    deps = {}
    for m in an.manifests:
        if m.get("top"):
            deps.update(m["deps"])
    return {"files": an.file_hashes, "hooks": an.hooks, "deps": deps, "network": sorted(an.network)[:200],
            "eval_count": an.eval_count, "binaries": an.binaries}


def _is_artifact(ctx, top):
    """True when the sample itself is the published package file (npm .tgz / PyPI sdist or wheel)."""
    fn = ctx.meta.get("file_name", "").lower()
    inner = (top.get("path") or "").split("!/", 1)[-1]
    if top["ecosystem"] == "npm":
        return fn.endswith((".tgz", ".tar.gz")) and inner.count("/") == 1
    return fn.endswith((".whl", ".tar.gz", ".zip")) and inner.count("/") <= 1


def _package_signatures(ctx, sample, inv, an, top):
    from . import sigverify, source as src_mod
    if not top or not top.get("name") or not top.get("version"):
        return
    eco, name, ver = top["ecosystem"], top["name"], top["version"]
    subject = f"{eco}:{name}"
    art = _is_artifact(ctx, top)
    if eco == "npm":
        info = src_mod.npm_registry_intel(ctx, name, ver)
        if not info:
            if ctx.meta.get("registry_presence") in ("not_found", "version_absent"):
                ctx.meta.setdefault("special_checks", []).append({"check": "npm_registry_signature", "status": "not_applicable",
                    "detail_zh": "该包/版本不在公共注册表，没有注册表签名可验证", "detail_en": "Package/version not in the public registry; no registry signature to verify"})
            return
        vdoc = info["vdoc"]
        integ = (vdoc.get("dist") or {}).get("integrity", "")
        sha512 = hashlib.sha512(sample.read_bytes()).hexdigest()
        covers = True
        if art and integ.startswith("sha512-"):
            if base64.b64decode(integ[7:]).hex() != sha512:
                covers = False
                if ctx.meta.get("original_url") is None:
                    ctx.add("medium", "S2", "PACKAGE_DIFFERS_FROM_REGISTRY", f"上传的 {name}@{ver} 与 npm 注册表发布的制品字节不同（被修改/重新打包），注册表签名不覆盖此文件",
                            f"Uploaded {name}@{ver} differs byte-wise from the npm-registry artifact (modified/repacked); registry signatures do not cover this file", top["path"], integ[:40])
        elif not art:
            covers = False
        r = sigverify.verify_npm_registry_signature(name, ver, vdoc, info.get("time"))
        if not covers and r["status"] == "verified":
            r = r | {"status": "not_applicable", "detail_zh": r["detail_zh"] + "；但样本不是该注册表制品本身，签名不覆盖样本",
                     "detail_en": r["detail_en"] + "; but the sample is not that registry artifact, so the signature does not cover it"}
        sigverify.record(ctx, r, top["path"], subject=subject, version=ver)
        repo = (vdoc.get("repository") or {}) if isinstance(vdoc.get("repository"), dict) else {"url": vdoc.get("repository")}
        for a in sigverify.verify_npm_attestations(name, ver, vdoc, sha512 if covers else None, repo.get("url")):
            if not covers and a["status"] == "verified":
                a = a | {"status": "not_applicable", "detail_zh": a["detail_zh"] + "（样本不是注册表制品本身）", "detail_en": a["detail_en"] + " (sample is not the registry artifact)"}
            sigverify.record(ctx, a, top["path"], subject=subject, version=ver)
    elif eco == "pypi" and art:
        import httpx
        try:
            r = httpx.get(f"{config.PYPI_URL}/pypi/{name}/{ver}/json", timeout=config.NET_STALL_TIMEOUT)
            if r.status_code == 404:
                ctx.meta.setdefault("special_checks", []).append({"check": "pypi_attestation", "status": "not_applicable",
                    "detail_zh": "该版本不在 PyPI", "detail_en": "Version not on PyPI"})
                return
            r.raise_for_status()
            files = r.json().get("urls", [])
        except Exception as e:
            ctx.miss("S2", "PYPI_METADATA_UNAVAILABLE", f"PyPI 元数据获取失败（{type(e).__name__}），签名/证明未检查",
                     f"PyPI metadata fetch failed ({type(e).__name__}); signatures/attestations not checked")
            return
        sha = ctx.meta.get("sha256")
        match = next((f for f in files if (f.get("digests") or {}).get("sha256") == sha), None)
        if not match:
            ctx.add("medium", "S2", "PACKAGE_DIFFERS_FROM_REGISTRY", f"样本与 PyPI 上 {name} {ver} 发布的任何文件都不一致（被修改/重新打包）",
                    f"Sample matches none of the files PyPI publishes for {name} {ver} (modified/repacked)", top["path"])
            return
        res = sigverify.verify_pypi_attestations(name, ver, match["filename"], str(sample))
        sigverify.record(ctx, res, top["path"], subject=subject, version=ver)


def _lockfiles(ctx, inv):
    from . import lockfiles
    locks = []
    for i in inv:
        if i.get("container"):
            continue
        n = Path(i["rel"].split("!/")[-1]).name
        inner = i["rel"].split("!/")[-1]
        if lockfiles.is_lockfile(n) and "node_modules/" not in inner and i["size"] < 50 * (1 << 20):
            try:
                locks.append((i["rel"], n, Path(i["abs"]).read_text(errors="replace")))
            except Exception:
                pass
    if not locks:
        ctx.meta.setdefault("special_checks", []).append({"check": "lockfile_hashes", "status": "not_applicable",
            "detail_zh": "样本中没有锁文件", "detail_en": "No lock file in the sample"})
        return
    res = lockfiles.LockChecker(ctx).run(locks, lockfiles.vendored_hashes(inv))
    ctx.meta.setdefault("special_checks", []).append(res)


def _source_diff(ctx, an):
    from . import source_diff
    top = getattr(ctx, "_top", None)
    if not top or not top.get("name") or not top.get("version") or top["ecosystem"] not in ("npm", "pypi"):
        ctx.meta.setdefault("special_checks", []).append({"check": "source_tag_diff", "status": "not_applicable",
            "detail_zh": "不是可识别版本的 npm/PyPI 包", "detail_en": "Not a versioned npm/PyPI package"})
        return
    inner_top = (top["path"] or "").split("!/", 1)[-1]
    root = inner_top.rsplit("/", 1)[0] if "/" in inner_top else ""
    if top["ecosystem"] == "pypi" and root.endswith((".dist-info", ".egg-info")):
        root = root.rsplit("/", 1)[0] if "/" in root else ""
    files = {}
    for k, v in an.file_hashes.items():
        if not root:
            files[k] = v
        elif k.startswith(root + "/"):
            files[k[len(root) + 1:]] = v
    if top["ecosystem"] == "npm":
        manifest = top.get("json") or {}
    else:
        manifest = top.get("text") or ""
        try:
            import httpx
            r = httpx.get(f"{config.PYPI_URL}/pypi/{top['name']}/{top['version']}/json", timeout=config.NET_STALL_TIMEOUT)
            if r.status_code == 200:
                info = r.json().get("info") or {}
                urls = list((info.get("project_urls") or {}).values()) + [info.get("home_page") or ""]
                manifest = "\n".join(f"Project-URL: x, {u}" for u in urls if u) + "\n" + manifest
        except Exception:
            pass
    if top["ecosystem"] == "npm":
        sc = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
        hook_paths = {re.sub(r"^\./", "", t) for h in ("preinstall", "install", "postinstall", "prepare")
                      for t in re.findall(r"[\w./\-]+\.(?:js|cjs|mjs|sh|py)", str(sc.get(h) or ""))}
    else:
        hook_paths = {"setup.py"}
    res = source_diff.run(ctx, top["ecosystem"], top["name"], top["version"], files, manifest, hook_paths)
    if res["status"] == "failed":
        ctx.miss("S4", "SOURCE_TAG_DIFF_FAILED", res["detail_zh"], res["detail_en"])
    ctx.meta.setdefault("special_checks", []).append(res)


# ---------------------------------------------------------------- S4
def _s4_diff(ctx, an, prog):
    prog("S4")
    _source_diff(ctx, an)
    pkg = ctx.meta.get("package")
    if not pkg or not pkg.get("name"):
        ctx.stage("S4", "not_applicable", "不是可识别版本的软件包，无基线可比", "Not a versioned package; no baseline applicable")
        ctx.diff = {"status": "not_applicable"}
        return
    from . import baselines as base_mod
    base = base_mod.resolve(pkg["ecosystem"], pkg["name"], pkg["version"])
    if not base:
        ctx.stage("S4", "skipped", "skipped(no_baseline)：首次出现的版本，已提高静态检测敏感度",
                  "skipped(no_baseline): first version seen; static sensitivity raised")
        ctx.diff = {"status": "skipped(no_baseline)"}
        _s4_unimpl(ctx)
        return
    old = json.loads(base["profile_json"])
    new = ctx._an_profile
    strip = lambda d: {re.sub(r"^package/", "", k): v for k, v in d.items()}
    of, nf = strip(old["files"]), strip(new["files"])
    added = sorted(set(nf) - set(of))
    removed = sorted(set(of) - set(nf))
    changed = sorted(k for k in set(nf) & set(of) if nf[k] != of[k])
    new_deps = sorted(set(new["deps"]) - set(old["deps"]))
    new_hooks = sorted(set(new["hooks"]) - set(old["hooks"]))
    new_net = sorted(set(new["network"]) - set(old["network"]))
    new_bins = sorted(set(new["binaries"]) - set(old["binaries"]))
    ctx.diff = {"status": "compared", "baseline_version": base["version"], "baseline_sha256": base["sha256"],
                "added_files": added[:50], "removed_files": removed[:50], "changed_files": changed[:50],
                "new_dependencies": new_deps, "new_install_hooks": new_hooks, "new_network_indicators": new_net[:30],
                "new_binaries": new_bins, "eval_delta": new["eval_count"] - old["eval_count"], "baseline_source": base.get("source") or "scan"}
    if new_hooks:
        ctx.add("high", "S4", "DIFF_NEW_INSTALL_HOOK", f"相对基线 {base['version']} 新增安装钩子：{', '.join(new_hooks)}",
                f"New install hook(s) vs baseline {base['version']}: {', '.join(new_hooks)}")
    hooked_deps = {f.path[len("dep:npm:"):].rsplit("@", 1)[0] for f in ctx.findings
                   if f.code in ("DEP_HAS_INSTALL_HOOK", "DEP_HOOK_SUSPICIOUS") and (f.path or "").startswith("dep:")}
    only_manifest = changed and set(changed) <= {"package.json"} and not added and not removed
    risky_new = [d for d in new_deps if d in hooked_deps]
    if only_manifest and risky_new:
        ctx.add("critical", "S4", "DIFF_MANIFEST_ONLY_HOOKED_DEP",
                f"相对基线 {base['version']} 只有 package.json 改变，且新增了带安装钩子的依赖 {', '.join(risky_new)}（与 2026-03 Axios 投毒手法一致）",
                f"Versus baseline {base['version']} only package.json changed, adding dependency with install hooks: {', '.join(risky_new)} (matches the 2026-03 Axios compromise pattern)",
                "package.json", ", ".join(risky_new))
    elif risky_new:
        ctx.add("high", "S4", "DIFF_NEW_HOOKED_DEP", f"新增带安装钩子的依赖：{', '.join(risky_new)}",
                f"New dependency with install hooks: {', '.join(risky_new)}", None, ", ".join(risky_new))
    elif new_deps:
        ctx.add("info", "S4", "DIFF_NEW_DEPS", f"新增依赖：{', '.join(new_deps[:10])}", f"New dependencies: {', '.join(new_deps[:10])}")
    if new_bins:
        ctx.add("medium", "S4", "DIFF_NEW_BINARIES", f"新增二进制文件：{', '.join(new_bins[:5])}", f"New binaries: {', '.join(new_bins[:5])}")
    if new_net:
        ctx.add("low", "S4", "DIFF_NEW_NETWORK", f"新增外部地址：{', '.join(new_net[:5])}", f"New external endpoints: {', '.join(new_net[:5])}")
    if ctx.diff["eval_delta"] >= 3:
        ctx.add("low", "S4", "DIFF_MORE_DYNAMIC_EXEC", f"动态执行调用增加 {ctx.diff['eval_delta']} 处", f"Dynamic-exec calls increased by {ctx.diff['eval_delta']}")
    ctx.stage("S4", "done", f"已与基线 {base['version']} 比对", f"Compared against baseline {base['version']}")
    _s4_unimpl(ctx)


def _s4_unimpl(ctx):
    pass


# ---------------------------------------------------------------- S5
def _s5_footprint(ctx, prog):
    prog("S5")
    seen, out = set(), []
    for f in ctx.footprint:
        k = f["en"]
        if k not in seen:
            seen.add(k)
            out.append(f)
    for f in ctx.findings:
        if f.code.startswith("YARA:FG_Persistence") or f.code.startswith("YARA:FG_Install_Script_Platform"):
            out.append({"kind": "predicted", "zh": f"可能建立持久化/投放文件：{f.path}", "en": f"May establish persistence / drop files: {f.path}"})
    ctx.footprint = out
    ctx.stage("S5", "done", f"静态预测 {len(out)} 项安装足迹（均为预测，非实际观察）",
              f"{len(out)} predicted install-footprint items (predicted, not observed)")


# ---------------------------------------------------------------- S7
def _s7_followup(ctx, report, verdict):
    sha = report.get("sha256")
    v = verdict["verdict"]
    if sha and v in ("BLOCK", "HIGH_RISK", "NO_FINDINGS") and not ctx.meta.get("cache_hit"):
        store.cache_put_hash(sha, ENGINE_VERSION, scanners.rules_version(), scanners.sigs_version(), v, ctx.scan_id)
    pkg = ctx.meta.get("package")
    if v == "NO_FINDINGS" and pkg and pkg.get("name") and hasattr(ctx, "_an_profile"):
        # only complete, clean scans become baselines
        store.baseline_put(pkg["ecosystem"], pkg["name"], pkg["version"], sha, ctx._an_profile, ctx.scan_id)
    if v == "NO_FINDINGS":
        for sg in ctx.meta.get("signers", []):
            store.signer_put(sg["subject"], sg["version"], sg["check"], sg["signer"], ctx.scan_id)
