"""S1/S2 download-source extras: typosquat domains, numeric IP hosts, ports, dynamic DNS, domain age (RDAP),
publisher/release anomalies (npm/PyPI registry metadata), published checksum sidecars, signatures, provenance."""
import base64
import hashlib
import re
import urllib.parse
from datetime import datetime, timezone

import httpx

from . import config, netutil

KNOWN_DOMAINS = ["github.com", "githubusercontent.com", "npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org", "python.org",
                 "nodejs.org", "microsoft.com", "windows.com", "google.com", "googleapis.com", "apple.com", "debian.org",
                 "ubuntu.com", "mozilla.org", "gitlab.com", "bitbucket.org", "sourceforge.net", "docker.com", "amazon.com",
                 "amazonaws.com", "cloudflare.com", "jetbrains.com", "oracle.com", "java.com", "adobe.com", "zoom.us",
                 "slack.com", "visualstudio.com", "golang.org", "rust-lang.org", "crates.io", "rubygems.org", "nuget.org"]
DYN_DNS = ("duckdns.org", "no-ip.org", "no-ip.com", "ddns.net", "hopto.org", "zapto.org", "sytes.net", "ngrok.io", "ngrok-free.app",
           "trycloudflare.com", "serveo.net", "000webhostapp.com", "freenom", "dynu.net", "afraid.org", "workers.dev", "pages.dev",
           "glitch.me", "repl.co", "herokuapp.com", "firebaseapp.com", "web.app", "transfer.sh", "anonfiles", "filebin")
CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i"})


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def reg_domain(host):
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def host_checks(ctx, url):
    p = urllib.parse.urlsplit(url)
    host = (p.hostname or "").lower()
    raw_host = p.netloc.rsplit("@", 1)[-1].split(":")[0]
    if re.fullmatch(r"0x[0-9a-f]+|\d{8,10}|0\d+(\.\d+)*|(\d+\.){1,2}\d+", raw_host, re.I):
        ctx.add("high", "S0", "URL_OBFUSCATED_IP", f"URL 使用十进制/十六进制/八进制等变形 IP：{raw_host}",
                f"URL uses an obfuscated numeric IP form: {raw_host}", None, raw_host)
    if p.port and p.port not in (80, 443):
        ctx.add("medium", "S1", "SOURCE_NONSTANDARD_PORT", f"使用非标准端口下载：{p.port}", f"Download uses a non-standard port: {p.port}", None, str(p.port))
    if not host or re.fullmatch(r"[\d.]+", host):
        return
    rd = reg_domain(host)
    if any(rd.endswith(d) or host.endswith(d) or d in host for d in DYN_DNS):
        ctx.add("medium", "S1", "SOURCE_DYNAMIC_DNS", f"来源使用免费/动态 DNS 或临时托管：{host}", f"Source uses free/dynamic DNS or ephemeral hosting: {host}", None, host)
    if rd in KNOWN_DOMAINS:
        return
    # subdomain impersonation: github.com.evil.io
    for k in KNOWN_DOMAINS:
        if host.startswith(k + ".") or f".{k}." in host:
            ctx.add("high", "S1", "DOMAIN_SUBDOMAIN_IMPERSONATION", f"子域名冒充知名域名：{host}（冒充 {k}）",
                    f"Subdomain impersonates a well-known domain: {host} (impersonating {k})", None, host)
            return
    label = rd.split(".")[0]
    norm = label.translate(CONFUSABLE).replace("rn", "m").replace("vv", "w")
    for k in KNOWN_DOMAINS:
        kl = k.split(".")[0]
        if len(kl) < 4:
            continue
        if norm == kl or _lev(label, kl) <= (1 if len(kl) <= 6 else 2) or any(ord(c) > 127 for c in host):
            if label != kl or rd != k:
                ctx.add("high", "S1", "DOMAIN_TYPOSQUAT", f"疑似仿冒域名：{host}（近似 {k}）", f"Possible typosquat domain: {host} (resembles {k})", None, host)
                return


def domain_age(ctx, host):
    if not host or re.fullmatch(r"[\d.]+", host):
        return
    rd = reg_domain(host)
    if rd in KNOWN_DOMAINS:
        return
    try:
        r = httpx.get(f"https://rdap.org/domain/{rd}", timeout=8, follow_redirects=True)
        if r.status_code != 200:
            raise ValueError(r.status_code)
        ev = {e.get("eventAction"): e.get("eventDate") for e in r.json().get("events", [])}
        reg = ev.get("registration")
        if reg:
            days = (datetime.now(timezone.utc) - datetime.fromisoformat(reg.replace("Z", "+00:00"))).days
            ctx.meta["domain_age_days"] = days
            if days < 30:
                ctx.add("medium", "S1", "DOMAIN_NEWLY_REGISTERED", f"来源域名注册仅 {days} 天", f"Source domain registered only {days} days ago", None, rd)
    except Exception as e:
        ctx.limit(f"域名注册时间（RDAP）未能查询：{rd}（{type(e).__name__}）", f"Domain age (RDAP) lookup failed for {rd} ({type(e).__name__})")


def checksum_sidecars(ctx, final_url, sha256, fname):
    """Look for published SHA256 sidecar files next to the download (SSRF-checked, small size cap)."""
    base = final_url.rsplit("/", 1)[0]
    cands = [final_url + ".sha256", final_url + ".sha256sum", final_url + ".sha256.txt", base + "/SHA256SUMS", base + "/sha256sums.txt", base + "/SHA256SUMS.txt"]
    for u in cands:
        try:
            host = urllib.parse.urlsplit(u).hostname
            r = netutil.safe_get(u, timeout=8, max_bytes=1_000_000)
            if r.status_code != 200 or len(r.content) > 1_000_000:
                continue
            txt = r.text
        except Exception:
            continue
        hashes = re.findall(r"\b([0-9a-fA-F]{64})\b\s+\*?(\S+)?", txt)
        relevant = [h for h, n in hashes if not n or n.lstrip("*").endswith(fname)] if hashes else []
        if not relevant:
            continue
        if sha256 in (h.lower() for h in relevant):
            ctx.meta.setdefault("integrity_checks", []).append(f"published checksum {u}")
            return "match"
        ctx.add("critical", "S2", "PUBLISHED_CHECKSUM_MISMATCH", f"文件 SHA-256 与官方发布的校验文件不一致（{u}）",
                f"File SHA-256 does not match the published checksum file ({u})", None, relevant[0])
        return "mismatch"
    return None


def signature_sidecars(ctx, final_url, sample_path):
    """Detached GPG signature next to the download (.asc/.sig/.gpg): verified against the signer key from the keyserver."""
    from . import sigverify
    res = sigverify.verify_gpg(final_url, str(sample_path))
    if res.get("sig_url"):
        ctx.meta["published_signature"] = res["sig_url"]
    p = urllib.parse.urlsplit(final_url)
    subject = "gpg:" + (p.hostname or "") + re.sub(r"\d+(\.\d+)*", "*", p.path.rsplit("/", 1)[0])
    sigverify.record(ctx, res, None, subject=subject, version=ctx.meta.get("sha256"))
    return res


def npm_registry_intel(ctx, name, version):
    """Publisher / maintainer / release-cadence anomalies from the npm packument (if the package is public)."""
    try:
        n = name.replace("/", "%2f") if name.startswith("@") else name
        r = httpx.get(f"{config.NPM_REGISTRY}/{n}", timeout=config.NET_STALL_TIMEOUT)
        if r.status_code == 404:
            ctx.meta["registry_presence"] = "not_found"
            return None
        r.raise_for_status()
        doc = r.json()
    except Exception as e:
        ctx.miss("S1", "NPM_REGISTRY_METADATA_UNAVAILABLE", f"npm 注册表元数据获取失败（{type(e).__name__}），发布者变化/签名未检查",
                 f"npm registry metadata fetch failed ({type(e).__name__}); publisher change / signatures not checked")
        return None
    versions = doc.get("versions") or {}
    times = doc.get("time") or {}
    if version not in versions:
        ctx.add("medium", "S1", "REGISTRY_VERSION_ABSENT", f"注册表中不存在 {name}@{version}（可能是被撤下的恶意版本或私自篡改的包）",
                f"{name}@{version} is not in the registry (possibly unpublished-malicious or tampered package)", None, f"{name}@{version}")
        ctx.meta["registry_presence"] = "version_absent"
        return None
    ordered = sorted((v for v in versions if v in times), key=lambda v: times[v])
    i = ordered.index(version) if version in ordered else -1
    cur = versions[version]
    if i > 0:
        prev = versions[ordered[i - 1]]
        pu, cu = (prev.get("_npmUser") or {}).get("name"), (cur.get("_npmUser") or {}).get("name")
        if pu and cu and pu != cu:
            ctx.add("medium", "S1", "PUBLISHER_CHANGED", f"发布者变化：{ordered[i - 1]} 由 {pu} 发布，{version} 由 {cu} 发布",
                    f"Publisher changed: {ordered[i - 1]} by {pu}, {version} by {cu}", None, f"{pu}->{cu}")
        if cur.get("_npmUser", {}).get("email") and prev.get("_npmUser", {}).get("email") and cur["_npmUser"]["email"] != prev["_npmUser"]["email"]:
            ctx.add("low", "S1", "PUBLISHER_EMAIL_CHANGED", "发布者邮箱与上一版本不同", "Publisher email differs from previous version")
        pm = {m.get("name") for m in prev.get("maintainers") or []}
        cm = {m.get("name") for m in cur.get("maintainers") or []}
        if cm - pm:
            ctx.add("low", "S1", "NEW_MAINTAINER", f"新增维护者：{', '.join(sorted(cm - pm))}", f"New maintainer(s): {', '.join(sorted(cm - pm))}")
        t0 = datetime.fromisoformat(times[ordered[i - 1]].replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(times[version].replace("Z", "+00:00"))
        if (t1 - t0).days > 365:
            ctx.add("low", "S1", "DORMANT_THEN_RELEASE", f"沉寂 {(t1 - t0).days} 天后突然发布新版本", f"New release after {(t1 - t0).days} days of dormancy")
        if prev.get("dist", {}).get("attestations") and not cur.get("dist", {}).get("attestations"):
            ctx.add("high", "S2", "PROVENANCE_DROPPED", "上一版本有 npm provenance 来源证明，本版本却没有（Axios 事件特征之一）",
                    "Previous version had npm provenance but this one does not (an Axios-incident trait)")
    burst = [v for v in ordered if abs((datetime.fromisoformat(times[v].replace("Z", "+00:00")) - datetime.fromisoformat(times[version].replace("Z", "+00:00"))).total_seconds()) < 86400]
    if len(burst) >= 4:
        ctx.add("low", "S1", "RELEASE_BURST", f"24 小时内连发 {len(burst)} 个版本", f"{len(burst)} versions released within 24h")
    if not cur.get("dist", {}).get("attestations"):
        ctx.limit("该 npm 版本没有 provenance 来源证明", "This npm version has no provenance attestation")
    ctx.meta["registry_presence"] = "found"
    return {"vdoc": cur, "time": times.get(version), "doc": doc}
