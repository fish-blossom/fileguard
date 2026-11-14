"""SSRF-hardened, size-limited downloader (S0/S2). Never executes anything it downloads."""
import ipaddress
import socket
import urllib.parse

import httpx

from . import config

USER_AGENT = "FileGuard/0.1 (+static-scanner)"


class DownloadError(Exception):
    def __init__(self, code, zh, en):
        super().__init__(en)
        self.code, self.zh, self.en = code, zh, en


def _allowed_extra(ip):
    return any(ip in ipaddress.ip_network(c.strip(), strict=False) for c in config.SSRF_EXTRA_ALLOWED_CIDRS)


def check_host(host):
    """Resolve host and reject private / loopback / link-local / metadata addresses."""
    if not host:
        raise DownloadError("SSRF_NO_HOST", "URL 缺少主机名", "URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise DownloadError("DNS_FAIL", f"无法解析域名 {host}", f"Cannot resolve host {host}")
    ips = sorted({i[4][0] for i in infos})
    for s in ips:
        ip = ipaddress.ip_address(s.split("%")[0])
        if _allowed_extra(ip):
            continue
        if not ip.is_global or ip.is_multicast or str(ip) in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254"):
            raise DownloadError("SSRF_BLOCKED", f"拒绝访问内网/回环/元数据地址：{host} -> {ip}",
                                f"Refused private/loopback/metadata address: {host} -> {ip}")
    return ips


def normalize_url(url):
    url = url.strip()
    p = urllib.parse.urlsplit(url)
    if p.scheme.lower() not in ("http", "https"):
        raise DownloadError("BAD_SCHEME", "只支持 http/https 链接", "Only http/https URLs are supported")
    if p.username or p.password:
        raise DownloadError("URL_CREDENTIALS", "URL 中不允许包含账号密码", "Credentials in URL are not allowed")
    host = (p.hostname or "").encode("idna").decode("ascii").lower()
    netloc = host + (f":{p.port}" if p.port else "")
    return urllib.parse.urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))


def download(url, dest_path, max_bytes=None, deadline_check=None):
    """Follow up to MAX_REDIRECTS redirects manually, re-checking SSRF at each hop.
    Returns dict(original_url, final_url, redirects, size, content_type, resolved_ips)."""
    max_bytes = max_bytes or config.MAX_FILE_BYTES
    original = url
    url = normalize_url(url)
    chain = []
    with httpx.Client(follow_redirects=False, timeout=config.DOWNLOAD_TIMEOUT_S,  # per-read stall timeout, not a total limit
                     
                      headers={"User-Agent": USER_AGENT}, trust_env=True) as client:
        for hop in range(config.MAX_REDIRECTS + 1):
            host = urllib.parse.urlsplit(url).hostname
            ips = check_host(host)
            with client.stream("GET", url) as r:
                if r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location")
                    if not loc:
                        raise DownloadError("BAD_REDIRECT", "重定向缺少目标地址", "Redirect without Location")
                    nxt = normalize_url(urllib.parse.urljoin(url, loc))
                    chain.append({"from": url, "to": nxt, "status": r.status_code})
                    url = nxt
                    continue
                if r.status_code != 200:
                    raise DownloadError("HTTP_STATUS", f"下载失败，HTTP 状态码 {r.status_code}",
                                        f"Download failed with HTTP {r.status_code}")
                declared = int(r.headers.get("content-length") or 0)
                if declared and declared > max_bytes:
                    raise DownloadError("TOO_LARGE", f"文件大小 {declared} 字节超过上限 {max_bytes} 字节",
                                        f"File size {declared} bytes exceeds limit {max_bytes} bytes")
                size = 0
                with open(dest_path, "wb") as fh:
                    for chunk in r.iter_bytes(1 << 16):
                        size += len(chunk)
                        if size > max_bytes:
                            raise DownloadError("TOO_LARGE", f"下载内容超过上限 {max_bytes} 字节",
                                                f"Downloaded content exceeds limit of {max_bytes} bytes")
                        fh.write(chunk)
                        if deadline_check:
                            deadline_check()
                return {"original_url": original, "final_url": url, "redirects": chain, "size": size,
                        "content_type": r.headers.get("content-type", ""), "resolved_ips": ips,
                        "content_disposition": r.headers.get("content-disposition", "")}
    raise DownloadError("TOO_MANY_REDIRECTS", f"重定向超过 {config.MAX_REDIRECTS} 次", f"More than {config.MAX_REDIRECTS} redirects")
