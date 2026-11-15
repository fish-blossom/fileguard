"""SSRF-hardened, size-limited downloader (S0/S2). Never executes anything it downloads."""
import ipaddress
import socket
import urllib.parse

import os

import httpx

from . import USER_AGENT, config


class DownloadError(Exception):
    def __init__(self, code, zh, en):
        super().__init__(en)
        self.code, self.zh, self.en = code, zh, en


def _allowed_extra(ip):
    return any(ip in ipaddress.ip_network(c.strip(), strict=False) for c in config.SSRF_EXTRA_ALLOWED_CIDRS)


_METADATA = ("169.254.169.254", "100.100.100.200", "fd00:ec2::254")


def ip_allowed(ip):
    ip = ipaddress.ip_address(str(ip).split("%")[0])
    if _allowed_extra(ip):
        return True
    return ip.is_global and not ip.is_multicast and str(ip) not in _METADATA


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
        if not ip_allowed(s):
            raise DownloadError("SSRF_BLOCKED", f"拒绝访问内网/回环/元数据地址：{host} -> {s}",
                                f"Refused private/loopback/metadata address: {host} -> {s}")
    return ips


def _proxied(url):
    """True when httpx will send this request through an env-configured proxy (the peer is then the proxy)."""
    try:
        return bool(httpx._utils.get_environment_proxies())  # noqa: SLF001
    except Exception:
        return any(os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"))


def check_peer(response, host, proxied):
    """Close the DNS-rebinding window: validate the IP the socket actually connected to,
    not just what an earlier, separate DNS lookup returned."""
    if proxied:
        return None
    ns = response.extensions.get("network_stream")
    addr = None
    try:
        addr = ns.get_extra_info("server_addr") if ns is not None else None
    except Exception:
        addr = None
    if not addr:
        raise DownloadError("SSRF_PEER_UNVERIFIED", f"无法确认 {host} 实际连接的 IP，已拒绝",
                            f"Could not verify the connected peer IP for {host}; refused")
    ip = addr[0]
    if not ip_allowed(ip):
        raise DownloadError("SSRF_BLOCKED", f"实际连接到了内网/回环/元数据地址（DNS 重绑定？）：{host} -> {ip}",
                            f"Connected peer is a private/loopback/metadata address (DNS rebinding?): {host} -> {ip}")
    return ip


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
                check_peer(r, host, _proxied(url))
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


class SmallResponse:
    def __init__(self, status_code, content, url):
        self.status_code, self.content, self.url = status_code, content, url

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")


def safe_get(url, timeout=15, max_bytes=5 * 1024 * 1024, follow_redirects=False):
    """Small GET with the same SSRF checks as download(): DNS check per hop plus a check of the
    connected peer IP. Returns SmallResponse (body truncated at max_bytes + 1)."""
    url = normalize_url(url)
    with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": USER_AGENT}, trust_env=True) as client:
        for _ in range(config.MAX_REDIRECTS + 1):
            host = urllib.parse.urlsplit(url).hostname
            check_host(host)
            with client.stream("GET", url) as r:
                check_peer(r, host, _proxied(url))
                if follow_redirects and r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                    url = normalize_url(urllib.parse.urljoin(url, r.headers["location"]))
                    continue
                buf = bytearray()
                for chunk in r.iter_bytes(1 << 16):
                    buf += chunk
                    if len(buf) > max_bytes:
                        break
                return SmallResponse(r.status_code, bytes(buf), url)
    raise DownloadError("TOO_MANY_REDIRECTS", f"重定向超过 {config.MAX_REDIRECTS} 次", f"More than {config.MAX_REDIRECTS} redirects")
