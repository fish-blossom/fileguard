"""Cryptographic signature verification (S2). Every function returns a status dict:
  {"check": ..., "status": "verified|invalid|not_applicable|unavailable|failed", "detail_zh":..., "detail_en":..., ...}
Policy (user decision):
  invalid signature                          -> HIGH evidence (HIGH_RISK)
  applicable but could not be completed      -> missing check (INCOMPLETE)
  not applicable / nothing published         -> reported only
  ecosystem normally provides it but missing -> evidence (not INCOMPLETE)
  signer differs from baseline               -> evidence
"""
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import config, netutil, tools

TIMEOUT = config.NET_STALL_TIMEOUT
import logging
logging.getLogger("sigstore").setLevel(logging.ERROR)   # we enforce identity ourselves after UnsafeNoOp


def _st(check, status, zh, en, **kw):
    return {"check": check, "status": status, "detail_zh": zh, "detail_en": en, **kw}


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


# ------------------------------------------------------------------ npm registry ECDSA signatures
_KEYS = {}


def npm_registry_keys():
    reg = config.NPM_REGISTRY
    if reg not in _KEYS:
        r = httpx.get(f"{reg}/-/npm/v1/keys", timeout=TIMEOUT)
        r.raise_for_status()
        _KEYS[reg] = {k["keyid"]: k for k in r.json().get("keys", [])}
    return _KEYS[reg]


def verify_npm_registry_signature(name, version, vdoc, publish_time=None):
    dist = (vdoc or {}).get("dist") or {}
    sigs = dist.get("signatures") or []
    integ = dist.get("integrity")
    if not sigs:
        return _st("npm_registry_signature", "missing_expected", "npm 注册表没有为该版本提供 ECDSA 签名（npm 自 2022 年起默认签名）",
                   "npm registry provides no ECDSA signature for this version (npm signs by default since 2022)")
    try:
        keys = npm_registry_keys()
    except Exception as e:
        return _st("npm_registry_signature", "failed", f"无法获取 npm 注册表公钥（{type(e).__name__}）", f"Could not fetch npm registry keys ({type(e).__name__})")
    msg = f"{name}@{version}:{integ}".encode()
    for s in sigs:
        k = keys.get(s.get("keyid"))
        if not k:
            continue
        exp = _ts(k.get("expires"))
        pt = _ts(publish_time)
        if exp and pt and pt > exp:
            return _st("npm_registry_signature", "invalid", f"签名所用公钥 {s['keyid']} 在发布时间之前已过期", f"Signing key {s['keyid']} had expired before publish time")
        pub = serialization.load_der_public_key(base64.b64decode(k["key"]))
        try:
            pub.verify(base64.b64decode(s["sig"]), msg, ec.ECDSA(hashes.SHA256()))
            return _st("npm_registry_signature", "verified", f"npm 注册表 ECDSA 签名有效（{s['keyid'][:20]}…）",
                       f"npm registry ECDSA signature valid ({s['keyid'][:20]}…)", keyid=s["keyid"], integrity=integ)
        except InvalidSignature:
            return _st("npm_registry_signature", "invalid", "npm 注册表签名验证失败：签名与包名/版本/完整性摘要不符（伪造或被篡改）",
                       "npm registry signature INVALID: does not match name/version/integrity (forged or tampered)", keyid=s.get("keyid"))
    return _st("npm_registry_signature", "failed", "签名使用的 keyid 不在注册表公钥列表中", "Signature keyid not found in registry key list")


# ------------------------------------------------------------------ Sigstore (npm provenance / publish attestations)
def _sigstore_verifier():
    from sigstore.verify import Verifier
    from sigstore.verify.verifier import TimestampSource, TimestampVerificationResult
    from sigstore.errors import VerificationError

    class NpmVerifier(Verifier):
        """sigstore-python 4.x only accepts rekor integrated time for dsse/hashedrekord 0.0.1.
        npm bundles use intoto/0.0.2 entries; the integrated time is equally bound by the
        inclusion promise (verified in _verify_common_signing_cert step 5), so accept it."""

        def _establish_time(self, bundle):
            inner = bundle.log_entry._inner
            kv = inner.kind_version
            if kv.kind == "intoto" and kv.version == "0.0.2" and inner.integrated_time and inner.inclusion_promise:
                out = []
                if bundle.verification_material.timestamp_verification_data and self._trusted_root.get_timestamp_authorities():
                    try:
                        out.extend(self._verify_timestamp_authority(bundle))
                    except Exception:
                        pass
                out.append(TimestampVerificationResult(source=TimestampSource.TRANSPARENCY_SERVICE,
                                                       time=datetime.fromtimestamp(inner.integrated_time, tz=timezone.utc)))
                return out
            return super()._establish_time(bundle)

        def verify_intoto_dsse(self, bundle, policy):
            from sigstore import dsse
            self._verify_common_signing_cert(bundle, policy)
            env = bundle._dsse_envelope
            dsse._verify(bundle.signing_certificate.public_key(), env)
            body = json.loads(bundle.log_entry._inner.canonicalized_body)
            spec = body["spec"]["content"]
            ph = spec.get("payloadHash", {})
            if ph.get("algorithm") != "sha256" or ph.get("value") != hashlib.sha256(env._inner.payload).hexdigest():
                raise VerificationError("tlog payload hash does not match bundle")
            logged = {base64.b64decode(s["sig"]) for s in spec["envelope"]["signatures"]}
            mine = {base64.b64encode(s.sig) for s in env._inner.signatures}
            if not mine & logged:
                raise VerificationError("tlog signatures do not match bundle")
            return env._inner.payload_type, env._inner.payload
    return NpmVerifier


_VERIFIER = None


def _verifier():
    global _VERIFIER
    if _VERIFIER is None:
        _VERIFIER = _sigstore_verifier().production()
    return _VERIFIER


def _repo_slug(url):
    if not url:
        return None
    m = re.search(r"github\.com[/:]([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:[/#?]|$)", url)
    return f"{m.group(1)}/{m.group(2)}".lower() if m else None


def verify_npm_attestations(name, version, vdoc, sha512_hex, repo_url=None):
    """Verify npm publish attestation (registry key) and SLSA provenance (Sigstore/Fulcio)."""
    att = ((vdoc or {}).get("dist") or {}).get("attestations")
    if not att:
        return [_st("npm_provenance", "not_applicable", "该版本没有发布 provenance 来源证明", "No provenance attestation published for this version")]
    url = att.get("url") or f"{config.NPM_REGISTRY}/-/npm/v1/attestations/{name}@{version}"
    if not url.startswith(config.NPM_REGISTRY):
        url = f"{config.NPM_REGISTRY}/-/npm/v1/attestations/{name}@{version}"
    try:
        doc = httpx.get(url, timeout=TIMEOUT).json()
    except Exception as e:
        return [_st("npm_provenance", "failed", f"provenance 获取失败（{type(e).__name__}）", f"Provenance fetch failed ({type(e).__name__})")]
    out = []
    for a in doc.get("attestations", []):
        pt = a.get("predicateType", "")
        b = a.get("bundle", {})
        check = "npm_provenance" if "slsa.dev/provenance" in pt else "npm_publish_attestation"
        try:
            if b.get("verificationMaterial", {}).get("publicKey"):
                payload = _verify_keyed_dsse(b)
                signer = "npm registry key " + b["verificationMaterial"]["publicKey"].get("hint", "")[:24]
            else:
                from sigstore.models import Bundle
                from sigstore.verify import policy
                bundle = Bundle.from_json(json.dumps(b))
                _, payload = _verifier().verify_intoto_dsse(bundle, policy.UnsafeNoOp())
                signer = _cert_identity(bundle.signing_certificate)
            st = json.loads(payload)
            digests = [s.get("digest", {}).get("sha512") for s in st.get("subject", [])]
            if sha512_hex and sha512_hex not in digests:
                out.append(_st(check, "invalid", "来源证明签名有效，但其中的制品摘要与本文件不符（文件被替换）",
                               "Attestation signature valid but its subject digest does not match this file (artifact replaced)", signer=signer))
                continue
            slug = _repo_slug(repo_url)
            if check == "npm_provenance" and slug and slug not in signer.lower():
                out.append(_st(check, "invalid", f"provenance 的构建身份 {signer} 与 package.json 声明的仓库 {slug} 不符",
                               f"Provenance build identity {signer} does not match declared repository {slug}", signer=signer))
                continue
            out.append(_st(check, "verified", f"{'SLSA provenance' if check == 'npm_provenance' else 'npm 发布证明'} 验证通过（{signer}）",
                           f"{'SLSA provenance' if check == 'npm_provenance' else 'npm publish attestation'} verified ({signer})", signer=signer))
        except Exception as e:
            from sigstore.errors import VerificationError
            from sigstore.models import InvalidBundle
            bad = isinstance(e, (VerificationError, InvalidSignature, InvalidBundle, ValueError))
            out.append(_st(check, "invalid" if bad else "failed",
                           f"{check} 验证{'失败（签名无效或被篡改）' if bad else '未完成'}：{type(e).__name__}: {str(e)[:120]}",
                           f"{check} {'INVALID' if bad else 'not completed'}: {type(e).__name__}: {str(e)[:120]}"))
    return out or [_st("npm_provenance", "failed", "provenance 文档为空", "Empty provenance document")]


def _verify_keyed_dsse(b):
    """DSSE envelope signed by an npm registry key (publish attestation)."""
    env = b["dsseEnvelope"]
    keyid = b["verificationMaterial"]["publicKey"]["hint"]
    k = npm_registry_keys().get(keyid)
    if not k:
        raise ValueError(f"unknown npm attestation key {keyid}")
    pub = serialization.load_der_public_key(base64.b64decode(k["key"]))
    payload = base64.b64decode(env["payload"])
    pt = env["payloadType"].encode()
    pae = b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)
    pub.verify(base64.b64decode(env["signatures"][0]["sig"]), pae, ec.ECDSA(hashes.SHA256()))
    return payload


def _cert_identity(cert):
    from cryptography.x509 import SubjectAlternativeName, UniformResourceIdentifier, RFC822Name
    try:
        san = cert.extensions.get_extension_for_class(SubjectAlternativeName).value
        v = san.get_values_for_type(UniformResourceIdentifier) or san.get_values_for_type(RFC822Name)
        return v[0] if v else "?"
    except Exception:
        return "?"


# ------------------------------------------------------------------ PyPI PEP 740 attestations
def verify_pypi_attestations(project, version, filename, sample_path):
    url = f"{config.PYPI_URL}/integrity/{project}/{version}/{filename}/provenance"
    try:
        r = httpx.get(url, timeout=TIMEOUT, headers={"Accept": "application/vnd.pypi.integrity.v1+json"})
    except Exception as e:
        return _st("pypi_attestation", "failed", f"PyPI 证明获取失败（{type(e).__name__}）", f"PyPI attestation fetch failed ({type(e).__name__})")
    if r.status_code == 404:
        return _st("pypi_attestation", "not_applicable", "该文件没有发布 PEP 740 证明", "No PEP 740 attestation published for this file")
    if r.status_code != 200:
        return _st("pypi_attestation", "failed", f"PyPI 证明接口返回 {r.status_code}", f"PyPI attestation endpoint returned {r.status_code}")
    from pypi_attestations import Distribution, Provenance
    tmp = Path(tempfile.mkdtemp(prefix="fg-pypi-"))
    try:
        p = tmp / filename
        shutil.copyfile(sample_path, p)
        dist = Distribution.from_file(p)
        prov = Provenance.model_validate_json(r.text)
        signers = []
        for bundle in prov.attestation_bundles:
            pub = bundle.publisher
            for att in bundle.attestations:
                try:
                    att.verify(pub, dist)
                except Exception as e:
                    return _st("pypi_attestation", "invalid", f"PEP 740 证明验证失败：{str(e)[:150]}", f"PEP 740 attestation INVALID: {str(e)[:150]}")
            signers.append(f"{pub.kind}:{getattr(pub, 'repository', '')}/{getattr(pub, 'workflow', '')}")
        return _st("pypi_attestation", "verified", f"PEP 740 证明验证通过（{', '.join(signers)}）", f"PEP 740 attestation verified ({', '.join(signers)})",
                   signer=", ".join(signers))
    except Exception as e:
        return _st("pypi_attestation", "failed", f"PEP 740 证明处理出错（{type(e).__name__}）", f"PEP 740 processing error ({type(e).__name__})")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ GPG detached signatures
def verify_gpg(final_url, sample_path):
    sig_url = None
    sig = None
    for ext in (".asc", ".sig", ".gpg"):
        u = final_url + ext
        try:
            r = netutil.safe_get(u, timeout=TIMEOUT, max_bytes=200_000)
        except Exception:
            continue
        if r.status_code == 200 and 0 < len(r.content) < 100_000:
            sig_url, sig = u, r.content
            break
    if not sig:
        return _st("gpg_signature", "not_applicable", "下载地址旁没有发布 .asc/.sig 签名", "No .asc/.sig signature published next to the download")
    if not shutil.which("gpg"):
        return _st("gpg_signature", "failed", "缺少 gpg", "gpg missing", sig_url=sig_url)
    home = tempfile.mkdtemp(prefix="fg-gpg-")
    try:
        sf = Path(home) / "file.sig"
        sf.write_bytes(sig)
        env = dict(os.environ, GNUPGHOME=home)
        pk = tools.run_limited(["gpg", "--batch", "--list-packets", str(sf)], capture_output=True, text=True, env=env, timeout=30)
        m = re.search(r"issuer fpr v4 ([0-9A-F]{40})", pk.stdout) or re.search(r"keyid ([0-9A-F]{16})", pk.stdout)
        if not m:
            return _st("gpg_signature", "invalid", "签名文件不是有效的 OpenPGP 签名", "Signature file is not a valid OpenPGP signature", sig_url=sig_url)
        fpr = m.group(1)
        trusted = _trusted_fprs()
        try:
            kr = httpx.get(f"{config.KEYSERVER}/vks/v1/by-{'fingerprint' if len(fpr) == 40 else 'keyid'}/{fpr}", timeout=TIMEOUT)
            if kr.status_code != 200:
                return _st("gpg_signature", "failed", f"密钥服务器上找不到签名公钥 {fpr}", f"Signing key {fpr} not found on keyserver", sig_url=sig_url, fingerprint=fpr)
            (Path(home) / "key.asc").write_bytes(kr.content)
            tools.run_limited(["gpg", "--batch", "--import", str(Path(home) / "key.asc")], capture_output=True, env=env, timeout=30)
        except Exception as e:
            return _st("gpg_signature", "failed", f"获取签名公钥失败（{type(e).__name__}）", f"Fetching signing key failed ({type(e).__name__})", sig_url=sig_url, fingerprint=fpr)
        v = tools.run_limited(["gpg", "--batch", "--status-fd", "1", "--verify", str(sf), sample_path], capture_output=True, text=True, env=env, timeout=120)
        if "[GNUPG:] BADSIG" in v.stdout:
            return _st("gpg_signature", "invalid", f"GPG 签名无效：文件与签名不符（签名公钥 {fpr}）", f"GPG signature BAD: file does not match signature (key {fpr})", sig_url=sig_url, fingerprint=fpr)
        g = re.search(r"\[GNUPG:\] VALIDSIG ([0-9A-F]{40})", v.stdout)
        if g:
            full = g.group(1)
            uid = re.search(r"\[GNUPG:\] GOODSIG \w+ (.+)", v.stdout)
            who = f"{full} {uid.group(1) if uid else ''}".strip()
            if full in trusted:
                return _st("gpg_signature", "verified", f"GPG 签名有效，签名者在信任列表中：{who}", f"GPG signature valid; signer is pinned as trusted: {who}", signer=full, sig_url=sig_url)
            return _st("gpg_signature", "verified_untrusted", f"GPG 签名在数学上有效，签名者 {who} 不在信任列表（只能证明“该密钥签过”）",
                       f"GPG signature cryptographically valid by {who}, but signer is not pinned as trusted", signer=full, sig_url=sig_url)
        return _st("gpg_signature", "failed", "GPG 验证未得出结论", "GPG verification inconclusive", sig_url=sig_url, fingerprint=fpr)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _trusted_fprs():
    p = config.INTEL_DIR / "trusted_gpg_fingerprints.txt"
    if not p.exists():
        return set()
    return {l.split("#")[0].strip().replace(" ", "").upper() for l in p.read_text().splitlines() if l.split("#")[0].strip()}


# ------------------------------------------------------------------ Authenticode chain + revocation
_CRL_CACHE = {}


def _ca_bundle():
    """System CA bundle, plus extra roots from FILEGUARD_EXTRA_CA (tests use a private code-signing CA)."""
    sysca = "/etc/ssl/certs/ca-certificates.crt"
    extra = os.environ.get("FILEGUARD_EXTRA_CA")
    if not extra:
        return sysca
    out = Path(tempfile.gettempdir()) / f"fg-ca-{os.getpid()}.pem"
    if not out.exists():
        out.write_bytes(Path(sysca).read_bytes() + b"\n" + Path(extra).read_bytes())
    return str(out)


def verify_authenticode(path):
    if not shutil.which("osslsigncode"):
        return _st("authenticode", "failed", "缺少 osslsigncode", "osslsigncode missing")
    ca = _ca_bundle()
    base = ["osslsigncode", "verify", "-CAfile", ca, "-TSA-CAfile", ca, "-in", path]
    r = tools.run_limited(base[:2] + ["-ignore-crl"] + base[2:], capture_output=True, text=True, timeout=config.TOOL_STALL_TIMEOUT, errors="replace")
    out = r.stdout + r.stderr
    signer = re.search(r"Signer #0:\s*\n\s*Subject:\s*(.+)", out)
    who = signer.group(1).strip()[:120] if signer else "?"
    cur = re.search(r"Current message digest\s*:\s*([0-9A-F]+)", out)
    calc = re.search(r"Calculated message digest\s*:\s*([0-9A-F]+)", out)
    if cur and calc and cur.group(1) != calc.group(1):
        return _st("authenticode", "invalid", "Authenticode 摘要与文件内容不符（签名后被篡改）", "Authenticode digest does not match content (modified after signing)", signer=who)
    if "No signature found" in out or "Unable to extract" in out or ("Signer #0" not in out and "Number of signers" not in out and r.returncode != 0):
        return _st("authenticode", "not_signed", "文件没有 Authenticode 签名", "File has no Authenticode signature")
    if not (r.returncode == 0 and "Succeeded" in out):
        if "Signature verification: failed" in out or "certificate verify" in out.lower():
            return _st("authenticode", "invalid", f"Authenticode 证书链验证失败（签名者 {who}）", f"Authenticode certificate chain verification failed (signer {who})", signer=who)
        return _st("authenticode", "failed", "Authenticode 验证未完成", "Authenticode verification not completed", signer=who)
    # revocation: download CRLs ourselves (osslsigncode's HTTP client fails behind proxies), pass as PEM
    # osslsigncode only prints the CRL distribution points when it attempts revocation; probe once for the URLs
    probe = tools.run_limited(base, capture_output=True, text=True, timeout=config.TOOL_STALL_TIMEOUT, errors="replace")
    po = probe.stdout + probe.stderr
    if probe.returncode == 0 and "Succeeded" in po:
        return _st("authenticode", "verified", f"Authenticode 签名有效，证书链与吊销状态均已检查：{who}", f"Authenticode valid; chain and revocation checked: {who}", signer=who)
    tsa_cdps = sorted(set(re.findall(r"TSA's CRL distribution point:\s*(\S+)", po)))
    cdps = sorted(set(re.findall(r"(?<!TSA's )CRL distribution point:\s*(\S+)", po)))
    if not cdps and not tsa_cdps:
        return _st("authenticode", "failed", f"Authenticode 签名有效（{who}），但证书未提供可用的吊销列表地址，吊销状态未检查",
                   f"Authenticode valid ({who}) but no CRL distribution point available; revocation unchecked", signer=who, chain="ok")
    cdps = [c for c in cdps if c not in tsa_cdps]
    tmp = tempfile.mkdtemp(prefix="fg-crl-")
    try:
        files = {}
        for kind, urls in (("crl", cdps), ("tsa", tsa_cdps)):
            pems = []
            for u in urls:
                try:
                    if u in _CRL_CACHE:
                        data = _CRL_CACHE[u]
                    else:
                        rr = netutil.safe_get(u, timeout=TIMEOUT, max_bytes=50 * 1024 * 1024, follow_redirects=True)
                        if rr.status_code != 200 or not rr.content:
                            raise IOError(f"HTTP {rr.status_code}")
                        data = _CRL_CACHE[u] = rr.content
                    from cryptography import x509
                    crl = x509.load_der_x509_crl(data) if not data.startswith(b"-----") else x509.load_pem_x509_crl(data)
                    pems.append(crl.public_bytes(serialization.Encoding.PEM))
                except Exception as e:
                    return _st("authenticode", "failed", f"Authenticode 签名有效（{who}），但吊销列表 {u} 无法获取（{type(e).__name__}），吊销状态未检查",
                               f"Authenticode valid ({who}) but CRL {u} unavailable ({type(e).__name__}); revocation unchecked", signer=who, chain="ok")
            if pems:
                f = Path(tmp) / f"{kind}.pem"
                f.write_bytes(b"".join(pems))
                files[kind] = str(f)
        args = base[:2] + (["-CRLfile", files["crl"]] if "crl" in files else []) + (["-TSA-CRLfile", files["tsa"]] if "tsa" in files else []) + base[2:]
        r2 = tools.run_limited(args, capture_output=True, text=True, timeout=config.TOOL_STALL_TIMEOUT, errors="replace")
        o2 = r2.stdout + r2.stderr
        if r2.returncode == 0 and "Succeeded" in o2:
            return _st("authenticode", "verified", f"Authenticode 签名有效，证书链与吊销状态（CRL）均已检查：{who}",
                       f"Authenticode valid; chain and revocation (CRL) checked: {who}", signer=who)
        if "revoked" in o2.lower():
            return _st("authenticode", "invalid", f"Authenticode 签名证书已被吊销（{who}）", f"Authenticode signing certificate is REVOKED ({who})", signer=who)
        return _st("authenticode", "failed", "Authenticode 吊销检查未通过/未完成", "Authenticode revocation check failed/incomplete", signer=who)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ recording results into the scan context
CODE = {"npm_registry_signature": "NPM_REGISTRY_SIGNATURE", "npm_publish_attestation": "NPM_PUBLISH_ATTESTATION",
        "npm_provenance": "NPM_PROVENANCE", "pypi_attestation": "PYPI_ATTESTATION", "gpg_signature": "GPG_SIGNATURE",
        "authenticode": "AUTHENTICODE"}


def record(ctx, res, rel=None, subject=None, version=None):
    """Map a verification result onto evidence / missing checks, per the user-decided policy."""
    code = CODE.get(res["check"], res["check"].upper())
    item = {k: v for k, v in res.items()} | ({"path": rel} if rel else {})
    ctx.meta.setdefault("special_checks", []).append(item)
    st = res["status"]
    if st == "invalid":
        ctx.add("high", "S2", f"{code}_INVALID", res["detail_zh"], res["detail_en"], rel, res.get("signer"))
    elif st == "failed":
        ctx.miss("S2", f"{code}_NOT_VERIFIED", res["detail_zh"], res["detail_en"], rel)
    elif st == "missing_expected":
        ctx.add("medium", "S2", f"{code}_MISSING", res["detail_zh"], res["detail_en"], rel)
    elif st == "verified_untrusted":
        ctx.limit(res["detail_zh"], res["detail_en"])
    elif st == "verified":
        ctx.meta.setdefault("integrity_checks", []).append(res["detail_en"][:120])
    signer = res.get("signer")
    if st in ("verified", "verified_untrusted") and signer and subject:
        from . import store
        prev = store.signer_previous(subject, res["check"], version)
        if prev and prev["signer"] != signer:
            ctx.add("medium", "S2", "SIGNER_CHANGED", f"签名者与已记录的基线不同（{prev['version']}：{prev['signer'][:80]} → 本次：{signer[:80]}）",
                    f"Signer differs from recorded baseline ({prev['version']}: {prev['signer'][:80]} -> now: {signer[:80]})", rel, signer[:100])
        ctx.meta.setdefault("signers", []).append({"subject": subject, "version": version, "check": res["check"], "signer": signer})
    return res
