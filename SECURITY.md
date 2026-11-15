# Security Policy / 安全策略

## Supported versions / 支持的版本

Only the **latest GitHub Release** of FileGuard receives security fixes. Installs update themselves
to the latest signed release (checked at most once a day).

只有**最新的 GitHub Release** 会收到安全修复。已安装的 FileGuard 每天最多检查一次，并自动更新到最新的已签名版本。

| Version | Supported |
| ------- | --------- |
| latest release | ✅ |
| older releases, `main` branch snapshots | ❌ |

## Reporting a vulnerability / 报告漏洞

Please report vulnerabilities **privately** through GitHub:
**Security → Advisories → [Report a vulnerability](https://github.com/fish-blossom/fileguard/security/advisories/new)**.
Do not open a public issue for security problems.

请通过 GitHub **私下**报告漏洞：仓库页面 **Security → Advisories → [Report a vulnerability](https://github.com/fish-blossom/fileguard/security/advisories/new)**。
请不要为安全问题开公开 issue。

Useful details: affected version (`fg version --json`), steps to reproduce, and impact. Never attach
live malware; use a hash or a harmless reproducer instead.

请附上受影响的版本（`fg version --json`）、复现步骤和影响。不要直接附上真实恶意样本，可以给 Hash 或无害的复现文件。

## How releases are protected / 发布如何防篡改

- Each release is built by the GitHub Actions workflow [`.github/workflows/release.yml`](.github/workflows/release.yml)
  on the version tag. It publishes `fileguard.tar.gz`, `manifest.json` (version, commit, SHA-256),
  `manifest.json.sig`, an `ssh-keygen -Y` signature by the FileGuard release key
  (namespace `fileguard-release`, public key in [`backend/release-signers`](backend/release-signers)),
  and a SLSA build-provenance attestation (`fileguard.tar.gz.intoto.jsonl`, also stored in the
  repository's attestations API).
- `install.sh` refuses to install unless the manifest signature verifies against the **already
  installed** public key (first install: the key shipped in the bootstrap download) and the tarball
  SHA-256 matches the manifest. These two checks are mandatory and work without `gh`.
- If the GitHub CLI (`gh`) is installed, `install.sh` also runs
  `gh attestation verify fileguard.tar.gz --repo fish-blossom/fileguard` and refuses to install when
  the attestation is missing or does not match. If `gh` is not installed, attestation is skipped.
- Third-party parsers (7-Zip, ClamAV) are official builds pinned by SHA-256; Python dependencies are
  installed from a hash-locked `requirements.lock` (wheels only).

Release key fingerprint: `SHA256:DlEdYt0Qop4w3SOxZftlpWCjDu9/EunWjVX+8olt6fs` (ED25519).

Verify a release by hand:

```bash
ssh-keygen -Y verify -f backend/release-signers -I fileguard-release@fish-blossom \
  -n fileguard-release -s manifest.json.sig < manifest.json
sha256sum -c fileguard.tar.gz.sha256
# Optional, when GitHub CLI is installed:
gh attestation verify fileguard.tar.gz --repo fish-blossom/fileguard
# Offline:
gh attestation verify fileguard.tar.gz --repo fish-blossom/fileguard --bundle fileguard.tar.gz.intoto.jsonl
```
