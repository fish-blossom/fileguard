# FileGuard

FileGuard is a **static** malware and software supply-chain poisoning scanner made to run with a [Grok Bot](https://grok.com). It inspects files, download URLs, and npm/PyPI packages for malicious code, suspicious install hooks, and known compromise patterns (including the 2026-03 Axios incident). It **never executes, installs, or runs macros**. There is no server, no port forwarding, and no MCP.

When someone adds the FileGuard bot from a template, the first conversation installs the engine onto **that user’s own Linux box** (Debian/Ubuntu, typically user `box`, `/workspace` writable). Later conversations update it silently when a newer signed GitHub Release is published.

中文简介：FileGuard 是一个只做静态分析的恶意文件 / 供应链投毒检测助手。检测在用户自己的 box 上用 CLI `fg` 完成本地扫描；结论只有 BLOCK、HIGH_RISK、INCOMPLETE、NO_FINDINGS、ERROR 五种。

## Repository layout

```
fileguard/
├── README.md                 This file
├── profile.json              Bot name, title, and operating description
├── system-instructions.md    Full rules: limits, five verdicts, report format
├── memory/profile.md         Standing rules for the bot
├── LICENSE                   PolyForm Strict License 1.0.0
├── SECURITY.md               How to report a vulnerability; how releases are signed
├── .github/workflows/        Tag-triggered release: sign, attest, publish
├── skills/
│   ├── fileguard-scan/       Fixed rules; the bot runs `fg help` for the current scan flow
│   └── getting-started/      First-conversation install / later silent updates
├── backend/                  Engine installed to /workspace/fileguard on the user’s box
│   ├── bootstrap.sh          Stable entry point: verify latest release, run its installer
│   ├── install.sh            Release installer (`--estimate`, `--tarball`, `--from-tree`; `--auto` -> bootstrap)
│   ├── VERSION               Engine version (semver)
│   ├── release-signers       Pinned public key that signs release manifests
│   ├── requirements.lock     Hash-locked Python dependencies (wheels only)
│   ├── fileguard/            Python engine (CLI, pipeline S0–S7, file store; no database)
│   ├── intel/                Local threat intel (known-bad hashes, malicious packages, IOCs)
│   ├── rules/fileguard.yar   YARA rules
│   ├── clamav/clamd.conf.in  clamd config template
│   ├── scripts/              fg, env.sh, start_clamd.sh, update_clamav_db.sh, build_release.sh
│   └── requirements.txt
└── docs/
    ├── detection-checklist.md
    ├── searchskill-submission.md
    └── sample-reports/       Illustrative reports (no EICAR test-file reports)
```

This repository does **not** include tests, sample malware fixtures, virtualenvs, or scan data.

## How the bot installs the engine

Installs come only from **signed GitHub Releases**, never from the moving `main` branch:

- `manifest.json` (version, commit, tarball SHA-256) + `manifest.json.sig` (signed with the key in `backend/release-signers`)
- `fileguard.tar.gz` (unpacks as `fileguard/`) + `fileguard.tar.gz.sha256`
- SLSA build provenance from GitHub Actions (`fileguard.tar.gz.intoto.jsonl`, also in the repository attestations API)
- Latest: `https://github.com/fish-blossom/fileguard/releases/latest/download/<file>`

`install.sh` verifies the manifest signature and the tarball SHA-256 before extracting anything (these checks are mandatory and work without `gh`). If `gh` is installed, it also runs `gh attestation verify` against the tarball and refuses to install when the attestation is missing or invalid; if `gh` is not installed, attestation is skipped. Versions are compared as semver, and a new release is checked at most once every 24 hours.

**Install and updates** go through `backend/bootstrap.sh` (installed as `/workspace/fileguard/bootstrap.sh`). It verifies the latest release (pinned-key signature, SHA-256, and `gh attestation verify` when `gh` is available), then runs **that release's** `install.sh`, so engine fixes never depend on the previously installed installer. If the lock is held only by this install's own clamd (old installer fd leak), it restarts that clamd first. The exact first-run commands are in `skills/getting-started/SKILL.md`; do not pipe a script to bash.

`install.sh` installs a few apt packages when sudo is available, builds a Python venv from the hash-locked `requirements.lock`, installs pinned official 7-Zip and ClamAV builds (SHA-256 checked), keeps its own ClamAV signature database under `data/`, and puts `fg` on PATH. Scan data lives in `$FILEGUARD_DIR/data` (or `FILEGUARD_DATA`) and is kept across updates.

### What the bot says to the user

- **First install only:** one line `⚙️ 正在初始化 FileGuard，预计约 N 分钟` (from `--estimate`), then a silent left-pad verification scan, then `✅ 初始化完成，可以开始检测了`. 

## Using `fg`

`fg` is also a bash job-control builtin. Always `source /workspace/fileguard/scripts/env.sh` in the same shell (it defines a function), or call `/workspace/fileguard/scripts/fg` by path.

```bash
source /workspace/fileguard/scripts/env.sh
fg submit_url https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz --lang zh
fg wait <scan_id> --lang zh
# optional: fg delivered <scan_id>
# INCOMPLETE: fg confirm_incomplete <scan_id> <sha256> <check1,check2> <name> [statement]
```

`submit_*` returns one compact JSON object with `estimate_text` covering the whole turn (engine + writing/sending the report) and starts the scan in a background process. `wait` blocks until done and prints a compact JSON result plus an HTML report path.

## Configuring the Grok Bot

1. Create a bot; name and description can follow `profile.json`.
2. Use `system-instructions.md` as the system instructions.
3. Import the two skills under `skills/`.
4. Optional listing copy: `docs/searchskill-submission.md`.

Do not attach an MCP server.

## Limits

- Static analysis only; payloads that decrypt or download only at runtime may be missed.
- Source-tag diff is GitHub-only; macOS code signatures cannot be verified on Linux; yarn berry lock hashes and Authenticode OCSP are not implemented.
- First install on a bare Debian/Ubuntu box usually takes a few minutes and apt steps need sudo.

YARA rules include an EICAR test-string detector. Antivirus alerts on that rule file are expected.

## License and security

FileGuard is licensed under the [PolyForm Strict License 1.0.0](LICENSE): free for noncommercial use; no modification or redistribution. To report a vulnerability, see [SECURITY.md](SECURITY.md).

许可证：[PolyForm Strict 1.0.0](LICENSE)，可免费非商业使用，不允许修改或再发布。发现安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。
