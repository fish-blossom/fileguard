# FileGuard

FileGuard is a **static** malware and software supply-chain poisoning scanner made to run with a [Grok Bot](https://grok.com). It inspects files, download URLs, and npm/PyPI packages for malicious code, suspicious install hooks, and known compromise patterns (including the 2026-03 Axios incident). It **never executes, installs, or runs macros**. There is no server, no port forwarding, and no MCP.

When someone adds the FileGuard bot from a template, the first conversation installs the engine onto **that user’s own Linux box** (Debian/Ubuntu, typically user `box`, `/workspace` writable). Later conversations update it silently if a newer version is on `main`.

中文简介：FileGuard 是一个只做静态分析的恶意文件 / 供应链投毒检测助手。检测在用户自己的 box 上用 CLI `fg` 完成本地扫描；结论只有 BLOCK、HIGH_RISK、INCOMPLETE、NO_FINDINGS、ERROR 五种。

## Repository layout

```
fileguard/
├── README.md                 This file
├── profile.json              Bot name, title, and operating description
├── system-instructions.md    Full rules: limits, five verdicts, report format
├── memory/profile.md         Standing rules for the bot
├── skills/
│   ├── fileguard-scan/       Two-command scan flow and how to format the three result messages
│   └── getting-started/      First-conversation install / later silent updates
├── backend/                  Engine installed to /workspace/fileguard on the user’s box
│   ├── install.sh            Idempotent install/update (`--estimate`, `--tarball`, `--dir`)
│   ├── VERSION               Published engine version (used for silent update checks)
│   ├── fileguard/            Python engine (CLI, pipeline S0–S7, file store; no database)
│   ├── intel/                Local threat intel (known-bad hashes, malicious packages, IOCs)
│   ├── rules/fileguard.yar   YARA rules
│   ├── clamav/clamd.conf.in  clamd config template
│   ├── scripts/              fg, env.sh, start_clamd.sh
│   └── requirements.txt
└── docs/
    ├── detection-checklist.md
    ├── searchskill-submission.md
    └── sample-reports/       Illustrative reports (no EICAR test-file reports)
```

This repository does **not** include tests, sample malware fixtures, virtualenvs, scan data, or a LICENSE file (none was present in the original package).

## How the bot installs the engine

Source of truth is this GitHub repo’s `main` branch (auto archive, not a Release asset):

- Archive: `https://github.com/fish-blossom/fileguard/archive/refs/heads/main.tar.gz`  
  Unpacks as `fileguard-main/backend/`.
- Or: `git clone https://github.com/fish-blossom/fileguard.git`
- Version pin for updates: `https://raw.githubusercontent.com/fish-blossom/fileguard/main/backend/VERSION`

Default env: `FILEGUARD_SOURCE_URL` and `FILEGUARD_SOURCE_VERSION_URL` point at those URLs. `install.sh --tarball` and `--dir` still work for local/testing installs.

**First install** (when `/workspace/fileguard` does not exist). Download, extract, estimate, then install — do not pipe the script to bash:

```bash
TMP=$(mktemp -d /tmp/fileguard-src.XXXXXX)
curl -fsSL https://github.com/fish-blossom/fileguard/archive/refs/heads/main.tar.gz -o "$TMP/src.tar.gz"
tar -xzf "$TMP/src.tar.gz" -C "$TMP"
SRC="$TMP/fileguard-main/backend"
FILEGUARD_DIR=/workspace/fileguard bash "$SRC/install.sh" --estimate
# After the one-line init message to the user:
FILEGUARD_DIR=/workspace/fileguard bash "$SRC/install.sh"
```

`install.sh` installs apt packages when sudo is available, creates a Python venv, tries `freshclam` (non-fatal), and puts `fg` on PATH. Scan data lives in `$FILEGUARD_DIR/data` (or `FILEGUARD_DATA`) and is kept across updates.

### What the bot says to the user

- **First install only:** one line `⚙️ 正在初始化 FileGuard，预计约 N 分钟` (from `--estimate`), then a silent left-pad verification scan, then `✅ 初始化完成，可以开始检测了`. On failure, one short line that scanning is not available. Never list components.

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
