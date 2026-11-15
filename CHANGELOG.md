# Changelog

## 0.5.6 (2026-11-15)

Follow-ups from test batch 20261115-0558 and the real-package false-positive check.

- **One finding per underlying issue.**
  - Overlapping matches of a single-pattern YARA rule (for example `>> ~/.bashrc` and `> ~/.bashrc` at the same spot) are reported once.
  - Findings with the same code and path whose evidence is a substring of another are merged, keeping the higher severity.
- **Encoded payload passed to `eval` is high.** `eval` / `Function` / `exec` called on a Base64 / `fromCharCode` / hex / `unescape` literal is reported as `OBFUSCATED_EVAL_PAYLOAD` (high); plain `eval` use stays as before.
- **Debian `sudo` is no longer HIGH_RISK.**
  - sudoers files in a `.deb` payload get a dedicated check: `NOPASSWD` or broad `ALL` grants to non-standard principals are high; the stock config shipped by the `sudo` package itself is info; other sudoers files are medium.
  - setuid files inside a `.deb` payload are low (still listed).
  - `LD_PRELOAD` handling is split: `/etc/ld.so.preload` stays medium, a bare `LD_PRELOAD` string in an ELF is low.
  - Context downgrades (docs/tests/examples paths) now also see the inner path of `.gz`/`.zst` streams.
- **Example tests.** `fg examples --lang zh|en` lists four example tests; `fg demo 1|2` scans a bundled inert fabricated sample from `backend/examples/` (temporary copy); `submit_pkg` / `submit_url` accept `--example`. Example scans are marked `demo: true` with a label in the summary and HTML report and are never cached. A fresh install's JSON carries `after_ready`, and the getting-started skill shows the examples (as a widget) right after the ready line; engines without `fg examples` skip this silently.
- **Tests are in the repository.** `tests/regression/`, `tests/run_batch.py` and the generated sample batch with its generator are committed; a `tests` workflow runs them. `tests/` is not in the release tarball.

## 0.5.5 (2026-11-15)

Fixes from test batch 20261115-0558 (38 generated samples).

- **.deb maintainer scripts are now inspected.** `.deb` (ar) archives are parsed in Python instead of 7-Zip, which treated a `.deb` as one package, exposed only `data.tar` and never showed `control.tar.*`. `preinst` / `postinst` / `prerm` / `postrm` / `config` now get install-hook analysis and YARA escalation. zstd members (`control.tar.zst`, `data.tar.zst`) are unpacked too.
  - Absolute symlinks inside a `.deb` `data.tar` (for example tzdata's `localtime -> /etc/localtime`) are no longer reported as `ARCHIVE_LINK_ESCAPE`; `../` escapes still are.
  - Debian control metadata (`conffiles`, `md5sums`, `shlibs`, ...) is no longer run through the script checks.
- **MSI CustomActions are no longer dropped.** `msi_checks` skipped the first 3 real CustomAction rows (`ca[3:]`), so MSIs with 3 or fewer actions reported none. Rows are now parsed with `msiinfo export`'s 3 header lines excluded explicitly.
- **Sample-retention wording matches behaviour.** The engine scans its own copy of the sample and deletes that copy and all unpacked files after the scan. The original file passed to `submit_file` is never modified or deleted. `fg help`, the report and the docs said "the sample is deleted", which read as if the submitted file were removed.
- **Separate evidence for under-reported indicators:**
  - `LOLBIN_DOWNLOAD` reports each tool once, so `certutil -urlcache` no longer hides behind `bitsadmin /transfer`.
  - Copying a file into the Windows Startup folder is reported as `PERSISTENCE_OR_MASQUERADE` (low).
  - PDF `/URI` link targets become network indicators, and a link to a bare IP is reported as `PDF_URI_BARE_IP` (low).
  - Single-pattern YARA rules report each distinct match (up to 3), so `eval($_POST…)` is its own evidence next to `assert($_COOKIE…)`.

## 0.5.4
Stable bootstrap; usage guide provided by the engine (`fg help`).

## 0.5.3
Install lock fd no longer leaks into clamd; leaked locks self-heal.

## 0.5.2
GitHub Actions build provenance for signed releases.

## 0.5.1
Restart outdated clamd; parser check uses the daemon version; calibrated init estimate.

## 0.5.0
Signed releases, pinned parsers, hash-locked dependencies, SSRF/rebinding fixes.
