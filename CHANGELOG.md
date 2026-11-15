# Changelog

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
