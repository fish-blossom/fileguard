# FileGuard examples (inert, fabricated)

These two files are **inert test fixtures** generated for FileGuard's own tests. They contain no working
malware: every suspicious code path is dead code (an early `exit` / `return`), and every host is a reserved
name or documentation address (`.invalid`, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Some antivirus
products may still flag them by pattern.

| `fg demo` | File | Type | Expected verdict |
|---|---|---|---|
| 1 | `uuidd-2.11.16.tgz` | npm package (typosquat, install hook `curl … \| sh`, manifest swap) | BLOCK |
| 2 | `invoice_431.pdf` | PDF (`/Launch`, `/OpenAction` JavaScript, encoded `eval`, link to a bare IP) | HIGH_RISK |

`fg demo <1|2> --lang zh|en` scans a temporary copy and marks the result as an example (`demo: true`).
It only runs when a user asks to see an example; it never replaces a real scan.
