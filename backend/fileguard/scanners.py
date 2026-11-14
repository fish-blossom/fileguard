"""ClamAV + YARA wrappers (S3). Static signature scanning only."""
import hashlib
import os
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

import yara

from . import config


# ---------------- versions (bound into cache keys) -----------------------
@lru_cache(maxsize=1)
def rules_version():
    h = hashlib.sha256()
    for p in sorted(config.RULES_DIR.glob("*.yar")) + sorted(config.INTEL_DIR.glob("*")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return "r-" + h.hexdigest()[:12]


def clamav_version():
    try:
        out = subprocess.run(["clamdscan", f"--config-file={config.CLAMD_CONF}", "--version"],
                             capture_output=True, text=True, timeout=20).stdout.strip()
        if out and "ClamAV" in out:
            return out
    except Exception:
        pass
    try:
        return subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception:
        return "unavailable"


def sigs_version():
    v = clamav_version()
    m = re.search(r"/(\d+)/", v)
    return f"daily-{m.group(1)}" if m else v


# ---------------- ClamAV --------------------------------------------------
def clamd_available():
    try:
        r = subprocess.run(["clamdscan", f"--config-file={config.CLAMD_CONF}", "--ping", "1"],
                           capture_output=True, text=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


_clamd_tried = False


def ensure_clamd():
    """If clamd is not running, try start_clamd.sh once. Returns True if clamd responds."""
    global _clamd_tried
    if clamd_available():
        return True
    if _clamd_tried:
        return clamd_available()
    _clamd_tried = True
    script = Path(config.BASE_DIR) / "scripts" / "start_clamd.sh"
    if not script.is_file():
        return False
    try:
        subprocess.run(["bash", str(script)], cwd=str(config.BASE_DIR),
                       timeout=130, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return False
    return clamd_available()


def clamav_scan(paths, timeout=600):
    """Scan a list of files. Returns (ok, detections{path: signature}, engine, error)."""
    paths = [str(p) for p in paths]
    if not paths:
        return True, {}, "none", None
    use_clamd = clamd_available() or ensure_clamd()
    if use_clamd:
        cmd = ["clamdscan", f"--config-file={config.CLAMD_CONF}", "--no-summary", "--multiscan", "--fdpass", "--file-list=-"]
        engine = "clamd"
    elif shutil.which("clamscan"):
        cmd = ["clamscan", "--no-summary", "--max-filesize=520M", "--max-scansize=1100M", "--file-list=-"]
        engine = "clamscan"
    else:
        return False, {}, "none", "ClamAV not installed"
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".lst", delete=False) as lf:
        lf.write("\n".join(paths) + "\n")
        listfile = lf.name
    cmd = [c if c != "--file-list=-" else f"--file-list={listfile}" for c in cmd]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
    except subprocess.TimeoutExpired:
        return False, {}, engine, "ClamAV timeout"
    finally:
        os.unlink(listfile)
    if "ERROR" in r.stderr:
        errors_pre = [l for l in r.stderr.splitlines() if "ERROR" in l]
    else:
        errors_pre = []
    det, errors = {}, list(errors_pre)
    for line in r.stdout.splitlines():
        if line.endswith(" FOUND"):
            p, sig = line[:-6].rsplit(": ", 1)
            det[p] = sig
        elif line.endswith(" ERROR") or "Can't" in line or "lstat()" in line:
            errors.append(line)
    # sanity: every file must be accounted for ("OK" or "FOUND"); otherwise the scan is incomplete
    seen = {l.rsplit(": ", 1)[0] for l in r.stdout.splitlines() if l.endswith((" OK", " FOUND", " Empty file"))}
    unaccounted = [p for p in paths if p not in seen and os.path.getsize(p) > 0]
    if unaccounted and not errors:
        errors.append(f"{len(unaccounted)} file(s) not reported by ClamAV")
    # clamdscan exit: 0 clean, 1 found, 2 error
    if r.returncode == 2 or errors:
        return False, det, engine, "; ".join(errors or [r.stderr.strip()])[:500]
    return True, det, engine, None


# ---------------- YARA ----------------------------------------------------
@lru_cache(maxsize=1)
def _compiled():
    files = {p.stem: str(p) for p in sorted(config.RULES_DIR.glob("*.yar"))}
    return yara.compile(filepaths=files, externals={"fg_ext": "", "fg_name": ""})


def yara_scan(path, display_name):
    """Returns list of dicts {rule, severity, zh, en, strings}."""
    name = Path(display_name.split("!/")[-1]).name.lower()
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    if os.path.getsize(path) > config.YARA_MAX_FILE_BYTES:
        raise ValueError("file too large for YARA")
    matches = _compiled().match(path, externals={"fg_ext": ext, "fg_name": name}, timeout=120)
    out = []
    for m in matches:
        snippets = []
        for s in m.strings[:3]:
            for inst in s.instances[:1]:
                snippets.append(inst.matched_data[:80].decode("latin-1", "replace"))
        out.append({"rule": m.rule, "severity": m.meta.get("severity", "medium"),
                    "zh": m.meta.get("desc_zh", m.rule), "en": m.meta.get("desc_en", m.rule),
                    "strings": snippets})
    return out


def yara_version():
    return f"yara-python {yara.__version__} / rules {rules_version()}"
