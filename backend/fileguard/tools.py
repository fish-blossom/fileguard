"""External tool resolution (vendored, pinned builds first) and resource-limited execution.

Untrusted samples are only ever *parsed* by these tools (list / extract / verify); nothing from a
sample is executed. Every external parser runs with address-space, CPU-time and output-size limits.
"""
import os
import re
import resource
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from . import config

VENDOR = Path(config.BASE_DIR) / "vendor"
CLAMAV_ROOT = VENDOR / "clamav"

# Minimum parser versions without known published vulnerabilities at release time.
MIN_7ZIP = (26, 6)
MIN_CLAMAV_14 = (1, 4, 6)
MIN_CLAMAV_15 = (1, 5, 4)

MEM_LIMIT = int(os.environ.get("FILEGUARD_TOOL_MEM_MB", "4096")) * 1024 * 1024
CPU_LIMIT = int(os.environ.get("FILEGUARD_TOOL_CPU_S", "900"))


def sevenzip():
    for p in (VENDOR / "7zip" / "7zzs", VENDOR / "7zip" / "7zz"):
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which("7zz") or shutil.which("7z")


def clam(name):
    """Path of a ClamAV binary (vendored official build first)."""
    for sub in ("bin", "sbin"):
        p = CLAMAV_ROOT / sub / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return shutil.which(name) or (f"/usr/sbin/{name}" if os.path.exists(f"/usr/sbin/{name}") else None)


def clam_env():
    env = dict(os.environ)
    lib = CLAMAV_ROOT / "lib"
    if lib.is_dir():
        env["LD_LIBRARY_PATH"] = str(lib) + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    return env


def _limits(mem=None, cpu=None, fsize=None):
    def apply():
        m = mem or MEM_LIMIT
        resource.setrlimit(resource.RLIMIT_AS, (m, m))
        c = cpu or CPU_LIMIT
        resource.setrlimit(resource.RLIMIT_CPU, (c, c + 5))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if fsize:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    return apply


def run_limited(cmd, *, mem=None, cpu=None, fsize=None, **kw):
    """subprocess.run with RLIMIT_AS / RLIMIT_CPU / RLIMIT_CORE (and optional RLIMIT_FSIZE)."""
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(cmd, preexec_fn=_limits(mem, cpu, fsize), **kw)


def _vtuple(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


@lru_cache(maxsize=1)
def sevenzip_version():
    exe = sevenzip()
    if not exe:
        return None, None
    try:
        out = subprocess.run([exe, "i"], capture_output=True, text=True, timeout=20, errors="replace").stdout
    except Exception:
        return exe, None
    m = re.search(r"7-Zip(?: \(\w+\))? (\d+\.\d+)", out)
    return exe, (m.group(1) if m else None)


@lru_cache(maxsize=1)
def clamav_engine_version():
    exe = clam("clamscan")
    if not exe:
        return None
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=60, env=clam_env()).stdout
    except Exception:
        return None
    m = re.search(r"ClamAV (\d+\.\d+\.\d+)", out or "")
    return m.group(1) if m else None


def parser_status():
    """[{tool, version, ok, min}] for the external parsers that handle untrusted input."""
    out = []
    exe, v7 = sevenzip_version()
    ok7 = bool(v7) and tuple(int(x) for x in v7.split(".")) >= MIN_7ZIP
    out.append({"tool": "7-Zip", "path": exe, "version": v7, "ok": ok7, "min": "26.06"})
    vc = clamav_engine_version()
    okc = False
    if vc:
        t = _vtuple(vc)
        okc = t >= MIN_CLAMAV_15 if t[:2] >= (1, 5) else t >= MIN_CLAMAV_14
    out.append({"tool": "ClamAV", "path": clam("clamscan"), "version": vc, "ok": okc, "min": "1.4.6 / 1.5.4"})
    return out
