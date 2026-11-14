"""Central configuration. Every limit can be overridden by an environment variable."""
import os
from pathlib import Path

BASE_DIR = Path(os.environ.get("FILEGUARD_HOME", Path(__file__).resolve().parent.parent))


def _int(name, default):
    return int(os.environ.get(name, default))


MAX_FILE_BYTES = _int("FILEGUARD_MAX_FILE_BYTES", 500 * 1024 * 1024)        # 500 MB
MAX_UNPACK_TOTAL_BYTES = _int("FILEGUARD_MAX_UNPACK_BYTES", 1024 * 1024 * 1024)  # 1 GB
MAX_UNPACK_DEPTH = _int("FILEGUARD_MAX_UNPACK_DEPTH", 5)
MAX_UNPACK_FILES = _int("FILEGUARD_MAX_UNPACK_FILES", 50000)
BOMB_RATIO = _int("FILEGUARD_BOMB_RATIO", 100)        # per-entry compression ratio considered bomb-like
MAX_DEP_DEPTH = _int("FILEGUARD_MAX_DEP_DEPTH", 5)
MAX_NEW_DEPS = _int("FILEGUARD_MAX_NEW_DEPS", 200)
MAX_REDIRECTS = _int("FILEGUARD_MAX_REDIRECTS", 5)
# No overall scan timeout (user decision). Only per-step hang protection: a single network request that
# makes no progress for NET_STALL_TIMEOUT seconds, or a single tool process exceeding its own limit,
# fails that check (-> missing check) instead of hanging the scan.
NET_STALL_TIMEOUT = _int("FILEGUARD_NET_STALL_TIMEOUT", 30)
TOOL_STALL_TIMEOUT = _int("FILEGUARD_TOOL_STALL_TIMEOUT", 600)
MAX_LIGHT_DEPS = _int("FILEGUARD_MAX_LIGHT_DEPS", 3000)      # light checks beyond depth 5 (separate cap)
MAX_LOCK_ENTRIES = _int("FILEGUARD_MAX_LOCK_ENTRIES", 3000)
CODELOAD_BASE = os.environ.get("FILEGUARD_CODELOAD", "https://codeload.github.com").rstrip("/")
KEYSERVER = os.environ.get("FILEGUARD_KEYSERVER", "https://keys.openpgp.org").rstrip("/")
MAX_REPO_TARBALL = _int("FILEGUARD_MAX_REPO_TARBALL", 300 * 1024 * 1024)
DOWNLOAD_TIMEOUT_S = _int("FILEGUARD_DOWNLOAD_STALL_TIMEOUT", 60)   # main sample download: per-read stall, no total limit
WORKERS = _int("FILEGUARD_WORKERS", 2)
YARA_MAX_FILE_BYTES = _int("FILEGUARD_YARA_MAX_FILE", 500 * 1024 * 1024)
TEXT_ANALYSIS_MAX_BYTES = _int("FILEGUARD_TEXT_MAX", 8 * 1024 * 1024)

DATA_DIR = Path(os.environ.get("FILEGUARD_DATA", BASE_DIR / "data"))
WORK_DIR = DATA_DIR / "work"
RULES_DIR = BASE_DIR / "rules"
INTEL_DIR = BASE_DIR / "intel"

CLAMD_CONF = os.environ.get("FILEGUARD_CLAMD_CONF", str(BASE_DIR / "clamav" / "clamd.conf"))

NPM_REGISTRY = os.environ.get("FILEGUARD_NPM_REGISTRY", "https://registry.npmjs.org").rstrip("/")
PYPI_URL = os.environ.get("FILEGUARD_PYPI", "https://pypi.org").rstrip("/")
OSV_API = os.environ.get("FILEGUARD_OSV_API", "https://api.osv.dev")
OSV_ENABLED = os.environ.get("FILEGUARD_OSV", "1") == "1"
# Optional threat-intel API keys (abuse.ch now requires an Auth-Key)
ABUSECH_AUTH_KEY = os.environ.get("FILEGUARD_ABUSECH_KEY", "")

# Extra CIDRs treated as "public" for SSRF checks. Needed on sandboxed hosts whose DNS
# returns proxy addresses (e.g. 198.18.0.0/15). Leave empty on a real server.
SSRF_EXTRA_ALLOWED_CIDRS = [c for c in os.environ.get("FILEGUARD_SSRF_ALLOW_CIDRS", "").split(",") if c.strip()]

for d in (WORK_DIR, DATA_DIR / "reports", DATA_DIR / "scans", DATA_DIR / "cache",
          DATA_DIR / "baselines", DATA_DIR / "confirmations", DATA_DIR / "dep_cache",
          DATA_DIR / "signers", DATA_DIR / "timings"):
    d.mkdir(parents=True, exist_ok=True)
