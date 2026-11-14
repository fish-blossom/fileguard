# Source me in the same shell before running `fg`.
# If FILEGUARD_HOME is already set (installer / tests), keep it.
_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export FILEGUARD_HOME="${FILEGUARD_HOME:-$_HERE}"
export FILEGUARD_DATA="${FILEGUARD_DATA:-$FILEGUARD_HOME/data}"
export PATH="$FILEGUARD_HOME/bin:$FILEGUARD_HOME/.venv/bin:$FILEGUARD_HOME/scripts:$PATH:/usr/sbin"
export PYTHONPATH="$FILEGUARD_HOME${PYTHONPATH:+:$PYTHONPATH}"
# `fg` is a bash job-control builtin; a function is required so `fg submit_url` hits FileGuard.
# Always `source` this file in the same shell before calling `fg`, or invoke the script by path.
fg() { "$FILEGUARD_HOME/scripts/fg" "$@"; }
export -f fg 2>/dev/null || true
# Optional: FILEGUARD_SSRF_ALLOW_CIDRS, FILEGUARD_ABUSECH_KEY, TZ — only set these when needed.
# Do not default a CIDR allow-list here; that is only for special proxy environments.
