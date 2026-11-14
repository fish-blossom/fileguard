"""File-backed persistence: scans, hash cache, dep cache, baselines, confirmations, signers, timings.

Replaces SQLite. All writes are atomic (temp file + rename) and serialized with fcntl locks.
Layout under FILEGUARD_DATA (default $FILEGUARD_HOME/data):

  scans/<scan_id>/meta.json       status, progress, pid, source, verdict, …
  scans/<scan_id>/result.json     full report
  scans/<scan_id>/input.bin       submitted sample (deleted after the scan)
  scans/<scan_id>/worker.log
  reports/<scan_id>.json          copy of the report
  reports/<scan_id>.<lang>.html
  cache/<sha256>.json             hash cache, entries keyed by engine/rules/sigs version
  dep_cache/<eco>/<name>/<ver>.json
  baselines/<eco>/<name>/<ver>.json
  confirmations/<sha256>/<id>.json
  signers/<subject>/<check>.json
  timings/<scan_id>.json
  delivery_times.json
  work/                           ephemeral unpack dir (deleted after each scan)
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from . import config

_SAFE = re.compile(r"[^A-Za-z0-9._@+-]+")


def _safe(part: str) -> str:
    part = (part or "").strip().replace("\\", "/").replace("/", "--")
    out = _SAFE.sub("_", part).strip("._")
    return (out[:180] or "_")


def _scan_dir(scan_id: str) -> Path:
    return config.DATA_DIR / "scans" / _safe(scan_id)


def scan_dir(scan_id: str) -> Path:
    p = _scan_dir(scan_id)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _lock_path(path: Path) -> Path:
    return path.with_name(path.name + ".lock")


@contextmanager
def _locked(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lp = _lock_path(path)
    fd = os.open(str(lp), os.O_CREAT | os.O_RDWR, 0o644)
    import fcntl
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_write(path: Path, text: str, mode: int = 0o644):
    """Write text atomically (tmp + fsync + rename). Caller should hold a lock if doing RMW."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp." + uuid.uuid4().hex[:8])
    data = text if isinstance(text, str) else text.decode("utf-8")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))


def write_json(path: Path, obj):
    atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2))


def read_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def _update_json(path: Path, mutator):
    with _locked(path):
        data = read_json(path, None)
        data = mutator(data)
        if data is not None:
            write_json(path, data)
        return data


# --------------------------------------------------------------------------- init / migrate

def init():
    for sub in (
        "scans", "reports", "cache", "dep_cache", "baselines",
        "confirmations", "signers", "timings", "work",
    ):
        (config.DATA_DIR / sub).mkdir(parents=True, exist_ok=True)
    _maybe_migrate_sqlite()


def _maybe_migrate_sqlite():
    src = config.DATA_DIR / "db" / "fileguard.sqlite3"
    if not src.is_file():
        return
    marker = config.DATA_DIR / "db" / "migrated_to_files"
    if marker.is_file():
        return
    try:
        con = sqlite3.connect(str(src), timeout=30)
        con.row_factory = sqlite3.Row
        # scans
        try:
            rows = con.execute("SELECT * FROM scans").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            sid = d.get("scan_id")
            if not sid:
                continue
            meta = {k: d.get(k) for k in (
                "scan_id", "status", "created_at", "updated_at", "input_kind",
                "input_ref", "lang", "sha256", "verdict", "progress",
            )}
            sd = scan_dir(sid)
            write_json(sd / "meta.json", meta)
            if d.get("report_json"):
                try:
                    rep = json.loads(d["report_json"])
                    write_json(sd / "result.json", rep)
                    write_json(config.DATA_DIR / "reports" / f"{sid}.json", rep)
                except Exception:
                    atomic_write(sd / "result.json", d["report_json"])
        # hash cache
        try:
            rows = con.execute("SELECT * FROM hash_cache").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            cache_put_hash(d["sha256"], d["engine_version"], d["rules_version"], d["sigs_version"],
                           d["verdict"], d["scan_id"], created_at=d.get("created_at"))
        # dep cache
        try:
            rows = con.execute("SELECT * FROM dep_cache").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            try:
                result = json.loads(d["result_json"]) if d.get("result_json") else {}
            except Exception:
                result = {}
            dep_cache_put(d["ecosystem"], d["name"], d["version"], d.get("artifact_sha"),
                          d["engine_version"], d["rules_version"], result, created_at=d.get("created_at"))
        # baselines
        try:
            rows = con.execute("SELECT * FROM baselines").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            try:
                profile = json.loads(d["profile_json"]) if d.get("profile_json") else {}
            except Exception:
                continue
            baseline_put(d["ecosystem"], d["name"], d["version"], d.get("sha256"), profile,
                         d.get("scan_id"), created_at=d.get("created_at"), source="migrated")
        # confirmations
        try:
            rows = con.execute("SELECT * FROM confirmations").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            try:
                missing = json.loads(d["missing_checks_json"]) if d.get("missing_checks_json") else []
            except Exception:
                missing = []
            add_confirmation(d.get("scan_id"), d.get("sha256"), missing,
                             d.get("confirmed_by"), d.get("statement") or "",
                             created_at=d.get("created_at"), cid=d.get("id"))
        # signers
        try:
            rows = con.execute("SELECT * FROM signers").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            signer_put(d["subject"], d.get("version"), d["check_name"], d["signer"], d.get("scan_id"),
                       created_at=d.get("created_at"))
        # timings
        try:
            rows = con.execute("SELECT * FROM timings").fetchall()
        except Exception:
            rows = []
        for r in rows:
            d = dict(r)
            try:
                feats = json.loads(d["features_json"]) if d.get("features_json") else {}
            except Exception:
                feats = {}
            timing_put(d["scan_id"], feats, d.get("estimated"), d.get("actual"), created_at=d.get("created_at"))
        con.close()
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(time.time()), encoding="utf-8")
        bak = src.with_suffix(".sqlite3.bak")
        try:
            src.replace(bak)
        except Exception:
            pass
    except Exception as e:
        # Leave the sqlite file in place if migration fails; file store still works for new data.
        (config.DATA_DIR / "db" / "migrate_error.txt").write_text(f"{type(e).__name__}: {e}", encoding="utf-8")


# --------------------------------------------------------------------------- scans

def create_scan(scan_id, kind, ref, lang, source=None, pid=None):
    now = time.time()
    meta = {
        "scan_id": scan_id,
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "input_kind": kind,
        "input_ref": ref,
        "lang": lang,
        "sha256": None,
        "verdict": None,
        "progress": "queued",
        "pid": pid,
        "source": source,
    }
    sd = scan_dir(scan_id)
    with _locked(sd / "meta.json"):
        write_json(sd / "meta.json", meta)
    return meta


def update_scan(scan_id, **kw):
    kw["updated_at"] = time.time()
    report = kw.pop("report", None)
    sd = _scan_dir(scan_id)
    path = sd / "meta.json"

    def mut(meta):
        if not isinstance(meta, dict):
            meta = {"scan_id": scan_id}
        meta.update(kw)
        return meta

    _update_json(path, mut)
    if report is not None:
        write_json(sd / "result.json", report)
        write_json(config.DATA_DIR / "reports" / f"{scan_id}.json", report)


def get_scan(scan_id):
    sd = _scan_dir(scan_id)
    meta = read_json(sd / "meta.json", None)
    if not meta:
        # fallback: a leftover reports/<id>.json from before the file store
        legacy = read_json(config.DATA_DIR / "reports" / f"{scan_id}.json", None)
        if not legacy:
            return None
        meta = {
            "scan_id": scan_id,
            "status": legacy.get("status", "done"),
            "created_at": None,
            "updated_at": None,
            "input_kind": None,
            "input_ref": legacy.get("file_name"),
            "lang": legacy.get("lang") or "zh",
            "sha256": legacy.get("sha256"),
            "verdict": legacy.get("verdict"),
            "progress": "finished",
            "report_json": json.dumps(legacy, ensure_ascii=False),
        }
        return meta
    result_path = sd / "result.json"
    if not result_path.is_file():
        alt = config.DATA_DIR / "reports" / f"{scan_id}.json"
        if alt.is_file():
            result_path = alt
    if result_path.is_file():
        try:
            meta["report_json"] = result_path.read_text(encoding="utf-8")
        except Exception:
            meta["report_json"] = None
    else:
        meta["report_json"] = None
    return meta


def _pid_alive(pid):
    try:
        pid = int(pid)
        if pid <= 0:
            return False
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def reap_dead_scans(grace_seconds=30):
    """Mark queued/running scans whose worker is gone as ERROR (never as safe)."""
    root = config.DATA_DIR / "scans"
    if not root.is_dir():
        return 0
    now = time.time()
    n = 0
    for d in root.iterdir():
        if not d.is_dir():
            continue
        meta = read_json(d / "meta.json", None)
        if not meta or meta.get("status") not in ("queued", "running"):
            continue
        pid = meta.get("pid")
        age = now - float(meta.get("updated_at") or meta.get("created_at") or now)
        dead = False
        if pid and not _pid_alive(pid):
            dead = True
        elif not pid and age > grace_seconds:
            dead = True
        if dead:
            update_scan(meta.get("scan_id") or d.name, status="error", verdict="ERROR",
                        progress="interrupted (worker process gone)")
            n += 1
    return n


# --------------------------------------------------------------------------- hash cache

def _cache_path(sha: str) -> Path:
    return config.DATA_DIR / "cache" / f"{_safe(sha).lower()}.json"


def cache_get_hash(sha, ev, rv, sv):
    data = read_json(_cache_path(sha), None)
    if not data:
        return None
    for e in data.get("entries") or []:
        if e.get("engine_version") == ev and e.get("rules_version") == rv and e.get("sigs_version") == sv:
            return e
    return None


def cache_put_hash(sha, ev, rv, sv, verdict, scan_id, created_at=None):
    path = _cache_path(sha)
    rec = {
        "sha256": sha,
        "engine_version": ev,
        "rules_version": rv,
        "sigs_version": sv,
        "verdict": verdict,
        "scan_id": scan_id,
        "created_at": created_at or time.time(),
    }

    def mut(data):
        data = data if isinstance(data, dict) else {"sha256": sha, "entries": []}
        entries = [e for e in (data.get("entries") or [])
                   if not (e.get("engine_version") == ev and e.get("rules_version") == rv and e.get("sigs_version") == sv)]
        entries.append(rec)
        data["entries"] = entries[-8:]
        data["sha256"] = sha
        return data

    _update_json(path, mut)
    return rec


# --------------------------------------------------------------------------- dep cache

def _dep_path(eco, name, version) -> Path:
    return config.DATA_DIR / "dep_cache" / _safe(eco) / _safe(name) / f"{_safe(version)}.json"


def dep_cache_get(eco, name, version, ev, rv):
    data = read_json(_dep_path(eco, name, version), None)
    if not data:
        return None
    for e in data.get("entries") or []:
        if e.get("engine_version") == ev and e.get("rules_version") == rv:
            return e.get("result")
    return None


def dep_cache_put(eco, name, version, artifact_sha, ev, rv, result, created_at=None):
    path = _dep_path(eco, name, version)
    rec = {
        "ecosystem": eco,
        "name": name,
        "version": version,
        "artifact_sha": artifact_sha,
        "engine_version": ev,
        "rules_version": rv,
        "result": result,
        "created_at": created_at or time.time(),
    }

    def mut(data):
        data = data if isinstance(data, dict) else {"ecosystem": eco, "name": name, "version": version, "entries": []}
        entries = [e for e in (data.get("entries") or [])
                   if not (e.get("engine_version") == ev and e.get("rules_version") == rv)]
        entries.append(rec)
        data["entries"] = entries[-8:]
        return data

    _update_json(path, mut)


def dep_cache_count(eco, names):
    """How many of `names` have any cached entry for this ecosystem (any engine/rules version)."""
    if not names:
        return 0
    n = 0
    root = config.DATA_DIR / "dep_cache" / _safe(eco)
    if not root.is_dir():
        return 0
    want = set(names)
    for name in want:
        p = root / _safe(name)
        if p.is_dir() and any(p.glob("*.json")):
            n += 1
    return n


# --------------------------------------------------------------------------- baselines

def _baseline_dir(eco, name) -> Path:
    return config.DATA_DIR / "baselines" / _safe(eco) / _safe(name)


def _baseline_path(eco, name, version) -> Path:
    return _baseline_dir(eco, name) / f"{_safe(version)}.json"


def baseline_get(eco, name, version):
    data = read_json(_baseline_path(eco, name, version), None)
    return _baseline_row(data) if data else None


def _baseline_row(data):
    if not data:
        return None
    profile = data.get("profile")
    return {
        "ecosystem": data.get("ecosystem"),
        "name": data.get("name"),
        "version": data.get("version"),
        "sha256": data.get("sha256"),
        "profile_json": json.dumps(profile, ensure_ascii=False) if not isinstance(profile, str) else profile,
        "scan_id": data.get("scan_id"),
        "created_at": data.get("created_at"),
        "source": data.get("source") or "scan",
    }


def baseline_latest(eco, name, exclude_version=None):
    d = _baseline_dir(eco, name)
    if not d.is_dir():
        return None
    best = None
    best_ts = -1
    for p in d.glob("*.json"):
        data = read_json(p, None)
        if not data:
            continue
        if exclude_version and data.get("version") == exclude_version:
            continue
        ts = float(data.get("created_at") or 0)
        if ts >= best_ts:
            best, best_ts = data, ts
    return _baseline_row(best) if best else None


def baseline_put(eco, name, version, sha, profile, scan_id, created_at=None, source="scan"):
    path = _baseline_path(eco, name, version)
    rec = {
        "ecosystem": eco,
        "name": name,
        "version": version,
        "sha256": sha,
        "profile": profile,
        "scan_id": scan_id,
        "created_at": created_at or time.time(),
        "source": source,
    }
    with _locked(path):
        write_json(path, rec)
    return rec


# --------------------------------------------------------------------------- confirmations

def add_confirmation(scan_id, sha, missing, who, statement, created_at=None, cid=None):
    cid = str(cid) if cid is not None else time.strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]
    rec = {
        "id": cid,
        "scan_id": scan_id,
        "sha256": sha,
        "missing_checks_json": json.dumps(list(missing or []), ensure_ascii=False),
        "missing_checks": list(missing or []),
        "confirmed_by": who,
        "statement": statement or "",
        "created_at": created_at or time.time(),
    }
    path = config.DATA_DIR / "confirmations" / _safe(sha) / f"{_safe(cid)}.json"
    with _locked(path):
        write_json(path, rec)
    # index under the scan dir for cheap lookup
    idx = _scan_dir(scan_id) / "confirmations.json"
    def mut(data):
        data = data if isinstance(data, list) else []
        data.append(cid)
        return data
    if scan_id:
        _update_json(idx, mut)
    return cid


def confirmations_for(scan_id):
    out = []
    # Prefer the per-scan index; fall back to a walk (legacy / migrated).
    idx = read_json(_scan_dir(scan_id) / "confirmations.json", None) or []
    seen = set()
    root = config.DATA_DIR / "confirmations"
    candidates = []
    if root.is_dir():
        for p in root.glob("*/*.json"):
            candidates.append(p)
    for p in candidates:
        rec = read_json(p, None)
        if not rec:
            continue
        if rec.get("scan_id") != scan_id and rec.get("id") not in idx:
            continue
        if rec.get("id") in seen:
            continue
        seen.add(rec.get("id"))
        if "missing_checks_json" not in rec and rec.get("missing_checks") is not None:
            rec["missing_checks_json"] = json.dumps(rec["missing_checks"], ensure_ascii=False)
        out.append(rec)
    out.sort(key=lambda r: (r.get("created_at") or 0, str(r.get("id"))))
    return out


# --------------------------------------------------------------------------- signers

def _signer_path(subject, check_name) -> Path:
    return config.DATA_DIR / "signers" / _safe(subject) / f"{_safe(check_name)}.json"


def signer_previous(subject, check_name, exclude_version):
    data = read_json(_signer_path(subject, check_name), None)
    if not data:
        return None
    best = None
    best_ts = -1
    for e in data.get("entries") or []:
        if exclude_version and e.get("version") == exclude_version:
            continue
        ts = float(e.get("created_at") or 0)
        if ts >= best_ts:
            best, best_ts = e, ts
    if not best:
        return None
    return {
        "subject": subject,
        "version": best.get("version"),
        "check_name": check_name,
        "signer": best.get("signer"),
        "scan_id": best.get("scan_id"),
        "created_at": best.get("created_at"),
    }


def signer_put(subject, version, check_name, signer, scan_id, created_at=None):
    path = _signer_path(subject, check_name)
    rec = {
        "subject": subject,
        "version": version or "",
        "check_name": check_name,
        "signer": signer,
        "scan_id": scan_id,
        "created_at": created_at or time.time(),
    }

    def mut(data):
        data = data if isinstance(data, dict) else {"subject": subject, "check_name": check_name, "entries": []}
        entries = [e for e in (data.get("entries") or []) if e.get("version") != rec["version"]]
        entries.append(rec)
        data["entries"] = entries[-20:]
        return data

    _update_json(path, mut)


# --------------------------------------------------------------------------- timings

def timing_put(scan_id, features, estimated, actual, created_at=None):
    rec = {
        "scan_id": scan_id,
        "features": features,
        "estimated": estimated,
        "actual": actual,
        "created_at": created_at or time.time(),
    }
    path = config.DATA_DIR / "timings" / f"{_safe(scan_id)}.json"
    with _locked(path):
        write_json(path, rec)
