"""Job service used by the CLI: submit returns scan_id, a detached worker runs the scan, wait/get_report poll files."""
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path

from . import config, scanners, store
from .report import render_markdown, write_html_report, build_summary

_initialized = False


def _init():
    global _initialized
    if _initialized:
        store.reap_dead_scans()
        return
    store.init()
    store.reap_dead_scans()
    try:
        scanners.ensure_clamd()
    except Exception:
        pass
    _initialized = True


def _norm_lang(lang):
    lang = (lang or "zh").lower()
    return "en" if lang.startswith("en") else "zh"


def _prepare_source(scan_id, source):
    """Copy file/base64 inputs into the scan dir so the detached worker can read them later."""
    src = dict(source)
    if src.get("kind") == "url":
        return src
    dest = store.scan_dir(scan_id) / "input.bin"
    filename = src.get("filename")
    if src.get("kind") == "path":
        p = Path(src["path"])
        if not p.is_file():
            return src
        filename = filename or p.name
        if p.resolve() != dest.resolve():
            shutil.copy2(p, dest)
    elif src.get("kind") == "base64":
        dest.write_bytes(base64.b64decode(src["data"]))
        filename = filename or "upload.bin"
    else:
        return src
    return {"kind": "path", "path": str(dest), "filename": filename}


def _spawn_worker(scan_id):
    log = store.scan_dir(scan_id) / "worker.log"
    env = os.environ.copy()
    env["FILEGUARD_HOME"] = str(config.BASE_DIR)
    env["FILEGUARD_DATA"] = str(config.DATA_DIR)
    pp = str(config.BASE_DIR)
    env["PYTHONPATH"] = pp + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    cmd = [sys.executable, "-m", "fileguard.cli", "_run", scan_id]
    with open(log, "ab") as lf:
        lf.write(f"\n--- worker start {datetime.now().isoformat(timespec='seconds')} ---\n".encode())
        lf.flush()
        proc = subprocess.Popen(
            cmd,
            stdout=lf,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=env,
            cwd=str(config.BASE_DIR),
        )
    store.update_scan(scan_id, pid=proc.pid)
    return proc.pid


def _maybe_refresh_signatures():
    """Kick off a detached ClamAV signature refresh when the DB check is older than 24 h.
    Never blocks the scan; clamd reloads the new DB by itself."""
    if os.environ.get("FILEGUARD_NO_AUTO_DB_UPDATE") == "1":
        return
    script = Path(config.BASE_DIR) / "scripts" / "update_clamav_db.sh"
    stamp = Path(config.DATA_DIR) / "clamav_db_checked"
    try:
        if not script.is_file() or (stamp.exists() and time.time() - stamp.stat().st_mtime < 86400):
            return
        if not (Path(config.BASE_DIR) / "vendor" / "clamav").is_dir():
            return
        lock = Path(config.DATA_DIR) / ".db_refresh_started"
        if lock.exists() and time.time() - lock.stat().st_mtime < 3600:
            return
        lock.touch()
        env = os.environ.copy()
        env["FILEGUARD_DATA"] = str(config.DATA_DIR)
        subprocess.Popen(["bash", str(script), "--if-older-than", "24"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True, env=env)
    except Exception:
        pass


def submit(source, lang="zh", expected_sha256=None, force_rescan=False):
    """No overall timeout: the scan runs to completion in a detached process."""
    _init()
    _maybe_refresh_signatures()
    from . import estimate as est_mod
    try:
        feats = est_mod.features(source)
        est = est_mod.estimate(feats)
    except Exception:
        feats, est = None, None
    scan_id = "fg_" + datetime.now().strftime("%Y%m%d%H%M%S") + "_" + uuid.uuid4().hex[:8]
    ref = source.get("url") or source.get("filename") or os.path.basename(source.get("path", "")) or "upload"
    stored = _prepare_source(scan_id, source)
    extra = {"expected_sha256": expected_sha256, "force_rescan": bool(force_rescan)}
    stored = {**stored, **{k: v for k, v in extra.items() if v}}
    store.create_scan(scan_id, source["kind"], ref, _norm_lang(lang), source=stored)
    if feats is not None:
        store.update_scan(scan_id, estimate=est, features=feats)
    _spawn_worker(scan_id)
    out = {"scan_id": scan_id, "status": "queued"}
    if est is not None:
        out.update(estimated_seconds=est, estimate_text=est_mod.human(est, _norm_lang(lang)),
                   estimate_text_zh=est_mod.human(est, "zh"), estimate_text_en=est_mod.human(est, "en"))
    return out


def run_worker(scan_id):
    """In-process entry for the detached worker (`fg _run <scan_id>`)."""
    _init()
    from .pipeline import run_scan
    s = store.get_scan(scan_id)
    if not s:
        print(f"worker: scan not found: {scan_id}", file=sys.stderr)
        return 1
    source = s.get("source") or {}
    if isinstance(source, str):
        try:
            source = json.loads(source)
        except Exception:
            source = {}
    lang = _norm_lang(s.get("lang"))
    expected = source.get("expected_sha256")
    force = bool(source.get("force_rescan"))
    # features/estimate may have been stashed on submit
    est = s.get("estimate")
    feats = s.get("features")
    t0 = time.time()
    store.update_scan(scan_id, status="running", progress="S0", pid=os.getpid())
    try:
        rep = run_scan(scan_id, source, lang,
                       progress=lambda st: store.update_scan(scan_id, progress=st, status="running"),
                       expected_sha256=expected, force_rescan=force)
        actual = time.time() - t0
        if est is None:
            est = (rep.get("timing") or {}).get("estimated_seconds")
        rep.setdefault("timing", {})
        rep["timing"]["estimated_seconds"] = est
        rep["timing"]["actual_seconds"] = round(actual, 1)
        if feats is not None:
            store.timing_put(scan_id, feats, est, actual)
        store.update_scan(scan_id, status=rep["status"], verdict=rep["verdict"], sha256=rep.get("sha256"),
                          report=rep, progress="finished")
    except Exception as e:
        store.update_scan(scan_id, status="error", verdict="ERROR",
                          progress=f"engine crash: {type(e).__name__}: {e}"[:300])
        traceback.print_exc()
        return 1
    finally:
        # privacy: drop the submitted copy; pipeline already deleted work/
        inp = store.scan_dir(scan_id) / "input.bin"
        try:
            if inp.is_file():
                inp.unlink()
        except Exception:
            pass
    return 0


def wait(scan_id, seconds=None):
    """Block until done/error. If seconds is None, wait with no overall timeout."""
    if seconds is None or seconds < 0:
        end = None
    else:
        end = time.time() + max(0, seconds or 0)
    while end is None or time.time() < end:
        store.reap_dead_scans()
        s = store.get_scan(scan_id)
        if s and s["status"] in ("done", "error"):
            break
        time.sleep(0.5)


def _confirmations(scan_id, sha, rules_at_scan=None):
    out = []
    for c in store.confirmations_for(scan_id):
        c = dict(c)
        c["valid"] = c.get("sha256") == sha
        # bound to the rule version the user saw; legacy records (no rules_version) follow the report's
        c["rules_ok"] = (c.get("rules_version") or rules_at_scan) == scanners.rules_version()
        try:
            c["created_at_str"] = datetime.fromtimestamp(c["created_at"]).astimezone().isoformat(timespec="seconds")
        except Exception:
            c["created_at_str"] = None
        if "missing_checks" not in c or isinstance(c.get("missing_checks_json"), str):
            try:
                c["missing_checks"] = json.loads(c.get("missing_checks_json") or "[]")
            except Exception:
                c["missing_checks"] = c.get("missing_checks") or []
        out.append(c)
    return out


def get_report(scan_id, lang=None, fmt="markdown"):
    _init()
    s = store.get_scan(scan_id)
    if not s:
        return {"scan_id": scan_id, "status": "not_found", "verdict": "ERROR",
                "message": "未找到该 scan_id / scan_id not found"}
    lang = _norm_lang(lang or s.get("lang"))
    if s["status"] in ("queued", "running"):
        from . import estimate as est_mod
        out = {"scan_id": scan_id, "status": s["status"], "progress": s.get("progress"),
               "stage": (s.get("progress") or "S0").split(":")[0], "stage_detail": est_mod.stage_label(s.get("progress"), lang),
               "message": "检测进行中，尚无结论，请稍后再查询。" if lang == "zh" else "Scan in progress; no verdict yet. Poll again shortly."}
        est = s.get("estimate")
        started = s.get("created_at")
        # prefer running start: updated_at after first progress, or created_at
        if est is not None:
            elapsed = time.time() - (started or time.time())
            rem, pct = est_mod.remaining(est, elapsed, s["progress"] if s["status"] == "running" else "S0")
            if s["status"] == "queued":
                rem = est
            out.update(elapsed_seconds=round(elapsed, 1), estimated_seconds=est, remaining_seconds_estimate=rem, percent_estimate=pct,
                       remaining_text=(f"约还需 {round(rem)} 秒" if lang == "zh" else f"about {round(rem)}s remaining") if rem < 90 else
                       (f"约还需 {round(rem / 60)} 分钟" if lang == "zh" else f"about {round(rem / 60)} min remaining"))
        return out
    if not s.get("report_json"):
        return {"scan_id": scan_id, "status": "error", "verdict": "ERROR", "progress": s.get("progress"),
                "message": ("检测异常终止，结论为 ERROR，禁止放行。" if lang == "zh" else "Scan aborted; verdict ERROR; do not allow.")}
    rep = json.loads(s["report_json"])
    confs = [c for c in _confirmations(scan_id, rep.get("sha256"), (rep.get("tools") or {}).get("rules_version"))
             if c["valid"] and c.get("rules_ok", True)]
    if rep.get("tools", {}).get("rules_version") != scanners.rules_version():
        rep["stale"] = {"zh": "规则库已更新，此前的结论与确认需要重新评估（建议重新扫描）",
                        "en": "Rules changed since this scan; prior verdict/confirmations should be re-evaluated (rescan advised)"}
    ch = rep.get("cache_hit") or {}
    pkg = rep.get("package") or {}
    out = {"scan_id": scan_id, "status": rep["status"], "verdict": rep["verdict"], "risk_level": rep["risk_level"],
           "sha256": rep.get("sha256"), "user_confirmable": rep["verdict"] == "INCOMPLETE", "timing": rep.get("timing"),
           "missing_checks": [m["code"] for m in rep.get("missing_checks", [])],
           "confirmations": confs,
           "summary": build_summary(rep, lang),
           "cache_hit": bool(ch),
           "reused_from": ch.get("from_scan_id"),
           "file_name": rep.get("file_name"),
           "file_size": rep.get("file_size"),
           "file_type": rep.get("file_type"),
           "ecosystem": rep.get("ecosystem") or pkg.get("ecosystem")}
    if fmt in ("markdown", "both"):
        out["report_markdown"] = render_markdown(rep, lang, confs)
    if fmt in ("json", "both"):
        out["report"] = rep
    if fmt == "html":
        out["report_html_path"] = str(write_html_report(rep, lang, confs))
    return out


def confirm_incomplete(scan_id, sha256, missing_checks, confirmed_by, statement=""):
    _init()
    s = store.get_scan(scan_id)
    if not s or not s.get("report_json"):
        return {"ok": False, "error": "SCAN_NOT_FOUND_OR_UNFINISHED", "message": "扫描不存在或尚未完成 / scan not found or unfinished"}
    rep = json.loads(s["report_json"])
    v = rep["verdict"]
    if v in ("BLOCK", "HIGH_RISK"):
        return {"ok": False, "error": "NOT_OVERRIDABLE", "message": f"{v} 永远不允许用户确认放行 / {v} can never be overridden"}
    if v != "INCOMPLETE":
        return {"ok": False, "error": "NOT_INCOMPLETE", "message": f"只有 INCOMPLETE 可以确认，当前为 {v} / only INCOMPLETE can be confirmed"}
    if (sha256 or "").lower().strip() != rep.get("sha256"):
        return {"ok": False, "error": "SHA256_MISMATCH", "message": "SHA-256 与该次扫描不一致，确认无效 / SHA-256 does not match this scan"}
    expected = sorted({m["code"] for m in rep.get("missing_checks", [])})
    given = sorted(set(missing_checks or []))
    if given != expected:
        return {"ok": False, "error": "MISSING_CHECKS_MISMATCH", "expected_missing_checks": expected,
                "message": "确认必须逐项列出全部缺失检查项 / confirmation must list exactly all missing checks"}
    if not confirmed_by:
        return {"ok": False, "error": "CONFIRMER_REQUIRED", "message": "需要确认人 / confirmed_by required"}
    rv = (rep.get("tools") or {}).get("rules_version")
    if rv and rv != scanners.rules_version():
        return {"ok": False, "error": "RULES_CHANGED",
                "message": "规则库在这次扫描之后已更新，请重新扫描后再确认 / rules changed since this scan; rescan before confirming"}
    cid = store.add_confirmation(scan_id, rep["sha256"], expected, confirmed_by, statement, rules_version=scanners.rules_version())
    return {"ok": True, "confirmation_id": cid, "scan_id": scan_id, "sha256": rep["sha256"], "verdict": "INCOMPLETE",
            "disposition": "user_accepted_risk", "missing_checks": expected,
            "message": "已记录用户确认；结论仍为 INCOMPLETE，若文件 SHA-256 改变或规则更新，确认自动失效。"
                       " / Confirmation recorded; verdict stays INCOMPLETE and the confirmation is void if the SHA-256 changes or rules update."}
