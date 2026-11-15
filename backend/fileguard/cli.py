#!/usr/bin/env python3
"""FileGuard CLI (`fg` / `python -m fileguard.cli`).

Two-round bot flow (estimates cover scan + writing/sending the report):

  fg submit_url <url> [--lang zh|en] [--expected-sha256 X] [--force]
  fg submit_file <path> [--lang zh|en] [--expected-sha256 X] [--force]
      Submit and print ONE compact JSON object with scan_id and total_estimated_seconds /
      estimate_text (engine time + delivery overhead). The scan runs in a detached
      background process. Tell the user estimate_text.

  fg submit_pkg npm|pypi <name> <version> [--lang zh|en] [--force]
      Resolve the official registry artifact (npm dist.tarball / PyPI sdist or wheel) and submit it.

  fg wait <scan_id> [--lang zh|en] [--timeout SECONDS]
      Block until the scan finishes (no overall scan timeout). With --timeout, return early
      (exit code 3) with {"status": "running", "stage", "stage_detail", "remaining_text"} so the
      bot can post one "still scanning" line and then call `fg wait` again. Progress goes to stderr only when
      the stage changes. When done, writes the HTML report and prints ONE compact JSON
      (verdict, summary, html_path, cache_hit, reused_from, timing). Never prints markdown.
      Also records a provisional delivery-overhead sample (submit→wait, minus engine time).

  fg delivered <scan_id>
      Optional. Call after the final user-visible report message is sent. Records wall-clock
      time from submit to now and replaces the provisional overhead. Does not need its own
      bot round — append it to a later shell command if convenient.
      When ≥5 *delivered* samples exist, submit uses their median overhead and p10/p90.

  fg confirm_incomplete <scan_id> <sha256> <check1,check2,...> <confirmed_by> [statement]
  fg report_html <scan_id> [--lang zh|en]
  fg get_report <scan_id> [--lang zh|en] [--format markdown|json|both|html]
  fg version [--json] / fg --version
      --json adds parser versions (7-Zip, ClamAV), signature DB date and missing components.
  fg scan <path|url>   (synchronous helper: submit + wait)

Env:
  FILEGUARD_HOME / FILEGUARD_DATA   install root and data dir
  FILEGUARD_DELIVERY_OVERHEAD_S     default 20 (seconds), used until 5 delivered samples exist
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import ENGINE_VERSION, config, service
from . import delivery as deliv


def _fail(msg, code=1):
    print(msg, file=sys.stderr)
    sys.exit(code)


def _dump(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def _version():
    vf = Path(config.BASE_DIR) / "VERSION"
    if vf.is_file():
        return vf.read_text(encoding="utf-8").strip().splitlines()[0].strip()
    return ENGINE_VERSION


def _missing_components():
    from . import scanners, tools
    missing = []
    if not tools.clam("clamdscan") and not tools.clam("clamscan"):
        missing.append("clamav")
    elif not scanners.clamd_available() and not tools.clam("clamscan"):
        missing.append("clamd_or_clamscan_running")
    if not _yara_python_ok():
        missing.append("yara")
    if not tools.sevenzip():
        missing.append("7zip")
    return missing


def _yara_python_ok():
    try:
        import yara  # noqa: F401
        return True
    except Exception:
        return False


def cmd_version(as_json=False):
    if not as_json:
        print(f"FileGuard {_version()}")
        return 0
    from . import scanners, tools
    parsers = tools.parser_status()
    db = scanners.db_info()
    checks = []
    if db.get("stale"):
        checks.append("CLAMAV_DB_STALE")
    if any(p["version"] and not p["ok"] for p in parsers):
        checks.append("PARSER_OUTDATED")
    info = {
        "version": _version(),
        "engine_version": ENGINE_VERSION,
        "dir": str(config.BASE_DIR),
        "data_dir": str(config.DATA_DIR),
        "missing_components": _missing_components(),
        "parsers": parsers,
        "clamav_db": db,
        "self_check_missing": checks,
        "ssrf_allow_cidrs": config.SSRF_EXTRA_ALLOWED_CIDRS,
    }
    _dump(info)
    return 0


def _size_human(n):
    if not isinstance(n, (int, float)) or n < 0:
        return None
    n = int(n)
    if n < 1024:
        return f"{n} B"
    kb = n / 1024
    if n < 1024 * 1024:
        return f"{kb:.1f} KB" if kb < 10 else f"{kb:.0f} KB"
    mb = n / (1024 * 1024)
    return f"{mb:.1f} MB"


def _type_label(r):
    eco = r.get("ecosystem")
    if eco and eco != "N/A":
        return str(eco)
    summary = r.get("summary") or {}
    name = (r.get("file_name") or summary.get("filename") or "") or ""
    lower = name.lower()
    for ext, lab in ((".tgz", "tgz"), (".tar.gz", "tar.gz"), (".zip", "zip"),
                     (".whl", "wheel"), (".exe", "exe"), (".dll", "dll"), (".pdf", "pdf")):
        if lower.endswith(ext):
            return lab
    ft = r.get("file_type") or ""
    if ft and ft != "N/A":
        return str(ft).split(",")[0].strip()[:40]
    return "file"


def cmd_submit(kind, target, lang, expected_sha256=None, force=False):
    lang = "en" if (lang or "zh").lower().startswith("en") else "zh"
    if kind == "url":
        src = {"kind": "url", "url": target}
    else:
        path = Path(target)
        if not path.is_file():
            _fail(f"submit_file: not a file: {target}")
        src = {"kind": "path", "path": str(path.resolve()), "filename": path.name}
    r = service.submit(src, lang, expected_sha256=expected_sha256, force_rescan=force)
    if not isinstance(r, dict) or not r.get("scan_id"):
        _fail(f"submit failed: {r}")
    engine = r.get("estimated_seconds")
    if engine is None:
        engine = 0
    oh, lo, hi, src_model = deliv.overhead_model()
    total = round(float(engine) + float(oh), 1)
    out = {
        "scan_id": r["scan_id"],
        "status": r.get("status") or "queued",
        "engine_estimated_seconds": engine,
        "delivery_overhead_seconds": oh,
        "total_estimated_seconds": total,
        "estimate_text": deliv.total_estimate_text(engine, oh, lo, hi, lang),
        "overhead_source": src_model,
    }
    deliv.mark_submitted(out["scan_id"], engine)
    _dump(out)
    return 0


def resolve_pkg(eco, name, version):
    """Official artifact URL for a registry package (never installs anything)."""
    import urllib.parse
    import httpx
    from . import USER_AGENT
    eco = eco.lower()
    h = {"User-Agent": USER_AGENT}
    if eco == "npm":
        q = urllib.parse.quote(name, safe="@")
        q = q.replace("/", "%2F") if not name.startswith("@") else "@" + urllib.parse.quote(name[1:], safe="")
        r = httpx.get(f"{config.NPM_REGISTRY}/{q}/{urllib.parse.quote(version, safe='')}", headers=h,
                      timeout=config.NET_STALL_TIMEOUT, follow_redirects=True)
        if r.status_code != 200:
            _fail(f"submit_pkg: npm {name}@{version} not found (HTTP {r.status_code})")
        dist = r.json().get("dist") or {}
        if not dist.get("tarball"):
            _fail(f"submit_pkg: npm {name}@{version} has no dist.tarball")
        return dist["tarball"], None
    if eco in ("pypi", "pip", "python"):
        r = httpx.get(f"{config.PYPI_URL}/pypi/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json",
                      headers=h, timeout=config.NET_STALL_TIMEOUT, follow_redirects=True)
        if r.status_code != 200:
            _fail(f"submit_pkg: PyPI {name}=={version} not found (HTTP {r.status_code})")
        files = r.json().get("urls") or []
        pick = (next((f for f in files if f.get("packagetype") == "sdist"), None)
                or next((f for f in files if f.get("filename", "").endswith("py3-none-any.whl")), None)
                or (files[0] if files else None))
        if not pick:
            _fail(f"submit_pkg: PyPI {name}=={version} has no files")
        return pick["url"], (pick.get("digests") or {}).get("sha256")
    _fail(f"submit_pkg: unsupported ecosystem {eco} (use npm or pypi)")


def cmd_wait(scan_id, lang, timeout=None):
    lang = "en" if (lang or "zh").lower().startswith("en") else "zh"
    last_stage = None
    t0 = time.time()
    while True:
        r = service.get_report(scan_id, lang, fmt="summary")
        if not isinstance(r, dict):
            _fail(f"wait failed: unexpected response: {r}")
        status = r.get("status")
        if status == "not_found":
            _fail(f"wait failed (not_found): {r.get('message') or 'scan_id not found'}")
        if status in ("queued", "running"):
            stage_key = r.get("progress") or r.get("stage") or status
            if stage_key != last_stage:
                last_stage = stage_key
                detail = r.get("stage_detail") or r.get("stage") or stage_key
                rem = r.get("remaining_text")
                line = f"FileGuard: {detail}"
                if rem:
                    line += f" — {rem}"
                print(line, file=sys.stderr, flush=True)
            if timeout is not None and time.time() - t0 >= timeout:
                print(json.dumps({"scan_id": scan_id, "status": status, "stage": r.get("stage"),
                                  "stage_detail": r.get("stage_detail"), "remaining_text": r.get("remaining_text"),
                                  "elapsed_seconds": r.get("elapsed_seconds")}, ensure_ascii=False))
                sys.exit(3)
            time.sleep(1)
            continue
        break

    html_path = None
    if status in ("done", "error"):
        try:
            html = service.get_report(scan_id, lang, fmt="html")
            if isinstance(html, dict):
                html_path = html.get("report_html_path")
                r = html
        except Exception as e:
            print(f"FileGuard: HTML report failed ({type(e).__name__}: {e})", file=sys.stderr)

    timing = r.get("timing") or {}
    engine_est = timing.get("estimated_seconds")
    engine_act = timing.get("actual_seconds")
    deliv.record_wait(scan_id, engine_est, engine_act)

    size = r.get("file_size")
    if size is None:
        size = (r.get("summary") or {}).get("size_bytes")
    out = {
        "scan_id": scan_id,
        "status": r.get("status"),
        "verdict": r.get("verdict"),
        "risk_level": r.get("risk_level"),
        "cache_hit": bool(r.get("cache_hit")),
        "reused_from": r.get("reused_from"),
        "sha256": r.get("sha256") if r.get("sha256") != "N/A" else None,
        "size_human": _size_human(size),
        "type_label": _type_label(r),
        "summary": r.get("summary"),
        "html_path": html_path,
        "timing": {
            "engine_estimated_seconds": engine_est,
            "engine_actual_seconds": engine_act,
        },
    }
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if len(text.encode("utf-8")) > 8192:
        sm = dict(out.get("summary") or {})
        sm["top_evidence"] = (sm.get("top_evidence") or [])[:3]
        for ev in sm["top_evidence"]:
            if isinstance(ev, dict) and ev.get("title") and len(ev["title"]) > 200:
                ev["title"] = ev["title"][:197] + "…"
        out["summary"] = sm
        text = json.dumps(out, ensure_ascii=False, indent=2)
    print(text)
    if r.get("status") not in ("done", "error"):
        sys.exit(1)
    return 0


def cmd_delivered(scan_id):
    rec, n, err = deliv.record_delivered(scan_id)
    if err:
        _fail(err)
    oh, lo, hi, src = deliv.overhead_model()
    _dump({
        "ok": True,
        "scan_id": scan_id,
        "total_elapsed_seconds": rec.get("total_elapsed_seconds"),
        "overhead_seconds": rec.get("overhead_seconds"),
        "engine_actual_seconds": rec.get("engine_actual_seconds"),
        "samples": n,
        "calibrated_overhead_seconds": oh if src == "calibrated" else None,
        "overhead_model": src,
        "overhead_range": [lo, hi],
        "message": (
            f"Recorded delivery time. {n} sample(s) stored; "
            + ("overhead is now calibrated from the sample median." if src == "calibrated"
               else f"need {max(0, 5 - n)} more for calibrated overhead (default {deliv.DEFAULT_OVERHEAD:g}s).")
        ),
    })
    return 0


def cmd_confirm(scan_id, sha256, missing, confirmed_by, statement=""):
    checks = [c for c in (missing or "").split(",") if c]
    r = service.confirm_incomplete(scan_id, sha256, checks, confirmed_by, statement)
    _dump(r)
    return 0 if r.get("ok") else 1


def cmd_get_report(scan_id, lang, fmt):
    r = service.get_report(scan_id, lang, fmt)
    if not isinstance(r, dict):
        _fail(f"get_report failed: {r}")
    if fmt == "html":
        path = r.get("report_html_path")
        # still dump JSON so tests can use it; report_html command prints only the path
        _dump(r)
        return 0 if path or r.get("status") in ("queued", "running") else 1
    if fmt == "markdown" and isinstance(r.get("report_markdown"), str) and r.get("status") == "done":
        print(json.dumps({k: v for k, v in r.items() if k != "report_markdown"}, ensure_ascii=False, indent=1))
        print("\n" + r["report_markdown"])
        return 0
    _dump(r)
    return 0 if r.get("status") != "not_found" else 1


def cmd_report_html(scan_id, lang):
    r = service.get_report(scan_id, lang, "html")
    if not isinstance(r, dict):
        _fail(f"report_html failed: unexpected response: {r}")
    path = r.get("report_html_path")
    if path:
        print(path)
        return 0
    status = r.get("status")
    msg = r.get("message") or r.get("error") or "no report_html_path"
    _fail(f"report_html failed ({status or 'unknown'}): {msg}")


def _cmd_scan(target, lang, expected, force):
    """Synchronous submit+wait; prints the wait compact JSON only."""
    lang = "en" if (lang or "zh").lower().startswith("en") else "zh"
    if target.startswith(("http://", "https://")):
        src = {"kind": "url", "url": target}
    else:
        path = Path(target)
        if not path.is_file():
            _fail(f"scan: not a file: {target}")
        src = {"kind": "path", "path": str(path.resolve()), "filename": path.name}
    r = service.submit(src, lang, expected_sha256=expected, force_rescan=force)
    if not r.get("scan_id"):
        _fail(f"submit failed: {r}")
    deliv.mark_submitted(r["scan_id"], r.get("estimated_seconds") or 0)
    return cmd_wait(r["scan_id"], lang)


def _parser():
    p = argparse.ArgumentParser(prog="fg", description="FileGuard CLI")
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="cmd")

    def add_lang(sp):
        sp.add_argument("--lang", default="zh")
        return sp

    su = add_lang(sub.add_parser("submit_url", help="submit a download URL; print estimate JSON"))
    su.add_argument("url")
    su.add_argument("--expected-sha256", "--sha256", dest="expected_sha256", default=None)
    su.add_argument("--force", action="store_true")
    sf = add_lang(sub.add_parser("submit_file", help="submit a local file; print estimate JSON"))
    sf.add_argument("path")
    sf.add_argument("--expected-sha256", "--sha256", dest="expected_sha256", default=None)
    sf.add_argument("--force", action="store_true")
    sp = add_lang(sub.add_parser("submit_pkg", help="submit a registry package: npm|pypi <name> <version>"))
    sp.add_argument("ecosystem")
    sp.add_argument("name")
    sp.add_argument("pkg_version")
    sp.add_argument("--expected-sha256", "--sha256", dest="expected_sha256", default=None)
    sp.add_argument("--force", action="store_true")
    sw = add_lang(sub.add_parser("wait", help="block until done; print compact result JSON"))
    sw.add_argument("scan_id")
    sw.add_argument("--timeout", type=float, default=None, help="return early (exit 3) with the current stage")
    sub.add_parser("delivered", help="record end-to-end delivery time (optional)").add_argument("scan_id")
    sc = sub.add_parser("confirm_incomplete")
    sc.add_argument("scan_id")
    sc.add_argument("sha256")
    sc.add_argument("missing_checks")
    sc.add_argument("confirmed_by")
    sc.add_argument("statement", nargs="*", default=[])
    add_lang(sub.add_parser("report_html")).add_argument("scan_id")
    gr = add_lang(sub.add_parser("get_report"))
    gr.add_argument("scan_id")
    gr.add_argument("--format", default="markdown", choices=["markdown", "json", "both", "html", "summary"])
    sub.add_parser("version").add_argument("--json", action="store_true")
    scn = add_lang(sub.add_parser("scan", help="submit + wait (synchronous helper)"))
    scn.add_argument("target")
    scn.add_argument("--expected-sha256", dest="expected_sha256", default=None)
    scn.add_argument("--force", action="store_true")
    sub.add_parser("_run", help=argparse.SUPPRESS).add_argument("scan_id")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("--version", "-V"):
        return cmd_version(as_json=False)
    if argv and argv[0] in ("-h", "--help") and len(argv) == 1:
        print(__doc__)
        return 0
    a = _parser().parse_args(argv)
    if a.version or a.cmd is None:
        cmd_version()
        if a.cmd is None and not a.version:
            print("usage: fg submit_url|submit_file|submit_pkg|wait|delivered|confirm_incomplete|report_html|get_report|version …",
                  file=sys.stderr)
        return 0
    if a.cmd == "submit_url":
        return cmd_submit("url", a.url, a.lang, a.expected_sha256, a.force)
    if a.cmd == "submit_file":
        return cmd_submit("file", a.path, a.lang, a.expected_sha256, a.force)
    if a.cmd == "submit_pkg":
        url, sha = resolve_pkg(a.ecosystem, a.name, a.pkg_version)
        return cmd_submit("url", url, a.lang, a.expected_sha256 or sha, a.force)
    if a.cmd == "wait":
        return cmd_wait(a.scan_id, a.lang, a.timeout)
    if a.cmd == "delivered":
        return cmd_delivered(a.scan_id)
    if a.cmd == "confirm_incomplete":
        return cmd_confirm(a.scan_id, a.sha256, a.missing_checks, a.confirmed_by, " ".join(a.statement))
    if a.cmd == "report_html":
        return cmd_report_html(a.scan_id, a.lang)
    if a.cmd == "get_report":
        return cmd_get_report(a.scan_id, a.lang, a.format)
    if a.cmd == "version":
        return cmd_version(as_json=a.json)
    if a.cmd == "scan":
        return _cmd_scan(a.target, a.lang, a.expected_sha256, a.force)
    if a.cmd == "_run":
        return service.run_worker(a.scan_id)
    _fail(f"unknown command: {a.cmd}")


if __name__ == "__main__":
    sys.exit(main() or 0)
