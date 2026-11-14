"""Delivery-overhead model and submit/wait/delivered sample records.

Default overhead is 20s (FILEGUARD_DELIVERY_OVERHEAD_S) until ≥5 *delivered*
samples exist in data/delivery_times.json; then the median and p10/p90 are used.
Wait records a provisional sample (not used for calibration — cache hits would
collapse the estimate). `fg delivered <scan_id>` is optional and may be appended
to a later shell command so it costs no extra bot round.
"""
from __future__ import annotations

import os
import re
import time
from datetime import datetime

from . import store

DEFAULT_OVERHEAD = float(os.environ.get("FILEGUARD_DELIVERY_OVERHEAD_S", "20"))


def _path():
    from . import config
    return config.DATA_DIR / "delivery_times.json"


def _load():
    data = store.read_json(_path(), None)
    if not isinstance(data, dict) or not isinstance(data.get("samples"), list):
        return {"samples": []}
    return data


def _save(data):
    store.write_json(_path(), data)


def _find(data, scan_id):
    for s in data.get("samples") or []:
        if s.get("scan_id") == scan_id:
            return s
    return None


def scan_id_ts(scan_id):
    m = re.match(r"fg_(\d{14})_", scan_id or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S").timestamp()
    except ValueError:
        return None


def _percentile(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def overhead_model():
    """Return (point, lo, hi, source)."""
    vals = []
    for s in _load().get("samples") or []:
        if s.get("overhead_source") != "delivered":
            continue
        try:
            vals.append(max(0.0, float(s.get("overhead_seconds"))))
        except (TypeError, ValueError):
            continue
    if len(vals) >= 5:
        return (
            round(_percentile(vals, 50), 1),
            round(_percentile(vals, 10), 1),
            round(_percentile(vals, 90), 1),
            "calibrated",
        )
    oh = DEFAULT_OVERHEAD
    return (round(oh, 1), round(max(8.0, oh * 0.7), 1), round(oh * 1.6, 1), "default")


def _fmt_secs(s, zh):
    s = max(1, int(round(s)))
    if s < 90:
        return f"{s} 秒" if zh else f"{s}s"
    m = max(1, round(s / 60))
    return f"{m} 分钟" if zh else f"{m} min"


def total_estimate_text(engine, overhead, lo_oh, hi_oh, lang):
    engine = float(engine or 0)
    total = max(1, engine + float(overhead))
    lo = max(1, engine * 0.6 + float(lo_oh))
    hi = max(lo + 1, engine * 1.8 + float(hi_oh))
    zh = lang != "en"
    t_i, lo_i, hi_i = int(round(total)), int(round(lo)), int(round(hi))
    if total < 90 and lo < 90 and hi < 90:
        if zh:
            return f"约 {t_i} 秒（通常 {lo_i}–{hi_i} 秒，含整理和发送报告）"
        return f"about {t_i}s (typically {lo_i}–{hi_i}s, including writing the report)"
    if zh:
        return f"约 {_fmt_secs(total, True)}（通常 {_fmt_secs(lo, True)}–{_fmt_secs(hi, True)}，含整理和发送报告）"
    return f"about {_fmt_secs(total, False)} (typically {_fmt_secs(lo, False)}–{_fmt_secs(hi, False)}, including writing the report)"


def mark_submitted(scan_id, engine_est):
    p = _path()
    def mut(data):
        data = data if isinstance(data, dict) and isinstance(data.get("samples"), list) else {"samples": []}
        rec = _find(data, scan_id)
        if rec is None:
            rec = {"scan_id": scan_id}
            data["samples"].append(rec)
        rec["submitted_at"] = time.time()
        rec["engine_estimated_seconds"] = engine_est
        return data
    with store._locked(p):
        data = mut(store.read_json(p, None))
        _save(data)


def record_wait(scan_id, engine_est, engine_actual):
    now = time.time()
    p = _path()
    def mut(data):
        data = data if isinstance(data, dict) and isinstance(data.get("samples"), list) else {"samples": []}
        rec = _find(data, scan_id)
        if rec is None:
            rec = {"scan_id": scan_id, "submitted_at": scan_id_ts(scan_id) or now}
            data["samples"].append(rec)
        rec["wait_finished_at"] = now
        if engine_est is not None:
            rec["engine_estimated_seconds"] = engine_est
        if engine_actual is not None:
            rec["engine_actual_seconds"] = engine_actual
        submitted = rec.get("submitted_at") or scan_id_ts(scan_id) or now
        rec["submitted_at"] = submitted
        rec["wait_elapsed_seconds"] = round(now - submitted, 2)
        if not rec.get("delivered_at"):
            eng = engine_actual if engine_actual is not None else (engine_est or 0)
            rec["overhead_seconds"] = round(max(0.0, rec["wait_elapsed_seconds"] - float(eng or 0)), 2)
            rec["overhead_source"] = "wait"
        return data
    with store._locked(p):
        data = mut(store.read_json(p, None))
        _save(data)
        return _find(data, scan_id)


def record_delivered(scan_id):
    now = time.time()
    p = _path()
    def mut(data):
        data = data if isinstance(data, dict) and isinstance(data.get("samples"), list) else {"samples": []}
        rec = _find(data, scan_id)
        if rec is None:
            ts = scan_id_ts(scan_id)
            if ts is None:
                return ("ERR", "delivered: no submit record for this scan_id and time could not be parsed")
            rec = {"scan_id": scan_id, "submitted_at": ts}
            data["samples"].append(rec)
        submitted = rec.get("submitted_at") or scan_id_ts(scan_id)
        if submitted is None:
            return ("ERR", "delivered: missing submitted_at")
        rec["submitted_at"] = submitted
        rec["delivered_at"] = now
        rec["total_elapsed_seconds"] = round(now - submitted, 2)
        eng = rec.get("engine_actual_seconds")
        if eng is None:
            eng = rec.get("engine_estimated_seconds") or 0
        rec["overhead_seconds"] = round(max(0.0, rec["total_elapsed_seconds"] - float(eng or 0)), 2)
        rec["overhead_source"] = "delivered"
        return data
    with store._locked(p):
        raw = store.read_json(p, None)
        data = mut(raw)
        if isinstance(data, tuple) and data[0] == "ERR":
            return None, 0, data[1]
        _save(data)
        n = sum(1 for s in data["samples"] if s.get("overhead_source") == "delivered")
        return _find(data, scan_id), n, None
