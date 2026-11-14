"""S6 deterministic rule engine. Five states only: BLOCK, HIGH_RISK, INCOMPLETE, NO_FINDINGS, ERROR.

Mapping (checklist section 4):
  critical evidence (ClamAV hit, known-bad hash, known-malicious package/IOC, EICAR, malicious install hook) -> BLOCK
  high evidence (phantom dep with install hook, download-and-exec at install, credential exfil,
                 reverse shell, typosquat + hook, ...)                                                    -> HIGH_RISK
  two or more distinct medium indicators (weak evidence corroborating each other)                          -> HIGH_RISK
  any mandatory check missing (encrypted/corrupt archive, dep/unpack limits, unavailable key check)        -> INCOMPLETE
  everything applicable completed and nothing medium+                                                      -> NO_FINDINGS
  engine failure / input rejected (no overall timeout)                                                               -> ERROR
A single weak indicator (e.g. only UPX, only a postinstall) never escalates by itself but is always reported.
ERROR/unknown is never converted into NO_FINDINGS.
"""
from .model import SEVERITY_ORDER

NON_OVERRIDABLE = ("BLOCK", "HIGH_RISK")


def decide(ctx, error, reused=None):
    if reused is not None:
        v = reused.get("verdict", {}).get("verdict") if isinstance(reused.get("verdict"), dict) else reused.get("verdict")
        if v in ("BLOCK", "HIGH_RISK", "NO_FINDINGS"):
            return {"verdict": v, "risk_level": reused.get("risk_level", "UNKNOWN"), "reason_zh": "复用同一 SHA-256 的缓存结果",
                    "reason_en": "Reused cached result for the same SHA-256", "overridable": v == "INCOMPLETE"}
    sev = [SEVERITY_ORDER[f.severity] for f in ctx.findings]
    top = max(sev) if sev else 0
    mediums = {f.code for f in ctx.findings if f.severity == "medium" and not f.downgraded}
    any_medium = any(f.severity == "medium" for f in ctx.findings)
    if error:
        # Even on error, confirmed critical evidence found before the failure still blocks.
        if top >= 4:
            return _v("BLOCK", "CRITICAL", "检测中途出错，但出错前已确认严重恶意证据", "Scan errored, but critical malicious evidence was confirmed before the failure")
        return _v("ERROR", "UNKNOWN", f"检测未完成：{error['zh']}", f"Scan not completed: {error['en']}")
    if top >= 4:
        return _v("BLOCK", "CRITICAL", "确认存在严重恶意证据", "Confirmed critical malicious evidence")
    if top == 3:
        return _v("HIGH_RISK", "HIGH", "存在高危可疑行为或特征", "High-risk suspicious behaviour or traits present")
    if len(mediums) >= 2:
        return _v("HIGH_RISK", "HIGH", f"多项中危特征相互印证（{len(mediums)} 项）", f"Multiple corroborating medium-risk indicators ({len(mediums)})")
    if ctx.missing:
        lvl = "MEDIUM" if any_medium else "UNKNOWN"
        return _v("INCOMPLETE", lvl, f"有 {len(ctx.missing)} 项必需检查缺失或无法完成", f"{len(ctx.missing)} mandatory check(s) missing or could not complete")
    lvl = "MEDIUM" if any_medium else ("LOW" if top >= 1 else "NONE")
    return _v("NO_FINDINGS", lvl, "所有适用的必需检查均已完成，未发现中高危风险" + ("（有中危提示，见证据）" if any_medium else ""),
              "All applicable mandatory checks completed; no medium/high risk found" + (" (medium-risk notes present, see evidence)" if any_medium else ""))


def _v(verdict, level, zh, en):
    return {"verdict": verdict, "risk_level": level, "reason_zh": zh, "reason_en": en,
            "overridable": verdict == "INCOMPLETE"}
