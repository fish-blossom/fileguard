"""S7 report: structured JSON (language-neutral, bilingual strings) + Markdown rendering in zh / en."""
import html
import time
from datetime import datetime, timezone
from pathlib import Path

from . import ENGINE_VERSION, config, scanners
from .model import SEVERITY_ORDER

STAGES = ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"]
STAGE_NAMES = {
    "S0": ("输入校验", "Input validation"), "S1": ("来源信誉", "Source reputation"),
    "S2": ("下载完整性", "Download integrity"), "S3": ("静态分析", "Static analysis"),
    "S4": ("版本差异", "Version diff"), "S5": ("安装足迹预测", "Install-footprint prediction"),
    "S6": ("风险裁决", "Risk decision"), "S7": ("交付与跟进", "Delivery & follow-up"),
}
DISCLAIMER = {
    "zh": "NO_FINDINGS 表示在已完成的静态检测范围内没有发现威胁，不代表文件绝对安全。本次检测没有进行动态行为分析。",
    "en": "NO_FINDINGS means no threat was found within the completed static-analysis scope; it does not mean the file is absolutely safe. No dynamic behaviour analysis was performed.",
}
STANDARD_LIMITS = [
    ("只做静态分析：未执行、未安装、未运行宏；运行时才解密/下载的载荷可能无法发现", "Static analysis only: nothing executed/installed; payloads decrypted or fetched only at runtime may be missed"),
    ("依赖检查基于注册表元数据、已知恶意名单与 OSV 情报，未下载并逐个解包每个依赖", "Dependency checks use registry metadata, known-malicious lists and OSV; dependency tarballs are not individually unpacked"),
    ("YARA 规则为 FileGuard 自研小规则集，覆盖面有限", "YARA ruleset is a small in-house set with limited coverage"),
]


def build_report(ctx, verdict, error, reused, elapsed):
    m = ctx.meta
    if reused is not None:
        rep = dict(reused)
        rep.update(scan_id=ctx.scan_id, cache_hit={"from_scan_id": reused.get("scan_id"), "verdict": verdict["verdict"]},
                   scanned_at=_now(), elapsed_seconds=round(elapsed, 2),
                   original_url=m.get("original_url", rep.get("original_url", "N/A")),
                   final_url=m.get("final_url", rep.get("final_url", "N/A")))
        rep["cache_stats"] = dict(rep.get("cache_stats", {}), file_hash_cache_hit=True)
        rep["coverage"]["S2"] = {"status": "done", "zh": "SHA-256 命中缓存，复用之前完整检测的结果", "en": "SHA-256 cache hit; reused a prior complete scan"}
        return rep
    ctx.stage("S7", "done", "已生成报告、Hash 校验命令；样本已删除，仅保留报告与 Hash",
              "Report and hash-verification commands generated; sample deleted, only report + hashes kept")
    for s in STAGES:
        if s not in ctx.stages:
            ctx.stages[s] = {"status": "not_run", "zh": "因检测提前终止未执行", "en": "Not run because the scan stopped early"}
    if error:
        for s in STAGES:
            if ctx.stages[s]["status"] == "not_run":
                ctx.stages[s]["status"] = "failed" if s not in ("S6", "S7") else ctx.stages[s]["status"]
    findings = sorted((f.to_dict() for f in ctx.findings), key=lambda f: -SEVERITY_ORDER[f["severity"]])
    deps = ctx.deps or {}
    st = deps.get("stats", {})
    sha = m.get("sha256")
    fname = m.get("file_name", "N/A")
    rep = {
        "scan_id": ctx.scan_id,
        "status": "error" if verdict["verdict"] == "ERROR" else "done",
        # ---- the 20 report fields (section 9) ----
        "file_name": fname,
        "file_type": m.get("file_type", "N/A"),
        "file_size": m.get("file_size", "N/A"),
        "original_url": m.get("original_url", "N/A"),
        "final_url": m.get("final_url", "N/A"),
        "sha256": sha or "N/A",
        "verdict": verdict["verdict"],
        "risk_level": verdict["risk_level"],
        "coverage": {s: ctx.stages[s] for s in STAGES},
        "tools": {"engine": f"FileGuard {ENGINE_VERSION}", "clamav": ctx.tools.get("clamav", "N/A"),
                  "clamav_db_updated": ctx.tools.get("clamav_db", "N/A"),
                  "unpacker": ctx.tools.get("unpacker", "N/A"),
                  "yara": ctx.tools.get("yara", scanners.yara_version()), "rules_version": scanners.rules_version(),
                  "dependency_intel": "local known-malicious list + OSV.dev" if config.OSV_ENABLED else "local list"},
        "evidence": findings,
        "dependency_stats": st if deps.get("applicable") else "N/A",
        "cache_stats": {"file_hash_cache_hit": False, "dependency_cache_hits": st.get("cache_hits", 0) if st else 0,
                        "dependency_new_checked": st.get("new_checked", 0) if st else 0},
        "unchecked_dependencies": deps.get("skipped", []) if deps.get("applicable") else "N/A",
        "light_checked_dependencies": deps.get("light_checked", []) if deps.get("applicable") else "N/A",
        "special_checks": [{k: v for k, v in c.items() if not isinstance(v, (bytes,))} for c in m.get("special_checks", [])],
        "version_diff": ctx.diff or "N/A",
        "install_footprint": ctx.footprint or "N/A",
        "missing_checks": [x.to_dict() for x in ctx.missing],
        "limitations": [{"zh": a, "en": b} for a, b in (STANDARD_LIMITS + ctx.limitations)],
        "hash_verify_commands": _hash_cmds(fname, sha) if sha else "N/A",
        "scanned_at": _now(),
        # ---- extra context ----
        "verdict_reason": {"zh": verdict["reason_zh"], "en": verdict["reason_en"]},
        "user_confirmable": verdict["verdict"] == "INCOMPLETE",
        "error": error,
        "hashes": {k: m.get(k) for k in ("sha256", "sha1", "md5") if m.get(k)},
        "redirects": m.get("redirects", []),
        "integrity_checks": m.get("integrity_checks", []),
        "network_indicators": m.get("network_indicators", []),
        "install_hooks": m.get("hooks", {}),
        "package": m.get("package"),
        "ecosystem": m.get("ecosystem"),
        "unpack_stats": m.get("unpack"),
        "files_inspected": len(ctx.files),
        "file_inventory": ctx.files[:300],
        "sample_deleted": m.get("sample_deleted", True),
        "elapsed_seconds": round(elapsed, 2),
        "disclaimer": DISCLAIMER,
    }
    return rep


def _hash_cmds(fname, sha):
    return {
        "linux": f"sha256sum '{fname}'   # expect {sha}",
        "macos": f"shasum -a 256 '{fname}'   # expect {sha}",
        "windows_powershell": f"Get-FileHash -Algorithm SHA256 '{fname}'   # expect {sha.upper()}",
    }


def _now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ------------------------------------------------------------------ rendering
SEV_LABEL = {"zh": {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"},
             "en": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}}
STATUS_LABEL = {"zh": {"done": "完成", "partial": "部分完成", "skipped": "跳过", "not_applicable": "不适用", "failed": "失败", "not_run": "未执行"},
                "en": {"done": "done", "partial": "partial", "skipped": "skipped", "not_applicable": "N/A", "failed": "failed", "not_run": "not run"}}
ADVICE = {
    "BLOCK": ("禁止放行。发现严重恶意证据，不提供用户确认放行。请删除该文件，不要安装或打开。", "Do not allow. Critical malicious evidence; no user override is offered. Delete the file; do not install or open it."),
    "HIGH_RISK": ("禁止放行。存在高危可疑行为，不提供用户确认放行。", "Do not allow. High-risk behaviour present; no user override is offered."),
    "INCOMPLETE": ("默认不放行：有必需检查没有完成。只有你本人针对这个 SHA-256 和列出的缺失项明确确认后，才会记录为“用户自担风险”。", "Not allowed by default: mandatory checks are missing. Only your explicit confirmation for this SHA-256 and the listed missing checks will be recorded as user-accepted risk."),
    "NO_FINDINGS": ("在已完成的静态检测范围内未发现威胁，可按策略放行，但不代表绝对安全。", "No threat found within the completed static scope; may be allowed per policy, but this is not a guarantee of safety."),
    "ERROR": ("检测没有完成，禁止放行。建议稍后重试。", "Scan did not complete; do not allow. Please retry later."),
}


def render_markdown(rep, lang="zh", confirmations=None):
    zh = lang != "en"
    L = (lambda a, b: a) if zh else (lambda a, b: b)
    t = lambda d: (d.get("zh") if zh else d.get("en")) if isinstance(d, dict) else d
    na = L("不适用", "N/A")
    v = rep["verdict"]
    out = []
    out.append(f"# FileGuard {L('检测报告', 'Scan report')} — **{v}**")
    out.append(f"**{L('结论', 'Conclusion')}：** {t(rep['verdict_reason'])}。{ADVICE[v][0 if zh else 1]}")
    if rep.get("cache_hit"):
        out.append(L(f"（同一 SHA-256 已于扫描 {rep['cache_hit']['from_scan_id']} 完整检测过，本次复用其结果）",
                     f"(Same SHA-256 was fully scanned in {rep['cache_hit']['from_scan_id']}; result reused)"))
    if confirmations:
        for c in confirmations:
            out.append(L(f"> 用户确认记录：{c['confirmed_by']} 于 {c['created_at_str']} 针对 SHA-256 {c['sha256'][:16]}… 确认接受缺失项风险（状态仍为 INCOMPLETE）。",
                         f"> User confirmation: {c['confirmed_by']} at {c['created_at_str']} accepted the missing-check risk for SHA-256 {c['sha256'][:16]}… (verdict remains INCOMPLETE)."))
    size = rep["file_size"]
    rows = [
        (L("1. 文件名", "1. File name"), rep["file_name"]),
        (L("2. 文件类型", "2. File type"), rep["file_type"]),
        (L("3. 文件大小", "3. File size"), f"{size:,} bytes" if isinstance(size, int) else na),
        (L("4. 原始 URL", "4. Original URL"), rep["original_url"] if rep["original_url"] != "N/A" else na),
        (L("5. 最终下载 URL", "5. Final download URL"), rep["final_url"] if rep["final_url"] != "N/A" else na),
        ("6. SHA-256", f"`{rep['sha256']}`" if rep["sha256"] != "N/A" else na),
        (L("7. 最终结论", "7. Verdict"), f"**{v}**"),
        (L("8. 风险等级", "8. Risk level"), rep["risk_level"]),
    ]
    out.append("")
    out.append(f"| {L('项目', 'Field')} | {L('内容', 'Value')} |\n|---|---|")
    out += [f"| {a} | {str(b).replace('|', '/')} |" for a, b in rows]
    out.append(f"\n## {L('9. S0–S7 覆盖情况', '9. S0–S7 coverage')}\n")
    out.append(f"| {L('阶段', 'Stage')} | {L('状态', 'Status')} | {L('说明', 'Notes')} |\n|---|---|---|")
    for s in STAGES:
        c = rep["coverage"].get(s, {})
        out.append(f"| {s} {STAGE_NAMES[s][0 if zh else 1]} | {STATUS_LABEL['zh' if zh else 'en'].get(c.get('status'), c.get('status'))} | {t(c)} |")
    tl = rep["tools"]
    out.append(f"\n## {L('10. 检测工具和规则版本', '10. Tools & rule versions')}\n")
    out += [f"- {k}: {v2}" for k, v2 in tl.items()]
    out.append(f"\n## {L('11. 恶意或可疑证据', '11. Malicious / suspicious evidence')}\n")
    ev = rep["evidence"]
    if not ev:
        out.append(L("未发现可疑证据。", "No suspicious evidence."))
    for f in ev[:60]:
        loc = f" — `{f['path']}`" if f.get("path") else ""
        e = f"（{L('证据', 'evidence')}：`{str(f['evidence'])[:100]}`）" if f.get("evidence") else ""
        kind = L("（预测）", " (predicted)") if f.get("kind") == "predicted" else ""
        out.append(f"- [{SEV_LABEL['zh' if zh else 'en'][f['severity']]}][{f['stage']}] {t(f)}{kind}{loc}{e}  `{f['code']}`")
    if len(ev) > 60:
        out.append(L(f"- ……另有 {len(ev) - 60} 条，见 JSON 报告", f"- …{len(ev) - 60} more in the JSON report"))
    ds = rep["dependency_stats"]
    out.append(f"\n## {L('12. 依赖统计', '12. Dependency statistics')}\n")
    if isinstance(ds, dict):
        out.append(L(f"生态：{', '.join(ds.get('ecosystems', []))}；去重依赖 {ds['total_unique']} 个；新检测 {ds['new_checked']} 个（上限 {config.MAX_NEW_DEPS}）；"
                     f"超额跳过 {ds['skipped_quota']} 个；第 {config.MAX_DEP_DEPTH} 层以下轻量检查 {ds.get('light_checked', 0)} 个（不占 200 额度，上限 {config.MAX_LIGHT_DEPS}）；获取失败 {ds['failed']} 个；最大深度 {ds['max_depth_seen']}",
                     f"Ecosystems: {', '.join(ds.get('ecosystems', []))}; unique deps {ds['total_unique']}; newly checked {ds['new_checked']} (limit {config.MAX_NEW_DEPS}); "
                     f"skipped by quota {ds['skipped_quota']}; light-checked beyond depth {config.MAX_DEP_DEPTH}: {ds.get('light_checked', 0)} (not counted toward the 200 quota; cap {config.MAX_LIGHT_DEPS}); failed {ds['failed']}; max depth {ds['max_depth_seen']}"))
        lc = rep.get("light_checked_dependencies")
        if isinstance(lc, list) and lc:
            out.append(L(f"\n第 {config.MAX_DEP_DEPTH} 层以下仅做轻量检查（已知恶意包 + OSV 恶意包 + 安装钩子）：", f"\nLight-checked beyond depth {config.MAX_DEP_DEPTH} (known-malicious + OSV malicious + install hooks):")
                       + " " + ", ".join(f"{d['name']}@{d.get('version')}" for d in lc[:30]) + (" …" if len(lc) > 30 else ""))
    else:
        out.append(na)
    sc = rep.get("special_checks") or []
    if sc:
        out.append(f"\n### {L('签名 / 来源证明 / 锁文件 / 源码 tag 比对', 'Signatures / provenance / lock files / source-tag diff')}\n")
        lab = {"zh": {"verified": "已验证", "verified_untrusted": "签名有效但签名者未被信任", "invalid": "无效", "failed": "未能完成",
                      "missing_expected": "应有但缺失", "not_applicable": "不适用", "unavailable": "不可用", "done": "已完成", "not_signed": "未签名"},
               "en": {}}
        for c in sc:
            stt = lab["zh"].get(c["status"], c["status"]) if zh else c["status"]
            out.append(f"- `{c['check']}`{(' — `' + c['path'] + '`') if c.get('path') else ''}: **{stt}** — {c.get('detail_zh') if zh else c.get('detail_en')}")
    cs = rep["cache_stats"]
    out.append(f"\n## {L('13. 缓存命中统计', '13. Cache statistics')}\n")
    out.append(L(f"文件 Hash 缓存命中：{'是' if cs.get('file_hash_cache_hit') else '否'}；依赖缓存命中 {cs.get('dependency_cache_hits', 0)} 个（不占 200 额度）",
                 f"File-hash cache hit: {'yes' if cs.get('file_hash_cache_hit') else 'no'}; dependency cache hits {cs.get('dependency_cache_hits', 0)} (not counted toward the 200 quota)"))
    out.append(f"\n## {L('14. 未检测的依赖列表', '14. Unchecked dependencies')}\n")
    ud = rep["unchecked_dependencies"]
    if isinstance(ud, list) and ud:
        for d in ud[:40]:
            out.append(f"- {d['ecosystem']}:{d['name']} {d.get('version') or d.get('spec') or ''} — {L('原因', 'reason')}: {d['reason']}, {L('深度', 'depth')} {d['depth']}")
        if len(ud) > 40:
            out.append(L(f"- ……共 {len(ud)} 个，完整列表见 JSON", f"- …{len(ud)} total; full list in JSON"))
    else:
        out.append(na if ud == "N/A" else L("无", "None"))
    out.append(f"\n## {L('15. 历史版本对比', '15. Version diff')}\n")
    vd = rep["version_diff"]
    if isinstance(vd, dict) and vd.get("status") == "compared":
        out.append(L(f"基线版本 {vd['baseline_version']}：新增文件 {len(vd['added_files'])}，删除 {len(vd['removed_files'])}，修改 {len(vd['changed_files'])}（{', '.join(vd['changed_files'][:5])}）；"
                     f"新增依赖 {', '.join(vd['new_dependencies']) or '无'}；新增安装钩子 {', '.join(vd['new_install_hooks']) or '无'}",
                     f"Baseline {vd['baseline_version']}: added {len(vd['added_files'])}, removed {len(vd['removed_files'])}, changed {len(vd['changed_files'])} ({', '.join(vd['changed_files'][:5])}); "
                     f"new deps {', '.join(vd['new_dependencies']) or 'none'}; new install hooks {', '.join(vd['new_install_hooks']) or 'none'}"))
    elif isinstance(vd, dict):
        out.append(vd.get("status", na) if vd.get("status") != "not_applicable" else na)
    else:
        out.append(na)
    out.append(f"\n## {L('16. 安装足迹预测', '16. Install-footprint prediction')}\n")
    fp = rep["install_footprint"]
    if isinstance(fp, list) and fp:
        out += [f"- {L('[预测]', '[predicted]') if x.get('kind') == 'predicted' else L('[观察]', '[observed]')} {t(x)}" for x in fp[:30]]
    else:
        out.append(na)
    out.append(f"\n## {L('17. 缺失的检查项', '17. Missing checks')}\n")
    if rep["missing_checks"]:
        out += [f"- `{x['code']}` [{x['stage']}] {t(x)}" + (f" — `{x['path']}`" if x.get("path") else "") for x in rep["missing_checks"]]
    else:
        out.append(L("无", "None"))
    out.append(f"\n## {L('18. 已知检测局限', '18. Known limitations')}\n")
    out += [f"- {t(x)}" for x in rep["limitations"]]
    out.append(f"\n## {L('19. SHA-256 校验命令', '19. SHA-256 verification commands')}\n")
    hc = rep["hash_verify_commands"]
    if isinstance(hc, dict):
        out.append("```\n" + "\n".join(hc.values()) + "\n```")
    else:
        out.append(na)
    out.append(f"\n## {L('20. 检测时间', '20. Scan time')}\n")
    out.append(f"{rep['scanned_at']}（{L('耗时', 'elapsed')} {rep['elapsed_seconds']}s"
               + (f"；{L('提交时预估', 'estimated at submit')} {rep['timing']['estimated_seconds']}s" if (rep.get('timing') or {}).get('estimated_seconds') else "") + "）")
    if rep.get("error"):
        out.append(f"\n**ERROR:** `{rep['error']['code']}` {t(rep['error'])}")
    out.append(f"\n> {DISCLAIMER['zh' if zh else 'en']}")
    out.append(L("\n> 样本已在扫描后删除，仅保留报告与 Hash。", "\n> The sample was deleted after scanning; only the report and hashes are kept."))
    return "\n".join(out)


# ------------------------------------------------------------------ HTML report + chat summary

SPECIAL_STATUS = {
    "zh": {
        "verified": "已验证", "verified_untrusted": "签名有效但签名者未被信任",
        "invalid": "无效", "failed": "未能完成", "missing_expected": "应有但缺失",
        "not_applicable": "不适用", "unavailable": "不可用", "done": "已完成",
        "not_signed": "未签名",
    },
    "en": {},
}

CHIP_STATUS = {
    "zh": {
        "done": "完成", "partial": "部分", "skipped": "跳过",
        "not_applicable": "不适用", "failed": "缺失", "not_run": "缺失",
    },
    "en": {
        "done": "done", "partial": "partial", "skipped": "skipped",
        "not_applicable": "N/A", "failed": "missing", "not_run": "missing",
    },
}

_SEV_RANK = SEVERITY_ORDER
_SEV_ORDER = ("critical", "high", "medium", "low", "info")
_SIG_CHECKS = (
    "npm_registry_signature", "npm_publish_attestation", "npm_provenance",
    "authenticode", "gpg_signature",
)


def _esc(v):
    if v is None:
        return ""
    return html.escape(str(v), quote=True)


def _pick(lang):
    zh = lang != "en"
    L = (lambda a, b: a) if zh else (lambda a, b: b)
    t = lambda d: (d.get("zh") if zh else d.get("en")) if isinstance(d, dict) else ("" if d is None else str(d))
    return zh, L, t


def _fmt_size(size, L):
    if not isinstance(size, int):
        return L("不适用", "N/A")
    return f"{size:,} bytes"


def _scan_time_line(rep, L, na="N/A"):
    scanned = rep.get("scanned_at") or na
    elapsed = rep.get("elapsed_seconds")
    timing = rep.get("timing") or {}
    line = str(scanned)
    extras = []
    if elapsed is not None:
        extras.append(f"{L('耗时', 'elapsed')} {elapsed}s")
    if timing.get("estimated_seconds"):
        extras.append(f"{L('提交时预估', 'estimated at submit')} {timing['estimated_seconds']}s")
    if extras:
        line += "（" + "；".join(extras) + "）"
    return line


def _short_sha(sha, n=16):
    if not sha or sha == "N/A":
        return ""
    return sha if len(sha) <= n else sha[:n] + "…"


def _display_url(val, na):
    if not val or val == "N/A":
        return na
    return val


def _special_status_label(st, zh):
    if zh:
        return SPECIAL_STATUS["zh"].get(st, st)
    return st or ""


def _chip_label(status, zh):
    lang = "zh" if zh else "en"
    return CHIP_STATUS[lang].get(status, status or "")


def _chip_class(status):
    return {
        "done": "ok",
        "partial": "warn",
        "skipped": "skip",
        "not_applicable": "na",
        "failed": "fail",
        "not_run": "fail",
    }.get(status, "skip")


def _special_chip_class(st):
    return {
        "verified": "ok", "done": "ok",
        "verified_untrusted": "warn", "missing_expected": "warn",
        "not_signed": "warn", "unavailable": "warn",
        "invalid": "fail", "failed": "fail",
        "not_applicable": "na",
    }.get(st, "skip")


def _special_to_key(st):
    return {
        "verified": "ok", "done": "ok",
        "verified_untrusted": "warn", "missing_expected": "warn",
        "not_signed": "warn", "unavailable": "warn",
        "invalid": "fail", "failed": "fail",
        "not_applicable": "na",
    }.get(st, "na")


def _worst_key(*statuses):
    rank = {"fail": 4, "warn": 3, "ok": 2, "skip": 1, "na": 0}
    found = [s for s in statuses if s]
    return max(found, key=lambda s: rank.get(s, 0)) if found else "na"


def _max_sev(items):
    if not items:
        return None
    return max(items, key=lambda f: _SEV_RANK.get(f.get("severity"), 0)).get("severity")



def _finding_counts(ev):
    counts = {k: 0 for k in _SEV_ORDER}
    for f in ev or []:
        sev = f.get("severity") or "info"
        counts[sev if sev in counts else "info"] += 1
    return counts


def _count_line(counts, lang="zh", verdict=None):
    zh = lang != "en"
    if verdict == "ERROR":
        return "检测未完成，没有结果" if zh else "Scan did not complete; no results"
    total = sum(counts.get(k, 0) for k in _SEV_ORDER)
    if total == 0:
        return "未发现问题" if zh else "No findings"
    labels = {
        "critical": ("严重", "critical"),
        "high": ("高危", "high"),
        "medium": ("中危", "medium"),
        "low": ("低危", "low"),
        "info": ("信息", "info"),
    }
    parts = []
    for k in _SEV_ORDER:
        n = counts.get(k, 0)
        if n:
            parts.append(f"{n} {labels[k][0 if zh else 1]}")
    if zh:
        return f"发现 {total} 条：" + "、".join(parts)
    noun = "finding" if total == 1 else "findings"
    return f"{total} {noun}: " + ", ".join(parts)


# Check-family order used to group evidence in the HTML report.
_FAMILY_ORDER = ("av", "hooks", "obf", "net", "deps", "sig", "archive", "other")
_FAMILY_LABEL = {
    "av": ("杀毒/YARA", "Antivirus/YARA"),
    "hooks": ("安装钩子/足迹", "Install hooks/footprint"),
    "obf": ("混淆/编码", "Obfuscation"),
    "net": ("网络与凭据", "Network/credential"),
    "deps": ("依赖", "Dependencies"),
    "sig": ("签名与来源证明", "Signature/provenance"),
    "archive": ("解包/归档", "Archive"),
    "other": ("其他", "Other"),
}


def _evidence_family(f):
    code = str((f or {}).get("code") or "")
    if code.startswith(("CLAMAV", "YARA:", "YARA_B64:", "KNOWN_BAD", "KNOWN_MALICIOUS_HASH")):
        return "av"
    if code.startswith(("DEP_", "PACKAGE_KNOWN_MALICIOUS")):
        return "deps"
    if code.startswith(("ARCHIVE_", "UNPACK_")):
        return "archive"
    if code.startswith((
        "NPM_REGISTRY", "NPM_PROVENANCE", "NPM_PUBLISH", "AUTHENTICODE", "GPG_",
        "PE_UNSIGNED", "SOURCE_DIFF", "LOCKFILE_",
    )):
        return "sig"
    if code.startswith((
        "NETWORK_IOC", "CREDENTIAL_", "MINER_POOL", "SOURCE_IP",
        "SOURCE_NONSTANDARD", "SOURCE_PLAINTEXT", "PE_KEYLOGGER",
    )):
        return "net"
    if code.startswith((
        "OBFUSCATION_", "JS_EMPTY_CATCH", "PE_HIGH_ENTROPY", "PE_NO_IMPORTS",
        "PE_TLS", "ELF_UPX", "ELF_PRELOAD",
    )):
        return "obf"
    if (
        "HOOK" in code
        or code.startswith((
            "INSTALL_HOOK", "NPM_HOOK", "PYPI_CUSTOM_INSTALL", "ANTI_FORENSICS",
            "PERSISTENCE", "POWERSHELL_STEALTH", "DEFENSE_EVASION", "MANIFEST_DECOY",
        ))
    ):
        return "hooks"
    if code.startswith("DIFF_"):
        return "deps"
    return "other"


def build_summary(rep, lang="zh"):

    """Compact object for chat: verdict, key checks, top evidence, missing checks."""
    zh, L, t = _pick(lang)
    ev = list(rep.get("evidence") or [])
    missing = list(rep.get("missing_checks") or [])
    specials = list(rep.get("special_checks") or [])
    by_check = {c.get("check"): c for c in specials}
    size = rep.get("file_size")
    coverage = rep.get("coverage") or {}

    def ev_match(pred):
        return [f for f in ev if pred(f)]

    def miss_match(pred):
        return [m for m in missing if pred(m)]

    # --- antivirus / YARA
    s3 = coverage.get("S3") or {}
    av = ev_match(lambda f: str(f.get("code", "")).startswith(("CLAMAV:", "YARA:", "YARA_B64:")))
    av_miss = miss_match(lambda m: str(m.get("code", "")).startswith("CLAMAV") or m.get("code") in ("YARA_FAILED", "YARA_TIMEOUT"))
    av_sev = _max_sev(av)
    if s3.get("status") in ("failed", "not_run"):
        av_st, av_tx = "fail", L("静态分析未完成，杀毒/YARA 结果不可用", "Static analysis did not finish; antivirus/YARA result unavailable")
    elif av_sev in ("critical", "high"):
        av_st, av_tx = "fail", t(av[0]) if av else L("杀毒或 YARA 检出高危", "Antivirus or YARA reported a high-severity hit")
    elif av_miss:
        av_st, av_tx = "warn", t(av_miss[0])
    elif av_sev == "medium":
        av_st, av_tx = "warn", t(av[0])
    elif s3.get("status") in ("done", "partial"):
        av_st, av_tx = "ok", L("ClamAV / YARA 未检出恶意", "ClamAV / YARA reported no malware")
    else:
        av_st, av_tx = "skip", L("杀毒/YARA 未执行", "Antivirus/YARA was not run")

    # --- signature & provenance
    sigs = [by_check[k] for k in _SIG_CHECKS if k in by_check]
    if not sigs:
        sig_st, sig_tx = "na", L("无签名或来源证明检查", "No signature or provenance checks")
    else:
        sig_st = _worst_key(*(_special_to_key(c.get("status")) for c in sigs))
        bits = []
        for c in sigs:
            lab = _special_status_label(c.get("status"), zh)
            bits.append(f"{c.get('check')}: {lab}")
        sig_tx = "；".join(bits) if zh else "; ".join(bits)

    # --- source tag diff
    src = by_check.get("source_tag_diff")
    src_ev = ev_match(lambda f: str(f.get("code", "")).startswith("SOURCE_DIFF"))
    src_sev = _max_sev(src_ev)
    if src is None:
        src_st, src_tx = "na", L("未做源码 tag 比对", "Source-tag diff not performed")
    elif src_sev in ("critical", "high") or _special_to_key(src.get("status")) == "fail":
        src_st, src_tx = "fail", t(src_ev[0]) if src_ev else (src.get("detail_zh") if zh else src.get("detail_en")) or src.get("status")
    elif src_sev == "medium" or _special_to_key(src.get("status")) == "warn":
        src_st = "warn"
        src_tx = t(src_ev[0]) if src_ev else (src.get("detail_zh") if zh else src.get("detail_en")) or src.get("status")
    else:
        src_st = _special_to_key(src.get("status"))
        src_tx = (src.get("detail_zh") if zh else src.get("detail_en")) or _special_status_label(src.get("status"), zh)

    # --- dependencies
    ds = rep.get("dependency_stats")
    dep_ev = ev_match(lambda f: str(f.get("code", "")).startswith((
        "DEP_", "PACKAGE_KNOWN_MALICIOUS", "NETWORK_IOC", "DEP_PHANTOM", "DEP_HOOK")))
    dep_miss = miss_match(lambda m: str(m.get("code", "")).startswith("DEP_"))
    dep_sev = _max_sev(dep_ev)
    if not isinstance(ds, dict):
        dep_st, dep_tx = "na", L("不适用（样本无依赖清单）", "N/A (no dependency manifest)")
    elif dep_sev in ("critical", "high"):
        dep_st, dep_tx = "fail", t(dep_ev[0])
    elif dep_miss or ds.get("failed") or ds.get("skipped_quota"):
        dep_st = "warn"
        dep_tx = (t(dep_miss[0]) if dep_miss else L(
            f"去重依赖 {ds.get('total_unique', 0)} 个；新检测 {ds.get('new_checked', 0)}；失败 {ds.get('failed', 0)}；超额跳过 {ds.get('skipped_quota', 0)}",
            f"Unique deps {ds.get('total_unique', 0)}; newly checked {ds.get('new_checked', 0)}; failed {ds.get('failed', 0)}; skipped by quota {ds.get('skipped_quota', 0)}"))
    else:
        dep_st, dep_tx = "ok", L(
            f"去重依赖 {ds.get('total_unique', 0)} 个，新检测 {ds.get('new_checked', 0)} 个，未发现恶意依赖",
            f"{ds.get('total_unique', 0)} unique deps, {ds.get('new_checked', 0)} newly checked; no malicious dependencies")

    # --- install hooks / footprint
    hooks = rep.get("install_hooks") or {}
    hook_ev = ev_match(lambda f: (
        "HOOK" in str(f.get("code", "")) or str(f.get("code", "")).startswith((
            "INSTALL_HOOK", "NPM_HOOK", "PYPI_CUSTOM_INSTALL", "ANTI_FORENSICS", "PERSISTENCE"))))
    hook_sev = _max_sev(hook_ev)
    fp = rep.get("install_footprint")
    fp_n = len(fp) if isinstance(fp, list) else 0
    if hook_sev in ("critical", "high"):
        hook_st, hook_tx = "fail", t(hook_ev[0])
    elif hook_sev == "medium":
        hook_st, hook_tx = "warn", t(hook_ev[0])
    elif hooks or hook_ev:
        n_hooks = len(hooks) if isinstance(hooks, dict) else 0
        hook_st, hook_tx = "ok", L(f"发现 {n_hooks or len(hook_ev)} 个安装钩子，未见中高危行为",
                                   f"{n_hooks or len(hook_ev)} install hook(s); no medium/high-risk behaviour")
    elif fp_n:
        hook_st, hook_tx = "ok", L(f"已预测 {fp_n} 项安装足迹", f"{fp_n} install-footprint prediction(s)")
    elif (coverage.get("S5") or {}).get("status") == "not_applicable":
        hook_st, hook_tx = "na", L("不适用", "N/A")
    else:
        hook_st, hook_tx = "ok", L("未发现安装钩子或可疑足迹", "No install hooks or suspicious footprint")

    # --- archive / unpack
    un = rep.get("unpack_stats")
    arch_ev = ev_match(lambda f: str(f.get("code", "")).startswith(("ARCHIVE_", "UNPACK_")))
    arch_miss = miss_match(lambda m: str(m.get("code", "")).startswith(("ARCHIVE_", "UNPACK_")))
    arch_sev = _max_sev(arch_ev)
    if arch_sev in ("critical", "high"):
        arch_st, arch_tx = "fail", t(arch_ev[0])
    elif arch_miss:
        arch_st, arch_tx = "warn", t(arch_miss[0])
    elif isinstance(un, dict) and (un.get("archives_unpacked") or un.get("files")):
        arch_st, arch_tx = "ok", L(
            f"已解包 {un.get('archives_unpacked', 0)} 个归档，{un.get('files', 0)} 个文件，共 {un.get('total_unpacked_bytes', 0):,} bytes",
            f"Unpacked {un.get('archives_unpacked', 0)} archive(s), {un.get('files', 0)} files, {un.get('total_unpacked_bytes', 0):,} bytes")
    elif arch_ev:
        arch_st, arch_tx = "warn", t(arch_ev[0])
    else:
        arch_st, arch_tx = "na", L("不是压缩包，或无需解包", "Not an archive, or unpack was not required")

    # --- version diff
    vd = rep.get("version_diff")
    vd_ev = ev_match(lambda f: str(f.get("code", "")).startswith(("VERSION_DIFF", "NEW_INSTALL_HOOK", "NEW_DEPENDENCY")))
    vd_sev = _max_sev(vd_ev)
    if not isinstance(vd, dict) or vd.get("status") in (None, "N/A", "not_applicable"):
        vd_st, vd_tx = "na", L("不适用", "N/A")
    elif str(vd.get("status", "")).startswith("skipped"):
        vd_st, vd_tx = "skip", vd.get("status")
    elif vd.get("status") == "compared":
        if vd_sev in ("critical", "high") or vd.get("new_install_hooks"):
            vd_st = "fail" if vd_sev in ("critical", "high") else "warn"
            vd_tx = t(vd_ev[0]) if vd_ev else L(
                f"相对 {vd.get('baseline_version')}：新增钩子 {', '.join(vd.get('new_install_hooks') or []) or '无'}",
                f"vs {vd.get('baseline_version')}: new hooks {', '.join(vd.get('new_install_hooks') or []) or 'none'}")
        else:
            vd_st, vd_tx = "ok", L(
                f"已与 {vd.get('baseline_version')} 对比：新增 {len(vd.get('added_files') or [])}，修改 {len(vd.get('changed_files') or [])}",
                f"Compared with {vd.get('baseline_version')}: added {len(vd.get('added_files') or [])}, changed {len(vd.get('changed_files') or [])}")
    else:
        vd_st, vd_tx = "skip", str(vd.get("status") or L("未对比", "not compared"))

    key_checks = [
        {"name": L("杀毒/YARA", "Antivirus/YARA"), "status": av_st, "text": av_tx},
        {"name": L("签名与来源证明", "Signature & provenance"), "status": sig_st, "text": sig_tx},
        {"name": L("源码 tag 比对", "Source tag diff"), "status": src_st, "text": src_tx},
        {"name": L("依赖", "Dependencies"), "status": dep_st, "text": dep_tx},
        {"name": L("安装钩子/足迹", "Install hooks/footprint"), "status": hook_st, "text": hook_tx},
        {"name": L("解包", "Archive/unpack"), "status": arch_st, "text": arch_tx},
        {"name": L("版本差异", "Version diff"), "status": vd_st, "text": vd_tx},
    ]

    ev_sorted = sorted(ev, key=lambda f: -_SEV_RANK.get(f.get("severity"), 0))
    top_evidence = [{"severity": f.get("severity"), "title": t(f), "path": f.get("path") or ""} for f in ev_sorted[:3]]
    missing_out = [{"code": m.get("code"), "text": t(m)} for m in missing]
    conclusion = t(rep.get("verdict_reason") or {})
    if conclusion and not conclusion.endswith(("。", ".", "！", "!", "？", "?")):
        conclusion += "。" if zh else "."

    counts = _finding_counts(ev)
    if rep.get("verdict") == "ERROR":
        na_tx = L("检测未完成，没有结果", "Scan did not complete; no result")
        key_checks = [dict(k, status="na", text=na_tx) for k in key_checks]
    return {
        "verdict": rep.get("verdict"),
        "risk_level": rep.get("risk_level"),
        "filename": rep.get("file_name"),
        "size_bytes": size if isinstance(size, int) else None,
        "sha256": rep.get("sha256") if rep.get("sha256") != "N/A" else None,
        "conclusion": conclusion,
        "key_checks": key_checks,
        "top_evidence": top_evidence,
        "missing_checks": missing_out,
        "counts": counts,
        "count_line": _count_line(counts, lang, rep.get("verdict")),
    }


def write_html_report(rep, lang="zh", confirmations=None, dest=None):
    """Render and write data/reports/<scan_id>.<lang>.html. Returns the absolute Path."""
    lang = "en" if (lang or "zh").lower().startswith("en") else "zh"
    html_doc = render_html(rep, lang, confirmations)
    dest = Path(dest) if dest else (config.DATA_DIR / "reports" / f"{rep['scan_id']}.{lang}.html")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(html_doc, encoding="utf-8")
    return dest.resolve()


def render_html(rep, lang="zh", confirmations=None):
    """One self-contained HTML file (inline CSS, no external fonts/JS/CDN, no network)."""
    zh, L, t = _pick(lang)
    na = L("不适用", "N/A")
    v = rep.get("verdict") or "ERROR"
    risk = rep.get("risk_level") or ""
    fname = rep.get("file_name") or "N/A"
    size = rep.get("file_size")
    sha = rep.get("sha256") or "N/A"
    html_lang = "zh-CN" if zh else "en"
    title = f"FileGuard {L('检测报告', 'Scan report')} — {v} — {fname}"
    conclusion = t(rep.get("verdict_reason") or {})
    advice = ADVICE.get(v, ADVICE["ERROR"])[0 if zh else 1]
    if conclusion and not conclusion.endswith(("。", ".", "！", "!", "？", "?")):
        conclusion += "。" if zh else "."
    banner_role = "alert" if v in ("BLOCK", "HIGH_RISK") else "status"
    scanned = rep.get("scanned_at") or ""
    elapsed = rep.get("elapsed_seconds")
    timing = rep.get("timing") or {}

    def chip(status, label=None):
        st = status or "skipped"
        return f'<span class="chip {_chip_class(st)}">{_esc(label or _chip_label(st, zh))}</span>'

    # ----- banner notes
    notes = []
    if rep.get("cache_hit"):
        ch = rep["cache_hit"]
        notes.append(
            L(f"同一 SHA-256 已于扫描 {_esc(ch.get('from_scan_id'))} 完整检测过，本次复用其结果。",
              f"Same SHA-256 was fully scanned in {_esc(ch.get('from_scan_id'))}; this result is reused."))
    if confirmations:
        for c in confirmations:
            notes.append(
                L(f"用户确认记录：{_esc(c.get('confirmed_by'))} 于 {_esc(c.get('created_at_str'))} 针对 SHA-256 "
                  f"{_esc(_short_sha(c.get('sha256')))} 确认接受缺失项风险（状态仍为 INCOMPLETE）。",
                  f"User confirmation: {_esc(c.get('confirmed_by'))} at {_esc(c.get('created_at_str'))} accepted the "
                  f"missing-check risk for SHA-256 {_esc(_short_sha(c.get('sha256')))} (verdict remains INCOMPLETE)."))
    if rep.get("stale"):
        notes.append(_esc(t(rep["stale"])))

    notes_html = "".join(f'<p class="note">{n}</p>' for n in notes)

    # ----- 1–8 + 20 key facts (20 also repeated as its own section)
    orig = _display_url(rep.get("original_url"), na)
    final = _display_url(rep.get("final_url"), na)
    facts = [
        (L("1. 文件名", "1. File name"), fname, True),
        (L("2. 文件类型", "2. File type"), rep.get("file_type") or na, False),
        (L("3. 文件大小", "3. File size"), _fmt_size(size, L), False),
        (L("4. 原始 URL", "4. Original URL"), orig, True),
        (L("5. 最终下载 URL", "5. Final download URL"), final, True),
        ("6. SHA-256", sha if sha != "N/A" else na, True),
        (L("7. 最终结论", "7. Verdict"), v, False),
        (L("8. 风险等级", "8. Risk level"), risk or na, False),
        (L("扫描编号", "Scan ID"), rep.get("scan_id") or na, True),
        (L("20. 检测时间", "20. Scan time"), _scan_time_line(rep, L, na), False),
    ]
    fact_cells = []
    for label, value, mono in facts:
        cls = "mono wrap" if mono else "wrap"
        fact_cells.append(
            f'<div class="fact"><div class="fact-k">{_esc(label)}</div>'
            f'<div class="fact-v {cls}">{_esc(value)}</div></div>')
    facts_html = "".join(fact_cells)

    # ----- 9. coverage timeline
    cov_items = []
    for s in STAGES:
        c = (rep.get("coverage") or {}).get(s, {})
        st = c.get("status")
        cov_items.append(
            f'<li class="stage">'
            f'<div class="stage-id">{_esc(s)}</div>'
            f'<div class="stage-body"><div class="stage-head">'
            f'<span class="stage-name">{_esc(STAGE_NAMES[s][0 if zh else 1])}</span>'
            f'{chip(st)}</div>'
            f'<p class="stage-note">{_esc(t(c))}</p></div></li>')
    coverage_html = "<ol class='timeline'>" + "".join(cov_items) + "</ol>"

    # ----- 10. tools (details)
    tools = rep.get("tools") or {}
    tool_rows = "".join(f"<li><span class='k'>{_esc(k)}</span> <span class='mono'>{_esc(v2)}</span></li>"
                        for k, v2 in tools.items())
    tools_html = (
        f"<details><summary>{L('10. 检测工具和规则版本', '10. Tools &amp; rule versions')}"
        f" <span class='muted'>{_esc(tools.get('engine', ''))}</span></summary>"
        f"<ul class='kv'>{tool_rows}</ul></details>"
    )

    # ----- 11. evidence grouped by check family, each family sorted by severity
    ev = list(rep.get("evidence") or [])
    counts = _finding_counts(ev)
    count_line = _count_line(counts, "zh" if zh else "en", rep.get("verdict"))

    def evidence_item(f):
        loc = f'<div class="mono path">{_esc(f["path"])}</div>' if f.get("path") else ""
        evd = ""
        if f.get("evidence"):
            evd = (
                f'<details class="snip"><summary>{_esc(L("原始片段", "Raw snippet"))}</summary>'
                f'<pre class="code">{_esc(str(f["evidence"])[:2000])}</pre></details>'
            )
        kind = f'<span class="chip skip">{_esc(L("预测", "predicted"))}</span>' if f.get("kind") == "predicted" else ""
        sev = f.get("severity") or "info"
        sev_word = SEV_LABEL["zh" if zh else "en"].get(sev, sev)
        return (
            f'<article class="ev sev-{_esc(sev)}">'
            f'<div class="ev-top"><span class="chip sev-{_esc(sev)}">{_esc(sev_word)}</span>'
            f'<span class="muted">{_esc(f.get("stage") or "")}</span>'
            f'{kind}<span class="mono rid">{_esc(f.get("code") or "")}</span></div>'
            f'<p class="ev-title">{_esc(t(f))}</p>{loc}{evd}</article>'
        )

    if not ev:
        evidence_body = f"<p class='empty'>{_esc(L('未发现可疑证据。', 'No suspicious evidence.'))}</p>"
    else:
        grouped = {k: [] for k in _FAMILY_ORDER}
        for f in ev:
            grouped[_evidence_family(f)].append(f)
        parts = []
        for fam in _FAMILY_ORDER:
            items = grouped[fam]
            if not items:
                continue
            items = sorted(items, key=lambda f: -_SEV_RANK.get(f.get("severity"), 0))
            lab = _FAMILY_LABEL[fam][0 if zh else 1]
            parts.append(
                f'<section class="ev-group">'
                f'<h3>{_esc(lab)} <span class="muted">{len(items)}</span></h3>'
                + "".join(evidence_item(f) for f in items)
                + "</section>"
            )
        evidence_body = "".join(parts)

    # severity count tiles (always render all five, worst first; zeros muted)
    tile_labels = {
        "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
        "low": "LOW", "info": "INFO",
    }
    tile_bits = []
    for sev in _SEV_ORDER:
        n = counts.get(sev, 0)
        muted = " muted" if n == 0 else ""
        tile_bits.append(
            f'<div class="tile sev-{sev}{muted}">'
            f'<div class="tile-n">{n}</div>'
            f'<div class="tile-k">{tile_labels[sev]}</div></div>'
        )
    tiles_html = (
        f'<section class="counts" aria-label="{_esc(L("发现统计", "Finding counts"))}">'
        f'<p class="count-line">{_esc(count_line)}</p>'
        f'<div class="tiles">{"".join(tile_bits)}</div></section>'
    )

    # ----- special checks
    sc = rep.get("special_checks") or []
    if sc:
        sc_items = []
        for c in sc:
            stt = _special_status_label(c.get("status"), zh)
            path = f'<div class="mono path">{_esc(c["path"])}</div>' if c.get("path") else ""
            detail = c.get("detail_zh") if zh else c.get("detail_en")
            sc_items.append(
                f'<article class="ev">'
                f'<div class="ev-top"><span class="mono rid">{_esc(c.get("check"))}</span>'
                f'<span class="chip {_special_chip_class(c.get("status"))}">{_esc(stt)}</span></div>'
                f'<p class="ev-title">{_esc(detail or "")}</p>{path}</article>'
            )
        special_html = (
            f"<section class='block'><h2>{_esc(L('签名 / 来源证明 / 锁文件 / 源码 tag 比对', 'Signatures / provenance / lock files / source-tag diff'))}</h2>"
            + "".join(sc_items) + "</section>"
        )
    else:
        special_html = ""

    # ----- 12. dependency stats
    ds = rep.get("dependency_stats")
    if isinstance(ds, dict):
        dep_p = L(
            f"生态：{', '.join(ds.get('ecosystems', []) or []) or na}；去重依赖 {ds.get('total_unique', 0)} 个；"
            f"新检测 {ds.get('new_checked', 0)} 个（上限 {config.MAX_NEW_DEPS}）；超额跳过 {ds.get('skipped_quota', 0)} 个；"
            f"第 {config.MAX_DEP_DEPTH} 层以下轻量检查 {ds.get('light_checked', 0)} 个（不占 200 额度，上限 {config.MAX_LIGHT_DEPS}）；"
            f"获取失败 {ds.get('failed', 0)} 个；最大深度 {ds.get('max_depth_seen', 0)}",
            f"Ecosystems: {', '.join(ds.get('ecosystems', []) or []) or na}; unique deps {ds.get('total_unique', 0)}; "
            f"newly checked {ds.get('new_checked', 0)} (limit {config.MAX_NEW_DEPS}); skipped by quota {ds.get('skipped_quota', 0)}; "
            f"light-checked beyond depth {config.MAX_DEP_DEPTH}: {ds.get('light_checked', 0)} "
            f"(not counted toward the 200 quota; cap {config.MAX_LIGHT_DEPS}); failed {ds.get('failed', 0)}; "
            f"max depth {ds.get('max_depth_seen', 0)}")
        dep_html = f"<p>{_esc(dep_p)}</p>"
        lc = rep.get("light_checked_dependencies")
        if isinstance(lc, list) and lc:
            names = ", ".join(f"{d.get('name')}@{d.get('version')}" for d in lc[:30]) + (" …" if len(lc) > 30 else "")
            dep_html += (
                f"<p>{_esc(L(f'第 {config.MAX_DEP_DEPTH} 层以下仅做轻量检查（已知恶意包 + OSV 恶意包 + 安装钩子）：', f'Light-checked beyond depth {config.MAX_DEP_DEPTH} (known-malicious + OSV malicious + install hooks):'))} "
                f"<span class='mono wrap'>{_esc(names)}</span></p>")
    else:
        dep_html = f"<p class='empty'>{_esc(na)}</p>"

    # ----- 13. cache
    cs = rep.get("cache_stats") or {}
    cache_p = L(
        f"文件 Hash 缓存命中：{'是' if cs.get('file_hash_cache_hit') else '否'}；依赖缓存命中 {cs.get('dependency_cache_hits', 0)} 个（不占 200 额度）",
        f"File-hash cache hit: {'yes' if cs.get('file_hash_cache_hit') else 'no'}; dependency cache hits {cs.get('dependency_cache_hits', 0)} (not counted toward the 200 quota)")

    # ----- 14. unchecked deps
    ud = rep.get("unchecked_dependencies")
    if isinstance(ud, list) and ud:
        ud_items = "".join(
            f"<li><span class='mono'>{_esc(d.get('ecosystem'))}:{_esc(d.get('name'))} {_esc(d.get('version') or d.get('spec') or '')}</span>"
            f" — {_esc(L('原因', 'reason'))}: {_esc(d.get('reason'))}, {_esc(L('深度', 'depth'))} {_esc(d.get('depth'))}</li>"
            for d in ud[:40])
        more = f"<li class='muted'>{_esc(L(f'共 {len(ud)} 个，以上为前 40 个', f'{len(ud)} total; first 40 shown'))}</li>" if len(ud) > 40 else ""
        ud_html = f"<ul class='plain'>{ud_items}{more}</ul>"
    else:
        ud_html = f"<p class='empty'>{_esc(na if ud == 'N/A' else L('无', 'None'))}</p>"

    # ----- 15. version diff
    vd = rep.get("version_diff")
    if isinstance(vd, dict) and vd.get("status") == "compared":
        added = len(vd.get("added_files") or [])
        removed = len(vd.get("removed_files") or [])
        changed = vd.get("changed_files") or []
        ch_s = ", ".join(changed[:5])
        new_deps = ", ".join(vd.get("new_dependencies") or []) or L("无", "none")
        new_hooks = ", ".join(vd.get("new_install_hooks") or []) or L("无", "none")
        ch_bit_zh = f"（{ch_s}）" if changed else ""
        ch_bit_en = f" ({ch_s})" if changed else ""
        vd_txt = L(
            f"基线版本 {vd.get('baseline_version')}：新增文件 {added}，删除 {removed}，修改 {len(changed)}{ch_bit_zh}；新增依赖 {new_deps}；新增安装钩子 {new_hooks}",
            f"Baseline {vd.get('baseline_version')}: added {added}, removed {removed}, changed {len(changed)}{ch_bit_en}; new deps {new_deps}; new install hooks {new_hooks}",
        )
        vd_html = f"<p>{_esc(vd_txt)}</p>"
    elif isinstance(vd, dict):
        txt = na if vd.get("status") == "not_applicable" else (vd.get("status") or na)
        vd_html = f"<p class='empty'>{_esc(txt)}</p>"
    else:
        vd_html = f"<p class='empty'>{_esc(na)}</p>"

    # ----- 16. footprint (details)
    fp = rep.get("install_footprint")
    if isinstance(fp, list) and fp:
        fp_items = "".join(
            f"<li><span class='chip skip'>{_esc(L('预测', 'predicted') if x.get('kind') == 'predicted' else L('观察', 'observed'))}</span> {_esc(t(x))}</li>"
            for x in fp[:80])
        fp_html = (
            f"<details><summary>{_esc(L('16. 安装足迹预测', '16. Install-footprint prediction'))} "
            f"<span class='muted'>{len(fp)}</span></summary><ul class='plain fp'>{fp_items}</ul></details>"
        )
    else:
        fp_html = (
            f"<section class='block'><h2>{_esc(L('16. 安装足迹预测', '16. Install-footprint prediction'))}</h2>"
            f"<p class='empty'>{_esc(na)}</p></section>"
        )

    # ----- 17. missing checks
    missing = list(rep.get("missing_checks") or [])
    if missing:
        miss_items = "".join(
            f"<li><span class='mono rid'>{_esc(x.get('code'))}</span> "
            f"<span class='muted'>[{_esc(x.get('stage'))}]</span> {_esc(t(x))}"
            + (f' <span class="mono path">{_esc(x["path"])}</span>' if x.get("path") else "")
            + "</li>"
            for x in missing)
        miss_html = f"<ul class='plain missing-list'>{miss_items}</ul>"
        miss_cls = "block alert"
    else:
        miss_html = f"<p class='empty'>{_esc(L('无', 'None'))}</p>"
        miss_cls = "block"

    # ----- 18. limitations (details)
    limits = list(rep.get("limitations") or [])
    lim_items = "".join(f"<li>{_esc(t(x))}</li>" for x in limits)
    lim_html = (
        f"<details><summary>{_esc(L('18. 已知检测局限', '18. Known limitations'))} "
        f"<span class='muted'>{len(limits)}</span></summary><ul class='plain'>{lim_items}</ul></details>"
    )

    # ----- 19. hash commands
    hc = rep.get("hash_verify_commands")
    if isinstance(hc, dict):
        hash_html = "<pre class='code'>" + _esc("\n".join(hc.values())) + "</pre>"
    else:
        hash_html = f"<p class='empty'>{_esc(na)}</p>"

    # ----- 20. scan time (full line, also in facts)
    time_line = _scan_time_line(rep, L, na)

    err_html = ""
    if rep.get("error"):
        err = rep["error"]
        err_html = f'<p class="error-line"><strong>ERROR:</strong> <span class="mono">{_esc(err.get("code"))}</span> {_esc(t(err))}</p>'

    disclaimer = DISCLAIMER["zh" if zh else "en"]
    deleted = L("样本已在扫描后删除，仅保留报告与 Hash。",
                "The sample was deleted after scanning; only the report and hashes are kept.")

    css = _HTML_CSS
    short = _short_sha(sha) if sha != "N/A" else na
    size_s = _fmt_size(size, L)

    return f"""<!DOCTYPE html>
<html lang="{html_lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{_esc(title)}</title>
<style>
{css}
</style>
</head>
<body>
<main class="page">
  <header class="top">
    <div class="brand">FileGuard</div>
    <div class="brand-sub">{_esc(L('静态检测报告', 'Static scan report'))}</div>
  </header>

  <section class="banner v-{_esc(v)}" role="{banner_role}" aria-label="{_esc(v)} — {_esc(L('结论', 'Verdict'))}">
    <div class="banner-row">
      <div class="verdict">{_esc(v)}</div>
      <div class="risk">{_esc(risk)}</div>
    </div>
    <div class="banner-meta">
      <span class="fn wrap">{_esc(fname)}</span>
      <span class="dot" aria-hidden="true"></span>
      <span>{_esc(size_s)}</span>
      <span class="dot" aria-hidden="true"></span>
      <span class="mono">{_esc(short)}</span>
    </div>
    <p class="conclusion">{_esc(conclusion)} {_esc(advice)}</p>
    {notes_html}
  </section>

  {tiles_html}

  <section class="block">
    <h2>{_esc(L('文件信息', 'File facts'))}</h2>
    <div class="facts">{facts_html}</div>
  </section>

  <section class="block">
    <h2>{_esc(L('9. S0–S7 覆盖情况', '9. S0–S7 coverage'))}</h2>
    {coverage_html}
  </section>

  <section class="block">
    <h2>{_esc(L('11. 恶意或可疑证据', '11. Malicious / suspicious evidence'))}</h2>
    {evidence_body}
  </section>

  {special_html}

  <section class="block">
    <h2>{_esc(L('12. 依赖统计', '12. Dependency statistics'))}</h2>
    {dep_html}
  </section>

  <section class="block">
    <h2>{_esc(L('13. 缓存命中统计', '13. Cache statistics'))}</h2>
    <p>{_esc(cache_p)}</p>
  </section>

  <section class="block">
    <h2>{_esc(L('14. 未检测的依赖列表', '14. Unchecked dependencies'))}</h2>
    {ud_html}
  </section>

  <section class="block">
    <h2>{_esc(L('15. 历史版本对比', '15. Version diff'))}</h2>
    {vd_html}
  </section>

  {fp_html}

  <section class="{miss_cls}">
    <h2>{_esc(L('17. 缺失的检查项', '17. Missing checks'))}</h2>
    {miss_html}
  </section>

  {lim_html}
  {tools_html}

  <section class="block">
    <h2>{_esc(L('19. SHA-256 校验命令', '19. SHA-256 verification commands'))}</h2>
    {hash_html}
  </section>

  <section class="block">
    <h2>{_esc(L('20. 检测时间', '20. Scan time'))}</h2>
    <p>{_esc(time_line)}</p>
    {err_html}
  </section>

  <footer class="foot">
    <p>{_esc(disclaimer)}</p>
    <p>{_esc(deleted)}</p>
  </footer>
</main>
</body>
</html>
"""



_HTML_CSS = """
:root {
  --bg: #f4f5f7;
  --card: #ffffff;
  --text: #1c1f26;
  --muted: #5c6570;
  --line: #e4e7ec;
  --soft: #f0f2f5;
  --focus: #0969da;
  --ok: #067647; --ok-bg: #e8f8ef; --ok-bd: #abefc6;
  --warn: #7a5800; --warn-bg: #fff8e1; --warn-bd: #e9c600;
  --fail: #c40000; --fail-bg: #fdecea; --fail-bd: #e40000;
  --skip: #4a5565; --skip-bg: #f2f4f7; --skip-bd: #d0d5dd;
  --na: #3d5a80; --na-bg: #eef3f8; --na-bd: #c5d4e3;
  --sev-critical: #e40000; --sev-critical-fg: #ffffff;
  --sev-high: #ff8800; --sev-high-fg: #1a1a1a;
  --sev-medium: #e9c600; --sev-medium-fg: #1a1a1a;
  --sev-low: #5fbb31; --sev-low-fg: #1a1a1a;
  --sev-info: #747474; --sev-info-fg: #ffffff;
  --verdict-block: #c40000;
  --verdict-high: #9a4e00;
  --verdict-incomplete: #7a5800;
  --verdict-ok: #067647;
  --verdict-error: #4a5565;
  --bar-block: #e40000;
  --bar-high: #ff8800;
  --bar-incomplete: #e9c600;
  --bar-ok: #5fbb31;
  --bar-error: #747474;
  --mono: ui-monospace, "SFMono-Regular", "Cascadia Mono", Consolas, "Liberation Mono", Menlo, monospace;
  --sans: "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Noto Sans SC", "Noto Sans CJK SC",
          "Microsoft YaHei", system-ui, -apple-system, sans-serif;
  --space: 8px;
  --radius: 8px;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101216; --card: #1a1d24; --text: #eceff3; --muted: #9aa3b0;
    --line: #2a2f3a; --soft: #22262e; --focus: #58a6ff;
    --ok: #5fbb31; --ok-bg: #0d2a1c; --ok-bd: #1b5c3a;
    --warn: #e9c600; --warn-bg: #2a230c; --warn-bd: #7a5800;
    --fail: #ff6b5a; --fail-bg: #2c1010; --fail-bd: #7a271a;
    --skip: #c0c6d0; --skip-bg: #22262e; --skip-bd: #3a404c;
    --na: #a8c0d8; --na-bg: #17202a; --na-bd: #31455c;
    --verdict-block: #ff6b5a;
    --verdict-high: #ff8800;
    --verdict-incomplete: #e9c600;
    --verdict-ok: #5fbb31;
    --verdict-error: #c0c6d0;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font-family: var(--sans); font-size: 16px; line-height: 1.5; }
.page { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
.top { display: flex; align-items: baseline; gap: 8px; margin-bottom: 16px; }
.brand { font-weight: 700; letter-spacing: .08em; text-transform: uppercase; font-size: 12px; color: var(--muted); }
.brand-sub { color: var(--muted); font-size: 14px; }
.banner, .block, details, .counts { background: var(--card); border: 1px solid var(--line);
  border-radius: var(--radius); }
.banner { padding: 16px 24px; margin-bottom: 16px; border-left-width: 8px; }
.banner.v-BLOCK { border-left-color: var(--bar-block); }
.banner.v-HIGH_RISK { border-left-color: var(--bar-high); }
.banner.v-INCOMPLETE { border-left-color: var(--bar-incomplete); }
.banner.v-NO_FINDINGS { border-left-color: var(--bar-ok); }
.banner.v-ERROR { border-left-color: var(--bar-error); background: var(--skip-bg); }
.banner-row { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }
.verdict { font-size: 32px; font-weight: 700; letter-spacing: .02em; line-height: 1.2; color: var(--text); }
.v-BLOCK .verdict { color: var(--verdict-block); }
.v-HIGH_RISK .verdict { color: var(--verdict-high); }
.v-INCOMPLETE .verdict { color: var(--verdict-incomplete); }
.v-NO_FINDINGS .verdict { color: var(--verdict-ok); }
.v-ERROR .verdict { color: var(--verdict-error); }
.risk { font-size: 12px; font-weight: 650; letter-spacing: .06em; text-transform: uppercase;
  color: var(--muted); border: 1px solid var(--line); border-radius: 999px; padding: 0 8px; line-height: 24px; }
.banner-meta { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 8px;
  color: var(--muted); font-size: 14px; }
.banner-meta .fn { color: var(--text); font-weight: 600; unicode-bidi: isolate; }
.dot { width: 4px; height: 4px; border-radius: 50%; background: var(--muted); display: inline-block; }
.conclusion { margin: 16px 0 0; }
.note { margin: 8px 0 0; padding: 8px; background: var(--soft); border-radius: var(--radius);
  font-size: 14px; color: var(--muted); }
.counts { padding: 16px 24px; margin-bottom: 16px; }
.count-line { margin: 0 0 16px; font-weight: 600; }
.tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
.tile { border: 1px solid var(--line); border-radius: var(--radius); padding: 8px;
  text-align: center; background: var(--soft); color: var(--muted); }
.tile-n { font-size: 24px; font-weight: 700; line-height: 1.2; font-variant-numeric: tabular-nums; }
.tile-k { font-size: 11px; font-weight: 700; letter-spacing: .04em; margin-top: 4px; }
.tile.sev-critical:not(.muted) { background: var(--sev-critical); color: var(--sev-critical-fg); border-color: var(--sev-critical); }
.tile.sev-high:not(.muted) { background: var(--sev-high); color: var(--sev-high-fg); border-color: var(--sev-high); }
.tile.sev-medium:not(.muted) { background: var(--sev-medium); color: var(--sev-medium-fg); border-color: var(--sev-medium); }
.tile.sev-low:not(.muted) { background: var(--sev-low); color: var(--sev-low-fg); border-color: var(--sev-low); }
.tile.sev-info:not(.muted) { background: var(--sev-info); color: var(--sev-info-fg); border-color: var(--sev-info); }
.tile.muted { background: var(--soft); color: var(--muted); border-color: var(--line); }
.block { padding: 16px 24px; margin-bottom: 16px; }
.block.alert { border-color: var(--warn-bd); background: var(--warn-bg); }
.block h2, .ev-group h3, details > summary { margin: 0 0 16px; font-size: 16px; font-weight: 700; }
.ev-group { margin: 0 0 16px; }
.ev-group:last-child { margin-bottom: 0; }
.ev-group h3 { margin-bottom: 8px; }
details { padding: 16px 24px; margin-bottom: 16px; }
details.snip { padding: 0; margin: 8px 0 0; border: 0; background: transparent; }
details.snip > summary { margin: 0; font-size: 14px; font-weight: 600; color: var(--muted); }
details > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: 8px; margin: 0; min-height: 24px; }
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: ""; width: 8px; height: 8px; border-right: 2px solid var(--muted);
  border-bottom: 2px solid var(--muted); transform: rotate(-45deg); margin-right: 4px; flex: 0 0 auto; }
details[open] > summary { margin-bottom: 8px; }
details[open] > summary::before { transform: rotate(45deg); }
summary:focus { outline: none; }
summary:focus-visible, details:focus-visible, a:focus-visible, button:focus-visible {
  outline: 2px solid var(--focus); outline-offset: 2px; }
.facts { display: grid; grid-template-columns: 1fr 1fr; gap: 8px 16px; }
.fact { min-width: 0; padding: 8px 0; border-bottom: 1px solid var(--line); }
.fact-k { font-size: 12px; letter-spacing: .04em; color: var(--muted); margin-bottom: 4px; }
.fact-v { unicode-bidi: isolate; }
.mono { font-family: var(--mono); font-size: 13px; word-break: break-all; }
.wrap, .path, .url, .fn { overflow-wrap: anywhere; word-break: break-word; unicode-bidi: isolate; }
.timeline { list-style: none; margin: 0; padding: 0; }
.stage { display: flex; gap: 16px; padding: 8px 0; border-bottom: 1px solid var(--line); }
.stage:last-child { border-bottom: 0; }
.stage-id { flex: 0 0 32px; font-family: var(--mono); font-size: 12px; font-weight: 700;
  color: var(--muted); padding-top: 4px; }
.stage-body { flex: 1; min-width: 0; }
.stage-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.stage-name { font-weight: 600; }
.stage-note { margin: 4px 0 0; color: var(--muted); font-size: 14px; }
.chip { display: inline-block; font-size: 12px; font-weight: 700; letter-spacing: .03em;
  border-radius: 999px; padding: 0 8px; line-height: 24px; border: 1px solid var(--skip-bd);
  background: var(--skip-bg); color: var(--skip); white-space: nowrap; }
.chip.ok { background: var(--ok-bg); color: var(--ok); border-color: var(--ok-bd); }
.chip.warn { background: var(--warn-bg); color: var(--warn); border-color: var(--warn-bd); }
.chip.fail { background: var(--fail-bg); color: var(--fail); border-color: var(--fail-bd); }
.chip.skip { background: var(--skip-bg); color: var(--skip); border-color: var(--skip-bd); }
.chip.na { background: var(--na-bg); color: var(--na); border-color: var(--na-bd); }
.chip.sev-critical { background: var(--sev-critical); color: var(--sev-critical-fg); border-color: var(--sev-critical); }
.chip.sev-high { background: var(--sev-high); color: var(--sev-high-fg); border-color: var(--sev-high); }
.chip.sev-medium { background: var(--sev-medium); color: var(--sev-medium-fg); border-color: var(--sev-medium); }
.chip.sev-low { background: var(--sev-low); color: var(--sev-low-fg); border-color: var(--sev-low); }
.chip.sev-info { background: var(--sev-info); color: var(--sev-info-fg); border-color: var(--sev-info); }
.ev { border: 1px solid var(--line); border-radius: var(--radius); padding: 8px 16px; margin: 0 0 8px; background: var(--card); }
.ev.sev-critical { border-left: 4px solid var(--sev-critical); background: color-mix(in srgb, var(--sev-critical) 8%, var(--card)); }
.ev.sev-high { border-left: 4px solid var(--sev-high); background: color-mix(in srgb, var(--sev-high) 8%, var(--card)); }
.ev.sev-medium { border-left: 4px solid var(--sev-medium); background: color-mix(in srgb, var(--sev-medium) 8%, var(--card)); }
.ev.sev-low { border-left: 4px solid var(--sev-low); background: color-mix(in srgb, var(--sev-low) 8%, var(--card)); }
.ev.sev-info { border-left: 4px solid var(--sev-info); background: color-mix(in srgb, var(--sev-info) 8%, var(--card)); }
.ev-top { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 4px; }
.ev-title { margin: 0 0 4px; }
.rid { color: var(--muted); }
.path { color: var(--muted); font-size: 13px; margin-top: 4px; }
.kv, .plain { margin: 0; padding-left: 24px; }
.kv li, .plain li { margin: 0 0 8px; }
.kv .k { color: var(--muted); display: inline-block; min-width: 9em; }
.fp li { display: flex; gap: 8px; align-items: flex-start; }
.missing-list li { margin: 0 0 8px; }
.empty, .muted { color: var(--muted); }
.code { margin: 8px 0 0; padding: 8px 16px; background: var(--soft); border-radius: var(--radius);
  overflow-x: auto; font-family: var(--mono); font-size: 13px; line-height: 1.5; white-space: pre; }
.banner, .block, details, .ev, .counts { break-inside: avoid; page-break-inside: avoid; }
@media print {
  .code { white-space: pre-wrap; word-break: break-all; overflow: visible; }
  .page { padding: 0; }
}
.error-line { color: var(--verdict-error); }
.foot { margin-top: 16px; padding: 8px 0 0; color: var(--muted); font-size: 14px; }
.foot p { margin: 0 0 8px; }
@media (max-width: 620px) {
  .page { padding: 16px; }
  .facts, .tiles { grid-template-columns: 1fr; }
  .verdict { font-size: 24px; }
  .banner, .block, details, .counts { padding-left: 16px; padding-right: 16px; }
  .tiles { grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 4px; }
  .tile { padding: 8px 4px; }
  .tile-n { font-size: 20px; }
  .tile-k { font-size: 9px; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
"""
