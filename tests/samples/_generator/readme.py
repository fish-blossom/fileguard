import json, sys
from pathlib import Path
d = Path(sys.argv[1]); m = json.load(open(d / "manifest.json"))
m["extra_clean_public_targets"] = [
  {"mode": "submit_pkg", "cmd": "fg submit_pkg npm left-pad 1.3.0 --lang zh", "expect": "NO_FINDINGS（源码比对/注册表查询缺项时 INCOMPLETE）"},
  {"mode": "submit_pkg", "cmd": "fg submit_pkg npm ms 2.1.3 --lang zh", "expect": "NO_FINDINGS"},
  {"mode": "submit_pkg", "cmd": "fg submit_pkg pypi requests 2.32.3 --lang zh", "expect": "NO_FINDINGS / INCOMPLETE（依赖较多）"},
  {"mode": "submit_url", "cmd": "fg submit_url https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz --lang zh", "expect": "NO_FINDINGS"},
  {"mode": "submit_url", "cmd": "fg submit_url https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl --lang zh --expected-sha256 70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6", "expect": "NO_FINDINGS / INCOMPLETE"},
]
m["engine_formats_not_built"] = ["NSIS / Inno Setup / InstallShield 安装包（box 上没有对应编译器）", "Mach-O（引擎对 Mach-O 恒报缺项 MACHO_CODESIGN_NOT_VERIFIED，必然 INCOMPLETE）", "RAR（没有 rar 打包器）", "加密压缩包（结果是 INCOMPLETE，不属于干净/可疑二分）"]
json.dump(m, open(d / "manifest.json", "w"), ensure_ascii=False, indent=2)
L = ["# FileGuard 测试样本集（" + m["generated_at"] + "）", "",
     "全部样本**无害、不可运行出任何效果**：可疑代码都在 `exit 0` / `return` / `goto :eof` / `WScript.Quit` / `Exit Sub` 之后，或在从不调用的函数里；所有网络地址都是保留地址（`*.invalid`、203.0.113.x、198.51.100.x、192.0.2.x）；PE 入口只有 `xor eax,eax; ret`；ELF 只打印一行；EICAR 是标准杀毒测试串。它们只是让静态分析“看起来可疑”。",
     "", f"随机种子 `{m['seed']}`（`secrets` 生成；`FG_SEED=<seed> FG_OUT=<dir> python _generator/gen.py` 可复现结构）。生成器在 `tests/samples/_generator/`。",
     "", "**只提交副本**：引擎只删除自己复制的副本，但为了不弄脏这份样本集，请总是提交临时副本（`tests/run_batch.py` 会自动这样做）。例如 `cp <样本> /tmp/ && fg submit_file /tmp/<文件名> --lang zh`。", "",
     "## 样本清单（ground truth）", "", "| # | 文件 | 场景 | 类别 | 植入数 | 植入行为（预期严重度） | 预期结论 |", "|---|---|---|---|---|---|---|"]
for n, s in enumerate(m["samples"], 1):
    pl = "<br>".join(f"{p['id']}（{p['severity_expected']}）：{p['desc']}" for p in s["planted"]) or "—"
    L.append(f"| {n} | `{s['path']}` | {s['scenario']} | {'干净' if s['label'] == 'clean' else '可疑'} | {s['planted_count']} | {pl} | {s['expected_verdict']}{('<br>备注：' + s['note']) if s['note'] else ''} |")
L += ["", "预期结论按引擎 verdict.py 规则推算：任一严重 → BLOCK；任一高危 → HIGH_RISK；≥2 种不同中危 → HIGH_RISK；否则 NO_FINDINGS，有缺项则 INCOMPLETE。实际结果还取决于 ClamAV 病毒库是否新鲜、依赖/注册表联网查询是否成功；引擎可能还会报出植入项之外的附带信号（例如解码后的 Base64 再次命中 YARA）。", "",
      "## pkg / url 模式的额外干净用例（真实公开包；可疑样本绝不上传到网上）", ""]
L += [f"- `{t['cmd']}` → {t['expect']}" for t in m["extra_clean_public_targets"]]
L += ["", "## 引擎支持但这次没造的格式", ""] + [f"- {x}" for x in m["engine_formats_not_built"]]
(d / "README.md").write_text("\n".join(L) + "\n")
for s in m["samples"]:
    print(f"{s['path']:64} {s['label'][:5]:5} {s['planted_count']}  {s['expected_verdict'][:20]}")
