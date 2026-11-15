"""Scan every sample of a generated batch through an installed FileGuard, on temporary COPIES, and compare
the verdicts with manifest.json.   python tests/run_batch.py [samples_dir] [fg_path] [out.json]"""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
T = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / "samples" / "20261115-0558")
FG = sys.argv[2] if len(sys.argv) > 2 else "/workspace/fileguard/scripts/fg"
OUT = sys.argv[3] if len(sys.argv) > 3 else "batch_results.json"
TMP = tempfile.mkdtemp(prefix="fg-batch-")
man = json.load(open(f"{T}/manifest.json"))
env = {k: v for k, v in os.environ.items() if not k.startswith("FILEGUARD_")}
rows = []
for i, s in enumerate(man["samples"]):
    d = f"{TMP}/{i:02d}"; os.makedirs(d, exist_ok=True)
    cp = os.path.join(d, os.path.basename(s["path"])); shutil.copyfile(f"{T}/{s['path']}", cp)
    sub = json.loads(subprocess.run([FG, "submit_file", cp, "--lang", "zh"], capture_output=True, text=True, env=env).stdout)
    w = json.loads(subprocess.run([FG, "wait", sub["scan_id"], "--lang", "zh"], capture_output=True, text=True, env=env).stdout)
    rows.append({"path": s["path"], "expected": s["expected_verdict"], "verdict": w["verdict"], "risk": w["risk_level"],
                 "count_line": w["summary"]["count_line"], "missing": w["summary"].get("missing_checks"), "html": w["html_path"],
                 "scan_id": sub["scan_id"], "cache_hit": w.get("cache_hit"), "copy_exists": os.path.exists(cp)})
    print(json.dumps(rows[-1], ensure_ascii=False), flush=True)
shutil.rmtree(TMP, ignore_errors=True)
json.dump(rows, open(OUT, "w"), ensure_ascii=False, indent=1)
bad = [r["path"] for r in rows if r["verdict"] not in r["expected"]]
print(f"{len(rows)} samples, {len(bad)} verdicts outside the expected text: {bad}", file=sys.stderr)
