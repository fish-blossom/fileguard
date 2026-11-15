"""S3 format-specific static analyzers + S5 install-footprint indicators.
Nothing here executes, imports, installs or evaluates sample content."""
import base64
import json
import math
import re
from collections import Counter
from pathlib import Path

import magic

from . import config
from . import installers as inst

URL_RE = re.compile(rb"https?://[A-Za-z0-9.\-]{3,253}(?::\d+)?(?:/[^\s\"'<>`)]{0,200})?")
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
B64_RE = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")
# dynamic execution whose argument is a decoder applied to an encoded string LITERAL (payload hidden in the file)
ENC_LIT = rb"""(?:'[A-Za-z0-9+/=%\\xu_\-]{24,}'|"[A-Za-z0-9+/=%\\xu_\-]{24,}"|`[A-Za-z0-9+/=%\\xu_\-]{24,}`)"""
EVAL_PAYLOAD_RE = re.compile(
    rb"(?:\beval|\bFunction|\bexecSync|\bexec|\bsetTimeout|\bsetInterval|\bvm\.runIn\w*Context|\bcompile)\s*\(\s*(?:new\s+)?(?:"
    rb"(?:atob|unescape|decodeURIComponent|Buffer\.from|base64\.b64decode|bytes\.fromhex|codecs\.decode|"
    rb"zlib\.decompress\s*\(\s*base64\.b64decode|__import__\(\s*['\"]base64['\"]\s*\)\.b64decode)\s*\(\s*" + ENC_LIT +
    rb"|String\.fromCharCode\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){15,})")
EVAL_RE = re.compile(rb"\b(eval|exec|Function|execSync|spawn|os\.system|subprocess|Invoke-Expression|IEX)\s*\(")
PDF_URI_RE = re.compile(rb"/URI\s*\(((?:[^()\\]|\\.){1,400})\)")
PDF_IP_HOST_RE = re.compile(rb"^[a-z][a-z0-9+.\-]*://(?:[^/@\s]*@)?(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d+)?(?:[/?#]|$)", re.I)
SCRIPT_EXT = {"nsi", "iss", "js", "cjs", "mjs", "ts", "py", "sh", "bash", "ps1", "psm1", "bat", "cmd", "vbs", "php", "pl", "rb", "pth", "hta"}
BENIGN_HOSTS = (b"github.com", b"npmjs.org", b"npmjs.com", b"pypi.org", b"python.org", b"w3.org", b"mozilla.org",
                b"apache.org", b"opensource.org", b"schemas.", b"example.com", b"localhost", b"googleapis.com",
                b"microsoft.com", b"nodejs.org", b"readthedocs", b"wikipedia.org", b"debian.org", b"ubuntu.com")
CRED_PATTERNS = [
    (rb"\.ssh/(id_rsa|id_ed25519|authorized_keys|config)", "SSH 密钥/配置", "SSH keys/config"),
    (rb"\.aws/credentials", "AWS 凭据", "AWS credentials"),
    (rb"\.npmrc", "npm 令牌文件", "npm token file"),
    (rb"\.pypirc", "PyPI 令牌文件", "PyPI token file"),
    (rb"\.git-credentials", "Git 凭据", "Git credentials"),
    (rb"\.docker/config\.json", "Docker 凭据", "Docker credentials"),
    (rb"\.kube/config", "Kubernetes 凭据", "Kubernetes credentials"),
    (rb"(Login Data|Cookies|Local State)[\"']", "浏览器 Cookie/密码库", "Browser cookies/password store"),
    (rb"\.env[\"'\s]", ".env 环境变量文件", ".env secrets file"),
    (rb"/etc/shadow", "/etc/shadow 系统密码", "/etc/shadow"),
    (rb"wallet\.dat|Ethereum[/\\]keystore|exodus", "加密货币钱包", "Crypto wallet"),
]
SYSTEM_WRITE = [
    (rb"/etc/(cron|systemd|init\.d|rc\.local|profile\.d|sudoers|ld\.so\.preload)", "系统启动/权限配置目录", "system startup/privilege config"),
    (rb"/usr/(local/)?bin/", "系统可执行目录", "system binary directory"),
    (rb"(\.bashrc|\.zshrc|\.profile|\.bash_profile)", "Shell 启动文件", "shell startup file"),
    (rb"crontab", "crontab 定时任务", "crontab"),
    (rb"systemctl\s+(enable|start)", "systemd 服务", "systemd service"),
    (rb"CurrentVersion\\\\?Run", "Windows Run 自启动键", "Windows Run key"),
    (rb"\\Startup\\|Start Menu\\Programs\\Startup", "Windows 启动文件夹", "Windows Startup folder"),
    (rb"schtasks", "Windows 计划任务", "Windows scheduled task"),
    (rb"LaunchAgents|LaunchDaemons", "macOS 自启动", "macOS launch agent"),
]


def file_type(path):
    try:
        return magic.from_file(path)[:200], magic.from_file(path, mime=True)
    except Exception:
        return "unknown", "application/octet-stream"


def entropy(data):
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def ecosystem_of(inventory):
    names = [Path(i["rel"].split("!/")[-1]).name for i in inventory]
    rels = [i["rel"] for i in inventory]
    if any(n == "package.json" for n in names):
        return "npm"
    if any(n in ("setup.py", "pyproject.toml", "PKG-INFO", "METADATA") for n in names) or any(r.endswith(".whl") for r in rels[:1]):
        return "pypi"
    if any(n in ("control", "postinst", "preinst") for n in names) or (inventory and inventory[0].get("container") == "ar"):
        return "debian"
    if inventory and inventory[0].get("container") == "rpm":
        return "rpm"
    return None


REQ_RE = re.compile(rb"""(?:require\s*\(\s*|import\s*\(\s*|from\s+|import\s+)['"]([@\w][\w@./\-]*)['"]""")
EMPTY_CATCH_RE = re.compile(rb"catch\s*(\(\s*\w*\s*\))?\s*\{\s*\}")
MANIFEST_DECOYS = ("package.md", "package.json.bak", "package.json.orig", "package.json.old", "package.bak", "package.json.md")


def _load_iocs():
    out = []
    p = config.INTEL_DIR / "network_iocs.txt"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.split("#")[0].strip().lower()
            if line:
                out.append(line)
    return out


NETWORK_IOCS = _load_iocs()


def _pkg_root(rel):
    """Directory (inside the sample) that contains the file."""
    return rel.rsplit("/", 1)[0] if "/" in rel.split("!/")[-1] else rel.rsplit("!/", 1)[0] + "!/"


class Analyzer:
    def __init__(self, ctx, yara_fn):
        self.ctx = ctx
        self.yara_fn = yara_fn
        self.network = set()
        self.eval_count = 0
        self.hooks = {}            # e.g. {"npm:postinstall": "node install.js"}
        self.hook_files = set()    # basenames referenced by install hooks
        self.manifests = []        # (ecosystem, name, version, deps dict, path)
        self.binaries = []
        self.max_entropy_script = 0.0
        self.module_refs = {}      # pkg_root -> set(module names referenced by require/import)
        self.manifest_files = {}   # pkg_root -> {basename: abs path}
        self.file_hashes = {}      # rel (sans container prefix) -> sha256 (for S4 diff)
        self.deb_payload = lambda rel: False   # set by the pipeline: is `rel` installed from a .deb data.tar?
        self.deb_package = None    # Package: field of a .deb control file
        self.deb_sudoers = []      # (rel, abs) sudoers files shipped in a .deb payload

    # --------------------------------------------------------------
    def analyze(self, item):
        path, rel = item["abs"], item["rel"]
        desc, mime = file_type(path)
        item["type"], item["mime"] = desc, mime
        name = Path(rel.split("!/")[-1]).name
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        with open(path, "rb") as f:
            head = f.read(8)
        is_text = mime.startswith("text/") or mime in ("application/json", "application/javascript", "application/x-sh") \
            or ext in SCRIPT_EXT or name in ("package.json", "setup.py", "postinst", "preinst", "postrm", "prerm")
        self._iocs(path, rel)
        inst.name_checks(self.ctx, rel, mime, desc)
        if name in (".npmrc", "package.json", "binding.gyp", "pyproject.toml", "entry_points.txt", "triggers"):
            inst.manifest_extras(self.ctx, self, rel, name, path)
        if "!/" in rel and (name.endswith(".rels") or (name.endswith(".xml") and "word/" in rel or "xl/" in rel)):
            with open(path, "rb") as fh:
                inst.office_xml_checks(self.ctx, rel, name, fh.read(4_000_000))
        if item.get("container") == "rpm":
            out = inst.rpm_checks(self.ctx, path, rel)
            if out:
                inst.text_checks(self.ctx, self, rel + "#scriptlets", "postinst", "", out.encode())
        if "MSI Installer" in desc or ext == "msi":
            out = inst.msi_checks(self.ctx, path, rel)
            if out:
                inst.text_checks(self.ctx, self, rel + "#tables", name, "ps1", out.encode())
        if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe") or (head[:4] == b"\xca\xfe\xba\xbe" and ext != "class"):
            self.binaries.append(rel)
            self._strings_net(path)
            self.ctx.miss("S2", "MACHO_CODESIGN_NOT_VERIFIED", "Mach-O 文件的 macOS 代码签名未验证（需要 macOS codesign）",
                          "Mach-O code signature not verified (requires macOS codesign)", rel)
        if item["depth"] == 0 and desc.strip() == "data" and not item.get("container"):
            self.ctx.add("info", "S0", "UNRECOGNIZED_FORMAT", "无法识别的文件格式：只做了通用特征扫描（ClamAV/YARA/字符串）",
                         "Unrecognized file format: only generic scanning (ClamAV/YARA/strings) was applied", rel)
            self.ctx.limit("文件格式无法识别，没有专用解析器", "File format not recognized; no format-specific parser applied")
        if name == "package.json" or name in MANIFEST_DECOYS:
            self.manifest_files.setdefault(_pkg_root(rel), {})[name] = path
        if name == "package.json":
            self._npm_manifest(path, rel)
        elif name == "setup.py":
            self._setup_py(path, rel)
        elif name in ("requirements.txt",):
            self._requirements(path, rel)
        elif name in ("PKG-INFO", "METADATA") and rel.split("!/")[-1].count("/") <= 1 and "!/" in rel:
            self._pkginfo(path, rel)
        elif ext == "pth":
            self.ctx.footprint.append({"kind": "predicted", "zh": f"安装后 Python 每次启动都会处理 .pth 文件：{rel}",
                                       "en": f"Python processes this .pth file at every interpreter start: {rel}"})
        elif name == "control" and "!/control.tar" in rel and self.deb_package is None:
            m = re.search(rb"^Package:\s*(\S+)", self._read_text(path)[:65536], re.M)
            self.deb_package = m.group(1).decode("latin-1").lower() if m else ""
        elif name in ("preinst", "postinst", "prerm", "postrm", "config"):
            self.hooks[f"debian:{name}"] = rel
            self.hook_files.add(name)
            self.ctx.footprint.append({"kind": "predicted", "zh": f"Debian 维护脚本会在安装/卸载时以 root 运行：{name}",
                                       "en": f"Debian maintainer script runs as root during install/remove: {name}"})
        if self.deb_payload(rel) and inst.SUDOERS_PATH_RE.search(rel.split("!/")[-1]):
            self.deb_sudoers.append((rel, path))
        if head[:2] == b"MZ":
            self._pe(path, rel, ext)
        elif head[:4] == b"\x7fELF":
            self._elf(path, rel)
        elif head[:4] == b"\xd0\xcf\x11\xe0" or (head[:2] == b"PK" and ext in ("docm", "xlsm", "pptm", "docx", "xlsx", "pptx", "doc", "xls", "ppt")):
            self._office(path, rel, ext)
        elif head[:4] == b"%PDF":
            self._pdf(path, rel)
        if is_text:
            self._text(path, rel, name, ext)

    # --------------------------------------------------------------
    def _read_text(self, path):
        with open(path, "rb") as f:
            return f.read(config.TEXT_ANALYSIS_MAX_BYTES)

    def _text(self, path, rel, name, ext):
        data = self._read_text(path)
        for u in URL_RE.findall(data)[:500]:
            if not any(b in u for b in BENIGN_HOSTS):
                self.network.add(u.decode("latin-1")[:200])
        for ip in set(IP_RE.findall(data[:2_000_000])):
            s = ip.decode()
            if not s.startswith(("0.", "127.", "255.", "1.0.", "2.0.")) and s.count(".") == 3 and not re.match(r"^\d\.\d+\.\d+\.\d+$", s):
                self.network.add(s)
        if ext in ("js", "cjs", "mjs", "ts", "jsx", "tsx"):
            refs = {m.decode("latin-1") for m in REQ_RE.findall(data)}
            norm = set()
            for r in refs:
                if r.startswith("."):
                    continue
                parts = r.split("/")
                norm.add("/".join(parts[:2]) if r.startswith("@") else parts[0])
            self.module_refs.setdefault(self._npm_root_of(rel), set()).update(norm)
            ec = len(EMPTY_CATCH_RE.findall(data))
            if ec and name in self.hook_files_pending():
                self.ctx.add("low", "S3", "JS_EMPTY_CATCH", f"安装脚本用空 try/catch 吞掉错误（{ec} 处）",
                             f"Install script silently swallows errors with empty try/catch ({ec})", rel)
        ev = len(EVAL_RE.findall(data))
        self.eval_count += ev
        if ext in SCRIPT_EXT or ext in ("jsx", "tsx", ""):
            m = EVAL_PAYLOAD_RE.search(data)
            if m:
                self.ctx.add("high", "S3", "OBFUSCATED_EVAL_PAYLOAD", "把编码后的隐藏代码解码后直接交给 eval/Function/exec 执行",
                             "Decodes an encoded payload literal and passes it straight to eval/Function/exec", rel, m.group(0)[:80].decode("latin-1"))
        inst.text_checks(self.ctx, self, rel, name, ext, data)
        if ext == "nsi":
            inst.nsis_script_checks(self.ctx, rel, data)
        # long encoded blobs -> decode statically and re-scan with YARA (never executed)
        blobs = B64_RE.findall(data)[:20]
        for b in blobs:
            try:
                dec = base64.b64decode(b + b"=" * (-len(b) % 4), validate=False)
            except Exception:
                continue
            printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in dec[:4000]) / max(1, min(len(dec), 4000))
            if printable > 0.85:
                hits = self.yara_fn(dec, rel + "#base64")
                for h in hits:
                    self.ctx.add(h["severity"] if h["severity"] != "medium" else "high", "S3", f"YARA_B64:{h['rule']}",
                                 f"Base64 解码后的隐藏内容命中：{h['zh']}", f"Hidden Base64-decoded payload matched: {h['en']}",
                                 rel, (h["strings"] or [""])[0])
                if len(dec) > 400 and re.search(rb"(eval|exec|child_process|subprocess|powershell|/bin/sh|http)", dec):
                    self.ctx.add("medium", "S3", "OBFUSCATION_ENCODED_CODE", "脚本中嵌入了经 Base64 编码的可执行代码",
                                 "Script embeds Base64-encoded executable code", rel, dec[:80].decode("latin-1"))
        if ext in SCRIPT_EXT and len(data) > 2000:
            lines = data.split(b"\n")
            longest = max(len(l) for l in lines)
            ent = entropy(data[:200000])
            self.max_entropy_script = max(self.max_entropy_script, ent)
            hexesc = len(re.findall(rb"\\x[0-9a-fA-F]{2}", data))
            if (ent > 5.6 and longest > 5000 and ev > 0) or hexesc > 2000:
                self.ctx.add("medium", "S3", "OBFUSCATION_HEURISTIC",
                             f"脚本高度混淆（熵 {ent:.2f}，最长行 {longest}，十六进制转义 {hexesc} 个，动态执行 {ev} 处）",
                             f"Script heavily obfuscated (entropy {ent:.2f}, longest line {longest}, {hexesc} hex escapes, {ev} dynamic exec)", rel)
        for pat, zh, en in CRED_PATTERNS:
            m = re.search(pat, data)
            if m and ext in SCRIPT_EXT | {""}:
                self.ctx.add("low", "S3", "CREDENTIAL_PATH_REFERENCE", f"脚本引用敏感凭据路径：{zh}",
                             f"Script references sensitive credential path: {en}", rel, m.group(0)[:60].decode("latin-1"))
                self.ctx.footprint.append({"kind": "predicted", "zh": f"可能读取 {zh}（{rel}）", "en": f"May read {en} ({rel})"})
        for pat, zh, en in SYSTEM_WRITE:
            m = re.search(pat, data)
            if m and ext in SCRIPT_EXT | {""}:
                self.ctx.footprint.append({"kind": "predicted", "zh": f"可能修改{zh}（{rel}）", "en": f"May modify {en} ({rel})"})

    def hook_files_pending(self):
        return self.hook_files

    def _npm_root_of(self, rel):
        # nearest enclosing directory that has a package.json (best effort: npm tarballs use package/)
        parts = rel.split("!/")
        inner = parts[-1]
        if "/node_modules/" in "/" + inner:
            i = inner.rfind("node_modules/")
            seg = inner[i + len("node_modules/"):].split("/")
            n = 2 if seg[0].startswith("@") else 1
            return "!/".join(parts[:-1] + [inner[:i] + "node_modules/" + "/".join(seg[:n])])
        return "!/".join(parts[:-1] + [inner.split("/")[0] if "/" in inner else ""])

    def _iocs(self, path, rel):
        if not NETWORK_IOCS:
            return
        with open(path, "rb") as f:
            data = f.read(config.TEXT_ANALYSIS_MAX_BYTES).lower()
        data = data.replace(b"[.]", b".").replace(b"(.)", b".").replace(b"[dot]", b".")
        for ioc in NETWORK_IOCS:
            if ioc.encode() in data:
                self.ctx.add("critical", "S3", "NETWORK_IOC_MATCH", f"命中已知恶意网络 IOC：{ioc}",
                             f"Matches known-malicious network IOC: {ioc}", rel, ioc)

    def finalize(self, dep_results):
        """Cross-file checks after every file was analyzed."""
        if self.deb_sudoers:
            inst.sudoers_checks(self.ctx, self.deb_sudoers, self.deb_package or "")
        # (5) anti-forensics: package.json vs sibling decoy manifest
        for root, files in self.manifest_files.items():
            if "package.json" not in files:
                continue
            for decoy in MANIFEST_DECOYS:
                if decoy not in files:
                    continue
                try:
                    a = json.loads(open(files["package.json"], "rb").read().decode("utf-8", "replace"))
                    b = json.loads(open(files[decoy], "rb").read().decode("utf-8", "replace"))
                except Exception:
                    a = b = None
                same = a == b if a is not None else open(files["package.json"], "rb").read() == open(files[decoy], "rb").read()
                if not same:
                    diff_keys = sorted(k for k in set(a or {}) | set(b or {}) if (a or {}).get(k) != (b or {}).get(k)) if a is not None else []
                    sev = "high" if any(k in diff_keys for k in ("scripts", "dependencies", "optionalDependencies", "main", "bin")) else "medium"
                    self.ctx.add(sev, "S3", "MANIFEST_DECOY_SWAP",
                                 f"package.json 与同目录 {decoy} 不一致（差异字段：{', '.join(diff_keys) or '内容'}），疑似安装后自我清理/替换清单的反取证手法",
                                 f"package.json differs from sibling {decoy} (fields: {', '.join(diff_keys) or 'content'}); possible anti-forensics manifest swap after install",
                                 f"{root}/{decoy}", ", ".join(diff_keys)[:120])
        # (2) phantom dependency: declared, never imported, and has install hooks
        hooked = {}
        for c in (dep_results or {}).get("checked", []):
            pass
        for f in self.ctx.findings:
            if f.code in ("DEP_HAS_INSTALL_HOOK", "DEP_HOOK_SUSPICIOUS") and f.path and f.path.startswith("dep:npm:"):
                nm = f.path[len("dep:npm:"):].rsplit("@", 1)[0]
                hooked[nm] = f.evidence
        for m in self.manifests:
            if m["ecosystem"] != "npm" or not m.get("top"):
                continue
            root = self._npm_root_of(m["path"])
            refs = self.module_refs.get(root, set())
            for dep in m["deps"]:
                if dep in hooked and dep not in refs:
                    self.ctx.add("high", "S3", "DEP_PHANTOM_WITH_INSTALL_HOOK",
                                 f"幽灵依赖：{dep} 在 package.json 中声明但代码从未 require/import，且带安装钩子（{hooked[dep]}）——典型的投毒注入手法",
                                 f"Phantom dependency: {dep} is declared in package.json but never require()/import'ed, and has an install hook ({hooked[dep]}) - classic poisoning injection",
                                 m["path"], dep)
                    self.ctx.footprint.append({"kind": "predicted", "zh": f"npm install 会自动运行幽灵依赖 {dep} 的安装钩子",
                                               "en": f"`npm install` would auto-run the install hook of phantom dependency {dep}"})

    # --------------------------------------------------------------
    def _npm_manifest(self, path, rel):
        try:
            pj = json.loads(self._read_text(path).decode("utf-8", "replace"))
        except Exception:
            self.ctx.miss("S3", "MANIFEST_PARSE_FAILED", f"package.json 无法解析：{rel}", f"package.json unparseable: {rel}", rel)
            return
        if not isinstance(pj, dict):
            return
        top = rel.count("!/") <= 2 and "node_modules" not in rel
        scripts = pj.get("scripts") or {}
        for hook in ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall"):
            cmd = scripts.get(hook) if isinstance(scripts, dict) else None
            if not cmd or not isinstance(cmd, str):
                continue
            self.hooks[f"npm:{hook}"] = cmd
            for tok in re.findall(r"[\w./\-]+\.(?:js|cjs|mjs|sh|py)", cmd):
                self.hook_files.add(Path(tok).name)
            self.ctx.footprint.append({"kind": "predicted", "zh": f"npm install 时会自动运行 {hook}：{cmd[:160]}",
                                       "en": f"`npm install` will automatically run {hook}: {cmd[:160]}"})
            sev, zh, en = "low", "存在 npm 安装钩子", "npm install hook present"
            if re.search(r"(curl|wget|Invoke-WebRequest)[^|]*\|\s*(ba)?sh|node\s+-e|base64|eval|\bnc\b|powershell", cmd, re.I):
                sev, zh, en = "critical", "npm 安装钩子直接下载/解码并执行代码", "npm install hook downloads/decodes and executes code"
            elif re.search(r"https?://|curl|wget", cmd):
                sev, zh, en = "high", "npm 安装钩子访问网络", "npm install hook accesses the network"
            self.ctx.add(sev, "S3", f"NPM_HOOK_{hook.upper()}", f"{zh}（{hook}）", f"{en} ({hook})", rel, cmd[:160])
        if isinstance(pj.get("bin"), (dict, str)):
            self.ctx.footprint.append({"kind": "predicted", "zh": "安装后会在 PATH 中注册命令（bin）", "en": "Registers command(s) on PATH (bin)"})
        deps = {}
        for k in ("dependencies", "optionalDependencies"):
            v = pj.get(k)
            if isinstance(v, dict):
                deps.update({str(a): str(b) for a, b in v.items()})
        name, ver = str(pj.get("name") or ""), str(pj.get("version") or "")
        self.manifests.append({"ecosystem": "npm", "name": name, "version": ver, "deps": deps, "path": rel, "top": top,
                               "maintainers": pj.get("maintainers") or pj.get("author"), "json": pj})

    def _setup_py(self, path, rel):
        data = self._read_text(path).decode("utf-8", "replace")
        self.hooks["pypi:setup.py"] = rel
        self.hook_files.add("setup.py")
        self.ctx.footprint.append({"kind": "predicted", "zh": "源码包安装时会运行 setup.py（任意 Python 代码）",
                                   "en": "Installing the sdist runs setup.py (arbitrary Python code)"})
        if re.search(r"cmdclass\s*=", data):
            self.ctx.add("low", "S3", "PYPI_CUSTOM_INSTALL_CMD", "setup.py 自定义了安装命令（cmdclass）",
                         "setup.py overrides install commands (cmdclass)", rel)
        m = re.search(r"install_requires\s*=\s*\[(.*?)\]", data, re.S)
        deps = {}
        if m:
            for s in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                n, v = _split_req(s)
                if n:
                    deps[n] = v
        nm = re.search(r"name\s*=\s*['\"]([^'\"]+)", data)
        vm = re.search(r"version\s*=\s*['\"]([^'\"]+)", data)
        self.manifests.append({"ecosystem": "pypi", "name": nm.group(1) if nm else "", "version": vm.group(1) if vm else "",
                               "deps": deps, "path": rel, "top": True})

    def _pkginfo(self, path, rel):
        """Core metadata of a PyPI sdist (PKG-INFO) or wheel (*.dist-info/METADATA): identity + Requires-Dist."""
        text = self._read_text(path).decode("utf-8", "replace")
        head = text.split("\n\n", 1)[0]
        nm = re.search(r"^Name:\s*(\S+)", head, re.M)
        vm = re.search(r"^Version:\s*(\S+)", head, re.M)
        if not nm or not vm or any(m.get("pkginfo") for m in self.manifests):
            return
        deps = {}
        for r in re.findall(r"^Requires-Dist:\s*(.+)$", head, re.M):
            if ";" in r and "extra" in r.split(";", 1)[1]:
                continue
            n, v = _split_req(r.split(";", 1)[0])
            if n:
                deps[n] = v
        self.manifests.append({"ecosystem": "pypi", "name": nm.group(1), "version": vm.group(1), "deps": deps, "path": rel,
                               "top": True, "pkginfo": True, "text": head})

    def _requirements(self, path, rel):
        deps = {}
        for line in self._read_text(path).decode("utf-8", "replace").splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            n, v = _split_req(line)
            if n:
                deps[n] = v
        self.manifests.append({"ecosystem": "pypi", "name": "", "version": "", "deps": deps, "path": rel, "top": True})

    # --------------------------------------------------------------
    def _pe(self, path, rel, ext):
        self.binaries.append(rel)
        self._strings_net(path)
        try:
            import pefile
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                                                   pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
            high_ent = [s.Name.rstrip(b"\0").decode("latin-1") for s in pe.sections if s.get_entropy() > 7.2]
            if high_ent:
                self.ctx.add("medium", "S3", "PE_HIGH_ENTROPY_SECTION", f"PE 节区熵值很高（疑似加壳/加密）：{', '.join(high_ent)}",
                             f"PE section(s) with very high entropy (packed/encrypted?): {', '.join(high_ent)}", rel)
            imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            if not imports:
                self.ctx.add("low", "S3", "PE_NO_IMPORTS", "PE 没有导入表（常见于加壳程序）", "PE has no import table (common in packed binaries)", rel)
            if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
                self.ctx.add("low", "S3", "PE_TLS_CALLBACK", "PE 含 TLS 回调（入口点之前执行的代码）", "PE has TLS callbacks (code before entry point)", rel)
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            if sec.Size == 0:
                self.ctx.add("info", "S2", "PE_UNSIGNED", "PE 文件没有 Authenticode 签名", "PE file has no Authenticode signature", rel)
            else:
                inst.authenticode(self.ctx, path, rel)
            names = {imp.name.decode("latin-1") for d in imports for imp in d.imports if imp.name}
            if {"GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW"} & names and {"GetAsyncKeyState"} & names:
                self.ctx.add("medium", "S3", "PE_KEYLOGGER_APIS", "PE 导入键盘记录相关 API", "PE imports keylogging-related APIs", rel)
            if {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"} & names and len({"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugStringA"} & names) >= 2:
                self.ctx.add("low", "S3", "PE_ANTI_DEBUG", "PE 导入反调试 API", "PE imports anti-debugging APIs", rel)
            kind = inst.pe_installer_kind(path)
            if kind == "inno":
                inst.inno_checks(self.ctx, path, rel)
            elif kind == "installshield":
                self.ctx.miss("S3", "INSTALLSHIELD_NOT_PARSED", "InstallShield 安装包脚本未解析", "InstallShield installer script not parsed", rel)
            elif kind == "nsis":
                self.ctx.footprint.append({"kind": "predicted", "zh": "NSIS 安装程序：安装脚本见解包出的 [NSIS].nsi", "en": "NSIS installer: script extracted as [NSIS].nsi"})
        except Exception as e:
            self.ctx.miss("S3", "PE_PARSE_FAILED", f"PE 结构解析失败（{type(e).__name__}）", f"PE structure parse failed ({type(e).__name__})", rel)

    def _strings_net(self, path):
        with open(path, "rb") as f:
            data = f.read(config.TEXT_ANALYSIS_MAX_BYTES)
        for u in URL_RE.findall(data)[:200]:
            if not any(b in u for b in BENIGN_HOSTS):
                self.network.add(u.decode("latin-1")[:200])
        if re.search(rb"stratum\+(tcp|ssl)://", data):
            self.ctx.add("high", "S3", "MINER_POOL_STRING", "二进制内嵌矿池地址", "Binary embeds a mining-pool address", None)

    def _elf(self, path, rel):
        self.binaries.append(rel)
        self._strings_net(path)
        with open(path, "rb") as f:
            data = f.read(min(4_000_000, config.TEXT_ANALYSIS_MAX_BYTES))
        if b"UPX!" in data:
            self.ctx.add("medium", "S3", "ELF_UPX_PACKED", "ELF 文件被 UPX 加壳", "ELF file packed with UPX", rel)
        if b"/etc/ld.so.preload" in data:
            self.ctx.add("medium", "S3", "ELF_PRELOAD", "ELF 引用 /etc/ld.so.preload（可能全局劫持动态库）",
                         "ELF references /etc/ld.so.preload (global library hijack)", rel, "/etc/ld.so.preload")
        elif b"LD_PRELOAD" in data:
            # many system tools (sudo, ld.so, fakeroot) only name LD_PRELOAD to sanitize or document it
            self.ctx.add("low", "S3", "ELF_PRELOAD", "ELF 引用 LD_PRELOAD 环境变量", "ELF references the LD_PRELOAD variable", rel, "LD_PRELOAD")

    def _office(self, path, rel, ext):
        try:
            from oletools.olevba import VBA_Parser
        except Exception:
            self.ctx.miss("S3", "OFFICE_ANALYZER_MISSING", "缺少 oletools，宏未分析", "oletools missing; macros not analyzed", rel)
            return
        try:
            vp = VBA_Parser(path)
        except Exception as e:
            if path.endswith(("msi",)) or ext == "msi":
                return
            # Not every OLE file is an Office doc (e.g. MSI)
            if "MSI" in file_type(path)[0] or ext == "msi":
                return
            self.ctx.miss("S3", "OFFICE_PARSE_FAILED", f"Office 文档解析失败（{type(e).__name__}）",
                          f"Office document parse failed ({type(e).__name__})", rel)
            return
        try:
            if vp.detect_vba_macros():
                results = vp.analyze_macros()
                auto = [k for t, k, d in results if t == "AutoExec"]
                susp = [k for t, k, d in results if t == "Suspicious"]
                iocs = [k for t, k, d in results if t == "IOC"]
                sev = "high" if auto and susp else ("medium" if auto or susp else "low")
                if auto and any(re.search(r"Shell|powershell|URLDownload|XMLHTTP|CreateObject|Run", k, re.I) for k in susp):
                    sev = "high"
                self.ctx.add(sev, "S3", "OFFICE_VBA_MACRO",
                             f"文档包含 VBA 宏；自动执行入口：{', '.join(auto[:5]) or '无'}；可疑关键字：{', '.join(susp[:8]) or '无'}",
                             f"Document has VBA macros; auto-exec: {', '.join(auto[:5]) or 'none'}; suspicious: {', '.join(susp[:8]) or 'none'}", rel)
                for i in iocs[:10]:
                    self.network.add(str(i)[:200])
                if auto:
                    self.ctx.footprint.append({"kind": "predicted", "zh": "打开文档并启用宏时会自动执行宏代码", "en": "Macro code auto-runs when the document is opened with macros enabled"})
            if getattr(vp, "detect_xlm_macros", None) and vp.detect_xlm_macros():
                self.ctx.add("high", "S3", "OFFICE_XLM_MACRO", "Excel 4.0 (XLM) 宏", "Excel 4.0 (XLM) macros present", rel)
        except Exception as e:
            self.ctx.miss("S3", "OFFICE_MACRO_ANALYSIS_FAILED", f"宏分析失败（{type(e).__name__}）", f"Macro analysis failed ({type(e).__name__})", rel)
        finally:
            vp.close()

    def _pdf(self, path, rel):
        with open(path, "rb") as f:
            data = f.read(config.TEXT_ANALYSIS_MAX_BYTES)
        keys = {k: len(re.findall(re.escape(k.encode()) + rb"[\s/<>\[(]", data)) for k in
                ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/XFA", "/AcroForm", "/RichMedia")}
        active = {k: v for k, v in keys.items() if v}
        if keys["/Launch"]:
            self.ctx.add("high", "S3", "PDF_LAUNCH", "PDF 含 /Launch 动作（可启动外部程序）", "PDF contains /Launch action (can start programs)", rel)
        if (keys["/JavaScript"] or keys["/JS"]) and (keys["/OpenAction"] or keys["/AA"]):
            self.ctx.add("medium", "S3", "PDF_AUTO_JS", "PDF 打开时自动执行 JavaScript", "PDF auto-runs JavaScript on open", rel)
        # link targets: /URI (...) actions are network indicators; a link straight to a bare IP is reported
        for m in PDF_URI_RE.finditer(data):
            uri = m.group(1).strip()[:200]
            if not uri or any(b in uri for b in BENIGN_HOSTS):
                continue
            self.network.add(uri.decode("latin-1"))
            h = PDF_IP_HOST_RE.match(uri)
            if h:
                self.ctx.add("low", "S3", "PDF_URI_BARE_IP", f"PDF 链接直接指向裸 IP 地址：{uri.decode('latin-1')[:100]}",
                             f"PDF link points straight to a bare IP address: {uri.decode('latin-1')[:100]}", rel, uri.decode("latin-1")[:100])
        if b"/ObjStm" in data and not active:
            self.ctx.limit("PDF 使用压缩对象流（ObjStm），关键字统计可能不完整", "PDF uses object streams (ObjStm); keyword counts may be incomplete")
        if active:
            self.ctx.meta.setdefault("pdf_keywords", {})[rel] = active


def _split_req(s):
    m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[.*?\])?\s*(?:(==|>=|<=|~=|!=|>|<)\s*([\w.*+\-]+))?", s)
    if not m:
        return None, None
    return m.group(1).lower(), (m.group(4) if m.group(3) == "==" else (m.group(3) or "") + (m.group(4) or ""))
