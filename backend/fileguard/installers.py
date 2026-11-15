"""Extra install-method / file-identity checks (checklist sections 1 & 3). All static:
external tools are only used in read/list/export modes (rpm -qp --scripts, msiinfo export,
innoextract --list, osslsigncode verify) - nothing from the sample is ever run."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import tools

COMMON_CMDS = {"npm", "npx", "node", "git", "sh", "bash", "zsh", "python", "python3", "pip", "pip3", "curl", "wget",
               "ls", "sudo", "ssh", "yarn", "pnpm", "docker", "kubectl", "code", "cd", "cp", "mv", "rm", "cat", "env"}
UNCOMMON_BACKENDS_OK = ("setuptools.build_meta", "poetry.core.masonry.api", "poetry.masonry.api", "flit_core.buildapi",
                        "hatchling.build", "pdm.backend", "pdm.pep517.api", "maturin", "scikit_build_core.build",
                        "mesonpy", "setuptools.build_meta:__legacy__", "sipbuild.api", "jupyter_packaging.build_api",
                        "whey", "enscons.api", "pbr.build")
RTLO = "\u202e"
EXEC_EXT = {"exe", "scr", "com", "bat", "cmd", "pif", "vbs", "js", "jse", "wsf", "hta", "lnk", "ps1", "msi", "jar", "dll", "cpl"}
DECOY_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "txt", "mp4", "mp3", "zip", "rar", "csv"}
SEC_DISABLE = [
    (rb"setenforce\s+0", "关闭 SELinux", "disables SELinux"),
    (rb"ufw\s+disable", "关闭 ufw 防火墙", "disables ufw firewall"),
    (rb"iptables\s+-F|iptables\s+--flush", "清空 iptables 规则", "flushes iptables"),
    (rb"systemctl\s+(stop|disable)\s+(firewalld|auditd|apparmor)", "停止安全服务", "stops security services"),
    (rb"Set-MpPreference\s+-Disable", "关闭 Windows Defender", "disables Windows Defender"),
    (rb"Add-MpPreference\s+-ExclusionPath", "添加 Defender 排除路径", "adds Defender exclusion"),
]
ANTI_FORENSICS = [
    (rb"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|>\s*~/\.bash_history", "清空 shell 历史", "clears shell history"),
    (rb"rm\s+-rf?\s+/var/log|>\s*/var/log/|shred\s+[^\n]*\.log|wevtutil\s+cl|Clear-EventLog", "删除/清空日志", "deletes or wipes logs"),
    (rb"unlinkSync\(\s*__filename\s*\)|os\.remove\(\s*__file__\s*\)|Remove-Item\s+\$MyInvocation", "脚本运行后删除自身", "script deletes itself after running"),
    (rb"renameSync\([^)]{0,80}package\.(md|json\.bak)[^)]{0,40}package\.json", "用另一份清单替换 package.json", "swaps package.json with another manifest"),
]
PERSIST_WRITE = [
    (rb">>?\s*~?/?[^\n]{0,40}\.ssh/authorized_keys", "写入 SSH authorized_keys（植入登录后门）", "writes SSH authorized_keys (login backdoor)", "high"),
    (rb">>?\s*/etc/sudoers|/etc/sudoers\.d/", "修改 sudoers 提权配置", "modifies sudoers", "high"),
    (rb"/etc/ld\.so\.preload", "写 /etc/ld.so.preload（全局库劫持）", "touches /etc/ld.so.preload (global library hijack)", "high"),
    (rb"(copy|cp|Copy-Item)\s+[^\n]{0,120}(powershell|cmd|wscript|cscript|mshta)\.exe[^\n]{0,120}\.exe", "把系统程序复制成其他名字（伪装 LOLBin）", "copies a system binary under another name (LOLBin masquerade)", "high"),
    (rb"/Library/Caches/com\.apple\.|/Library/LaunchDaemons/com\.apple\.|\\Windows\\Temp\\svchost\.exe|%APPDATA%\\[^\n]{0,30}svchost", "伪装成系统组件的落地路径", "drop path masquerading as a system component", "medium"),
]
ENV_TOKENS = rb"\b(GITHUB_TOKEN|GH_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|PYPI_TOKEN|TWINE_PASSWORD|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|SLACK_TOKEN|OPENAI_API_KEY)\b"
LOLBIN_DL = rb"certutil(\.exe)?\s+[^\n]{0,40}-urlcache|bitsadmin(\.exe)?\s+[^\n]{0,20}/transfer|Invoke-WebRequest|iwr\s+-Uri|Start-BitsTransfer|mshta\s+https?://|regsvr32\s+[^\n]{0,30}/i:https?://"
EXEC_AFTER = rb"Start-Process|\bIEX\b|Invoke-Expression|cmd(\.exe)?\s+/c|&\s*\$|\.exe\b|ExecWait|Exec\s"


def name_checks(ctx, rel, mime, desc):
    """Double extension, RTLO, magic/extension mismatch - for the sample and every archive member."""
    name = rel.split("!/")[-1].rsplit("/", 1)[-1]
    if RTLO in name or "\u202d" in name or "\u2066" in name or "\u2067" in name:
        ctx.add("high", "S3", "FILENAME_RTLO", f"文件名含 Unicode 方向控制字符，用来伪装扩展名：{name!r}",
                f"Filename contains a Unicode bidi override hiding the real extension: {name!r}", rel, repr(name))
    parts = name.lower().split(".")
    if len(parts) >= 3 and parts[-1] in EXEC_EXT and parts[-2] in DECOY_EXT:
        ctx.add("high", "S3", "DOUBLE_EXTENSION", f"双扩展名伪装：{name}", f"Double-extension disguise: {name}", rel, name)
    ext = parts[-1] if len(parts) > 1 else ""
    is_exe = mime in ("application/x-dosexec", "application/vnd.microsoft.portable-executable", "application/x-executable",
                      "application/x-pie-executable", "application/x-mach-binary", "application/x-sharedlib")
    if is_exe and ext in DECOY_EXT:
        ctx.add("high", "S3", "EXTENSION_MISMATCH", f"扩展名与真实类型不符：{name} 实为可执行文件（{desc[:50]}）",
                f"Extension/type mismatch: {name} is actually an executable ({desc[:50]})", rel, desc[:60])
    if ext == "lnk" and "!/" in rel:
        ctx.add("medium", "S3", "ARCHIVE_HIDES_LNK", f"压缩包中藏有快捷方式文件：{name}", f"Archive contains a shortcut (.lnk): {name}", rel)


def text_checks(ctx, an, rel, name, ext, data):
    script = ext in ("js", "cjs", "mjs", "ts", "py", "sh", "bash", "ps1", "psm1", "bat", "cmd", "vbs", "php", "pl", "rb", "nsi", "iss", "") \
        or name in ("postinst", "preinst", "postrm", "prerm", "config")
    if not script:
        return
    for pat, zh, en in SEC_DISABLE:
        m = re.search(pat, data, re.I)
        if m:
            ctx.add("medium", "S3", "DEFENSE_EVASION", f"关闭安全机制：{zh}", f"Defense evasion: {en}", rel, m.group(0)[:80].decode("latin-1"))
    for pat, zh, en in ANTI_FORENSICS:
        m = re.search(pat, data, re.I)
        if m:
            sev = "high" if b"package" in m.group(0) else "medium"
            ctx.add(sev, "S3", "ANTI_FORENSICS", f"掩盖痕迹：{zh}", f"Anti-forensics: {en}", rel, m.group(0)[:80].decode("latin-1"))
    for pat, zh, en, sev in PERSIST_WRITE:
        m = re.search(pat, data, re.I)
        if m:
            ctx.add(sev, "S3", "PERSISTENCE_OR_MASQUERADE", zh, en, rel, m.group(0)[:80].decode("latin-1"))
            ctx.footprint.append({"kind": "observed", "zh": f"代码中直接可见：{zh}（{rel}）", "en": f"Directly visible in code: {en} ({rel})"})
    toks = set(re.findall(ENV_TOKENS, data))
    if toks:
        net = re.search(rb"https?://|fetch\(|request\(|urlopen|requests\.(get|post)|Invoke-WebRequest|curl|wget", data)
        sev = "high" if net and len(toks) >= 2 else "low"
        ctx.add(sev, "S3", "ENV_TOKEN_ACCESS", f"读取环境变量中的凭据令牌：{', '.join(t.decode() for t in sorted(toks))}" + ("，且具备外发能力" if sev == "high" else ""),
                f"Reads credential tokens from environment: {', '.join(t.decode() for t in sorted(toks))}" + (" with network egress" if sev == "high" else ""), rel)
    m = re.search(LOLBIN_DL, data, re.I)
    if m:
        sev = "high" if re.search(EXEC_AFTER, data[m.end(): m.end() + 600], re.I) else "medium"
        ctx.add(sev, "S3", "LOLBIN_DOWNLOAD", "使用系统工具下载文件" + ("并随后执行" if sev == "high" else ""),
                "Uses a living-off-the-land tool to download" + (" then execute" if sev == "high" else ""), rel, m.group(0)[:80].decode("latin-1"))
    if ext in ("ps1", "psm1", "bat", "cmd", "vbs", "js"):
        flags = [f for f in (rb"-ExecutionPolicy\s+Bypass|-ep\s+bypass", rb"-WindowStyle\s+Hidden|-w\s+hidden", rb"-EncodedCommand|-enc\s") if re.search(f, data, re.I)]
        if len(flags) >= 2:
            ctx.add("medium", "S3", "POWERSHELL_STEALTH_FLAGS", "PowerShell 以隐藏窗口/绕过执行策略/编码命令方式运行",
                    "PowerShell launched hidden / with ExecutionPolicy Bypass / encoded command", rel)
    if name.lower() in ("sitecustomize.py", "usercustomize.py"):
        ctx.add("medium", "S3", "PY_SITECUSTOMIZE", f"包含 {name}：每次启动 Python 都会自动执行",
                f"Ships {name}: runs automatically at every Python start", rel)
        ctx.footprint.append({"kind": "predicted", "zh": f"{name} 会在每次启动 Python 时自动运行", "en": f"{name} runs at every Python interpreter start"})
    if name == "setup.py":
        if re.search(rb"^(?!\s*def )[^\n#]*(os\.system|subprocess\.(Popen|call|run|check_output)|\bexec\(|\beval\(|\bcompile\()", data, re.M):
            ctx.add("low", "S3", "PY_SETUP_EXEC", "setup.py 在安装时执行系统命令或动态代码", "setup.py runs shell commands or dynamic code at install time", rel)
        if re.search(rb"(urllib\.request|requests\.|socket\.|http\.client)", data):
            ctx.add("low", "S3", "PY_SETUP_NETWORK", "setup.py 引用网络模块", "setup.py references network modules", rel)


def manifest_extras(ctx, an, rel, name, path):
    """npm extras (.npmrc, bin overrides, native build/prebuilt download) + Python packaging metadata."""
    raw = open(path, "rb").read(2_000_000)
    if name == ".npmrc":
        txt = raw.decode("utf-8", "replace")
        if re.search(r"_authToken|_auth\s*=|_password", txt):
            ctx.add("high", "S3", "NPMRC_TOKEN", "包内 .npmrc 含有认证令牌", "Bundled .npmrc contains an auth token", rel)
        m = re.search(r"^\s*(@[\w-]+:)?registry\s*=\s*(\S+)", txt, re.M)
        if m and "registry.npmjs.org" not in m.group(2):
            ctx.add("medium", "S3", "NPMRC_REGISTRY_OVERRIDE", f"包内 .npmrc 修改了 registry 地址：{m.group(2)}",
                    f"Bundled .npmrc overrides the registry: {m.group(2)}", rel, m.group(2)[:100])
    elif name == "package.json":
        try:
            pj = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            return
        if not isinstance(pj, dict):
            return
        b = pj.get("bin")
        cmds = [pj.get("name", "").split("/")[-1]] if isinstance(b, str) else list(b.keys()) if isinstance(b, dict) else []
        over = [c for c in cmds if c in COMMON_CMDS]
        if over:
            ctx.add("high", "S3", "NPM_BIN_HIJACK", f"bin 字段注册了与常用命令同名的全局命令：{', '.join(over)}",
                    f"bin registers global commands shadowing common tools: {', '.join(over)}", rel, ", ".join(over))
        scripts = pj.get("scripts") or {}
        allscripts = " ".join(str(v) for v in scripts.values()) if isinstance(scripts, dict) else ""
        deps = {**(pj.get("dependencies") or {}), **(pj.get("optionalDependencies") or {})} if isinstance(pj.get("dependencies") or {}, dict) else {}
        for tool in ("prebuild-install", "node-pre-gyp", "@mapbox/node-pre-gyp", "node-gyp", "prebuildify"):
            if tool in allscripts or tool in deps:
                host = (pj.get("binary") or {}).get("host") if isinstance(pj.get("binary"), dict) else None
                ctx.add("low", "S3", "NPM_NATIVE_BUILD", f"安装时编译原生模块或下载预编译二进制（{tool}）" + (f"，下载地址 {host}" if host else ""),
                        f"Compiles a native addon or downloads a prebuilt binary at install ({tool})" + (f", host {host}" if host else ""), rel, host or tool)
                ctx.footprint.append({"kind": "predicted", "zh": f"安装时会编译/下载原生二进制（{tool}）", "en": f"Install compiles/downloads a native binary ({tool})"})
                break
    elif name == "binding.gyp":
        ctx.footprint.append({"kind": "predicted", "zh": "存在 binding.gyp：npm install 会调用 node-gyp 编译原生代码", "en": "binding.gyp present: npm install runs node-gyp to compile native code"})
        if re.search(rb"<!\(|<!@\(", raw):
            ctx.add("medium", "S3", "GYP_COMMAND_EXPANSION", "binding.gyp 使用命令展开 <!(...)，编译时会执行命令",
                    "binding.gyp uses command expansion <!(...) which runs commands at build time", rel)
    elif name == "pyproject.toml":
        m = re.search(rb"build-backend\s*=\s*['\"]([^'\"]+)", raw)
        if m and m.group(1).decode() not in UNCOMMON_BACKENDS_OK:
            ctx.add("medium", "S3", "PY_UNCOMMON_BACKEND", f"pyproject.toml 使用不常见的构建后端：{m.group(1).decode()}",
                    f"pyproject.toml uses an uncommon build backend: {m.group(1).decode()}", rel)
        if re.search(rb"backend-path", raw):
            ctx.add("medium", "S3", "PY_INTREE_BACKEND", "pyproject.toml 使用包内自带的构建后端（backend-path）", "pyproject.toml uses an in-tree build backend (backend-path)", rel)
    elif name == "entry_points.txt":
        txt = raw.decode("utf-8", "replace")
        sec = re.search(r"\[console_scripts\](.*?)(\n\[|$)", txt, re.S)
        if sec:
            names = [l.split("=")[0].strip() for l in sec.group(1).splitlines() if "=" in l]
            over = [n for n in names if n in COMMON_CMDS]
            if over:
                ctx.add("high", "S3", "PY_ENTRYPOINT_HIJACK", f"console_scripts 覆盖常用命令：{', '.join(over)}",
                        f"console_scripts shadow common commands: {', '.join(over)}", rel)
    elif name in ("triggers",):
        ctx.footprint.append({"kind": "predicted", "zh": "Debian triggers：其他包变动时会触发本包维护脚本", "en": "Debian triggers: maintainer scripts fire when other packages change"})


def office_xml_checks(ctx, rel, name, data):
    if name.endswith(".rels") and re.search(rb"attachedTemplate[^>]{0,300}Target=\"https?://", data):
        ctx.add("high", "S3", "OFFICE_REMOTE_TEMPLATE", "Office 文档引用远程模板（模板注入）", "Office document references a remote template (template injection)", rel)
    if name.endswith(".rels") and re.search(rb"oleObject[^>]{0,300}TargetMode=\"External\"", data):
        ctx.add("high", "S3", "OFFICE_EXTERNAL_OLE", "Office 文档引用外部 OLE 对象", "Office document links an external OLE object", rel)
    if name.endswith(".xml") and re.search(rb"DDEAUTO|<w:instrText[^>]*>\s*DDE\b|\bDDE\s+\"", data):
        ctx.add("high", "S3", "OFFICE_DDE", "Office 文档包含 DDE 字段（可执行命令）", "Office document contains a DDE field (can run commands)", rel)
    if re.search(r"/embeddings/oleObject\d*\.bin$", rel):
        ctx.add("low", "S3", "OFFICE_EMBEDDED_OLE", "Office 文档内嵌 OLE 对象", "Office document embeds an OLE object", rel)


# ---------------------------------------------------------------- installers needing external tools
def rpm_checks(ctx, path, rel):
    if not shutil.which("rpm"):
        ctx.miss("S3", "RPM_SCRIPTLETS_NOT_PARSED", "缺少 rpm 工具，RPM 安装脚本未解析", "rpm tool missing; RPM scriptlets not parsed", rel)
        return ""
    try:
        r = tools.run_limited(["rpm", "-qp", "--nosignature", "--nodigest", "--scripts", "--triggers", path], capture_output=True, text=True, timeout=60, errors="replace")
        fl = tools.run_limited(["rpm", "-qp", "--nosignature", "--nodigest", "--qf", "[%{FILEMODES:perms} %{FILENAMES}\n]", path],
                            capture_output=True, text=True, timeout=60, errors="replace")
    except subprocess.TimeoutExpired:
        ctx.miss("S3", "RPM_SCRIPTLETS_NOT_PARSED", "RPM 解析超时", "RPM parsing timed out", rel)
        return ""
    if r.returncode != 0:
        ctx.miss("S3", "RPM_SCRIPTLETS_NOT_PARSED", f"RPM 头解析失败：{r.stderr.strip()[:100]}", f"RPM header parse failed: {r.stderr.strip()[:100]}", rel)
        return ""
    for m in re.finditer(r"^(\w+) scriptlet", r.stdout, re.M):
        ctx.footprint.append({"kind": "predicted", "zh": f"RPM {m.group(1)} 脚本会在安装/卸载时以 root 运行", "en": f"RPM {m.group(1)} scriptlet runs as root at install/remove"})
    for line in fl.stdout.splitlines():
        perms, _, fn = line.partition(" ")
        if "s" in perms[:10].lower()[3:4] + perms[6:7].lower():
            ctx.add("medium", "S3", "RPM_SETUID", f"RPM 安装 setuid/setgid 文件：{fn}", f"RPM installs a setuid/setgid file: {fn}", rel, fn)
        if re.match(r"/etc/(cron|profile\.d|ld\.so\.preload|sudoers)|/usr/lib/systemd|/etc/systemd", fn):
            ctx.footprint.append({"kind": "predicted", "zh": f"RPM 会写入敏感位置：{fn}", "en": f"RPM writes to a sensitive location: {fn}"})
    return r.stdout


def msi_checks(ctx, path, rel):
    if not shutil.which("msiinfo"):
        ctx.miss("S3", "MSI_CUSTOM_ACTIONS_NOT_PARSED", "缺少 msitools，MSI CustomAction 未解析", "msitools missing; MSI CustomActions not parsed", rel)
        return ""
    try:
        tables = tools.run_limited(["msiinfo", "tables", path], capture_output=True, text=True, timeout=60).stdout.split()
    except Exception:
        tables = []
    if not tables:
        ctx.miss("S3", "MSI_CUSTOM_ACTIONS_NOT_PARSED", "MSI 表无法读取", "MSI tables unreadable", rel)
        return ""
    out = ""
    for t in ("CustomAction", "Registry", "ServiceInstall", "ScheduledTask", "InstallExecuteSequence"):
        if t in tables:
            out += f"\n### {t}\n" + tools.run_limited(["msiinfo", "export", path, t], capture_output=True, text=True, timeout=60, errors="replace").stdout
    ca = re.findall(r"^([^\t\n]+)\t(\d+)\t([^\t\n]*)\t([^\n]*)$", out.split("### Registry")[0], re.M)
    for name, typ, src, target in ca[3:]:
        base = int(typ) & 0x3F if typ.isdigit() else 0
        kind = {1: "DLL", 2: "EXE", 5: "JScript", 6: "VBScript", 18: "EXE", 34: "EXE", 37: "JScript", 38: "VBScript", 50: "EXE"}.get(base)
        if kind:
            sev = "medium" if kind in ("JScript", "VBScript") or re.search(r"powershell|cmd|http", target, re.I) else "low"
            ctx.add(sev, "S3", "MSI_CUSTOM_ACTION", f"MSI CustomAction {name} 运行 {kind}：{target[:100]}", f"MSI CustomAction {name} runs {kind}: {target[:100]}", rel, target[:100])
            ctx.footprint.append({"kind": "predicted", "zh": f"MSI 安装时运行自定义动作 {name}（{kind}）", "en": f"MSI runs custom action {name} ({kind}) during install"})
    if re.search(r"CurrentVersion\\\\?Run", out, re.I):
        ctx.footprint.append({"kind": "predicted", "zh": "MSI 写入 Run/RunOnce 自启动注册表项", "en": "MSI writes Run/RunOnce autostart registry keys"})
        ctx.add("medium", "S3", "MSI_AUTORUN_REGISTRY", "MSI 写入自启动注册表项", "MSI writes autostart registry keys", rel)
    if "ServiceInstall" in tables:
        ctx.footprint.append({"kind": "predicted", "zh": "MSI 安装 Windows 服务", "en": "MSI installs a Windows service"})
    return out


def pe_installer_kind(path):
    with open(path, "rb") as f:
        data = f.read(8 << 20)
    if b"Nullsoft" in data or b"NullsoftInst" in data:
        return "nsis"
    if b"Inno Setup Setup Data" in data or b"Inno Setup" in data:
        return "inno"
    if b"InstallShield" in data:
        return "installshield"
    return None


def inno_checks(ctx, path, rel):
    if not shutil.which("innoextract"):
        ctx.miss("S3", "INNO_SCRIPT_NOT_PARSED", "缺少 innoextract，Inno Setup 安装脚本未解析", "innoextract missing; Inno Setup script not parsed", rel)
        return
    r = tools.run_limited(["innoextract", "--list", "--silent", path], capture_output=True, text=True, timeout=120, errors="replace")
    if r.returncode != 0:
        ctx.miss("S3", "INNO_SCRIPT_NOT_PARSED", "Inno Setup 安装包无法解析", "Inno Setup installer could not be parsed", rel)
        return
    ctx.limit("Inno Setup：已列出安装文件，但 [Code]/[Run] 段的 Pascal 脚本未反编译",
              "Inno Setup: file list read, but [Code]/[Run] Pascal script is not decompiled")
    ctx.miss("S3", "INNO_CODE_SECTION_NOT_DECOMPILED", "Inno Setup [Run]/[Code] 段未反编译", "Inno Setup [Run]/[Code] sections not decompiled", rel)


def nsis_script_checks(ctx, rel, data):
    for pat, zh, en, sev in [
        (rb"\b(inetc|NSISdl|INetC)::(get|download)", "NSIS 安装脚本下载远程文件", "NSIS script downloads remote files", "medium"),
        (rb"\bExec(Wait|Shell)?\b[^\n]{0,200}(powershell|cmd|http|\.ps1|\.vbs)", "NSIS 安装脚本执行 PowerShell/命令/脚本", "NSIS script executes PowerShell/cmd/scripts", "high"),
        (rb"WriteRegStr[^\n]{0,80}CurrentVersion\\\\Run", "NSIS 写入 Run 自启动", "NSIS writes a Run autostart key", "medium"),
    ]:
        m = re.search(pat, data, re.I)
        if m:
            ctx.add(sev, "S3", "NSIS_SCRIPT", zh, en, rel, m.group(0)[:100].decode("latin-1"))
            ctx.footprint.append({"kind": "observed", "zh": f"NSIS 脚本中直接可见：{zh}", "en": f"Visible in NSIS script: {en}"})


def authenticode(ctx, path, rel):
    """Authenticode: digest, certificate chain, timestamp and revocation (CRL) via sigverify."""
    from . import sigverify
    n = ctx.meta.setdefault("_authenticode_count", 0)
    if n >= 50:
        ctx.miss("S2", "AUTHENTICODE_QUOTA", "签名 PE 超过 50 个，其余的签名未验证", "More than 50 signed PEs; remaining signatures not verified")
        return
    ctx.meta["_authenticode_count"] = n + 1
    res = sigverify.verify_authenticode(path)
    if res["status"] == "not_signed":
        res["status"] = "not_applicable"
    base = re.sub(r"[-_ .]?v?\d+(\.\d+)*", "", rel.split("!/")[-1].rsplit("/", 1)[-1].lower())
    sigverify.record(ctx, res, rel, subject=f"pe:{base}", version=ctx.meta.get("sha256"))
