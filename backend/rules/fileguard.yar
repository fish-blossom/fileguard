/*
  FileGuard YARA ruleset v2026.11.14
  meta.severity: critical | high | medium | low
  meta.desc_zh / meta.desc_en: shown in reports
  All rules are static string/structure matches; nothing is executed.
*/

rule FG_EICAR_Test_File
{
    meta:
        severity = "critical"
        desc_zh = "EICAR 反病毒测试特征串"
        desc_en = "EICAR anti-virus test string"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $e
}

rule FG_JS_Obfuscated_Eval
{
    meta:
        severity = "medium"
        desc_zh = "JavaScript 混淆后动态执行（eval/Function 与编码串组合）"
        desc_en = "Obfuscated JavaScript dynamic execution (eval/Function with encoded payload)"
    strings:
        $ev1 = /eval\s*\(\s*(atob|unescape|decodeURIComponent|Buffer\.from)\s*\(/ ascii
        $ev2 = /new\s+Function\s*\(\s*(atob|Buffer\.from|unescape)/ ascii
        $ev3 = /eval\s*\(\s*String\.fromCharCode\s*\(/ ascii
        $hex = /(\\x[0-9a-fA-F]{2}){40,}/ ascii
        $obf = /_0x[0-9a-f]{4,6}\s*\[/ ascii
    condition:
        any of ($ev*) or (#obf > 20 and $hex)
}

rule FG_JS_Child_Process_Network
{
    meta:
        severity = "high"
        desc_zh = "JavaScript 同时具备命令执行与网络下载能力（下载并执行特征）"
        desc_en = "JavaScript combines command execution with network download (download-and-execute pattern)"
    strings:
        $cp1 = "child_process" ascii
        $cp2 = /\b(execSync|spawnSync|exec|spawn)\s*\(/ ascii
        $n1 = /require\(\s*['"](https?|net|dns)['"]\s*\)/ ascii
        $n2 = /\b(curl|wget)\s+(-[a-zA-Z]+\s+)*https?:\/\// ascii
        $n3 = "fetch(" ascii
        $sh = /\|\s*(ba)?sh\b/ ascii
    condition:
        $cp1 and $cp2 and filesize < 2MB and ($sh or $n2) and any of ($n*)
}

rule FG_JS_Credential_Exfil
{
    meta:
        severity = "high"
        desc_zh = "脚本读取敏感凭据文件（.npmrc/.ssh/.aws/环境变量）并外发"
        desc_en = "Script reads credential files (.npmrc/.ssh/.aws/env) and sends them out"
    strings:
        $c1 = ".npmrc" ascii
        $c2 = ".ssh/id_rsa" ascii
        $c3 = ".aws/credentials" ascii
        $c4 = /JSON\.stringify\(\s*process\.env\s*\)/ ascii
        $c5 = ".git-credentials" ascii
        $c6 = "Local State" ascii
        $x1 = /https?:\/\/[a-z0-9.\-]+\.(xyz|top|tk|ml|ga|cf|gq|ru|su|pw|onion)\b/ ascii nocase
        $x2 = "discord.com/api/webhooks" ascii nocase
        $x3 = /\.request\(|http\.request|https\.request|XMLHttpRequest|fetch\(/ ascii
        $x4 = "pastebin.com" ascii nocase
        $x5 = "ngrok" ascii nocase
    condition:
        filesize < 5MB and 2 of ($c*) and any of ($x*)
}

rule FG_PowerShell_Encoded_Download
{
    meta:
        severity = "high"
        desc_zh = "PowerShell 编码命令/内存加载/下载执行"
        desc_en = "PowerShell encoded command / in-memory load / download-and-execute"
    strings:
        $e1 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ ascii nocase
        $e2 = "FromBase64String" ascii nocase
        $i1 = /\bIEX\b|Invoke-Expression/ ascii nocase
        $d1 = "DownloadString" ascii nocase
        $d2 = "DownloadFile" ascii nocase
        $d3 = "Net.WebClient" ascii nocase
        $d4 = "Invoke-WebRequest" ascii nocase
        $h1 = "-w hidden" ascii nocase
        $h2 = "-windowstyle hidden" ascii nocase
        $h3 = "bypass" ascii nocase
        $r1 = "[Reflection.Assembly]::Load" ascii nocase
        $ps = "powershell" ascii nocase
    condition:
        filesize < 5MB and not (uint16(0) == 0x5A4D or uint32(0) == 0x464c457f) and
        (($e1 and $ps) or ($i1 and any of ($d*)) or ($e2 and ($i1 or $r1)) or (any of ($h*) and any of ($d*) and $i1))
}

rule FG_Shell_Download_Pipe_Exec
{
    meta:
        severity = "high"
        desc_zh = "Shell 脚本下载远程内容并直接执行（curl|sh / wget|bash）"
        desc_en = "Shell script downloads remote content and executes it (curl|sh / wget|bash)"
    strings:
        $p1 = /(curl|wget)[^\n|;]{0,200}https?:\/\/[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/ ascii
        $p2 = /(curl|wget)[^\n]{0,200}-[oO]\s*\/tmp\/[^\n]{0,100}(chmod\s+\+x|&&\s*\/tmp\/)/ ascii
        $p3 = /base64\s+(-d|--decode)[^\n]{0,40}\|\s*(ba)?sh\b/ ascii
    condition:
        any of them
}

rule FG_Shell_Reverse_Shell
{
    meta:
        severity = "critical"
        desc_zh = "反弹 Shell 特征"
        desc_en = "Reverse shell pattern"
    strings:
        $r1 = /bash\s+-i\s+>&\s*\/dev\/tcp\// ascii
        $r2 = /nc(at)?\s+(-[a-z]*e[a-z]*\s+\/bin\/(ba)?sh|[^\n]{0,60}-e\s+\/bin\/(ba)?sh)/ ascii
        $r3 = /socket\.socket\([^\n]{0,200}\.connect\([^\n]{0,200}(subprocess|pty\.spawn|os\.dup2)/ ascii
    condition:
        any of them
}

rule FG_Persistence_Mechanisms
{
    meta:
        severity = "low"
        desc_zh = "持久化/自启动特征（crontab、systemd、shell 启动文件、Run 注册表键）"
        desc_en = "Persistence / autostart indicators (crontab, systemd, shell rc, Run registry key)"
    strings:
        $a = /crontab\s+(-l|-)/ ascii
        $b = "/etc/systemd/system/" ascii
        $c = /(>>|>)\s*(~|\$HOME|\/home\/[^\/\s]+|\/root)\/\.(bashrc|zshrc|profile|bash_profile)/ ascii
        $d = "CurrentVersion\\Run" ascii nocase
        $e = "/etc/rc.local" ascii
        $f = "authorized_keys" ascii
        $g = "LaunchAgents" ascii
    condition:
        filesize < 10MB and any of them
}

rule FG_Python_Setup_Network_Exec
{
    meta:
        severity = "high"
        desc_zh = "setup.py 安装阶段同时出现网络访问与命令/代码执行"
        desc_en = "setup.py performs network access together with command/code execution at install time"
    strings:
        $s = "setup(" ascii
        $n1 = "urllib.request" ascii
        $n2 = "urlopen(" ascii
        $n3 = "requests.get(" ascii
        $n4 = "socket.socket" ascii
        $n5 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ ascii
        $x1 = "os.system(" ascii
        $x2 = "subprocess." ascii
        $x3 = /\bexec\s*\(/ ascii
        $x4 = /\beval\s*\(/ ascii
        $x5 = "base64.b64decode" ascii
    condition:
        fg_name == "setup.py" and $s and any of ($n*) and any of ($x*)
}

rule FG_Python_Exec_Encoded
{
    meta:
        severity = "high"
        desc_zh = "Python 解码后动态执行（exec/eval + base64/zlib/marshal）"
        desc_en = "Python decodes then dynamically executes code (exec/eval + base64/zlib/marshal)"
    strings:
        $x = /\b(exec|eval)\s*\(\s*(__import__\(['"](base64|zlib|marshal)['"]\)|base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode)/ ascii
    condition:
        $x
}

rule FG_Python_PTH_Code
{
    meta:
        severity = "high"
        desc_zh = ".pth 文件中包含 import 执行代码（Python 启动时自动执行）"
        desc_en = ".pth file contains executable import line (runs automatically at interpreter start)"
    strings:
        $i = /(^|\n)import\s+[^\n]{0,200}(exec|eval|base64|subprocess|os\.system|urllib|socket)/ ascii
    condition:
        fg_ext == "pth" and $i and filesize < 1MB
}

rule FG_Office_AutoExec_Macro_Strings
{
    meta:
        severity = "medium"
        desc_zh = "文档包含自动执行宏入口与 Shell/下载调用"
        desc_en = "Document contains auto-exec macro entry points plus shell/download calls"
    strings:
        $a1 = "AutoOpen" ascii nocase
        $a2 = "Document_Open" ascii nocase
        $a3 = "Workbook_Open" ascii nocase
        $a4 = "Auto_Open" ascii nocase
        $s1 = "WScript.Shell" ascii nocase
        $s2 = "Shell(" ascii nocase
        $s3 = "URLDownloadToFile" ascii nocase
        $s4 = "MSXML2.XMLHTTP" ascii nocase
        $s5 = "powershell" ascii nocase
        $s6 = "CreateObject" ascii nocase
    condition:
        (uint32(0) == 0xE011CFD0 or fg_ext == "vba" or fg_ext == "bas") and any of ($a*) and 2 of ($s*)
}

rule FG_PDF_Active_Content
{
    meta:
        severity = "low"
        desc_zh = "PDF 包含自动动作与 JavaScript/启动外部程序"
        desc_en = "PDF contains automatic action with JavaScript / Launch"
    strings:
        $pdf = "%PDF" ascii
        $o = "/OpenAction" ascii
        $aa = "/AA" ascii
        $js = "/JavaScript" ascii
        $l = "/Launch" ascii
        $ef = "/EmbeddedFile" ascii
    condition:
        $pdf at 0 and ($o or $aa) and ($js or $l or $ef)
}

rule FG_PE_Packed_UPX
{
    meta:
        severity = "medium"
        desc_zh = "PE 文件被 UPX 加壳"
        desc_en = "PE file packed with UPX"
    strings:
        $u0 = "UPX0" ascii
        $u1 = "UPX1" ascii
        $u2 = "UPX!" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule FG_PE_Suspicious_Injection_APIs
{
    meta:
        severity = "medium"
        desc_zh = "PE 文件导入进程注入相关 API 组合"
        desc_en = "PE imports a process-injection API combination"
    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii
        $d = "NtUnmapViewOfSection" ascii
        $e = "SetWindowsHookEx" ascii
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule FG_Crypto_Miner
{
    meta:
        severity = "high"
        desc_zh = "加密货币挖矿程序特征（矿池协议/常见矿工）"
        desc_en = "Cryptocurrency miner indicators (stratum pool / known miners)"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $m1 = "xmrig" ascii nocase
        $m2 = "cryptonight" ascii nocase
        $m3 = "minexmr" ascii nocase
    condition:
        any of ($s*) or 2 of ($m*)
}

rule FG_Webshell_PHP
{
    meta:
        severity = "high"
        desc_zh = "PHP WebShell 特征（eval/assert 执行请求参数）"
        desc_en = "PHP webshell pattern (eval/assert of request input)"
    strings:
        $w = /(eval|assert|system|passthru|shell_exec)\s*\(\s*(base64_decode\s*\()?\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
    condition:
        $w
}

rule FG_JS_Reverse_Base64_XOR_Decoder
{
    meta:
        severity = "high"
        desc_zh = "多层混淆解码器：字符串反转 + 替换后 Base64 解码 + XOR 解密（Axios 投毒 dropper 手法）"
        desc_en = "Multi-layer decoder: string reverse + substituted Base64 decode + XOR (Axios-compromise dropper technique)"
    strings:
        $rev1 = /split\(\s*['"]{2}\s*\)\s*\.\s*reverse\(\s*\)\s*\.\s*join\(/ ascii
        $rev2 = /\[\s*\.\.\.\s*\w+\s*\]\s*\.\s*reverse\(\s*\)/ ascii
        $sub1 = /replace\(\s*\/_\/g\s*,\s*['"]=['"]\s*\)/ ascii
        $sub2 = /replace(All)?\(\s*['"]_['"]\s*,\s*['"]=['"]\s*\)/ ascii
        $b64a = /Buffer\.from\([^)]{0,80}['"]base64['"]/ ascii
        $b64b = "atob(" ascii
        $xor1 = /charCodeAt\([^)]{0,40}\)\s*\^/ ascii
        $xor2 = /\^\s*\w+\.charCodeAt\(/ ascii
        $xor3 = /\^ ?(0x[0-9a-fA-F]{1,4}|[0-9]{2,4})[^0-9]/ ascii
    condition:
        filesize < 2MB and any of ($rev*) and any of ($b64*) and any of ($xor*) and (any of ($sub*) or #xor3 > 0)
}

rule FG_Install_Script_Platform_Dropper
{
    meta:
        severity = "high"
        desc_zh = "安装脚本按操作系统分支并调用 curl/osascript/powershell/nohup（跨平台投放器特征）"
        desc_en = "Install script branches on OS platform and spawns curl/osascript/powershell/nohup (cross-platform dropper)"
    strings:
        $p1 = /os\.platform\(\)|process\.platform/ ascii
        $o1 = "darwin" ascii
        $o2 = "win32" ascii
        $o3 = "linux" ascii
        $s1 = /\b(execSync|exec|spawn|spawnSync|execFile)\s*\(/ ascii
        $t1 = /\bcurl\b/ ascii
        $t2 = "osascript" ascii
        $t3 = /powershell/ ascii nocase
        $t4 = /\bnohup\b/ ascii
        $d1 = "/Library/Caches/" ascii
        $d2 = "PROGRAMDATA" ascii nocase
        $d3 = /\/tmp\/[\w.\-]+\.(py|sh)/ ascii
        $d4 = /%TEMP%|process\.env\.TEMP|os\.tmpdir\(\)/ ascii
    condition:
        filesize < 2MB and $p1 and 2 of ($o*) and $s1 and 2 of ($t*) or
        (filesize < 2MB and $p1 and $s1 and any of ($t*) and 2 of ($d*))
}
