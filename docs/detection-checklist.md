# FileGuard 检测清单：安装方式、下载源、下载的文件

原则：只做静态分析，不执行、不安装。每一项都要留下证据（命中的文件、行号、字符串、规则名）。查不了的项记为缺失，计入 INCOMPLETE。

---

## 一、安装方式（S5 安装足迹预测 + S3 脚本分析）

目标：在不安装的前提下，找出“安装那一刻会自动运行什么”。Axios 事件的木马就是在这一步运行的。

### 1. npm / Node.js
- package.json 的 `preinstall`、`install`、`postinstall`、`prepare`、`preuninstall` 脚本，逐条列出内容。
- 脚本指向的文件（如 `node setup.js`）要追进去分析，不只看命令本身。
- **幽灵依赖**：依赖在代码里从没被 `require` 或 `import`，却带安装脚本，判为高危。
- `binding.gyp`、`node-gyp` 编译步骤，以及下载预编译二进制的行为（`prebuild-install`、`node-pre-gyp` 指向的地址）。
- `bin` 字段注册的全局命令，是否覆盖 `npm`、`node`、`git` 等常用命令名。
- `.npmrc` 里改了 registry 地址或带了 token。
- 安装脚本按 `os.platform()` 分支，分别调用 curl、PowerShell、osascript、nohup，判为高危。
- 空的 `try/catch`（吞掉错误，让安装看起来正常）作为辅助证据。

### 2. Python
- `setup.py` 里在安装时执行的代码：联网（`urllib`、`requests`、`socket`）、执行命令（`os.system`、`subprocess`）、`exec`/`eval`/`compile`、base64 或 zlib 解码后执行。
- 自定义的 `cmdclass`（重写 install、develop、egg_info）。
- `pyproject.toml` 里非常见的 build-backend。
- `.pth` 文件：以 `import` 开头的行会在每次启动 Python 时自动运行，属高危位置。
- `sitecustomize.py`、`usercustomize.py`。
- wheel 包里的 `entry_points`、`console_scripts` 是否覆盖常用命令。

### 3. Debian / RPM 包
- Debian：`preinst`、`postinst`、`prerm`、`postrm`、`config` 维护脚本，以及 triggers。
- RPM：`%pre`、`%post`、`%preun`、`%postun`、`%pretrans`、`%posttrans`、`%triggerin`。
- 安装路径落在 `/etc`、`/usr/bin`、`/usr/lib/systemd`、`/etc/cron*`、`/etc/profile.d`、`/etc/ld.so.preload` 的文件。
- 带 setuid/setgid 权限的文件。

### 4. Windows 安装包
- MSI：CustomAction 表（运行 EXE、脚本、DLL）、Run/RunOnce 注册表项、服务安装、计划任务。
- NSIS / Inno Setup / InstallShield：解出安装脚本，看 `Exec`、`ExecWait`、下载插件（`inetc`、`NSISdl`）。
- 写入启动文件夹、`%PROGRAMDATA%`、`%TEMP%` 后再执行的行为。
- 把系统程序复制成别的名字（Axios 事件里 PowerShell 被复制成 `wt.exe`）。

### 5. Shell 一键安装脚本
- `curl ... | sh`、`wget -O- ... | bash` 这类下载后直接执行。
- 改 `~/.bashrc`、`~/.profile`、`~/.ssh/authorized_keys`、`/etc/sudoers`。
- 关闭安全机制：`setenforce 0`、`ufw disable`、清空 iptables、删除日志。

### 6. 持久化与凭据访问（所有平台通用）
- 自启动：cron、systemd unit、launchd plist（`~/Library/LaunchAgents`）、Windows Run 键、计划任务、服务。
- 读取凭据：`~/.ssh`、`~/.aws/credentials`、`~/.npmrc`、`~/.pypirc`、`~/.docker/config.json`、`~/.kube/config`、浏览器 Cookie 和密码库、加密钱包文件、环境变量里的 token（`GITHUB_TOKEN`、`NPM_TOKEN`、`AWS_*`）。
- 伪装成系统程序（Axios 事件里 macOS 木马叫 `com.apple.act.mond`）。

### 7. 掩盖痕迹
- 安装后删除或替换自身文件（Axios 事件用 `package.md` 换掉 `package.json`）。
- 包里存在两份内容不同的清单文件（`package.json` 和 `package.md`、`package.json.bak`）。
- 清理日志、清空 shell history。

**输出**：一张“安装时会发生什么”的列表，每条标注是“预测的行为”还是“从代码中直接看到的行为”。

---

## 二、下载源（S0 输入校验 + S1 来源信誉 + S2 下载完整性）

### 1. URL 本身（S0）
- 规范化 URL：大小写、编码、多余的 `@`、端口号、IP 地址形式（十进制、十六进制 IP）。
- **防 SSRF**：拒绝内网地址（`127.0.0.0/8`、`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`、IPv6 本地地址）、云元数据地址（`169.254.169.254`），以及非 http/https 的协议（`file://`、`gopher://`）。每次重定向后重新检查。
- 记录完整的重定向链，最多跟随 5 次；跨域名的重定向要标出来。
- 只允许 HTTPS；用 HTTP 下载要记为风险项。

### 2. 域名和发布者信誉（S1）
- 是否是官方来源：npm 官方仓库、PyPI、GitHub Releases、项目官网、操作系统官方镜像。
- **仿冒域名**：和知名域名只差一两个字母（`githubb.com`）、用相似字符（`rn` 冒充 `m`、西里尔字母）、子域名冒充（`github.com.evil.io`）。
- 域名注册时间很新（比如 30 天内）、使用免费域名或动态 DNS、短链接跳转，作为风险项。
- 直接用 IP 地址下载、非标准端口（Axios 事件用的是 8000 端口），作为风险项。
- 和威胁情报里的恶意域名、恶意 IP 比对（含 Axios 事件的下载域名）。
- **包名仿冒**：和常用包名只差一两个字母（`axois`、`reqeusts`）、加前后缀（`axios-js`）、作用域冒充（`@axios/core`）。
- **依赖混淆**：公开仓库里出现和公司内部包同名的包，且版本号异常高。
- 发布者变化：这个版本的发布者、维护者邮箱和以往不同；账号刚创建；突然出现新维护者。
- 发布行为异常：沉寂很久后突然发新版本、短时间内连发多个版本、版本号跳跃。

### 3. 下载完整性（S2）
- 下载限制：单文件最大 500 MB、超时、只跟随 5 次重定向、下载到隔离目录。
- 计算 SHA-256，和以下来源比对：
  - 官方发布页公布的校验值（`SHA256SUMS`、`.sha256` 文件）。
  - npm 的 `integrity` 字段（sha512）、PyPI 的文件 hash。
  - `package-lock.json`、`yarn.lock`、`poetry.lock` 里锁定的 hash。
- 签名校验：GPG 签名（`.asc`、`.sig`）、Windows Authenticode 签名、macOS 代码签名、Sigstore / cosign。
- 来源证明：npm provenance、SLSA 证明；本该有却没有，要记录。
- 签名者和以往版本不同、证书刚签发或已吊销，作为风险项。
- 任何拿不到的校验（没公布 hash、没签名）都要在报告里写明“未能校验”。

---

## 三、下载的文件（S3 静态分析 + S4 版本差异）

### 1. 文件识别
- 按文件头（magic bytes）识别真实类型，不信扩展名。
- 扩展名和真实类型不一致（`.pdf` 实际是 EXE）、双扩展名（`invoice.pdf.exe`）、Unicode 反转字符藏扩展名，判为高危。

### 2. 压缩包
- 递归解压，最多 5 层，解压后总共不超过 1 GB；不执行任何内容。
- **压缩炸弹**：压缩比异常高（比如超过 100 倍）、文件数异常多。
- **路径穿越**：文件名含 `../`、绝对路径、指向外部的符号链接或硬链接。
- 加密压缩包：无法检查内容，记为缺失，INCOMPLETE。
- 损坏的压缩包：记为缺失，INCOMPLETE。
- 压缩包里藏可执行文件、脚本、快捷方式（`.lnk`）。

### 3. 特征和规则扫描
- ClamAV：病毒特征库，记录库版本和更新时间。
- YARA：FileGuard 自己的规则，记录规则版本。
- 已知恶意 Hash 比对。
- 已知恶意包名单比对（含 Axios 1.14.1、0.30.4 和 `plain-crypto-js@4.2.1`）。

### 4. 脚本分析（JS、Python、PowerShell、Shell、BAT、VBS）
- **混淆**：超长单行、高熵字符串、大段 base64 或十六进制、`eval`/`Function()`/`exec` 执行解码结果、字符串反转加 base64 加 XOR（Axios 手法）、`String.fromCharCode` 拼接。
- **下载并执行**：`curl`、`wget`、`Invoke-WebRequest`、`DownloadString`、`certutil -urlcache`、`bitsadmin`，后面紧跟执行。
- **命令执行**：`child_process`、`subprocess`、`os.system`、`Start-Process`、`-EncodedCommand`、`-ExecutionPolicy Bypass`、`-WindowStyle Hidden`。
- **网络地址**：提取所有 URL、域名、IP，与情报比对。
- **凭据读取**：见第一部分第 6 节的路径和环境变量。
- **反弹 Shell**：`/dev/tcp/`、`nc -e`、`bash -i`。
- **挖矿**：矿池地址、`stratum+tcp`、xmrig 特征。

### 5. 文档
- Office：用 oletools 提取 VBA 宏，看自动运行入口（`AutoOpen`、`Document_Open`、`Workbook_Open`）、Shell 调用、下载行为；DDE 字段；远程模板注入；嵌入的 OLE 对象。
- PDF：`/JavaScript`、`/OpenAction`、`/Launch`、`/EmbeddedFile`、`/URI`，以及结构异常。

### 6. 可执行文件（EXE、DLL、ELF、SO、Mach-O）
- 加壳（UPX 等）、节区高熵、导入表异常少。
- 可疑 API：进程注入（`VirtualAllocEx`、`WriteProcessMemory`、`CreateRemoteThread`）、键盘记录、反调试。
- 签名状态：未签名、签名无效、签名者和发布者不符。
- 内嵌的 URL、IP、矿池地址等字符串。
- ELF：`LD_PRELOAD` 相关、写 `/etc/ld.so.preload`。

### 7. 依赖分析
- 递归最多 5 层，每次最多新检测 200 个依赖，缓存命中不占额度；广度优先，去重。
- 每个依赖都要走一遍：已知恶意名单、包名仿冒、安装脚本、幽灵依赖。
- 超出限制跳过的依赖全部列出，结论计入 INCOMPLETE。

### 8. 版本差异（S4）
- 和上一个已批准的基线版本对比：新增或修改的文件、新增依赖、新增安装脚本、新增可执行文件、新增网络地址、发布者变化。
- **只改了清单文件**（如只改 `package.json`）却新增了带安装脚本的依赖，重点标记（Axios 手法）。
- 发布包内容和源码仓库对应 tag 不一致。
- 没有基线时记为 `skipped(no_baseline)`。

---

## 四、最终裁决（S6）怎么用上面的证据

| 证据 | 结论 |
|---|---|
| ClamAV 命中、已知恶意 Hash、已知恶意包、EICAR | BLOCK |
| 幽灵依赖带安装脚本、安装时下载并执行、凭据外传、反弹 Shell、仿冒包名加安装脚本 | HIGH_RISK |
| 加密或损坏的压缩包、超出依赖或解压限制、关键校验拿不到 | INCOMPLETE |
| 所有适用检查都完成且没有发现 | NO_FINDINGS |
| 检测程序故障或超时 | ERROR |

单独一条弱证据（比如只有 UPX 加壳，或只有一个 postinstall）不直接判高危，但必须写进报告。
