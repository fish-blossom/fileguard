# FileGuard 检测引擎（本机 CLI）

FileGuard 是一个**只做静态分析**的恶意文件 / 软件供应链投毒检测引擎。它按固定顺序执行 S0–S7 八个阶段，由本机 CLI `fg` 在用户自己的 box 上运行。没有服务器、没有端口转发、也没有 MCP 或数据库。

- 不执行、不安装、不运行宏或安装脚本；不使用沙箱，不使用 Cloud Agent。
- 检测没做完绝不说安全：适用但没做成的检查一律计入 `INCOMPLETE`，引擎故障一律 `ERROR`。
- 没有总超时：检测一直跑到完成；只对单个卡住的步骤（一次网络请求 30 秒没有任何进展、单个工具进程超出自身上限）做保护，这一步记为失败 / 缺失项。
- `fg submit_*` 立刻返回全程预计耗时（引擎时间 + 整理/发送报告的开销，`estimate_text`）；`fg wait` 阻塞到结束并给出精简 JSON 和 HTML 报告路径。
- 样本扫完立即删除，只保留报告和 Hash。
- 报告语言跟随 `lang` 参数（`zh` / `en`），状态名、SHA-256、YARA 等术语保留英文。

> 每个通过 Grok Bot 模板添加 FileGuard 的用户，会在第一次对话里把引擎安装到**自己的 box** 上（见 `install.sh`）。

---

## 1. 目录结构

```
/workspace/fileguard          # 默认安装位置（FILEGUARD_DIR）
├── install.sh              # 校验签名后安装 / 更新（--estimate、--auto、--tarball、--dir）
├── VERSION                 # 发布版本（semver，与 fileguard/__init__.py 的 ENGINE_VERSION 一致）
├── release-signers         # 固定的发布签名公钥（ssh-keygen -Y verify）
├── requirements.lock       # 带 SHA-256 的完整依赖锁定（只装 wheel）
├── vendor/                 # 安装时下载的官方 7-Zip、ClamAV（按 SHA-256 固定）
├── .venv/                  # Python 虚拟环境
├── fileguard/              # 引擎源码
│   ├── cli.py              # `fg` / `python -m fileguard.cli`：submit / wait / delivered / confirm …
│   ├── config.py           # 所有上限（500MB、1GB、5 层、200 依赖…），均可用环境变量覆盖
│   ├── pipeline.py         # S0–S7 主流程
│   ├── store.py            # 文件持久化：扫描记录、Hash 缓存、依赖缓存、版本基线、确认、签名者、耗时
│   ├── delivery.py         # 全程预计时间中的“整理和发送报告”开销，及 delivered 校准
│   ├── baselines.py        # 本地基线文件；没有本地基线时从注册表拉取上一版本再做文件比较
│   ├── netutil.py          # 防 SSRF（含连接后核对对端 IP，防 DNS 重绑定）、限大小、逐跳重定向检查的下载器
│   ├── tools.py            # 外部解析工具定位（优先 vendor/）与 RLIMIT 资源限制
│   ├── source.py           # S1/S2 来源信誉
│   ├── sigverify.py        # 签名验证：npm 注册表 ECDSA、发布证明 + SLSA、PyPI PEP 740、GPG、Authenticode
│   ├── source_diff.py      # 发布包 vs 源码仓库对应 tag
│   ├── lockfiles.py        # 锁文件哈希 vs 注册表元数据 / 内嵌制品
│   ├── estimate.py         # 引擎耗时预估与运行中剩余时间
│   ├── unpack.py / scanners.py / analyzers.py / installers.py / deps.py
│   ├── verdict.py / report.py / service.py
│   └──（无 mcp_server、无 SQLite）
├── rules/fileguard.yar
├── intel/                  # 本地情报：已知恶意 Hash、恶意包名单、网络 IOC、热门包名
├── clamav/                 # clamd.conf.in / freshclam.conf.in 模板（脚本写入实际路径）
├── scripts/                # fg、env.sh、start_clamd.sh、update_clamav_db.sh、build_release.sh
├── （本公开仓库不含 tests/）
└── data/                   # 运行时（FILEGUARD_DATA，默认 $FILEGUARD_HOME/data）
    ├── scans/<scan_id>/    # meta.json、result.json、worker.log
    ├── reports/            # JSON / HTML 报告
    ├── cache/<sha256>.json # 按引擎/规则/病毒库版本命中
    ├── baselines/<eco>/<name>/<version>.json
    ├── dep_cache/  confirmations/  signers/  timings/
    ├── clamav-db/          # FileGuard 自己的 ClamAV 病毒库（每天最多更新一次）
    ├── local_config.json   # 本机配置（如探测到的 SSRF 代理网段）
    ├── update_state.json   # 上次检查新版本的时间
    ├── delivery_times.json
    └── work/               # 临时样本，扫完即删
```

## 2. 已安装的组件

| 组件 | 来源 | 用途 |
|---|---|---|
| ClamAV 1.4.6（clamd、clamscan、freshclam） | Cisco Talos 官方 .deb，SHA-256 固定，解到 `vendor/clamav` | 病毒特征库扫描；病毒库在 `data/clamav-db`，每天最多更新一次 |
| 7-Zip 26.06（7zzs 静态版） | 7-zip.org 官方链接的 GitHub Release，SHA-256 固定，放在 `vendor/7zip` | 7z / RAR / deb / rpm / NSIS 解包（只解不执行） |
| yara-python 4.5 | PyPI wheel（哈希锁定） | FileGuard 自有规则 |
| rpm、msitools、innoextract、osslsigncode、gpg | 系统 apt | 只读解析 RPM 脚本、MSI 表、Inno 安装包；验证 Authenticode、GPG 签名 |
| sigstore、pypi-attestations、cryptography | PyPI wheel（哈希锁定） | npm provenance / PyPI PEP 740 的 Sigstore 验证，npm 注册表 ECDSA 签名 |
| oletools、pefile、python-magic | PyPI wheel（哈希锁定） | Office 宏、PE 结构、真实文件类型识别 |
| httpx、node-semver、packaging | PyPI wheel（哈希锁定） | 下载、依赖版本解析 |

Python 依赖：`requirements.txt` 是顶层清单，`requirements.lock` 是带哈希的完整锁定，安装时用 `pip install --require-hashes --only-binary=:all:`。所有外部解析工具都带 `RLIMIT_AS`（默认 4 GB）/ `RLIMIT_CPU` 限制运行。7-Zip 或 ClamAV 版本低于已修复漏洞的版本、病毒库超过 7 天未更新时，扫描会记缺失项（`PARSER_OUTDATED` / `CLAMAV_DB_STALE`），`fg version --json` 也会显示。

## 3. 如何运行

```bash
# 安装或更新：bootstrap.sh 校验最新 Release 后运行新版本自己的 install.sh（install.sh --auto 也会转给它）。
./bootstrap.sh --dir /workspace/fileguard
# 当前版本的完整使用说明（Bot 每次对话第一次检测前运行）：
fg help --lang zh
# 安装或更新到最新的已签名 Release。--estimate 只预估耗时、不改动系统。
./install.sh --estimate
./install.sh
# 每天的静默维护（24 小时内最多查一次新版本，并更新病毒库）：
./install.sh --auto
# 用已下载的发布包（仍会对照签名 manifest 校验）：
./install.sh --tarball /path/to/fileguard.tar.gz

cd /workspace/fileguard
source scripts/env.sh          # 设置 PATH / PYTHONPATH，并定义 fg 函数（避开 bash 内建的作业控制命令）

# 如需单独启动 clamd（首次约 10 秒加载特征库）。扫描时若 clamd 未运行会尝试拉起，否则回退到 clamscan。
scripts/start_clamd.sh

# Bot 使用的两次调用（全程预计时间含整理和发送报告）
fg submit_url https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz --lang zh
fg wait <scan_id> --lang zh --timeout 55   # 55 秒没扫完返回当前阶段（退出码 3），再 wait 一次
fg submit_pkg npm left-pad 1.3.0 --lang zh   # 只给包名和版本
# 可选校准：fg delivered <scan_id>
# 确认 INCOMPLETE：fg confirm_incomplete <scan_id> <sha256> <check1,check2> <确认人> [说明]

# 同步扫一次（调试用）
fg scan /path/to/file --lang zh
fg --version
```

安装源只用 GitHub Release（`https://github.com/fish-blossom/fileguard/releases/latest/download/`）：`manifest.json` + `manifest.json.sig`（发布密钥签名）+ `fileguard.tar.gz`，以及 GitHub Actions 生成的 SLSA 构建证明。`install.sh` 先用已安装副本里固定的公钥（首次安装用下载包自带的公钥）验证 manifest 签名，再核对 tarball 的 SHA-256，这两步是必做的，不依赖 `gh`。如果本机有 `gh`，还会运行 `gh attestation verify --repo fish-blossom/fileguard`，证明缺失或无效就拒绝安装；没有 `gh` 则跳过构建证明，只靠签名和哈希。都通过才解压。更新先在 `.stage/` 里建好新代码、venv 和工具并自检，再整体替换，失败自动回滚；旧版本目录 `.prev-*` 留到下次安装时清理。安装锁（`data/.install.lock` 上的 flock）只由外层安装进程持有，clamd 等长期子进程启动时会关掉继承的描述符；0.5.2 及更早版本的安装会把锁泄漏给 clamd，0.5.3 起的安装脚本发现锁只被本目录自己的 clamd 占用时，会重启这个 clamd 再继续（别的进程占锁仍返回 busy）。发布由 `.github/workflows/release.yml` 在版本标签上调用 `scripts/build_release.sh`（基于 `git archive`，可复现）并附加构建证明。

对用户只在**第一次安装**时说一句「⚙️ 正在初始化 FileGuard，预计约 N 分钟」，完成后（含静默的 left-pad 验证）再说「✅ 初始化完成，可以开始检测了」。已经是最新版或后台更新时，什么都不要说；更新失败就继续用旧版本，只有引擎无法使用时才告知用户。不要列举安装了哪些组件。

## 4. 检测流程（S0–S7）

| 阶段 | 内容 |
|---|---|
| S0 输入校验 | URL 规范化；只允许 http/https；拒绝账号密码形式；**每一跳重定向都重新做 SSRF 检查**（内网、回环、链路本地、云元数据、十进制/十六进制 IP）；最多 5 次重定向；500 MB 上限（流式计数，不信 Content-Length）；magic bytes 识别真实类型 |
| S1 来源信誉 | 网络 IOC（含 Axios 事件 sfrclak[.]com）、IP 直连、非标准端口、短链、高风险顶级域、Punycode、仿冒域名（编辑距离 / rn→m / 西里尔字母 / 子域名冒充）、免费或动态 DNS、RDAP 域名注册时间、跨域重定向、明文 HTTP、官方来源识别；npm 包的发布者 / 维护者 / 邮箱变化、沉寂后突然发布、24 小时内连发、provenance 消失 |
| S2 下载完整性 | SHA-256/SHA-1/MD5；已知恶意 Hash；用户提供的期望 Hash；npm `dist.integrity`（sha512）/ PyPI sha256 比对；同目录 `SHA256SUMS` / `.sha256` 校验文件；**密码学签名验证**（见第 8 节）；**锁文件哈希比对**；同一 SHA-256 的结果缓存（绑定引擎版本、规则版本、病毒库版本） |
| S3 静态分析 | 安全解压 → ClamAV（全部文件）→ YARA → 按格式分析 → 依赖递归（详见下节） |
| S4 版本差异 | **发布包 vs 源码仓库 tag 比对**（第 8 节）；与上一个**完整且 NO_FINDINGS** 的基线版本比较：新增/删除/修改文件、新依赖、新安装钩子、新二进制、新网络地址、动态执行增量；**只改了 package.json 却新增带安装钩子的依赖 → 严重**（Axios 手法）；无基线记 `skipped(no_baseline)` |
| S5 安装足迹预测 | 汇总“安装那一刻会发生什么”，逐条标注“预测”或“代码中直接可见” |
| S6 风险裁决 | 确定性规则引擎，见第 6 节 |
| S7 交付 | 20 项字段报告、Hash 校验命令、删除样本、写入缓存与基线 |

### S3 检查明细

- **压缩包**：递归最多 5 层，总量 ≤ 1 GB，文件数 ≤ 50,000；压缩比 ≥ 100 视为炸弹；Zip Slip、绝对路径、指向包外的符号/硬链接、设备文件、setuid、头部伪造大小；加密、损坏 → 缺失项；压缩包里的 `.lnk`。
- **文件身份**：扩展名与真实类型不符、双扩展名（`invoice.pdf.exe`）、Unicode 方向控制字符（RTLO）→ 高危。
- **npm**：逐条列出 preinstall/install/postinstall/prepare/preuninstall；追进钩子指向的脚本，脚本命中高危规则 → 严重；**幽灵依赖**（声明了但代码从未 require/import 且带安装钩子）→ 高危；`bin` 覆盖 npm/node/git 等命令；包内 `.npmrc` 改 registry 或带 token；node-gyp / prebuild-install / binding.gyp 命令展开；空 try/catch（辅助证据）；`package.json` 与 `package.md`/`.bak` 不一致（反取证替换）。
- **Python**：setup.py 联网 + 执行、exec/eval 解码执行、cmdclass、非常见 build-backend、in-tree backend、`.pth` 中的 import 行、sitecustomize/usercustomize、`console_scripts` 覆盖常用命令。
- **Debian / RPM**：preinst/postinst/prerm/postrm/config/triggers；`rpm -qp --scripts` 只读列出 %pre/%post 等；setuid 文件；写入 /etc/cron*、systemd、profile.d、ld.so.preload。
- **Windows 安装包**：`msiinfo` 导出 CustomAction/Registry/ServiceInstall；NSIS 用 7z 解出 `[NSIS].nsi` 看 Exec/ExecWait/inetc/NSISdl；Inno 用 innoextract 列文件；把 powershell.exe 复制成别的名字。
- **脚本**：混淆（熵、超长行、十六进制转义、Base64 大段 → 静态解码后再跑 YARA）、反转 + Base64 + XOR 解码器、按 `os.platform()` 分支调用 curl/osascript/powershell/nohup、curl|sh、certutil/bitsadmin/Invoke-WebRequest 下载后执行、PowerShell 隐藏/绕过/编码、反弹 Shell、挖矿、WebShell、凭据路径和 `GITHUB_TOKEN`/`NPM_TOKEN`/`AWS_*` 外传、写 authorized_keys/sudoers、关闭 SELinux/防火墙/Defender、清 history 和日志、自删除。
- **文档**：olevba 宏（自动执行入口 + Shell/下载）、XLM 宏、DDE、远程模板注入、外部 OLE、内嵌 OLE；PDF 的 /JavaScript、/OpenAction、/AA、/Launch、/EmbeddedFile。
- **可执行文件**：UPX、节区高熵、无导入表、TLS 回调、注入/键盘记录/反调试 API、Authenticode、内嵌 URL 和矿池地址；ELF 的 LD_PRELOAD；Mach-O 标记为签名未验证。
- **依赖**：广度优先，按生态+包名+版本去重；先查缓存（绑定引擎版本和规则版本），缓存命中不占 200 额度；每个依赖检查已知恶意名单、OSV.dev（MAL-* 恶意包 / 已知漏洞）、仿冒包名（编辑距离、字母对调、加前后缀、作用域冒充；PyPI 按 PEP 503 规范化，`charset_normalizer` = `charset-normalizer`）、安装钩子内容、异常高版本号、内部包名（`FILEGUARD_INTERNAL_PREFIXES`）、公共仓库不存在（依赖混淆）。
- **5 层以下**：不再计入 INCOMPLETE，改为**轻量检查**——已知恶意名单、OSV 的 MAL-* 恶意包情报、安装钩子（可疑钩子仍是高危）。报告里单列“第 5 层以下仅轻量检查”。**轻量检查不占 200 个完整检查额度**（额度只用于第 1–5 层的完整检查），单独上限 `FILEGUARD_MAX_LIGHT_DEPS`=3000，超过才计入 INCOMPLETE（`DEP_LIGHT_QUOTA_EXCEEDED`）。第 1–5 层超过 200 额度、注册表获取失败（含请求卡住）仍计入 INCOMPLETE。
- **上下文降级**：软件包或压缩包里位于 docs/ci/tests/examples 且不被安装钩子引用的启发式命中会降一级（仍会列出），避免 CI 脚本里的 `curl | sh` 把正常包判成高危。严重证据不降级。

## 5. 版本基线与缓存

- 基线以 JSON 文件保存在 `data/baselines/<ecosystem>/<name>/<version>.json`（文件列表和哈希、安装钩子、依赖、网络 IOC）。只有完整、结论为 NO_FINDINGS 的扫描会写入本地基线。
- 没有本地基线时，会从 npm / PyPI 拉取该包的上一发布版本，生成一份仅用于比较的快照再做差异分析（不是对旧版本下结论）。拉取失败则记 `skipped(no_baseline)`。
- 同一 SHA-256 再次提交时，若引擎版本、规则版本、病毒库版本都没变，直接复用之前的 BLOCK / HIGH_RISK / NO_FINDINGS（INCOMPLETE 和 ERROR 不缓存），`wait` 的 JSON 里会带 `cache_hit` 和 `reused_from`。`fg submit_* --force` 可强制重扫。
- Hash 缓存、依赖缓存、INCOMPLETE 确认、签名者历史都是 `data/` 下的普通文件，写入采用临时文件 + 重命名，并用文件锁防止并发冲突。
- 规则更新后，旧报告在 `get_report` 中会标注“需要重新评估”。

## 6. 结论规则（S6）

| 证据 | 结论 |
|---|---|
| ClamAV 命中、已知恶意 Hash、已知恶意包、网络 IOC、EICAR、安装钩子执行的脚本带高危特征、只改清单却新增带钩子依赖 | **BLOCK**（不可确认放行） |
| 幽灵依赖带安装钩子、安装时下载并执行、凭据外传、反弹 Shell、仿冒包名、压缩炸弹、路径穿越、伪装扩展名；**签名 / 来源证明无效、锁文件哈希不符、安装钩子脚本只在发布包里有**；或两项以上不同的中危证据相互印证 | **HIGH_RISK**（不可确认放行） |
| 加密 / 损坏压缩包、超出解压限制或第 1–5 层依赖额度、**适用但没能完成的检查**（如注册表/仓库/密钥服务器/CRL 拿不到、某一步卡住） | **INCOMPLETE**（默认不放行，可由用户本人确认） |
| 所有适用检查完成且没有中高危 | **NO_FINDINGS**（不代表绝对安全；单条中危会写进报告但不升级） |
| 输入被拒（超 500 MB、SSRF）、主样本下载失败、引擎故障（没有总超时） | **ERROR** |

`confirm_incomplete` 规则：只接受 INCOMPLETE；SHA-256 必须与该次扫描完全一致；`missing_checks` 必须逐项等于报告里的缺失项代码；记录确认人、时间和缺失项；结论仍显示 INCOMPLETE（处置为 `user_accepted_risk`）；文件 Hash 一变确认即失效，规则更新后提示重新评估。

## 7. 测试

本公开仓库不包含测试套件、测试样本或测试结果。引擎本身仍识别 EICAR 测试串（YARA 规则与已知 Hash 列表）；见仓库根 README。

## 8. 签名、来源证明、锁文件、源码 tag 比对（真实实现）

`FILEGUARD_STRICT_UNIMPLEMENTED` 已删除。每项检查在报告里都有状态：已验证 / 无效 / 未能完成 / 应有但缺失 / 不适用 / 不可用。

| 检查 | 做法 | 结论映射 |
|---|---|---|
| npm 注册表签名 | 从 `/-/npm/v1/keys` 取公钥，ECDSA P-256 验证 `${name}@${version}:${integrity}`；检查密钥在发布时是否已过期 | 无效 → HIGH_RISK；npm 包没有签名 → 中危证据 |
| npm 发布证明 + SLSA provenance | 下载 attestation；发布证明用 npm 密钥验 DSSE；provenance 用 sigstore-python 验 Fulcio 证书链、Rekor 收录承诺、DSSE 签名，再核对制品 sha512 和构建身份（GitHub 仓库须与 package.json 一致） | 无效 / 摘要不符 / 身份不符 → HIGH_RISK；上一版有、这一版没有 → 高危（`PROVENANCE_DROPPED`） |
| PyPI PEP 740 | `/integrity/<project>/<ver>/<file>/provenance`，pypi-attestations 验证发布者与制品摘要 | 无效 → HIGH_RISK |
| GPG | 下载地址旁的 `.asc/.sig/.gpg`；从签名读出公钥指纹，到密钥服务器（`FILEGUARD_KEYSERVER`，默认 keys.openpgp.org）取公钥，在临时 GNUPGHOME 里验证 | BADSIG → HIGH_RISK；签名有效但指纹不在 `intel/trusted_gpg_fingerprints.txt` → 写进报告“签名有效但签名者未被信任” |
| Authenticode | osslsigncode 验证摘要、证书链、时间戳；FileGuard 自己下载证书里的 CRL 分发点再交给 osslsigncode 做吊销检查 | 摘要不符 / 证书链失败 / 已吊销 → HIGH_RISK；CRL 拿不到 → 缺失项 |
| 签名者变化 | 每次 NO_FINDINGS 扫描记录签名者（npm/PyPI 构建身份、Authenticode 主体、GPG 指纹） | 与已记录基线不同 → 中危证据 `SIGNER_CHANGED` |
| 锁文件 | package-lock / npm-shrinkwrap（v1–v3）、yarn.lock v1、pnpm-lock.yaml、poetry.lock、Pipfile.lock、带 `--hash` 的 requirements；与注册表公布的 integrity/sha256 比对；样本内附带的 `.tgz/.whl` 与锁定哈希比对 | 不符 → HIGH_RISK（`LOCKFILE_HASH_MISMATCH` / `LOCKFILE_VENDORED_MISMATCH`）；注册表中不存在 → 中危；明文 HTTP 地址 → 中危；注册表拿不到 → 缺失项；yarn berry 的校验和是 yarn 内部格式 → 记为不支持 |
| 源码 tag 比对 | npm `repository`（含 monorepo 的 `directory`、按包名找子目录）/ PyPI project_urls → GitHub；依次试 `v{ver}`、`{ver}`、`{name}@{ver}` 等 tag，从 codeload 下载（≤300 MB）比对 | 安装钩子脚本只在发布包里有 → HIGH_RISK（源码里的 package.json 声明了同一钩子则视为构建生成，低危）；发布包新增钩子或新增依赖 → HIGH_RISK；少量非构建产物代码文件只在包里 → 中危；大量差异（像构建产物）→ 信息；仓库不在 GitHub / 找不到 tag → “不可用”（低危说明）；下载失败 → 缺失项。git 子模块不在 tag 压缩包里，自动排除 |

**适用性规则**：适用但没做成 → INCOMPLETE；不适用 → 只写进报告；生态通常会提供但缺了 → 证据（不是 INCOMPLETE）。

## 9. 卡住保护与耗时预估

- 没有面向用户的总超时，`timeout_seconds` 已删除。只有单步保护：每次网络请求 `FILEGUARD_NET_STALL_TIMEOUT`（默认 30 秒）内没有任何进展就放弃；主样本下载每次读取 60 秒无进展；外部工具进程各自有上限（`FILEGUARD_TOOL_STALL_TIMEOUT`=600 秒）。放弃的这一步记为失败 / 缺失项（例如 `DEP_REGISTRY_ERROR`），结论按规则变成 INCOMPLETE，扫描本身继续完成。
- 预估只用便宜的特征：文件大小、类型、压缩包条目数和解压后大小（zip 读中心目录；≤100 MB 的 tar.gz 流式列目录）、生态、声明的依赖数量和其中已在缓存里的数量、是否会做源码 tag 比对和签名验证。系数按本机真实耗时校准（约每个文件 0.002 秒、每 MB 解压内容 0.2 秒、每个新依赖 0.02 秒、源码 tag 比对 0.4 秒 + 每 MB 0.25 秒），范围取 0.6–1.8 倍。每次扫描的特征、预估和实际耗时写入 `data/timings/<scan_id>.json`，可继续校准。

## 10. 已知局限

- 依赖只做元数据级检查（不逐个下载解包依赖制品）；本次扫描的包本身是完整解包检查的。
- 在线 URL/Hash 情报（URLhaus、MalwareBazaar）需要 abuse.ch 的 Auth-Key，未配置时只用本地 IOC 列表（`FILEGUARD_ABUSECH_KEY`）。
- Authenticode 只做 CRL，不做 OCSP。部分代理环境对明文 HTTP 的 CRL 地址（如 crl.sectigo.com）会返回错误，这时真实签名的 PE 吊销检查可能做不成，结论是 INCOMPLETE；网络畅通时会走完。
- GPG 只能证明“该密钥签过”；要证明“是官方的密钥”需要在 `intel/trusted_gpg_fingerprints.txt` 里固定官方指纹（目前为空）。
- 源码 tag 比对只支持 GitHub；GitLab/Bitbucket/自建仓库记为“不可用”。很多包（如 lodash）发布内容由构建脚本生成，差异会以“信息”级别列出，不判定。
- npm provenance 的身份核对是“构建身份包含 package.json 声明的 GitHub 仓库”；没有声明仓库时只验证签名本身。
- macOS 代码签名无法在 Linux 上验证（Mach-O 计为缺失项）；Inno Setup 的 [Code]/[Run] 段不反编译（计为缺失项）；InstallShield 不解析（计为缺失项）。
- DNS 重绑定：下载前解析并检查 IP，连接建立后再核对实际连接的对端 IP；走环境变量配置的出站代理时，对端是代理，由代理负责解析。
- YARA 规则是自研小规则集；只做静态分析，运行时才解密或下载的载荷可能看不到。

## 11. 安装到用户的 box（不再部署公共服务器）

每个用户在自己的 Debian/Ubuntu box 上安装引擎，不需要公网服务、端口转发或 MCP。推荐方式见仓库根 README：下载最新 Release 的 `fileguard.tar.gz`，`sha256sum -c` 校验后解压，运行其中的 `install.sh --estimate` 与 `install.sh --tarball <tarball>`（安装脚本会再验签名和哈希；若有 `gh` 还会验构建证明）。

第一次对话由 Bot 调用 `install.sh --estimate`，向用户只展示一句初始化预计时间，再执行安装。apt 需要 sudo；没有 sudo 时会跳过系统包。只有默认目录 `/workspace/fileguard` 的安装会写 `/usr/local/bin/fg`；其他目录的安装会复用默认安装正在运行的 clamd，不再另起一个。

SSRF 代理网段：安装时如果探测到 github.com、registry.npmjs.org 等公共域名被解析到 `198.18.0.0/15`（伪 IP 代理环境），才把这个网段写进 `data/local_config.json` 放行；普通服务器上不放行。环境变量 `FILEGUARD_SSRF_ALLOW_CIDRS` 仍可覆盖。

可选：设置 `FILEGUARD_ABUSECH_KEY`，并在 `intel/trusted_gpg_fingerprints.txt` 填入可信的官方 GPG 指纹。`data/` 在更新时保留。更新失败会尽量回滚到上一版本；Bot 对用户保持沉默，只有引擎已经无法使用时才提示。
