# FileGuard 检测报告 — **BLOCK**
**结论：** 确认存在严重恶意证据。禁止放行。发现严重恶意证据，不提供用户确认放行。请删除该文件，不要安装或打开。

| 项目 | 内容 |
|---|---|
| 1. 文件名 | plain-crypto-js-4.2.1.tgz |
| 2. 文件类型 | gzip compressed data, was "plain-crypto-js-4.2.1.tgz", last modified: Sat Nov 14 11:44:04 2026, max compression, original size modulo 2^32 10240 |
| 3. 文件大小 | 1,183 bytes |
| 4. 原始 URL | 不适用 |
| 5. 最终下载 URL | 不适用 |
| 6. SHA-256 | `611d34826e88a917a6d6711148fd4208a920c35848da5785c65d912ffbb0d26b` |
| 7. 最终结论 | **BLOCK** |
| 8. 风险等级 | CRITICAL |

## 9. S0–S7 覆盖情况

| 阶段 | 状态 | 说明 |
|---|---|---|
| S0 输入校验 | 完成 | 输入已受理：类型识别、大小校验 |
| S1 来源信誉 | 不适用 | 用户直接上传，无下载来源；包名仿冒检查在 S3 进行 |
| S2 下载完整性 | 完成 | 已计算 SHA-256/SHA-1/MD5；已比对已知恶意 Hash；官方校验：无可用 |
| S3 静态分析 | 完成 | 解包、ClamAV、YARA、格式分析、混淆/编码分析、网络与凭据特征、依赖(无清单) |
| S4 版本差异 | 跳过 | skipped(no_baseline)：首次出现的版本，已提高静态检测敏感度 |
| S5 安装足迹预测 | 完成 | 静态预测 4 项安装足迹（均为预测，非实际观察） |
| S6 风险裁决 | 完成 | 规则引擎裁决：BLOCK |
| S7 交付与跟进 | 完成 | 已生成报告、Hash 校验命令；样本已删除，仅保留报告与 Hash |

## 10. 检测工具和规则版本

- engine: FileGuard 0.3.0
- clamav: ClamAV 1.4.3/28183/Sat Nov 14 14:24:17 2026 (clamd)
- yara: yara-python 4.5.4 / rules r-bf00a731d1e2
- rules_version: r-bf00a731d1e2
- dependency_intel: local known-malicious list + OSV.dev

## 11. 恶意或可疑证据

- [严重][S3] 安装钩子会自动执行的脚本 setup.js 含高危恶意特征（FG_JS_Reverse_Base64_XOR_Decoder, FG_Install_Script_Platform_Dropper） — `plain-crypto-js-4.2.1.tgz!/package/setup.js`  `INSTALL_HOOK_MALICIOUS_CODE`
- [严重][S3] 该包版本为已知恶意版本：plain-crypto-js@4.2.1 — `plain-crypto-js-4.2.1.tgz!/package/package.json`  `PACKAGE_KNOWN_MALICIOUS`
- [高危][S3] 掩盖痕迹：用另一份清单替换 package.json — `plain-crypto-js-4.2.1.tgz!/package/setup.js`（证据：`renameSync('package.md', 'package.json`）  `ANTI_FORENSICS`
- [高危][S3] 把系统程序复制成其他名字（伪装 LOLBin） — `plain-crypto-js-4.2.1.tgz!/package/setup.js`（证据：`copy %SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe %PROGRAMDAT`）  `PERSISTENCE_OR_MASQUERADE`
- [高危][S3] 多层混淆解码器：字符串反转 + 替换后 Base64 解码 + XOR 解密（Axios 投毒 dropper 手法） — `plain-crypto-js-4.2.1.tgz!/package/setup.js`（证据：`split('').reverse().join(`）  `YARA:FG_JS_Reverse_Base64_XOR_Decoder`
- [高危][S3] 安装脚本按操作系统分支并调用 curl/osascript/powershell/nohup（跨平台投放器特征） — `plain-crypto-js-4.2.1.tgz!/package/setup.js`（证据：`os.platform()`）  `YARA:FG_Install_Script_Platform_Dropper`
- [高危][S3] package.json 与同目录 package.md 不一致（差异字段：description, scripts, version），疑似安装后自我清理/替换清单的反取证手法 — `plain-crypto-js-4.2.1.tgz!/package/package.md`（证据：`description, scripts, version`）  `MANIFEST_DECOY_SWAP`
- [中危][S3] 掩盖痕迹：脚本运行后删除自身 — `plain-crypto-js-4.2.1.tgz!/package/setup.js`（证据：`unlinkSync(__filename)`）  `ANTI_FORENSICS`
- [中危][S3] 伪装成系统组件的落地路径 — `plain-crypto-js-4.2.1.tgz!/package/setup.js`（证据：`/Library/Caches/com.apple.`）  `PERSISTENCE_OR_MASQUERADE`
- [中危][S3] PowerShell 以隐藏窗口/绕过执行策略/编码命令方式运行 — `plain-crypto-js-4.2.1.tgz!/package/setup.js`  `POWERSHELL_STEALTH_FLAGS`
- [低危][S3] 存在 npm 安装钩子（postinstall） — `plain-crypto-js-4.2.1.tgz!/package/package.json`（证据：`node setup.js`）  `NPM_HOOK_POSTINSTALL`
- [低危][S3] 安装脚本用空 try/catch 吞掉错误（2 处） — `plain-crypto-js-4.2.1.tgz!/package/setup.js`  `JS_EMPTY_CATCH`

## 12. 依赖统计

不适用

### 签名 / 来源证明 / 锁文件 / 源码 tag 比对

- `npm_registry_signature` — `plain-crypto-js-4.2.1.tgz!/package/package.json`: **已验证** — npm 注册表 ECDSA 签名有效（SHA256:qDOzBkvJ3k9Z4…）
- `npm_provenance` — `plain-crypto-js-4.2.1.tgz!/package/package.json`: **不适用** — 该版本没有发布 provenance 来源证明
- `lockfile_hashes`: **不适用** — 样本中没有锁文件
- `source_tag_diff`: **不适用** — 包没有声明源码仓库

## 13. 缓存命中统计

文件 Hash 缓存命中：否；依赖缓存命中 0 个（不占 200 额度）

## 14. 未检测的依赖列表

不适用

## 15. 历史版本对比

skipped(no_baseline)

## 16. 安装足迹预测

- [预测] npm install 时会自动运行 postinstall：node setup.js
- [观察] 代码中直接可见：把系统程序复制成其他名字（伪装 LOLBin）（plain-crypto-js-4.2.1.tgz!/package/setup.js）
- [观察] 代码中直接可见：伪装成系统组件的落地路径（plain-crypto-js-4.2.1.tgz!/package/setup.js）
- [预测] 可能建立持久化/投放文件：plain-crypto-js-4.2.1.tgz!/package/setup.js

## 17. 缺失的检查项

无

## 18. 已知检测局限

- 只做静态分析：未执行、未安装、未运行宏；运行时才解密/下载的载荷可能无法发现
- 依赖检查基于注册表元数据、已知恶意名单与 OSV 情报，未下载并逐个解包每个依赖
- YARA 规则为 FileGuard 自研小规则集，覆盖面有限
- 该 npm 版本没有 provenance 来源证明

## 19. SHA-256 校验命令

```
sha256sum 'plain-crypto-js-4.2.1.tgz'   # expect 611d34826e88a917a6d6711148fd4208a920c35848da5785c65d912ffbb0d26b
shasum -a 256 'plain-crypto-js-4.2.1.tgz'   # expect 611d34826e88a917a6d6711148fd4208a920c35848da5785c65d912ffbb0d26b
Get-FileHash -Algorithm SHA256 'plain-crypto-js-4.2.1.tgz'   # expect 611D34826E88A917A6D6711148FD4208A920C35848DA5785C65D912FFBB0D26B
```

## 20. 检测时间

2026-11-14T03:47:26-08:00（耗时 0.07s；提交时预估 0.8s）

> NO_FINDINGS 表示在已完成的静态检测范围内没有发现威胁，不代表文件绝对安全。本次检测没有进行动态行为分析。

> 样本已在扫描后删除，仅保留报告与 Hash。