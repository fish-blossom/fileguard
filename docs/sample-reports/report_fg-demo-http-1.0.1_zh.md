# FileGuard 检测报告 — **BLOCK**
**结论：** 确认存在严重恶意证据。禁止放行。发现严重恶意证据，不提供用户确认放行。请删除该文件，不要安装或打开。

| 项目 | 内容 |
|---|---|
| 1. 文件名 | fg-demo-http-1.0.1.tgz |
| 2. 文件类型 | gzip compressed data, was "fg-demo-http-1.0.1.tgz", last modified: Sat Nov 14 11:44:04 2026, max compression, original size modulo 2^32 10240 |
| 3. 文件大小 | 410 bytes |
| 4. 原始 URL | 不适用 |
| 5. 最终下载 URL | 不适用 |
| 6. SHA-256 | `8c7d41053a65a750485850c00c2043ad5102cff640ea0171a997534aabb583c1` |
| 7. 最终结论 | **BLOCK** |
| 8. 风险等级 | CRITICAL |

## 9. S0–S7 覆盖情况

| 阶段 | 状态 | 说明 |
|---|---|---|
| S0 输入校验 | 完成 | 输入已受理：类型识别、大小校验 |
| S1 来源信誉 | 不适用 | 用户直接上传，无下载来源；包名仿冒检查在 S3 进行 |
| S2 下载完整性 | 完成 | 已计算 SHA-256/SHA-1/MD5；已比对已知恶意 Hash；官方校验：无可用 |
| S3 静态分析 | 完成 | 解包、ClamAV、YARA、格式分析、混淆/编码分析、网络与凭据特征、依赖 |
| S4 版本差异 | 完成 | 已与基线 1.0.0 比对 |
| S5 安装足迹预测 | 完成 | 静态预测 1 项安装足迹（均为预测，非实际观察） |
| S6 风险裁决 | 完成 | 规则引擎裁决：BLOCK |
| S7 交付与跟进 | 完成 | 已生成报告、Hash 校验命令；样本已删除，仅保留报告与 Hash |

## 10. 检测工具和规则版本

- engine: FileGuard 0.3.0
- clamav: ClamAV 1.4.3/28183/Sat Nov 14 14:24:17 2026 (clamd)
- yara: yara-python 4.5.4 / rules r-bf00a731d1e2
- rules_version: r-bf00a731d1e2
- dependency_intel: local known-malicious list + OSV.dev

## 11. 恶意或可疑证据

- [严重][S4] 相对基线 1.0.0 只有 package.json 改变，且新增了带安装钩子的依赖 fg-crypto-helper（与 2026-03 Axios 投毒手法一致） — `package.json`（证据：`fg-crypto-helper`）  `DIFF_MANIFEST_ONLY_HOOKED_DEP`
- [高危][S3] 幽灵依赖：fg-crypto-helper 在 package.json 中声明但代码从未 require/import，且带安装钩子（node setup.js）——典型的投毒注入手法 — `fg-demo-http-1.0.1.tgz!/package/package.json`（证据：`fg-crypto-helper`）  `DEP_PHANTOM_WITH_INSTALL_HOOK`
- [信息][S3] 依赖 fg-crypto-helper@4.2.1 含安装钩子 postinstall — `dep:npm:fg-crypto-helper@4.2.1`（证据：`node setup.js`）  `DEP_HAS_INSTALL_HOOK`

## 12. 依赖统计

生态：npm；去重依赖 2 个；新检测 1 个（上限 200）；超额跳过 0 个；第 5 层以下轻量检查 0 个（不占 200 额度，上限 3000）；获取失败 0 个；最大深度 1

### 签名 / 来源证明 / 锁文件 / 源码 tag 比对

- `npm_registry_signature`: **不适用** — 该包/版本不在公共注册表，没有注册表签名可验证
- `lockfile_hashes`: **不适用** — 样本中没有锁文件
- `source_tag_diff`: **不适用** — 包没有声明源码仓库

## 13. 缓存命中统计

文件 Hash 缓存命中：否；依赖缓存命中 1 个（不占 200 额度）

## 14. 未检测的依赖列表

无

## 15. 历史版本对比

基线版本 1.0.0：新增文件 0，删除 0，修改 1（package.json）；新增依赖 fg-crypto-helper；新增安装钩子 无

## 16. 安装足迹预测

- [预测] npm install 会自动运行幽灵依赖 fg-crypto-helper 的安装钩子

## 17. 缺失的检查项

无

## 18. 已知检测局限

- 只做静态分析：未执行、未安装、未运行宏；运行时才解密/下载的载荷可能无法发现
- 依赖检查基于注册表元数据、已知恶意名单与 OSV 情报，未下载并逐个解包每个依赖
- YARA 规则为 FileGuard 自研小规则集，覆盖面有限

## 19. SHA-256 校验命令

```
sha256sum 'fg-demo-http-1.0.1.tgz'   # expect 8c7d41053a65a750485850c00c2043ad5102cff640ea0171a997534aabb583c1
shasum -a 256 'fg-demo-http-1.0.1.tgz'   # expect 8c7d41053a65a750485850c00c2043ad5102cff640ea0171a997534aabb583c1
Get-FileHash -Algorithm SHA256 'fg-demo-http-1.0.1.tgz'   # expect 8C7D41053A65A750485850C00C2043AD5102CFF640EA0171A997534AABB583C1
```

## 20. 检测时间

2026-11-14T03:47:25-08:00（耗时 0.24s；提交时预估 0.9s）

> NO_FINDINGS 表示在已完成的静态检测范围内没有发现威胁，不代表文件绝对安全。本次检测没有进行动态行为分析。

> 样本已在扫描后删除，仅保留报告与 Hash。