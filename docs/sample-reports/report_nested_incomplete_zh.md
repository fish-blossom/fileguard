# FileGuard 检测报告 — **INCOMPLETE**
**结论：** 有 1 项必需检查缺失或无法完成。默认不放行：有必需检查没有完成。只有你本人针对这个 SHA-256 和列出的缺失项明确确认后，才会记录为“用户自担风险”。
> 用户确认记录：示例用户于 2026-01-01T00:00:00-08:00 针对 SHA-256 c787d5fd7e4fbbf8… 确认接受缺失项风险（状态仍为 INCOMPLETE）。

| 项目 | 内容 |
|---|---|
| 1. 文件名 | nested_7_levels.zip |
| 2. 文件类型 | Zip archive data, made by v2.0 UNIX, extract using at least v2.0, last modified Nov 14 2026 03:44:04, uncompressed size 605, method=deflate |
| 3. 文件大小 | 704 bytes |
| 4. 原始 URL | 不适用 |
| 5. 最终下载 URL | 不适用 |
| 6. SHA-256 | `c787d5fd7e4fbbf8be31a71f68cdd18b3b5f901ce80a9c5dc66d4016674facd9` |
| 7. 最终结论 | **INCOMPLETE** |
| 8. 风险等级 | UNKNOWN |

## 9. S0–S7 覆盖情况

| 阶段 | 状态 | 说明 |
|---|---|---|
| S0 输入校验 | 完成 | 输入已受理：类型识别、大小校验 |
| S1 来源信誉 | 不适用 | 用户直接上传，无下载来源；包名仿冒检查在 S3 进行 |
| S2 下载完整性 | 完成 | 已计算 SHA-256/SHA-1/MD5；已比对已知恶意 Hash；官方校验：无可用 |
| S3 静态分析 | 部分完成 | 解包、ClamAV、YARA、格式分析、混淆/编码分析、网络与凭据特征、依赖(无清单) |
| S4 版本差异 | 不适用 | 不是可识别版本的软件包，无基线可比 |
| S5 安装足迹预测 | 完成 | 静态预测 0 项安装足迹（均为预测，非实际观察） |
| S6 风险裁决 | 完成 | 规则引擎裁决：INCOMPLETE |
| S7 交付与跟进 | 完成 | 已生成报告、Hash 校验命令；样本已删除，仅保留报告与 Hash |

## 10. 检测工具和规则版本

- engine: FileGuard 0.3.0
- clamav: ClamAV 1.4.3/28183/Sat Nov 14 14:24:17 2026 (clamd)
- yara: yara-python 4.5.4 / rules r-bf00a731d1e2
- rules_version: r-bf00a731d1e2
- dependency_intel: local known-malicious list + OSV.dev

## 11. 恶意或可疑证据

未发现可疑证据。

## 12. 依赖统计

不适用

### 签名 / 来源证明 / 锁文件 / 源码 tag 比对

- `lockfile_hashes`: **不适用** — 样本中没有锁文件
- `source_tag_diff`: **不适用** — 不是可识别版本的 npm/PyPI 包

## 13. 缓存命中统计

文件 Hash 缓存命中：否；依赖缓存命中 0 个（不占 200 额度）

## 14. 未检测的依赖列表

不适用

## 15. 历史版本对比

不适用

## 16. 安装足迹预测

不适用

## 17. 缺失的检查项

- `UNPACK_DEPTH_LIMIT` [S3] 嵌套压缩超过 5 层，内层内容未检测 — `nested_7_levels.zip!/level1.zip!/level2.zip!/level3.zip!/level4.zip!/level5.zip`

## 18. 已知检测局限

- 只做静态分析：未执行、未安装、未运行宏；运行时才解密/下载的载荷可能无法发现
- 依赖检查基于注册表元数据、已知恶意名单与 OSV 情报，未下载并逐个解包每个依赖
- YARA 规则为 FileGuard 自研小规则集，覆盖面有限

## 19. SHA-256 校验命令

```
sha256sum 'nested_7_levels.zip'   # expect c787d5fd7e4fbbf8be31a71f68cdd18b3b5f901ce80a9c5dc66d4016674facd9
shasum -a 256 'nested_7_levels.zip'   # expect c787d5fd7e4fbbf8be31a71f68cdd18b3b5f901ce80a9c5dc66d4016674facd9
Get-FileHash -Algorithm SHA256 'nested_7_levels.zip'   # expect C787D5FD7E4FBBF8BE31A71F68CDD18B3B5F901CE80A9C5DC66D4016674FACD9
```

## 20. 检测时间

2026-11-14T03:47:19-08:00（耗时 0.03s；提交时预估 0.5s）

> NO_FINDINGS 表示在已完成的静态检测范围内没有发现威胁，不代表文件绝对安全。本次检测没有进行动态行为分析。

> 样本已在扫描后删除，仅保留报告与 Hash。