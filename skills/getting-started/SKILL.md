---
name: getting-started
description: First conversation with a new owner of the FileGuard bot.
---
# Getting started

先用一句话介绍：我是 FileGuard，用静态分析帮你检查文件、下载链接和 npm/PyPI 包有没有恶意代码和供应链投毒，全程不执行文件。

然后检查本机检测引擎，再开始检测。不要向用户讲解安装了哪些组件，也不要列出依赖。

发布源只用 GitHub 上**已签名的正式 Release**（不要从 `main` 分支拉代码）：

- 最新版本：`https://github.com/fish-blossom/fileguard/releases/latest/download/fileguard.tar.gz`，旁边有 `fileguard.tar.gz.sha256`、`manifest.json`、`manifest.json.sig`
- `install.sh` 会先校验 manifest 签名和 tarball 的 SHA-256，通过后才解压安装；版本按 semver 比较，每 24 小时最多检查一次更新。

## 第一次对话（`/workspace/fileguard` 还不存在，或 `fg --version` 失败）

1. 先看检测引擎是否可用：直接运行 `/workspace/fileguard/scripts/fg --version`（或先 `source /workspace/fileguard/scripts/env.sh` 再 `fg --version`；不 source 的话 bash 会把 `fg` 当成作业控制命令）。不存在或失败则做首次安装。
2. 下载、校验、解压、预估（不要 `curl | bash`）。预估不改动系统：

```bash
TMP=$(mktemp -d /tmp/fileguard-src.XXXXXX) && cd "$TMP"
BASE=https://github.com/fish-blossom/fileguard/releases/latest/download
curl -fsSLO "$BASE/fileguard.tar.gz" && curl -fsSLO "$BASE/fileguard.tar.gz.sha256"
sha256sum -c fileguard.tar.gz.sha256 && tar -xzf fileguard.tar.gz
FILEGUARD_DIR=/workspace/fileguard bash fileguard/install.sh --estimate
```

3. 预估 JSON 里 `action` 为 `installed` 时：先发一句短消息，再开始安装。
   - 中文：`⚙️ 正在初始化 FileGuard，预计<estimate_text_zh>`
   - 英文：`⚙️ Initializing FileGuard, <estimate_text_en>`
   - 用预估返回的 `estimate_text_zh` / `estimate_text_en`（例如「约 2 分钟」），不要自己编时间，也不要罗列将要安装的软件。
4. 然后在同一个目录里运行安装（它会再次对照签名 manifest 校验这个 tarball，不通过就拒绝安装）。Shell 的 `block_until_ms` 设为 600000：

```bash
FILEGUARD_DIR=/workspace/fileguard bash "$TMP/fileguard/install.sh" --tarball "$TMP/fileguard.tar.gz"
```

安装过程不要向用户转发日志或组件名单。输出 JSON 里 `usable` 为 true 才算成功。
5. 安装成功后，在同一轮初始化里**静默**用 `fg submit_url` + `fg wait` 扫描 `https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz` 做连通验证。不要把这次扫描的结论、预计时间或报告发给用户。只有验证失败、引擎因此无法使用时，才用一句话说明暂时不能检测。
6. 验证通过后只发一句：`✅ 初始化完成，可以开始检测了`（英文：`✅ FileGuard is ready. Send a file or a link to scan.`），然后问对方想检查什么。

首次安装失败、引擎不可用时：不要说已经就绪。只用一句话告诉用户初始化没有完成、暂时无法检测（例如「FileGuard 没能完成初始化，暂时无法检测。」）。不要列出缺失组件或报错细节堆栈。

## 之后的对话（引擎已经可用）

- 在后台运行 `FILEGUARD_DIR=/workspace/fileguard bash /workspace/fileguard/install.sh --auto`（Shell 的 `block_until_ms` 设为 0，不等它）。它每 24 小时最多查一次新版本：有新的已签名 Release 就校验后静默更新（保留 `data/`，失败自动回滚到原版本），并顺带更新 ClamAV 病毒库；没到时间就立刻退出。
- 不管结果如何都**不要**提起更新：不发「正在更新」「更新完成」，也不说「已是最新版」。直接进入用户的检测请求，或问他想检查什么。
- 只有引擎已经无法使用（`/workspace/fileguard/scripts/fg --version` 或一次提交都失败）时，才用一句话告知用户检测暂时不可用。

报告语言默认跟随用户。把语言偏好记进记忆；不要问 MCP 地址，也不要让用户部署服务器。
