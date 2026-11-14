# searchskill.ai 提交信息 / Submission Info

## 它有什么作用？ / What does it do?
中文：FileGuard 用静态分析检测文件和下载链接，判断里面有没有恶意代码、可疑行为和供应链投毒，全程不执行任何文件。它会检查安装脚本、下载来源、签名和 Hash、压缩包和依赖，还能识别 Axios 投毒那种“代码没改、只加了一个带安装脚本的依赖”的手法。最后给出 BLOCK、HIGH_RISK、INCOMPLETE、NO_FINDINGS、ERROR 五种结论之一，并附上证据。

English: FileGuard uses static analysis to check files and download links for malicious code, suspicious behavior, and supply-chain poisoning, without ever executing them. It inspects install scripts, download sources, signatures and hashes, archives, and dependencies, and catches tricks like the Axios attack, where the library code was untouched but a dependency with an install script was added. Every scan ends in one of five evidence-backed verdicts: BLOCK, HIGH_RISK, INCOMPLETE, NO_FINDINGS, or ERROR.

## 启动提示 / Starter prompts
中文：
- 帮我检查这个 npm 包安不安全：axios@1.7.9
- 这个下载链接里的文件有没有问题？
- 我上传了一个压缩包，帮我扫一下有没有恶意代码
- 这个安装脚本会在我电脑上做什么？

English:
- Is this npm package safe to install: axios@1.7.9?
- Can you check the file behind this download link?
- I uploaded an archive. Scan it for malicious code.
- What will this install script do to my machine?

## 使用说明 / Usage
中文：直接上传文件，或者发一个下载链接、包名和版本号。FileGuard 会先告诉你大概要多久，然后按 S0 到 S7 七个阶段检测，扫得久时会告诉你进行到哪一步。报告包含结论、风险等级、证据、Hash 和校验方法。单个文件最大 500 MB，压缩包最多解 5 层，文件只做静态分析、扫完即删，只保留报告和 Hash。NO_FINDINGS 表示在已完成的静态检测范围内没有发现威胁，不代表绝对安全。

English: Upload a file, or send a download link or a package name and version. FileGuard first tells you roughly how long the scan will take, then runs a seven-stage check (S0 to S7) and updates you on long scans. The report includes the verdict, risk level, evidence, SHA-256, and how to verify it. Files can be up to 500 MB, archives are unpacked up to 5 levels deep, and files are only analyzed statically, then deleted after the scan, keeping just the report and hashes. NO_FINDINGS means no threat was found within the completed static checks; it does not guarantee a file is safe.

## 公共模板链接 / Public template link
（待生成 / To be generated after the bot is created）
