# 逆向工程大神养成路线图（RE-ROADMAP）

> 目标：从"会用工具"到"看透任何二进制"。
> 每日学习任务（cron 10:33）按本图推进，并回写进度。
> 本地弹药库：`skills/reverse-engineering/`（方法论）+ `skills/ctf-reverse/`（实战模式库）

## 信息源矩阵（每日巡检清单）

| 类别 | 站点 | 说明 |
|---|---|---|
| 中文社区 | 看雪论坛 bbs.kanxue.com | 国内 RE/安全第一站，看雪CTF、智能破解 |
| 中文社区 | 吾爱破解 52pojie.cn | 脱壳、破解实战氛围浓，工具区宝藏多 |
| 中文媒体 | FreeBuf、先知社区（xz.aliyun.com）、安全客 | 恶意软件分析、APT 报告转载与原创 |
| 官方博客 | Hex-Rays Blog（IDA）、Binary Ninja Blog、Ghidra GitHub | 反编译器前沿：新特性、插件、脚本 |
| 研究团队 | Google Project Zero、Mandiant FLARE、Trail of Bits、Quarkslab、Synacktiv、Zimperium zLabs | 顶级漏洞研究与工具发布（capa、floss、FLARE-VM） |
| 英文社区 | r/ReverseEngineering、secret club、MalwareTech、NSA 的 GHIDRA 讨论区 | 小型技术社区，writeup 密度高 |
| CTF | CTFtime.net、ctf.kanxue.com | 赛事日历与赛后 writeup |
| 工具发布 | GitHub Releases（frida/angr/rizin/Qiling/pycdc/blutter） | 版本更新=新能力 |
| 前沿方向 | AI 辅助逆向（LLM+Ghidra/IDA 插件）、eBPF 逆向辅助、WebAssembly 逆向 | 差异化竞争力 |

## 阶段一：基本功（预计 4 周）

| # | 主题 | 要点 | 输出物 |
|---|---|---|---|
| 1 | 文件格式 | ELF 头/节区/段、PE 结构（DOS头/NT头/节表）、Mach-O；静态 vs 动态链接、PLT/GOT 惰性绑定 | 手绘三种格式结构笔记 |
| 2 | 汇编阅读 | x86/x64 核心指令集、System V 与 Win64 调用约定、栈帧/EBP 帧指针、SIMD 初识 | 能徒手讲清 main→func 调用全程 |
| 3 | 静态工具链 | file/strings/xxd/objdump/readelf/nm → rizin(radare2) → Ghidra 反编译对比（dogbolt.org 并排验证） | r2 常用命令卡 + Ghidra 脚本 1 篇 |
| 4 | 动态基础 | strace/ltrace/GDB(pwndbg)：断点、watchpoint、内存搜索、PIE 相对断点 | GDB 速查卡 |
| 5 | 加密模式速识 | 单字节 XOR、已知明文 XOR、RC4、xorshift32/64 魔数、位置相关变换 | 常见模式速查表 |

**阶段一过关标准**：拿到陌生 ELF，10 分钟内说清保护措施、入口点、关键函数与验证逻辑走向。

## 阶段二：对抗与多平台（预计 6 周）

| # | 主题 | 要点 | 参考弹药 |
|---|---|---|---|
| 6 | 反调试对抗 | ptrace/TracerPid、PEB.BeingDebugged、NtQueryInformationProcess、时序(rdtsc)、TLS 回调、DR寄存器检测 | skills/ctf-reverse/anti-analysis.md（30+ 方法） |
| 7 | 反 VM/反插桩 | CPUID、MAC/工件检测、Frida 检测（端口27042、/proc/self/maps、内联hook）、反 DBI | anti-analysis.md + bypass 策略 |
| 8 | 脱壳与混淆 | UPX 及魔改、VMProtect/Themida（handler 表追踪）、MBA 表达式识别与化简、opaque predicate | tools-advanced.md（D-810/GOOMBA/Miasm） |
| 9 | 动态插桩 | Frida hook（strcmp/memcmp 捕获、ptrace 返回值篡改、内存扫描）、LD_PRELOAD oracle | tools-dynamic.md |
| 10 | 符号执行与模拟 | angr（路径探索、约束、hook 昂贵函数）、Qiling（跨平台模拟、无痕反反调试）、Unicorn 混合模式 | tools-dynamic.md |
| 11 | 多语言特性 | Go(GoReSym/字符串结构)、Rust(demangling/panic路径)、Swift(witness table)、Python字节码、.NET(dnSpy)、Flutter(Blutter)、IL2CPP | languages*.md 系列 |
| 12 | 移动与平台 | Android(APK/jadx/JNI RegisterNatives/DEX运行时patch)、iOS(Mach-O/砸壳frida-ios-dump)、固件(binwalk/UART/QEMU)、内核模块(.ko/ioctl) | platforms*.md 系列 |

**阶段二过关标准**：VMProtect 层的题目能定位 VM 入口与 handler 表；Frida 脚本能稳定绕过主流反调试；Go/Rust 二进制不再发怵。

## 阶段三：实战与前沿（持续循环）

| # | 主题 | 要点 |
|---|---|---|
| 13 | CTF 实战库 | 按 patterns*.md 五个文件逐类消化：时序侧信道、自定义VM键链爆破、GLSL shader VM、CVP/LLL 格攻击、信号侧信道…每类至少亲手复现 1 题 |
| 14 | 恶意软件分析 | FLARE 方法论：静态(capa/floss)→动态(沙箱)→C2 协议还原→IOC 提取 |
| 15 | 方法论内化 | TRACE 循环：Triage→Record→Abstract→Challenge→Explain；证据分级（observed/likely/guessed 永不混写）；先界面后内里；最小可复现探针 | skills/reverse-engineering/protocol.md、evidence-ladder.md |
| 16 | 前沿差异化 | LLM 辅助反编译质量评估、AI 生成的混淆识别、eBPF trace 用于逆向、供应链投毒样本分析 | 每周从信息源矩阵捕获 1 个新趋势 |

**阶段三过关标准**（= 大神标准）：
- 陌生保护方案：30 分钟内形成可证伪假设并给出验证路径
- 输出物达到研究团队水准：接口图 + 证据标签化报告 + 复现脚本
- 每类 CTF 模式都有肌肉记忆；反分析手段条件反射式反制

## 进度追踪（每日任务回写）

- [x] 2026-11-06 体系建立日 + 试运行第 1 期（16:48 手动触发，链路全通）：知识点「ELF 与 PE 结构对照」完成讲解，练习已布置（readelf 三件套 / PE 模板定位入口与导入表）；巡检产出 8 条动态（Frida 17.26.0、Ghidra 12.2、P0 BigSleep vs Fuzzilli、Zyxel 0Day、GhostMap、52pojie×2、看雪 VMP）
- [x] 2026-11-06 闭环机制上线 + 首轮验证（17:00 用户指令）：四步闭环写入 cron prompt 与本文件；当晚完成白银任务「手写 ELF64 解析器」4/4 验收通过（e_entry/段表与 readelf 全量一致、AST 验纯手解），产出 mini_elf.py + ELF64 速查卡 + 4 条踩坑规则，归档 artifacts/2026-11-06/
- [x] 2026-11-07（cron 10:33 第 2 期）：知识点「x86-64 调用约定 SysV vs MS x64」完成（真实反汇编实证 add8 示例）；巡检 8 条（IDA 9.5 三反编译器+MCP、IDA 恶意分析 Add-on、P0 BigSleep 45>Fuzzilli 37、GhostMap 无限重启、NIKKE CDN 投毒、VeilDHT、看雪 ARM64 VMP、rz-frida）；rekit 白银「动态段→DT_NEEDED」4/4 PASS 0 返工（< 基线 A），M1 25%；产出调用约定速查卡 + R6/R7 规则，归档 artifacts/2026-11-07/
- [x] 2026-11-08（cron 10:33 第 3 期）：知识点「栈帧建立/销毁全过程」完成（自构造 add8 八参数样本实证 prologue/epilogue/栈参数/endbr64 环境差异）；巡检 8 条（Frida 17.26 Stalker 反检测、REA 专访、Quarkslab 反 AI 逆向、ToB 人机补丁质量、Unit42 AI 载荷、52pojie Flutter iOS、rizin CVE、FLARE 学习中心）；rekit 白银「符号表解析」A1–A5 全 PASS（138/138 vs readelf），1 返工，M1 40%；产出栈帧识别清单 + R8–R12，归档 artifacts/2026-11-08/
- [x] 2026-11-09（cron 10:33 第 4 期）：知识点「重定位机制与 PLT/GOT 联动」（静态工具链 #3 主题，与 rekit 子任务同频共振）完成（五类类型语义 + 三大反直觉实测：静态二进制 22 条 IRELATIVE / full-RELRO 无 .got.plt / COPY 符号非 UND）；巡检 8 条（MythicRatatoskr 去中心化 C2、VOLTA LLM 受害者画像、Claude Code 客户端逆向、Ghidra 无头+LLM 流水线、REA 仓库栈分析、DIE 4.0 Beta、生成式 UI 沙箱越界、静态库符号重命名）；rekit 白银「重定位解析」13/13 验收 PASS（325/325 vs readelf 逐行 + objdump 三方复核 + 122 条落 .got 区间），2 返工（R12 二次复现→升级 R13 防空转 R14），M1 55%，pytest 25 断言常绿；产出知识卡 + R13–R15 + 可复用验证脚本，归档 artifacts/2026-11-09/
- [x] 2026-11-10（cron 10:33 第 5 期）：知识点「SIMD 初识」（阶段一 #2 收尾）完成（本机 AVX-512 实证：O3 定长循环 vmovdqu+vpaddd ymm 一吃八、O2 变长循环不向量化的 cost model 细节、bin_ls.elf 385 处 xmm 全 SSE 零 ymm 的发行版基线现象、movaps/movdqa/pxor 三巨头分布）；巡检 8 条（SSHhole Alpine OpenSSH 绕过+Frida 17.26.1/2 三连发+52pojie 14 层洋葱与 CKEY Unidbg AI 辅助逆向+Hex-Rays 收购 HexAI+Quarkslab CVE-2026-9539 快照工作流+ToB 包管理器完整性 2/25+看雪 Livewire 与 IoT 固件审计 Skill+REA 生态 probing-tools）；rekit 白银「checksec 三态」A1–A5 全 PASS（6 样本 18/18 格 vs readelf 权威表全等、全状态覆盖、pytest 25→34），1 返工（heredoc 权限→R18），**顺手修出 DT_TAGS 三处错位史潜伏 bug**（R16），M1 65%；产出 checksec 知识卡 + R16–R18 + verify 模板，归档 artifacts/2026-11-10/
- [x] 2026-11-11（cron 10:33 第 6 期）：**阶段一 #2 结业小测通过**——自构 mix.c（8 整参+2 浮参+AVX256）徒手讲清调用全程且工具自证闭环（main 侧双轨传参 rdi..r9∥xmm0/1、栈参右→左 push 8 后 push 7、call 隐式压返回址；mix 侧 rbp 帧锚取 [rbp+0x10] 栈参、and rsp,-32 重对齐、vzeroupper ABI 义务；手算 4×7000+popcount(36)=28002 与运行输出全等）；实战坑：**-O2 内联吞噬 call**（首编译 main 无 call mix → R19 noinline 纪律）+ 编译器把 set1(x)+set1(y)+add_pd 合并成标量 vaddsd 再广播（指令≠源码一一对应）+ 浮点依赖链循环不向量化 vs 整型位计数被 vpsravd 树形归约（向量化甜区边界）；巡检 8 条（52pojie 魔改 SQLCipher 三轮复盘+阿里 libsgmain 花指令三形态+看雪射频吉他拾音器、Doctor Web 假 GitHub 安全工具 2000+ 感染、Elastic RevStealer 14 间接 syscall+假 Claude 项目、ESET Lazarus 无人机链、rizin 0.8.2 CVE-2026-22780+Ghidra<12.2 zip bomb"分析工具自身成靶"、Quarkslab Avira 提权链）；rekit 白银·分析「M1 收口评估」A1–A5 全 PASS（对账 12/12 全证据化、两缺口量化：导出表系统正样本全缺→自构造路线/Rich 头 cli-64.exe+pefile 双就位、决策补 2 白银后收口再进 M1.5 不跳过），0 返工，M1 70%；产出对账决策报告 + 调用约定知识卡 R19–R21 + 3 份证据日志，归档 artifacts/2026-11-11/
- [x] 2026-11-12（cron 10:33 第 7 期）：知识点「数据结构识别」完成（阶段一 #3：偏移访问模式→字段表→struct 还原三步法 + [rbp-x]/[reg+disp] 判据 + stride×count 判数组 + 指针域判链表 + IDA/Ghidra 结构创建操作路径）；巡检 8 条（看雪 Polaris RE 鸿蒙三后端+证据契约、看雪阿里 sgmian 四神 VM 分类、ToB patching-bugs/regression-hunt 插件、Claude Code 配置泄密 1122 份、rizin 0.9.x RzArch、安全客 cPGuard 更新通道投毒、看雪安卓 FPS 外挂自解压 ELF 壳、Acronis 575+ 恶意 OpenClaw skills）；rekit 白银#1「Rich 头解析」C1–C5 全 PASS（11 对 vs pefile 逐项全等、5 负样本全 None 含双陷阱、双向锚定对照实验、pytest 34→40），1 返工（prodid/build 标签对调），**修正昨日"9/10 对"预研误读**（R22 权威工具输出须源码级对齐），M1 80%；产出 Rich 知识卡 R22–R24 + 双陷阱构造器 + 4 份证据，归档 artifacts/2026-11-12/
- [x] 2026-11-13（cron 10:33 第 8 期）：知识点「数据结构识别（下）·PE 导出表」（阶段一 #3 收尾，与 rekit 白银#2 同频共振：IMAGE_EXPORT_DIRECTORY 10 字段 + EAT/名字表/序号表三数组联动 + 纯序号导出 + 转发器语义 + 名字表序≠EAT 序反陷阱）；巡检 7 条（FreeBuf Expiro 感染型病毒新变种（PE 结构不动型感染：入口不变+CC int3 填充替换+末尾 UPX1 数据块）、L3akCTF 2026 RE 6 题全 writeup（subleq VM/MBA+BKZ 格攻击/.wwc VM+Feistel/Unity 3D 几何藏 flag/SHA-256 长度扩展）、Wiz AI 逆向工具挖出 GitHub 高危漏洞、crackmes.one 纯 RE CTF 2026、FreeBuf Blind Eagle APT-C-36 拉美虚假法院通知、REA investigation model 深度分析、rizin 2025 年度总结（RzIL 多架构 uplifting/RzArch/C++ demangler 重写））；rekit 白银#2「自构造 minidll+导出表解析」B1–B5 全 PASS（objdump 三方全等 4 函数/ordinal1–4/名字映射反陷阱、纯序号导出捕获、负样本 None、fixtures 9→10、pytest 40→49），核心交付 0 返工、**验收脚本 3 返工触发降档条款**（R25–R27 验证脚本三板斧），M1 90%；产出导出表知识卡 + verify_exports.py 模板 + 4 份证据，归档 artifacts/2026-11-13/
- [x] 2026-11-14（cron 10:33 第 9 期）：**rekit M1 收口日 ✅ 100%**——知识点「静态分析流水线（上）：Ghidra 无头流水线」（headless analyzer 三阶段/项目模型/postScript 钩子/脚本 API FlatProgramAPI 要点/与本机状态对照：JDK 21 已备、Ghidra 未装列为阶段二装机项）；巡检 7 条（IDA 9.5 官方 MCP+Assist agentic 时代、Quarkslab《Defeating AI-Assisted RE》实验（混淆未被 LLM 攻破、agent 被推进幻觉、AI 改变的是吞吐量）、Ghidra 12.2、rizin 0.9.x RzArch+ESIL→RzIL、52pojie 听书订阅逆向（同名类≠真实入口，可观察 UI 特征定位）、ArcticRAT 隐藏 VNC+AI 过滤短信、MS-SQL 爆破链 FortiGuard）；rekit 白银·收口（降档从轻执行）「统一 cli.py+终对账+R25 加固」D1–D5 全 PASS（10 fixtures cli≡模块逐字节、三负样本 exit 2/2/3 零 traceback、12/12 对账全证据、--selftest 锚点自检可证伪、pytest 49→58），**核心+验证脚本双 0 返工**（R25 前置自检当日实证）；超额项回写 CHARTER 走 CHANGELOG；产出 M1_CLOSEOUT_AUDIT.md + verify_cli.py 模板 + Ghidra 知识卡，归档 artifacts/2026-11-14/；**M1.5 MCP 化为下一子任务**（与 IDA 官方 MCP 方向同频）
- [x] 2026-11-15（cron 10:33 第 10 期）：**rekit M1.5 MCP 化完成 ✅**——知识点「动态基础：断点/watchpoint/内存搜索/PIE 相对断点」（阶段一 #4 上：int3 软件断点 vs DR0–DR3 硬件断点×4、watchpoint 数据断点抓变量改写、find/search 内存搜索、PIE 相对断点=starti 后 `break *$base+RVA`；本机无 gdb 无 root→ASLR 实证替代（两次 ldd libc 基址不同）+ rekit MCP 静态侧给 RVA（entry 0x6760），gdb+pwndbg 装机列为环境准备项）；巡检 8 条（Frida 17.26.3 barebone 内核模块加载注入、Cutter 2.5.0（Rizin 0.9.1、调试增强）、ToB AI-native playbook（94 插件 201 skills 开源）、看雪"逆向已死，AI 当立"行业讨论、FreeBuf C3RB3R NAS 勒索链（Synology DSM 双 9.8 洞+ChaCha20+RSA-OAEP）、GhostFrame ESXi 层窃凭证（Recorded Future TAG-218）、看雪罗克韦尔 .acd 工程归档逆向（不连 PLC 还原变量树）、Quarkslab PQC 库差异 fuzzing）；rekit 白银「M1.5 MCP 化」E1–E5 全 PASS（rekit/mcp.py 236 行纯 stdlib JSON-RPC stdio 服务器 + cli mcp 双身份短路；rekit_info/rekit_map 两工具；独立 stdio 客户端真实调用 35/35：握手回显/版本回退/通知零响应/bin_ls.elf 11 字段 readelf 全等（FLAGS BIND_NOW→Full RELRO）/段类型+flags 序列全等/pefile 节名全等/7 负路径 isError+连接存活；pytest 58→73 全绿），2 返工 < 3 不降档；R30 双错误语义、R31 期望提取防边界吞噬、R32 命名对齐权威源；产出 MCP 知识卡 + verify_mcp.py 客户端模板，归档 artifacts/2026-11-15/；下一子任务 M2 fingerprint
- [ ] 下期知识点：**阶段一 #5 加密模式速识**：单字节 XOR、已知明文 XOR、RC4、xorshift32/64 魔数、位置相关变换（补课项：GDB 实操——gdb+pwndbg 装机后做 watchpoint/PIE 断点实验；Ghidra 12.2 + JDK 21 已就绪仍为装机项）；rekit 进 M2 fingerprint（UPX/壳识别、编译器指纹、净室观察法，完成标准 ≥5 已知样本 100% 识别 0 误报）；信息源照常 + GitHub Trending（reverse-engineering）+ CTFtime 近期 writeup

## 任务-验收闭环（每日实操纪律，2026-11-06 起生效）

**四步闭环**（嵌入每日 10:33 任务，缺一不可）：
1. **布置任务**：从当前主题派生一个动手任务，优先本机可真实执行（解析真实二进制 / 写脚本 / 复现 writeup / 工具实操）
2. **先定验收标准**：至少 3 条，可量化、可证伪、有证据输出物（命令输出、脚本、对比结果）——标准在执行前写下，不许事后放宽
3. **执行与自验**：真实执行、逐条核对；未达标项如实记录原因，列入次日补课清单
4. **总结归档**：所学归纳为可复用规则/清单/脚本 → `learning/artifacts/YYYY-MM-DD/`，并回写 ROADMAP 进度

**任务分级**（由低到高）：
- 🥉 青铜·复现型：按文档操作跑通，验证理解（如 readelf 三件套）
- 🥈 白银·构建型：自写解析器/脚本，输出与权威工具交叉验证（如手写 ELF 解析器 vs readelf）
- 🥇 黄金·对抗型：脱壳、反反调试、VM 还原，产出接口图+证据标签化报告

**验收标准三原则**：交叉验证（与权威工具输出比对）、数字化（覆盖率/一致率有数）、可复查（证据存档）。

**红线**：严禁虚报完成；未达标不跳级，次日先补课再前进。

## 长期项目 #1：rekit 自研逆向工具包（2026-11-07 立项）

**定位**：逆向大神的核心资产——自己的工具链。每日实操任务的产出汇入本项目（闭环与项目合流，不增加并行负担）。

- 章程/里程碑/变更规则：`learning/rekit/CHARTER.md`（M1 loader → M2 fingerprint → M3 map&patch → M4 cfg → M5 mini-decompiler）
- 进度与速度基线：`learning/rekit/PROGRESS.md`（每日回写：完成项 + 耗时/返工 vs 基线）
- 任务/验收标准变更：`learning/rekit/CHANGELOG.md`（**仅长期项目可依此变更任务与标准**，须记日志、不得掩盖当日失败、不可证伪性不降）
- 每日任务量已依基线实测定标：1 白银/日（扩展型 1–2 min、从零型 5–8 min），返工 ≥3 次次日降档
- 现状：**M1.5 ✅ MCP 化完成（2026-11-15，E1–E5 全 PASS 35/35）**——rekit 三身份：CLI（`rekit.cli <file>` ELF/PE 自动识别）/ 模块（elf.py/pe.py 独立直调）/ **MCP（`rekit mcp` stdio 服务器，rekit_info 分诊摘要 + rekit_map 内存映射，双错误语义 R30）**；回归 73 断言常绿（fixtures 10）；CHARTER M1.5 完成标准"日报实际调用 rekit MCP 工具交叉验证"已达成（独立 stdio 客户端 + readelf/pefile 权威对拍，artifacts/2026-11-15/）；**下一步：M2 fingerprint**（UPX/壳识别、编译器指纹、stripped/RELRO/NX 净室检测，≥5 样本 100%/0 误报）；规则累计 R1–R32

## 纪律

1. 每日知识点按阶段主题池轮换，不跳级
2. 所有结论标注证据等级，学到的坑当天记入本文件或 TOOLS.md
3. 逢周五顺带复盘一周，调整下周节奏
4. 任务-验收闭环的四个部分（布置/标准/执行/验收）必须出现在日报中，总结归纳必须落成文件
5. **授权边界红线**（2026-11-07，借鉴 craft-anything 的明示授权边界）：日常分析对象仅限系统二进制、自构造样本、公开 CTF 样本与明确授权的软件；不碰未授权商业软件的破解实操（社区帖仅作知识学习）
6. 信息源矩阵补 GitHub Trending（reverse-engineering 类目）与 REA/craft-anything 等新工具的 release 页——10-31 爆红的 craft-anything 到 11-07 才被用户点进来才扫到，巡检盲区已暴露，必须补
