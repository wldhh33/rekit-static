# rekit 进度档案

## 速度基线数据（2026-11-07 实测）

| 基线 | 任务类型 | 时钟耗时 | 工具轮次 | 返工次数 | 验收结果 |
|---|---|---|---|---|---|
| A | 同模块扩展（ELF 节区解析） | 1.2 min | ~8 | 1（验收脚本正则错位） | A1–A3 全 PASS，30/30 节全字段一致 |
| B | 新领域从零（PE 构造+解析+三方验证） | 7.2 min | ~19 | 8（详见下） | B1–B4 全 PASS |

### 基线 B 的 8 次返工明细（价值最高的数据）
1. 构造器 OptHdr 格式串漏 CheckSum（I）
2. 构造器节表格式串漏 RelocPtr/LineNumPtr（II）
3. 解析器 OptHdr 同样漏 CheckSum
4. 解析器节表同样漏 2 个 I
5. 解析器 OptHdr 解包起点 opt+20 应为 opt+16
6. 解析器 NumRvaAndSizes 偏移 112 应为 108
7. **构造器把导入目录写进 DataDirs[0]（Export 位）**——objdump 三方验证抓出
8. **构造器 .idata 布局重叠**（DLL 名 RAW 0x620 覆盖终止 descriptor 0x614–0x628）——运行时 "KERN/EL32/.dll 被当 RVA" 症状定位

## 规律沉淀（写代码前必读）

- **R1 字段计数先行**：连续同类型字段多的 struct 串，先列字段表数个数再写串（CheckSum 在 3 处漏了 3 次）
- **R2 构造器先画 RVA→RAW 地址表**，检查区间不重叠再写字节（返工 #8 的教训）
- **R3 三方交叉验证是金标准**：构造器 / 解析器 / objdump 互相独立，抓出了 #7、#8 两个"自以为对"的真 bug
- **R4 验收失败先怀疑验收器**：基线 A 的唯一返工是验收脚本自身的正则错位
- **R5 PE32 与 PE32+ 差异清单**：ImageBase 4/8B、栈堆 4/8B×4、BaseOfData 仅 PE32、DataDirs 起点 96/112

## 每日任务量校准（依据基线数据定标，2026-11-07）

- **白银·扩展型**（rekit 既有模块加功能）：期望 1–2 min / 5–8 轮
- **白银·从零型**（新模块）：期望 5–8 min / 15–20 轮，预留 2 次返工
- 每日实操任务 = **1 个白银**（优先 rekit 当前进度）+ 可选 1 个青铜热身
- 黄金任务拆成 ≤ 白银粒度的子任务，每个子任务独立验收
- 若当日返工 ≥ 3 次：次日该模块任务降档为青铜复现型（巩固后再前进）

## 进度追踪

- [x] 2026-11-07 立项 + 双基线实测（A/B 全 PASS）+ rekit.elf 节区解析 + rekit.pe 完整导入表 + minipe.exe 测试样本；M1 进度 15%
- [x] 2026-11-07 白银·扩展：elf.py 动态段解析（PT_DYNAMIC→Elf64_Dyn→DT_NEEDED，vaddr 经 PT_LOAD 换算）——4/4 验收 PASS（3 样本 NEEDED/段字段 vs readelf 全一致 + 静态 ELF 鲁棒 + 直用 vaddr 反证越界）；耗时 ≈1.5 min / ≈8 轮 / **0 返工**（基线 A 预留 1–2，优于基线）；新规则 R6（vaddr≠offset 必换算）R7（glibc 2.34+ libm 并入 libc）；M1 进度 25%
- [x] 2026-11-08 白银·扩展：elf.py 符号表解析（SHT_SYMTAB/SHT_DYNSYM→Elf64_Sym→sh_link 找字符串表节→符号名+st_value+bind/type）——A1–A5 全 PASS（4 样本数量 8/8、bin_ls .dynsym 138/138 逐行 vs readelf、122 个 UND 全 value=0、main/_start 快照 0x1129/0x1040、nm -D 复核一致、pytest 新增 7 断言全套件 18/18 绿）；耗时 ≈8 min（时钟，含 pytest 编写）/ ≈15 工具轮 / **1 返工**（测试正则分组对调，R12 重复模式）；高于基线 A 时钟主因 = 断言固化纪律成本（CHANGELOG 11-07 已预估 +3–5 轮，实测符合）；新规则 R8–R12；M1 进度 40%
- [x] 2026-11-09 白银·扩展：elf.py 重定位解析（SHT_RELA→Elf64_Rela→r_info 拆解→sym_idx 查 .dynsym→五类类型名表；CLI readelf -r 风格）——验收 13/13 PASS（A1 四样本节数条数 8/8 组全等、A2 bin_ls 全量 325 条 (offset,type,name,addend) 逐行 vs readelf diff=0、A2' objdump -R 三方复核含 *ABS* 伪符号、A3 全量 sym_idx 落界+查表名一致+122 条 JUMP_SLOT/GLOB_DAT 落 .got 区间+6 条 COPY 落 .bss 且 st_value==r_offset、A4 pytest 18→25 断言全绿）；耗时 ≈7 min（时钟，含 pytest）/ ≈14 工具轮 / **2 返工**（#1 验收脚本元组下标 e[3]≠e[2] 空转+objdump 伪符号未适配；#2 测试正则漏捕获括号→组后移连锁，R12 二次复现→升级 R13）；基线 A 预留 1–2 返工，符合上限；新规则 R13–R15（正则分组清单/验收防空转/工具显示怪癖清单）；基线勘察推翻"静态无重定位"直觉（dyn_static 22 条 IRELATIVE）；M1 进度 55%
- [x] 2026-11-10 白银·扩展：elf.py 安全态检测（PT_GNU_STACK flags→NX、PT_GNU_RELRO×三路立即绑定→RELRO 三态、e_type×PT_INTERP→PIE、W+X 段扫描；CLI 顶部 checksec 行）——验收 A1–A5 全 PASS（A1 6 样本 18/18 格 vs readelf 权威期望表全等、A2 NX{en,dis}/RELRO{full,partial,none}/PIE{yes,no} 全状态覆盖（新构造 dyn_norelro/dyn_execstack 两 fixture 补缺格）、A3 FLAGS(30)&0x8/FLAGS_1&0x1 位掩码路径真实覆盖（tag-24 防御性收录如实标注 untested-by-sample）、A4 pytest 25→34 断言全绿（+9）、A5 CLI 证据留档）；耗时 ≈5 min（时钟，含 2 fixture 构造+证据采集）/ ≈10 工具轮 / **1 返工**（heredoc 追加 test_elf.py 遭 root 属主权限拒绝→R18 工具分层）；轮次略超基线 A 上限（5–8），原因：任务实为"扩展+样本构造"混合型，构造/权威采集占 3 轮；**顺手修复 DT_TAGS 常量表 3 处错位史**（15/21/23→RPATH/DEBUG/JMPREL，真值 BIND_NOW=24——潜伏两日在语义依赖时爆雷）；新规则 R16–R18；M1 进度 65%
- [x] 2026-11-11 白银·分析：M1 收口评估（CHARTER M1 清单 12 项对账 + 两缺口量化 + 收口决策）——验收 A1–A5 全 PASS（A1 对账 12/12 项全证据化（代码行号/断言数/当日命令输出）；A2 导出表：系统正样本全缺（.NET DLL 导出表全空、cli-64.exe EXE 无导出）→ 定自构造 minidll 路线（objdump 三方验证可行）、Rich 头：正样本 setuptools/cli-64.exe（Rich@0xe8 key=0x31a563a3 10 对 comp.id）+ pefile 权威对照当日 venv 装通；A3 pytest 34 绿 + CLI 7/7 fixtures exit 0 双证据留档；A4 决策：**补 2 白银后收口再进 M1.5，不跳过**（11-12 Rich 头扩展型 2–4 min / 11-13 导出表从零型≈基线 B / 11-14 统一 cli.py+终对账）；A5 超额项 4 条（重定位/checksec/fixtures 7>5/断言 34）单列供 CHARTER 修订）；耗时 ≈12 min / ≈12 工具轮 / **0 返工**（超基线 A 时钟属评估型任务盘点成本，非返工）；顺带完成阶段一 #2 收尾小测（mix 样本 28002 手算闭环，R19–R21）；两个预研坑记入明日 TASK（Rich 限 DOS stub 区防深域误匹配 / pefile values 尾部语义须源码确认）；M1 进度 70%
- [x] 2026-11-12 白银·扩展：pe.py Rich 头解析（限界找明文 Rich+key → 回找 DanS^key 双向锚定 → 解密 [DanS,0,0,0]+N 对；CLI 含 prodid/build 解码）——验收 C1–C5 全 PASS（C1 key=0x31A563A3、11 对逐项 vs pefile values 配对全等、DanS@0x80/Rich@0xe8；C2 五负样本全 None：minipe/自构造双陷阱 fakerich（stub 区 Rich+key 无 DanS 锚 + .text 深处 Rich）/28MB Aspose（深处 0x147ba89 真实 "Rich" 字节串）/Autofac/DepInj；C3 单向对照实验证明双向锚定必要性（单向被骗出 key=0x11223344 垃圾）；C4 pytest 34→40 断言全绿（+6 测试函数，含 pefile importorskip 交叉验证）、fixtures 7→9；C5 知识卡 R22–R24）；耗时 ≈20 min（时钟，含 ~12 min 语义定标预研）/ ≈14 工具轮 / **1 返工**（CLI prodid/build 标签对调——30729=MSC19.29 佐证 build 在低 16 位，自验收抓出）；**修正 11-11 预研日志"9 对"误读**（尾对 (0x1027f14,1) 是真实第 11 对而非 Rich^key+key，0x01027f14^key=0x30a71cb7≠'Rich' 证伪；gap audit 草案"10 对"同源笔误），根因=未读 pefile 源码即解释 values 格式 → R22；新规则 R22（权威工具输出须源码级对齐）R23（双向锚定防御巧合字节串）R24（存储域/明文域话术统一律）；M1 进度 80%（Rich ✅，余导出表+cli.py 统一+终对账）
- [x] 2026-11-13 白银#2·从零：自构造 minidll + pe.py 导出表解析（make_minidll.py 纯 struct 构造 PE32+ DLL：IMAGE_FILE_DLL 位+ .edata 节 + IMAGE_EXPORT_DIRECTORY 40B + 三数组；parse_exports：DataDirs[0]→三数组联动，遍历全 EAT 捕获纯序号项；CLI 导出段输出）——验收 B1–B5 全 PASS（B1 objdump 无报错读出全表与构造参数一致 4 函数/ordinal1–4/minidll.dll；B2 rekit↔objdump EAT 逐项+名字→ordinal 映射全等 Add→1/Sub→2/Mul→3（构造时故意名字表字母序≠EAT 序、序号表 [0,2,1] 反陷阱）；B3 纯序号导出 (None,4,0x1040) 呈现；B4 负样本 minipe/cli-64 → None 不崩；B5 fixtures 9→10、pytest 40→49（+9）全绿）；耗时 ≈11 min（时钟）/ ≈13 工具轮 / 返工 3 次（**全部在验收脚本** verify_exports.py：正则吃 "Export RVA" Type 列 → split 锚点不唯一（"Export Address Table" 出现 3 次）→ hint 列双空格；核心交付构造器+解析器 0 返工，R1/R2 红利）；**触发 ≥3 次降档条款**：11-14 收口任务按从轻执行+内嵌锚点唯一性自检；新规则 R25–R27（验证脚本三板斧：锚点唯一性/正则边界对齐列语义/列宽 \s+）；M1 进度 90%（解析能力集齐：头/节/导入/导出/Rich，余 cli.py 统一+终对账）
- [x] 2026-11-14 白银·收口（**降档从轻**，11-13 三返工降档条款执行）：统一 cli.py（argparse + detect_format 两级 magic 校验：ELF 魔数 / MZ+e_lfanew→PE\0\0；elf/pe main 参数化复用渲染通道保输出一致；负样本 exit 2 分诊失败 / exit 3 解析失败，零 traceback）+ 终对账（M1_CLOSEOUT_AUDIT.md 12/12 项全证据 ✅；超额项重定位/checksec/fixtures 10/断言 58 回写 CHARTER，走 CHANGELOG 11-14 条目）+ R25 加固（verify_cli.py anchor_line() 前置锚点唯一断言 + --selftest 重复/缺失锚点双负例，证明自检可证伪）——验收 D1–D5 全 PASS（D1 10 fixtures cli≡模块直调逐字节 identical=True + 审计字段锚点提取；D2 text/MZ无签名/截断ELF 三负样本 exit 2/2/3 友好降级；D3 对账+回写完成；D4 selftest 拦截成功；D5 pytest 49→58 全绿（+9 test_cli.py：自动识别/负样本/截断/format 覆写/cli≡模块/10 fixtures 全量））；耗时 ≈7.5 min（时钟，纯执行 1.5 + 对账分析 6）/ ≈12 工具轮 / **0 返工（核心+验证脚本双零）**——R25 前置自检的当日实证（优于扩展型基线 A）；**M1 收口 ✅ 100%**，进入 M1.5 MCP 化；规则沉淀 R28（分诊工具崩溃路径可控律：exit 码语义分层）R29（模板函数参数化保输出一致律）

- [x] 2026-11-15 白银·M1.5「`rekit mcp` MCP 服务器」：rekit/mcp.py（236 行纯 stdlib：JSON-RPC 2.0 行分帧、initialize 版本协商回显/回退、通知零响应、tools/list+tools/call、ping、坏帧 stderr 跳过）+ cli.py 手动短路 `mcp` 子命令（argparse 行为零改动，58 断言不破）；工具 rekit_info（ELF：arch/bits/endian/type/entry/段节数/NX·RELRO·PIE/needed/interpreter；PE：arch/bits/type/entry_rva/image_base/imports/exports/Rich 摘要）+ rekit_map（ELF 段表（readelf 风格 GNU_* 命名）/节表；PE 节表 RVA/VSize/RawPtr/RawSize）；验收 E1–E5 全 PASS（verify_mcp.py **独立 stdio 客户端子进程真实调用** 35/35：E1 握手 5（回显 2025-06-18/未知版本回退 LATEST/通知零响应 id 跳跃验证）、E2 schema 5、E3 bin_ls.elf 11 字段 vs readelf -h/-lW/-SW/-d 全等（DYN/0x6760/14 段/30 节/NX enabled/**Full RELRO（FLAGS BIND_NOW 三路判定）**/PIE yes/interp/needed×3/arch）、E4 map 7（段类型+flags 序列 14 项全等/节数 30/pefile 节名 .text·.edata/kind 缺省）、E5 负路径 7（不存在/text/缺 path/非法 kind→isError、错误后连接存活、-32601、未知通知+ping））；pytest 58→73 全绿（test_mcp.py 15 断言：握手×2/通知零响应/双工具 schema/ELF·PE info 锚点/map×3/负路径×4/双身份不串台）；返工 2 次（cli.py 编辑重复行自纠、verify 正则 `\S+` 吞 `]` 假 FAIL→R31）< 3 不降档；耗时 ≈8 min / ≈22 工具轮（新协议层从零+包装既有解析，量级介于基线 A/B 之间偏 A）；沉淀 R30（协议服务器双错误语义）R31（期望提取防边界吞噬）R32（新接口层命名对齐权威源）；CHARTER M1.5 ✅（完成标准"日报实际调用 rekit MCP 工具交叉验证"由 E3/E4 达成）

## 工程资产清单（2026-11-07 起）

- `tests/fixtures/`：bin_ls.elf（系统 PIE）/ dyn_pie / dyn_nopie（非 PIE）/ dyn_static / dyn_norelro（-z norelro）/ dyn_execstack（-z execstack，NX off）/ minipe.exe（PE）/ cli-64.exe（MSVC 正样本，Rich 头）/ minipe_fakerich.exe（Rich 双陷阱负样本）/ minidll.dll（自构造带导出表 DLL，2026-11-13）——回归样本已固化 10 个，不再依赖 /tmp
- `tests/test_elf.py` + `tests/test_pe.py` + `tests/test_cli.py` + `tests/test_mcp.py` + `tests/test_fingerprint.py` + `tests/test_map.py`(25) + `tests/test_iat.py`(17) + `tests/test_disasm.py`(70) + `tests/test_recdesc.py`(40)：**244 断言常绿**（含重定位、checksec readelf 交叉验证、Rich pefile 交叉验证、导出表 objdump 交叉验证、CLI 自动识别/负样本/format 覆写、MCP 握手/工具调用/负路径、fingerprint 19 条、map 的三种 query_mode 与节身份分层、iat 的修复往返/幂等/拒绝覆盖/反例/E8 负路径）；验证器三份：`tests/verify_fingerprint.py`（E9 载体）、`tests/verify_map.py`（映射+IAT 矩阵，2402 格）、`tests/verify_iat.py`（IAT 对拍/反例/selftest），均先校验真值 sha256
- `learning/artifacts/2026-11-15/`：TASK_m15_mcp.md（先行的 E1–E5 标准）、verify_mcp.py（独立 stdio MCP 客户端 + readelf/pefile 权威对拍，可复用为 MCP/子进程协议服务器类任务模板）、evidence_mcp_verify.log（35/35 PASS）/ evidence_pytest.log（73 passed）、mcp_knowledge_and_rules.md（MCP 协议知识卡 + PIE 相对断点知识 + R30–R32）
- M3 任务卡与证据：`2026-11-15/m3-task-card/outputs/TASK_m3_map_patch.md`（U0–U4、E1–E9、E1.1 输出契约）、`m3-task-card/work/evidence_map_2026-11-15.log`（§1–§7：含 GT 冻结指纹、逐格归因、加壳单列、幂等/反例/selftest、收口对账）、`m3-task-card/work/map_ground_truth.json`(+`.sha256`) 与 `collect_map_gt.py`
- `learning/artifacts/2026-11-14/`：TASK_m1_closeout.md（先行的 D1–D5 标准）、M1_CLOSEOUT_AUDIT.md（12 项终对账全证据 + 超额项 + D1–D5 验收结果）、verify_cli.py（D1/D2/D4 验证脚本，内嵌 anchor_line() 锚点唯一性自检 + --selftest 负测试，可复用为 CLI 类任务模板）、evidence_verify_cli.log / evidence_pytest.log、ghidra_headless_knowledge.md（知识点知识卡）
- [x] 下一子任务（M1.5 MCP 化）✅ 2026-11-15 完成（见进度日志）：`rekit mcp` 本地服务器，info/map 包装为 MCP 工具，stdlib 实现；完成标准"cron 日报自我验收环节实际调用 rekit MCP 工具完成一次交叉验证"已达成（E3/E4，35/35）
- [x] 2026-11-15 白银·M2「fingerprint 指纹层」：rekit/fingerprint.py（纯 stdlib，6 顶层键 format/packer/compiler/stripped/mitigations/evidence）+ CLI 短路 `fingerprint` + MCP `rekit_fingerprint`；UPX 正判（PE 节名 UPX*/`UPX!` 魔数、ELF 节表移除降级）、编译器指纹（GCC `.comment`、MSVC Rich build→19.29、Go `.go.buildinfo`/`Go buildinf:`、Rust `rustc/<commit>`，**Rich≠MSVC** 防线）、stripped/COFF、ELF NX·RELRO·PIE 三态 + PE DllChar 位——验收 E1–E9 全 PASS（E1 接口/CLI≡模块/MCP 注册；E2 UPX 3/3（PE×2+ELF×1，各 2 证据，`upx -t` 全 OK）；E3 15 未加壳负样本误报 0；E4 gcc 14.2.0 5/5 且无 `.comment` 必 unknown；E5 Rich 仲裁 rust 不判 msvc；E6 go 1.27.3 PE/ELF 双口径；E7 stripped 只认 `.symtab`、PE 报 COFF；E8 ELF 18 格 + PE 位全等；**E9 `verify_fingerprint.py --all --matrix` PASS：18 样本 / 132 可判定格 132 命中（100%）/ 12 不可判定格全部正确弃权 / 误报 0 / 违规 0 / 异常 0**）；pytest 73→92 断言全绿（新增 19；补装 GNU binutils 2.47 后原 objdump 红测转绿、4 条 readelf 跳过转真跑，0 skipped）；**G3 关闭：upx.exe 5.3.0 win64 可交叉压缩 ELF（`-d` 往返 sha256 全等）**，PE 往返非逐字节等价（145/1606 字节差，节表/Rich 全等）已登记为口径 caveat；耗时 未单独计时（分 3 轮会话：任务卡+U1 / UPX 补测 / E9 收口）/ ≈45 工具轮 / **返工 6**（实现 4：PE DllChar 误取 COFF chars、MSVC 取最大 build 32532 误判、UPX-ELF `e_shnum=0` 崩溃降级、render_text 把 unknown 显示 yes；验收器 2：verify_e3 列索引、E9 矩阵 family/version 混表重跑）——实现 4 ≥3 触发明日降档条款（M3 首日按从轻执行）；环境坑 2 个不计返工（UPX 不认非 ASCII 路径、gettext 镜像拒访改官方源）；**GT 冻结前修正 2 处样本标注错误**（S5 go_linux nx、S7 busybox relro，readelf 复核，非判据改动）；沉淀 R33（GT 标注须独立证据复核）R34（矩阵分键与分母：family/version 不混表、弃权格单列）R35（unknown 三态裁决：对不可判定格给确定值即误报）；CHARTER M2 ✅ 收口

- [x] 下一子任务（M2 fingerprint）✅ 2026-11-15 完成（见上行进度日志）：UPX/常见壳识别、编译器指纹、stripped/RELRO/NX 检测（净室观察法）；完成标准「≥5 已知样本识别率 100%、误报 0」以 18 样本 / 132 格实测达成
- [x] 2026-11-15 白银·M3「map&patch 收口」：rekit/mapview.py（映射单元：ELF=PT_LOAD / PE=头区+节；三值语义 hit/not_in_file/unmapped；`addr_to_off`/`off_to_addr` 双向；NOBITS 一律 not_in_file + `host_section`；节身份分层 = 裸地址保守 / 节级按 `section=` 判定）+ rekit/iat.py（`headers`/`rva_to_off`/`locate_bytes`/`repair_bytes`/`repair_file`：descriptor 20B 扫描、slot 级解码 name|#ordinal+hint、按 INT 回填、写回只产新文件）+ CLI `rekit map --addr/--off/--section`、`rekit iat --json/--repair-out` + MCP `rekit_map`(addr/off/section) 与只读 `rekit_iat`——验收：**A) verify_map --all --matrix 可判定格 2402/2402（100%）失配 0 误报 0 弃权 2，exit 0；B) verify_iat --all --selftest 未加壳解码 2202 格 + 修复 545 slots/30 区间逐字节全等、加壳 136 格解码 0 失配但 24 slots 全 unresolved 零写入，反例与 selftest 均按预期失败/检出，exit 0；C) pytest 134 passed，exit 0**；IAT 加壳与未加壳分维度统计（`iat` / `iat_packed`），加壳结构性不可修复在 CLI/MCP 输出里以 `repairable=false`+`caveats` 可解释（不只给一堆 unresolved）；耗时：未独立计时（M3 跨 4 个会话窗口 U0/U1、U2、U3、U4）/ 工具轮 ≈70（估算，口径=会话内工具调用次数，非独立计时；量级高于从零型基线 B 因含 3 份独立验证器与真值冻结）；**返工 7**（实现 5：`.tbss` NOBITS 优先级缺失、fakerich 零长度节建单元、`off_to_addr` 缺 `query_mode`、裸地址与节级输出不可区分、`iat.locate` 跨描述符序号 NameError；验证器 2：`verify_iat.py` 列表推导缺括号、加壳组漏做幂等检查）+ 判据变更 1（E4 加严，用户裁决，不计返工）——实现项多集中在"输出契约/边界"而非算法，说明 M3 的新风险在接口层；沉淀 R36–R42；CHARTER M3 ✅ 收口

- [x] 2026-11-15 白银·M4-U1「x86-64 线性扫描」：rekit/disasm.py（前缀族/长度表/ModRM·SIB·disp/立即数族逐类；表外与 VEX/EVEX 一律 `unsupported` 停止，不猜长度；每条指令复用 M3 `addr_to_off` 标文件落点）+ CLI `rekit disasm --section/--limit/--json` + `tests/verify_disasm.py`（objdump 2.47 `-z` 逐行边界，首分歧定位到字节，capstone 第三方仲裁）+ `tests/test_disasm.py` 70 项——验收：7 样本长度不一致 0 条、分歧 0、selftest 注入长度 +1 检出；pytest 134→204；盲区（数据当指令/跳转表/VEX）写入输出 caveats。返工见下方 M4 汇总。
- [x] 2026-11-15 白银·M4-U2「递归下降 + 基本块」：rekit/recdesc.py（PE 导出 EAT/.pdata/EntryPoint + ELF e_entry/STT_FUNC/.eh_frame FDE 手解；种子分 authoritative/heuristic/derived 且成功率分列；函数 end 限制；重叠解码记录；启发式默认关闭）+ `tests/verify_recdesc.py`（7 样本：种子分级、三方同址同长、范围覆盖归因、线性↔递归差集、abstain 量化、selftest）+ `tests/test_recdesc.py` 31 项 + 自建 AVX 样本 `avx_dense.exe`（VEX 密度 47.2%）——验收：不可解释边界 0、权威 41/41·331/331·1067/1090 等分列、AVX 弃权 3 点漏 38 条(71.7%)、dyn_static 107 点漏 12385 条(10.9%)；pytest 204→235。
- [x] 2026-11-15 白银·M4-U3「基本块规则显式化 + CFG 边分级」：块规则写死（leader/终结符/call 不终结/块只属一个函数）；`_build_cfg` 五类边（definite/speculative/cross_function/undecoded/unresolved）+ 调用边单列；`.pdata`/FDE/st_size 作为函数硬边界，越界分支不并进当前函数、跨函数单列；CLI 输出 CFG 摘要，确定边为 0 时解释结构性原因；`verify_recdesc.py` 增 `cfg_check` 独立重算——验收：确定∩疑似=∅、间接 target=None、跨函数不混入；pytest 235→242（+7）。
- [x] 2026-11-15 白银·M4 收口：全量 **pytest 244 passed**（exit 0）+ 4 验证脚本 exit 0（verify_disasm / verify_map 2402/2402 / verify_iat 失配 0 / verify_recdesc PASS）；CHARTER M4 行回写、完成标准定标、R43–R48 入 CHANGELOG；证据 `work/evidence_m4_closeout_2026-11-15.log`。M4 ✅ 收口。
  - 收口补记①（环境前置，非代码回归）：objdump 不在系统 PATH 时 pytest 为 `1 failed / 238 passed / 4 skipped`（test_pe 的 minidll 对拍 FileNotFoundError）。挂 `m2-task-card/work/tools/binutils-2.47/mingw64/bin` 后 244 passed / 0 skipped，两次结果都留在收口证据 §0。
  - 收口补记②（R48 补强）：“确定边为 0”原来把**真零**（minidll 全是单条 ret 桩，确实无控制流）和**标签性零**（dyn_pie 有 13 条边但无声明边界）用同一句话收尾，易被误读。现按“有无跳转/分支指令”三分支输出，并新增断言 `test_true_zero_edges_told_apart_from_label_zero`（243→244）。
  - **M4 返工/自纠明细（三日合计 9 项，实现 5 / 验收器 3 / 环境 1）**：
    实现：①`.eh_frame` FDE 的 CIE 引用基址取成长度字段（应为 CIE_pointer 字段自身）；②personality 的 indirect 编码直接抛错（改为只跳过不解引用）；③重叠解码被当冲突拒绝（glibc jcc 跳过 lock 前缀，改为字节并集 + 允许重叠）；④顺序流未用 FDE/st_size 截断而外溢到填充/下一函数；⑤CFG 分支目标越界仍沿用原函数 origin（改为另起 unknown 根）+ 函数末尾假 fallthrough（改为 `end==range_end` 不连边）。
    验收器：⑥verify_recdesc `check_boundaries` 传参类型错（传 dict 而非长度表）；⑦minidll 对拍未加 objdump `-z` 导致零填充里的 ret 被判“漏指令”；⑧test_recdesc 三处断言与样本事实/API 不符（FDE 数 >=3→>=2 并加首地址断言、`_one` 缺 opcode 键、CLI 标签中英文）。
    环境：⑨mingw `as` 目标为 COFF，无法生成 ELF（AVX 样本改用 PE32+，ELF 侧用 dyn_static 量化，不计返工）。
  - 新增规则：**R43** 种子权威性分列（权威/启发式/派生成功率不得合并，权威分不得被启发式补分）；**R44** 边置信分级（确定/疑似/跨函数/未解出/未解析互斥，猜的边不得进确定集）；**R45** 间接目标不猜（jmp/call 间接一律 target=None + unresolved）；**R46** 函数边界硬约束（`.pdata`/FDE/st_size 为界，越界不并函数，跨函数边单列）；**R47** 弃权代价量化（abstain 必须给条数与占比，不许写“未量化”）；**R48** 零值可解释（关键计数为 0 必须在输出里说明结构性原因，不得让人误读为“不存在”）。
  - **R36 写回类操作最小纪律**：只产新文件；`dst==src` 双重拒绝（同串 `samefile` + `realpath`），非只查字符串；写盘 `tmp` + `os.replace`。改样本字节的能力越强，越要先把"不许动原件"做成代码而不是注释。
  - **R37 幂等必须可证**：同一输入两次写同一产物路径，比对两次 `dst_sha256`；"幂等"声明不算证据。附：原样本 sha256 每次写完复核。
  - **R38 修复正确性用原件字节证明**：区间 sha256 / 逐 slot 字节 / 产物整文件 sha256 三层，"能启动/看起来对"不作判据；验证器必须做一次故意破坏并确认其失败（`--selftest`），否则 PASS 无意义。
  - **R39 名称源缺失时一律 unresolved**：PE `OriginalFirstThunk=0` 时 INT 与 IAT 同址，拿 IAT 充当 INT 会把伪地址写入名称源区（测一次即自毁），不许用"猜测回填"换成功率。
  - **R40 加壳/未加壳分维度**：成功率分母按 `iat` 与 `iat_packed` 拆开，加壳样本只报"结构上不可修复"的条数，不并入未加壳成功率。
  - **R41 参照工具自身被证伪时**：弃用该参照但**保留样本格数**（如 objdump 对 Go 长节名 RVA→节错位），并在真值里标 `*_reliable=False`；不许以"跳过样本"达成好看数字。
  - **R42 弃权必须可解释**：结构性做不到的弃权要随结果带 `repairable=false` + 人话 `caveats`（CLI/MCP 都要），只给状态枚举等于让使用者自己猜；同时只报结构后果，不据单一信号下"这就是加壳"的结论（是否加壳归指纹层）。
- [x] 2026-11-15 白银·M5-U1：expr.py 函数内表达式恢复（白名单 + abstain 必须带 missing；间接目标 None）+ VEX/EVEX 长度表补齐。
  - 复用 M4 函数域/块/边，不重做。全二进制（仅声明边界域）：cli-64 41/85 函数、1433/1463 指令（abstain 2.05%）；bin_ls 331/331、16867/17475（3.48%）；dyn_static 1084/1089、85464/94722（9.77%）。
  - VEX/EVEX 弃权变化：avx_dense abstain 3→0、权威种子 2/5→5/5、覆盖 <35%→94.8%；dyn_static abstain 107→0、确定边 26882→30202、目标未解出 42→18（未解析 123 不变，间接目标仍不猜）。
  - 验收：verify_expr 抽样 57（池 41→18 / 331→18 / 1084→21；分层等距 + 5 类强制覆盖，无随机数）；Ghidra 对读入口 15/18、8/18、18/21；重叠集块数 14/15、8/8、15/18；调用集 8/15、5/8、12/18；分歧逐条归因（并入相邻函数 / 尾跳转呈 call / 间接 jmp 不猜致 case 块不可达 / 块切分口径）。
  - 回归：pytest **280 passed**（exit 0）+ verify_disasm / verify_recdesc / verify_map / verify_iat / verify_expr 全部 PASS，四个 selftest 均能检出；证据 work/evidence_expr_2026-11-15.log、work/evidence_m5_pytest.log。
  - 自纠：VEX3 无保留位（最初多加 P1[2] 检查致 dyn_static 误弃权，已删）；人工对读抓到 fs/gs 段前缀被丢弃（fs:[0x28] 渲染成绝对 0x28），已修并加断言 → R52。
  - **2026-11-16 验收补强（外部 oracle + 可失败自证）**：verify_expr 新增与 Ghidra 无关的硬判据——objdump 全节线性反汇编对照（抽样函数的每条指令必须是 objdump 指令起点；call/branch/jmp 站点助记符与直接目标逐条相等，间接形式不得是直接操作数）+ 下层账目（`insns = 下层归属指令数`、`lifted+abstained = insns`、verdict 与 abstain/boundary 一致）。`--selftest` 两处注入（一条直接调用目标 +1、`lifted` +1）均被检出，未篡改 0 失败。M5-U1 已公布数字逐项复跑**相等**：抽样 57（18/18/21）、Ghidra 入口 15/18、8/18、18/21、块数 14/15、8/8、15/18、调用集 8/15、5/8、12/18。已知残差显式报出、不判失败也不表述为零分歧：函数域内 objdump 线性扫描比 expr 多解 cli 1 条（1/18 函数）、bin_ls 403 条（7/18）、dyn_static 390 条（13/21），口径为 CFG 可达子集 vs 线性全扫，未逐指令归因（早先探针按每样本前 40 个声明函数统计为 cli 3 / bin_ls 3 / dyn 1 个函数，与 57 抽样口径不同）。pytest 554 passed 不变。
- [x] 2026-11-15 白银·M5-U2：跳转表候选层 switchcand.py（默认关闭、独立模块、不写回 res）。
  - 识别 rel32（lea→movsxd→add→jmp）与 abs64（jmp [rip+idx*8]）两形态；表长只认 `cmp idx,imm` + `ja/jae` 上界；无 guard 时表长未证明，证据最多 medium 且扫描有上限。
  - 基准收益（dyn_static 0x401870，弱参照 Ghidra 55 块）：我方既有 23 块，候选新增 20 块 → 候选口径 43 块；**补回 20 块、补错 0 块**，剩余 12 块属既有块切分口径差异（不是候选漏项）。
  - 负向基线：冻结 tests/fixtures/definite_baseline.json；开/关候选后 recdesc 17 项 + expr 8 项 + 0x401870 函数指标逐项不变（28 项全等），pytest test_switchcand 15 项通过。
  - 拒绝理由可见：跨函数/数据、落在已解出指令内部、不可解、表项越界四类各自带 reason；dyn_static 全量 34 候选（high 29 / low 5）、未识别 87、整条被拒 2。
- [x] 2026-11-15 白银·M5-U3：控制流结构化输出 struct.py（默认关闭，`--structured` 才输出）。
  - 结构：支配/后支配 + 最近公共后支配求汇合点；自然循环（回边+dom）分 while / do-while / for(;;)；if-then / if-else；循环内 break/continue 按「另一条边是否在循环体内」判定。
  - switch 分级：只有候选证据 `high` 才渲染 `switch (idx) { case N: goto … }`；medium/low/无候选一律保留 goto，reason 写明证据等级与依据（R45 口径不变）。
  - 可回溯硬约束：每节点带 block/edges/join；`check_traceable` 校验块存在、不重复、**每个可达块必须出现且仅出现一次**、edges 必须是 recdesc 真实后继、case 目标必须属于 high 候选集。三样本逐函数 violations=0，emitted==reachable 无一例外。
  - 不可结构形态如实单列：不可约 0/441/2407 块（0/12/77 函数）；条件不可判 3/21/206；goto 密集 9/79/240 函数（阈值 >30%，写在 stats 里）。不强行套 if/loop。
  - 实测结构量（cli-64 / bin_ls / dyn_static）：if 88/1193/5905、else 17/334/1560、while 20/50/425、do-while 2/1/21、for 0/1/9、switch 0/3/9、goto 60/887/4347。dyn_static 29 个 high 候选 = switch 9 + 未展开块(label) 20，账目对平。
  - 回归：pytest **316 passed**（exit 0，新增 tests/test_struct.py 21 项）+ 8 个验证脚本全部 exit 0（verify_fingerprint 按 E9 需 --all --matrix，VERDICT PASS 132/132）；证据 work/evidence_m5u3_*.log。
  - 注：负向基线文件已移到 `tests/baselines/definite_baseline.json`（放在 tests/fixtures/ 会被夹具扫描当成第 11 个样本），U2 条目里的旧路径按此为准。
  - 收口结论：M5 三单元（表达式 / 候选层 / 结构化）全部达成；剩余差异只有切块粒度（0x401870 我方 23 块 vs Ghidra 55 块，12 块按裁决记为已知差异，不改核心切块口径）。
- `learning/artifacts/2026-11-13/`：TASK_minidll.md（先行的 B1–B5 标准）、make_minidll.py 配套 verify_exports.py（导出表三方比对模板，可传任意 DLL）、evidence_pytest.log / evidence_objdump_minidll.txt / evidence_rekit_cli_minidll.log / evidence_exports_verify.log（三方全等 5 项 PASS）、export_knowledge_and_rules.md（知识卡 + R25–R27）
- `learning/artifacts/2026-11-11/`：TASK_m1_gap_audit.md（先行的 A1–A5 标准）、M1_GAP_AUDIT.md（对账表+缺口量化+三日收口路径决策）、evidence_pytest.log / evidence_cli_fixtures.log / evidence_rich_probe.log（Rich 正负样本探测+pefile 权威输出，含两个预研坑）、mix.c + mix_disasm.txt（阶段一 #2 收尾小测样本）、knowledge_call_conv_simd.md（调用约定×AVX 知识卡，R19–R21）
- `learning/artifacts/2026-11-10/`：TASK_checksec.md（先行的验收标准+权威期望表）、verify_checksec.py（18 格全等比对脚本，可复用为三态类任务模板）、evidence_*.log（readelf 权威快照/18/18 PASS/CLI+pytest 证据）、checksec_knowledge_and_rules.md（知识卡 + R16–R18）
- `learning/artifacts/2026-11-09/`：TASK_relocations.md、verify_relocations.py（RELA 类任务模板）、evidence_*.log、relocation_knowledge_and_rules.md（R13–R15）
- 借鉴来源：craft-anything（storytold/craft-anything，10-31 开源）的基线审计/CLI+MCP 双身份/净室分层/授权边界四项实践，经 2026-11-07 CHANGELOG 变更流程吸收
- [x] 2026-11-15 白银·M6-U1：调用图 + 保守的跨过程观察（callgraph.py，CLI 子命令 `rekit callgraph`）。
  - 口径：调用点 = 全部已解出 call 指令（e8 / FF 解码为 call），不沿用 recdesc.cfg.calls——后者只记块末调用（cli-64 13 条 vs 实际 153 条），两口径单列并注明不合并。 **已知偏低（2026-11-16 裁决标注）**：`_call_insns` 按首字节 e8/ff 过滤，带前缀 call 被漏（cli-64 0 / bin_ls 13 / dyn_static 53）；本条目及下一条目的调用点与三态数字均按旧口径，修正见 M7-U2（明细 outputs/TASK_m7u1_join.md §12）；**2026-11-16 已修正**：调用点 1154 / 3609、间接 38 / 152，旧数仅作历史对照（见 M7-U2 条目）。
  - 三态（分母=直接调用点）：cli-64 98 直接 → decoded 63 (64.29%) / plt_or_import 35 (35.71%) / unresolved 0；bin_ls 1116 → 428 (38.35%) / 688 (61.65%) / 0；dyn_static 3456 → 3049 (88.22%) / 402 (11.63%) / 5 (0.14%，目标在 .init/0x0)。 **分母已知偏低**：bin_ls 漏的 13 条全为间接 call（`41 ff d6` 等），直接分母 1116 不变、间接 25→38；dyn_static 漏 52 间接 + 1 直接（`67 e8`），直接分母 3456→3457、间接 100→152；上述占比按旧分母计算。**重定标结果**：dyn decoded 3049(88.22%)→3050(88.23%)，plt 402(11.63%) 与 unresolved 5(0.14%) 不变；cli 与 bin_ls 三态数字不变（新调用全为间接/已解出目标）。
  - 判据：PE 导入走 IAT 槽 → dll!name；ELF 走 .rela.plt/.rela.dyn 的 JUMP_SLOT/GLOB_DAT；导入跳板 = 单条 jmp [槽]；槽回指不到名字就只报槽地址，不按序号猜。
  - 间接调用候选层：默认关闭，--indirect-candidates 开启后单列、带证据等级（cli-64 52/3/0、bin_ls 1/2/22、dyn_static 0/1/99）；high 只表示「调用点操作数定位到导入槽」，不并入三态。
  - 观察：同块窗口内的前最后定义 / 后首次使用（before 464/3785/10928、after 309/2275/6356），未建模指令处截断并记原因（3/50/163），rsp 改写单独标注（34/166/368）；不做 ABI 推断。
  - 环：Tarjan SCC，自递归 0/2/15、互递归 0/0/2；渲染 visited + 节点上限 120 + 深度 12，两次渲染逐字节一致。
  - 回归：pytest 339 passed（316→339，新增 test_callgraph 23 项）+ 9 个验证脚本 exit 0（新增 verify_callgraph；verify_fingerprint --all --matrix E9 132/132）；负向基线 17 项 + 表达式 sha256 + 0x401870 sha256 全等；build 前后 res 快照一致（只读）。证据 work/evidence_m6u1_*.log。

- [x] 2026-11-15 白银·M6-U2：跨函数参数传递的事实层（callfacts.py，CLI 子命令 `rekit callfacts`）。
  - 证据三级：declared（节表 / IAT / .rela.plt 重定位 / 符号表 / .pdata·FDE，链接器写的）/ observed（指令原始字节、目标地址算术）/ derived（同块倒扫的最后定义、顺序扫描的首次使用、FF25 跳板形态判定、启发式函数入口、块归属）；每条证据只属一级，`counts.evidence` 与 `counts.target_evidence` 分开计数，不合并成"已确定"。
  - 操作数事实的 declared 恒为 0（结构上不可能）：字节是 observed，"这是最后一次写"是 derived。`cli-64` @0x1061 目标 0x1000 只有启发式种子，记 `derived[function_start]`，不写成"已声明函数"。
  - 不做 ABI 推断：无参数列表字段；每站固定 `full_argument_set` abstain；间接调用目标 abstain；窗口被未解码指令截断记 `window_before/after`；栈槽基址在"定义点之后、调用点之前"被改写 → `slot:[…]` abstain（缺栈指针/帧基址值追踪）。
  - 实测（cli-64 / bin_ls / dyn_static）：站点 153/1141/3556（**1141/3556 已知偏低**：分别漏 13/53 条带前缀 call，明细见 M6-U1 口径注释；直接 98/1116/3456 + 间接 55/25/100 同为旧口径；**M7-U2 修正后为 153/1154/3609，直接 98/1116/3457 + 间接 55/38/152**），before 450/3771/10847、after 309/2275/6356；abstain 225/1230/3905（full_argument_set 153/1141/3556、target 55/25/105、slot 14/14/81、窗口 3/50/163）；操作数证据 declared 0/0/0、observed 759/6046/17203、derived 759/6046/17203；目标证据 declared 68/1804/3451；函数域 declared 153/1141/3553、derived 0/0/3。
  - 一致性：事实层**独立重算**目标三态证据，再与调用图 `edges[].state` 逐点比对（直接站点两边都有且相等、间接站点事实层不得有 state、站点总数 == `call_sites`）；三样本 checked == sites、矛盾 0；注入两种不一致（篡改 state、删站点）都能被检出。
  - 口径升级（非回归）：与 `callgraph --observe` 逐站点比，寄存器集合相等、槽集合是子集；before 464→450 / 3785→3771 / 10928→10847，差值 14/14/81 恰好等于槽 abstain 数，after 完全一致。
  - 跨块：本轮未开任何例外（没有可验证判据），每站点 `cross_block="not_traced"`，报告顶层写明规则。
  - 回归：pytest **364 passed**（339→364，新增 tests/test_callfacts.py 25 项）+ **10 个验证脚本 exit 0**（新增 verify_callfacts；verify_fingerprint --all --matrix）；负向基线 17 项 + 表达式 sha256 + 0x401870 sha256 全等；build 前后 res 快照一致（只读）。证据 work/evidence_m6u2_*.log。

- [x] 2026-11-16 白银·M6 收口：调用图（U1）+ 参数事实层（U2）逐条对账达标（交付 outputs/TASK_m6_closeout.md）。
  - 达标对账：U1 五条（确定边/候选层隔离、观察只报事实、三态占比、环与有界渲染、零回归）与 U2 五条（三级证据、ABI 禁令、跨块不追、与调用图一致、零回归）全部 ✅；收口五条（declared=0 解释、退出码入证、文档回写、达标·边界·下一里程碑、环境记录入文档）全部 ✅。
  - 操作数级 declared = 0 的正式口径：declared 只覆盖文件能声明的对象（节表 / IAT / 重定位 / 符号 / 函数范围 / CFA），没有任何文件结构声明"这条指令在准备参数"或"这是最后一次写"；一条操作数事实只有 observed（字节）+ derived（扫描规则）两部分，故 declared 恒 0 是结构性恒等式。由此必须 abstain 的结论：参数序号、参数来源、参数溢出槽、参数个数、返回值/调用约定。目标侧 declared 非零（68/1804/3451）来自节表/重定位/函数声明，两个计数器分开正是为了不混淆。
  - 当日回归（2026-11-16）：pytest **364 passed**（exit 0）；10 个验证脚本**全部 exit 0**（逐行退出码见 work/evidence_m6_closeout_scripts.log）；pytest 日志 work/evidence_m6_closeout_pytest.log；负向基线 17 项 + 表达式 sha256 + 0x401870 sha256 全等，build 前后 res 快照一致。
  - **M6 返工/自纠明细（两单元合计 13 项：实现 9 / 验收器 2 / 文档 1 / 环境 1）**：①cfg.calls 只记块末调用（13 vs 153）→ 全量扫描 call 指令；②ELF `.comment`（addr=0）误判 → 只收非零节；③`fde@0x…` 当符号名 → 过滤；④`_effects` 把 lea 槽 / `mov` 目的当使用 → 修正读写判定；⑤窗口字段名误导 → 拆 before/after 指令数与已解码数；⑥渲染树只从 entry 出发 → 补 roots；⑦槽基址 `rstrip` 解析脆弱 → 改 split；⑧facts 计数漏目标证据 → 新增 target_evidence；⑨`_render_observations` 脏 replace → 直接中文；⑩verify_callfacts 的 `path and ".text"` 笔误 → `".text"`；⑪旧 verify 未覆盖槽口径与 `--observe` 交叉 → 新增核对；⑫TASK_m6_callgraph 初稿凭记忆写样例（0x26de/0x30c0）→ 实测改为 0x2690/0x30c8；⑬objdump 中文路径需 LC_ALL=C（环境，不计代码返工）。
  - 规则编号：M6 共 R59–R67（U1：R59–R62；U2：R63–R65；收口：R66–R67）。R66 某等级证据计数为 0 时必须写明"结构性恒等 / 缺失"及由此 abstain 的结论，不得只留数字；R67 回归依赖外部工具时，PATH / 编码 / locale 前置必须写入文档环境记录，不得只留在日志。
  - 下一里程碑建议：M7-U1 先做"三层拼接"（图 / 事实 / 伪 C 同一调用点），纯拼装零推断；跨块数据流须先给可验证判据再开；参数绑定须先有调用约定声明来源。（2026-11-16 裁决改号：M7-U2 = 带前缀 call 修正 + 重定标，跨块与参数绑定顺延为 U3 / U4。）无调试信息的参数名/类型与运行期间接目标属"结构上做不到"，跨块 / ABI / 拼接属"还没做"。
  - 环境记录（入文档，不只日志）：见 CHARTER「运行环境记录（回归前置）」与 outputs/TASK_m6_closeout.md §6.3——Python 3.14.0、`PYTHONIOENCODING=utf-8`、objdump 2.47 项目内路径、**中文路径需 `LC_ALL=C`**。
- [x] 2026-11-16 白银·M7-U1：三层拼接（rekit/sitejoin.py，CLI 子命令 `rekit sitejoin`；交付 outputs/TASK_m7u1_join.md）。
  - 对齐键：主键 = 调用指令虚拟地址（from）——三层同源于 recdesc，地址是唯一不依赖任何一层文本格式、且可复算的键；键重复（recdesc 允许重叠块）报 `duplicate_key`(data_anomaly)，不合并、不取其一。
  - 结构化侧无地址：用 (函数, 块起始) + 块内第 j 个调用回指，j 由**本块已解出 call 的地址顺序**确定（不用事实层站点顺序，否则下层漏 call 会连带错位）；行序含指向 call 的 abstain 注释行、body/term 两段都看；三重机械校验（行数 / 文本目标 == 事实层 target / 行号切片）。
  - 键覆盖独立账：本层自己按「跳空前缀后的 opcode」枚举已解出 call（不复用下层 e8/ff 首字节过滤），账目 `decoded_calls == keys + 两层都漏`。
  - 实测：cli-64 153/153 键、覆盖完整、aligned 153、冲突 0；bin_ls 1141 键 / 已解出 1154 / 漏 13 / aligned 1141；dyn_static 3556 键 / 已解出 3609 / 漏 53 / aligned 3553 + 3 条口径差异（not_declared 函数）。
  - 真实缺陷（单列未修）：`callgraph._call_insns` 按首字节 e8/ff 过滤，漏掉带前缀的 call——bin_ls 13 条 `41 ff d6`、dyn_static 52 条 `43 ff 14 fe` + 1 条 `67 e8`；两层共用该枚举故同时缺。修改会牵动 M6 已公布计数与 expr 文本基线，属 M7-U2 重定标，本单元按「单列 + 归因 + 可复现」处理。
  - 能失败自证：三注入（改 state / 删图边 / 破坏文本行）全部检出；`verify_sitejoin.py --selftest` 打断行定位后报出 98 条 struct_line_count_mismatch；真实缺口逐条复核「该地址确是 call、首字节确非 e8/ff」。
  - 只读：check() 纯函数；build() 前后 graph/facts/sidx/res 四项深比较快照全等；无任何副作用（struct_index 只读输入、算新对象）。
  - 回归：pytest **382 passed**（364→382，新增 tests/test_sitejoin.py 18 项）+ **11 个验证脚本 exit 0**（新增 verify_sitejoin）+ selftest exit 0；负向基线 17 项 + 表达式 sha256 全等。证据 work/evidence_m7u1_join.log / evidence_m7u1_pytest.log / evidence_m7u1_scripts.log。
  - 规则：R68 三层对齐以调用指令地址为主键，重复不合并；R69 冲突必须逐条归因且归因由可复现的字节/字段比对支撑；R70 拼接层只读、下层缺陷只单列不在本层修补。
- [x] 2026-11-16 M7-U2：带前缀 call 漏检修正 + 重定标（`callgraph._call_insns`；输出 outputs/TASK_m7u2_prefix_call.md）。
  - 修法：新增 `_LEGACY_PREFIX` / `_opcode_of`（跳 legacy 前缀 + REX 取 opcode）；`e8` 直接放行，`ff` 须 ModRM.reg ∈ {2,3}，再交 `expr.decode` 复核 `family == "call"`；同类判据 `_Ctx.rip_mem_target` / `thunk_of` 改为 `_rip_mem`（跳前缀、disp 偏移按实际前缀数，不写死 6/+2）。
  - 重定标（前→后）：cli-64 153→153；bin_ls 1141→**1154**（直接 1116 不变，间接 25→38）；dyn_static 3556→**3609**（直接 3456→3457，间接 100→152）。三态：cli 63/35/0、bin_ls 428/688/0 不变；dyn 3049(88.22%)→3050(88.23%)，plt 402、unresolved 5 不变。候选层 low 22→35 / 99→151，high/medium 未增。函数节点 85/331/1089 与环 0/2/17 **完全不变**。
  - 拼接层：bin_ls 键 1141→1154、aligned 1141→1154、硬冲突 13→0；dyn 键 3556→3609、aligned 3553→3606、硬冲突 53→0、口径差异 3（struct_function_absent）保留。`callfacts` abstain 1230→1257 / 3905→4012；栈槽事实 2898→2951；槽弃权 14→14 / 81→82；窗口截断 50→51 / 163→164——弃权与截断均**只增不减**。
  - 未动：`recdesc`/`disasm`/`expr`/`struct`/`switchcand`/`callfacts` 零改动；`tests/baselines/definite_baseline.json` 未改（sha256 `e6d62a5f…1a6c`），三样本 expr 文本 sha256 前后逐字相同（`600291…` / `ca75e9…` / `59959b…`）。
  - 校验器同错（新发现，审计第 12 项）：`tests/verify_callgraph.py` 与 `tests/test_callgraph.py` 的「直接调用点 == E8 集合」同样按 raw 首字节判定，修正前与被测模块同错、形成自洽假象；已改独立 `_opcode()`（跳前缀），并把一致性检查从 bin_ls 扩到 dyn_static。
  - 收紧而非放宽：`verify_sitejoin.py` 的 `KNOWN_HARD` 由 `{call_site_missing}` 改为 `set()`；新增第 4 类注入「两层同时删同一站点 → call_site_missing」，日志显示 `注入自证: state=检出, edge=检出, struct=检出, coverage=检出`；`--selftest` 仍报 98 条 `struct_line_count_mismatch`。
  - 回归：pytest **383 passed**；11 个验证脚本 + `verify_sitejoin --selftest` **12 条 exit 0**；修正前后日志逐行 diff 仅数字与耗时变化（work/evidence_m7u2_pytest.log、evidence_m7u2_scripts.log）。
  - 规则：R71 指令类别必须按「跳 legacy 前缀 + REX 后的 opcode」判定，`ff` 还须核 ModRM.reg；R72 已公布数字发现偏低必须就地标注「已知偏低 + 差额 + 修正单元」；**R73 校验器不得与被测模块共用同一判据实现，且每条"恒成立"不变量至少要有一次注入/反向验证**，否则「同错」会互相背书（本轮 verify_callgraph 即实例）。
- [x] 2026-11-16 M7 收口：逐条对账 + 同错方法学复盘 + 权威口径（交付 outputs/TASK_m7_closeout.md；证据 work/evidence_m7close_pytest.log / evidence_m7close_scripts.log / evidence_m7close_snapshot.json）。
  - U1 对账（五条全达标）：键唯一可解释（三样本 153/1154/3609，重复 0、键集合 == facts∪graph）；冲突单列三类归因（硬冲突 0/0/0，dyn 保留 3 条 caliber_difference）；能失败自证（state/edge/struct/coverage 四类注入全检出 + `--selftest` 98 条）；只读（res/graph/facts/sidx 四项深比较全等）；零回归。
  - U2 对账（五条全达标）：修法符合 R71（跳前缀 opcode + ModRM.reg∈{2,3} + expr 复核）；对比表按 §14 字段给全；四条「不是放宽」有证据（硬冲突 13/53→0、abstain 1230→1257 / 3905→4012、截断 50→51 / 163→164、KNOWN_HARD 空集、新增第 4 类注入、基线未改）；12 条验证命令 exit 0 + 383 passed；三样本数字与三处「变好看」已单列解释。
  - 权威口径：调用点/三态/站点/环数以 outputs/TASK_m7u2_prefix_call.md §3 + work/evidence_m7close_snapshot.json 为准；CHARTER/PROGRESS 中 1141/3556 等旧数仅作历史对照（均已就地标注「已知偏低 → 已修正」）。
  - 方法学（用户必答）：同错机制 = 校验器与被测模块各自用「raw 首字节」写同一判据，且期望值取自同一 res["instructions"]，集合相等型不变量在两端同步出错时恒真；M6 负向基线只锁计数、不覆盖类别完整性。发现手段分三层：强共享（验收脚本 import 被测私有判据）可静态扫描；有外部 oracle 的判据可差分（objdump）；**语义重复只能人工审 + 修正后全量重跑 diff**——不存在全局自动手段，如实写明。本轮扫描 6 个测试/验收文件 15 处私有符号引用，verify_callfacts 的 `CG._effects` 列入复检清单（本轮不改代码）。
  - 返工/自纠明细 7 项：①`_call_insns` 首字节过滤（实现）；②`rip_mem_target`/`thunk_of` 写死 disp 偏移（实现）；③verify_callgraph/test_callgraph 同错（验收器）；④KNOWN_HARD 曾放行 call_site_missing（验收器偏松）；⑤test_sitejoin 常量过期（测试）；⑥旧数字未标注（文档）；⑦审计脚本误把 VEX 当无前缀（审计，虚报 4716 条 → 0）。
  - 规则：R74 每条硬不变量至少一条独立来源路径（外部工具/独立重算），来源须写入文档；R75 判据修正后必须全量重跑校验器并做前后 diff，校验器 FAIL 优先怀疑校验器同错。M7 规则编号收束为 R68–R75。
  - 下一里程碑建议：M8-U0（thunk_of 口径扩展 + 序言按 opcode，**还没做**）→ M8-U1（跨块数据流，判据先行，**还没做**）→ M8-U2（参数绑定，仅 declared 来源，**还没做**）→ M8-U3（字符串/数据引用交叉，**还没做**）；无调试信息的参数名/类型、运行时间接目标、跨函数精确别名、混淆控制流还原属**结构上做不到**。
- [x] 2026-11-16 M8-U0（R71/R74 落地 + 两处口径扩展）
  - 第一优先 `verify_callfacts` D 段（栈槽纪律）独立化：写集合改由外部 `objdump -d -M intel` 文本重算
    （`_objdump_writes` / `_writes` / `_slot_scan`），不再 import `callgraph._effects` / `_Ctx`；
    地址对齐改跟踪 `Disassembly of section .text:` + 首指令推 delta（stripped ELF 无 `<.text>:` 符号头）。
  - 独立路径与实现路径的 7 个差异点及处理：数据来源、`call` 暂态 rsp 写、目的操作数约定、寄存器别名归一、
    未建模助记符（不结论 + >50% 判 FAIL）、指令集合取交集、**只证伪不证真**；首版把 `call` 记成写 rsp →
    三样本 23/28/380 条误报，逐条归因后确认全部是同一种误报（中间调用返回即复原 rsp），已并入 R76。
  - 自证：`--selftest` 正例伪造槽事实必须检出、负例干净窗口不得误报；覆盖实测 501/602/6537 次查写，
    未建模 0、违规 0。
  - 两处口径扩展（R71）：`thunk_of` = 「填充*（nop/int3/endbr64，按 opcode 跳前缀）+ 一条 jmp [槽]」；
    序言识别 `_prologue_len()` 按 opcode，REX 仅允许 0x48。**三样本数字全部不变**（序言 1/1/25、
    thunk 28/0/0，padding 扩展 0，参数桩 3 保持不命名）——属判据对齐而非修实测缺陷。
    带前缀实测：cli-64 有 3 处 `48 ff 25` 跳板（0x1d81/0x21e7/0x23ef，分别指向 TerminateProcess /
    InitializeSListHead / SetUnhandledExceptionFilter），按首字节判会漏；dyn_static 有 2 处 `55 4c 89 e5`
    （0x44f886 / 0x46155f，`push rbp; mov r12,rbp`）在宽松 REX 规则下会误判为序言种子。
  - 私有符号清点：`tests/**/*.py` 共 14 个不同私有符号 / 25 处代码行。独立化 3 个
    （`sitejoin._text_lines` / `_slice` / `_KIND_ATTR` → 本地 `_JOIN_LINES` / `_JOIN_SLICE` /
    `_KIND_ATTR_EXPECT`），消除 2 个（`CG._effects` / `CG._Ctx`），保留 9 个并写明理由
    （白盒单测 / 取输入 / 取被测输出 / 仅定位或自证）。
  - 规则：新增 **R76** 独立判据不得把「暂态写」（如 call 压栈返回复原）计入持久改写；
    **R77** 验收脚本引用被测私有符号按「取输入 / 取被测输出 / 仅定位自证 / 当期望值」四类定性，
    只有最后一类必须独立化。
  - 数字：本轮无任何已公布数字变化；证据 work/evidence_m8u0_pytest.log（383 passed）+
    work/evidence_m8u0_scripts.log（13 条命令 EXIT=0）。

- [x] 2026-11-16 M8-U1：跨块数据流（判据先行；交付 outputs/TASK_m8u1_crossflow.md；证据 work/evidence_m8u1_pytest.log / evidence_m8u1_scripts.log / evidence_m8u1_numbers.log）
  - R76 判据化（不是特例豁免）：w 对 (r,t) 是暂态写 ⇔ 存在 b（a<b≤t）是同一函数内**已解出**的指令且把 r 复原为 a 之前的值（T1），且 (a,b)、(b,t) 内无对 r 的其它写（T2/T3）。本轮可判定复原证据集合为空：call 的复原证据在被调方 ret 体内，`ret imm16` 的净效果取决于调用约定（禁止 ABI 推断）⇒ call 对 rsp 的写是**持久写**。可判定地执行：`--selftest` 的 R76 正例（0x1077 窗口含 call 0x1061）必检出；实现一旦回到「call 不写 rsp」立刻 FAIL。
  - 落地：窗口内含 call 的 rsp 槽事实改为 abstain，文案点名 call 地址与「缺：被调函数的栈平衡契约」。槽事实 96→73 / 378→350 / 2951→2571；槽弃权 14→37 / 14→42 / 82→462（其中 why=call 恰为 23/28/380）。
  - 跨块：`_cross_index` 只从 `cfg.edges.definite` 建前驱表；speculative / cross_function / undecoded / unresolved 进 `nondet_in`，命中即 abstain（不拿疑似边补覆盖率）；回边用回溯栈检测；合流要求所有确定前驱同址；深度 64 / 分支 32 超限即 abstain。失败根因逐层传播（嵌套 ambiguous 不再吞掉 loop/nondet/entry），文案按 entry / nondet / loop / disagree / barrier / depth / breadth / 栈槽 / 窗口截断分类。
  - 实测：跨块事实 0/9/78（站点 0/30/124），跨块弃权 0/22/75（bin_ls：回边 13 / 合流分歧 3 / 屏障 1 / 栈槽 2 / 窗口截断 3；dyn：回边 20 / 合流分歧 21 / 非确定入边 1 / 入口 1 / 屏障 5 / 栈槽 26 / 窗口 1）。cli-64 为 0 的原因不是没跑，而是没有可追操作数：153 个调用点无读操作数（98 个 `call rel32` + 55 个 `call [rip+disp]`，rip 相对既非基址/索引寄存器也不构成 `[rsp/rbp±d]` 槽）。
  - 期望值来源（不取被测实现）：外部 objdump 文本做 5 项复核——定义指令真写该操作数、块内其后无再写、逐跳后继、前驱完整性反推、账目对平；实测逐跳复核 45/216、定义指令确认 9/78、未建模 0、前驱不完整 0。另有 3 例手工读数：bin_ls 0x48f6→0x48ea；dyn 0x404b4f→0x404b46；dyn 0x4517a0→0x45177a（含 `ja` 回跳合流，两条确定前驱同址）。
  - 数字分列（不合并净增量）：**新解出** = 跨块事实 0/9/78（另新增弃权 0/22/75）；**收紧减少** = 槽事实 −23/−28/−380（对应槽弃权 +23/+28/+380）；站点 153/1154/3609、after 309/2293/6466、窗口截断 3/51/164 全部不变。
  - 更正 M8-U0 §1.3/§1.4：call 压栈后 rsp 确实变了，独立侧没有判错；错在实现侧报出了本应 abstain 的槽事实。431 条（23+28+380）的归因以本轮为准。
  - 返工 3 项：①`call` 判定窗口漏 `a > d["at"]`（cli 槽弃权一度 55，应为 37）；②合流各支被拼成一条 `blocks` 列表（重复块、无法逐跳复核）→ 改为每支一条线性 `branches`；③嵌套失败根因被 `ambiguous` 吞掉（循环案例文案里没有"回边"）→ 逐层传播 why/classes/kinds + 新增 `test_cross_block_loop_abstains_and_names_the_cycle`。
  - 回归：pytest **388 passed**（387→388，新增 loop 判据单测）+ **13 条验证命令 exit 0**；负向基线 17 项、表达式 sha256、0x401870 sha256 全等。
  - 规则：R76 落地为暂态写判据（可判定、可证伪）；跨块口径 = 只走确定边、只追定义侧、合流同址、回边 abstain、失败必须写缺什么。

- [x] 2026-11-16 M8-U2：参数绑定只认 declared 来源（交付 outputs/TASK_m8u2_param_binding.md；证据 work/evidence_m8u2_numbers.log / evidence_m8u2_verify.log / evidence_m8u2_pytest.log / evidence_m8u2_scripts.log）
  - 判据（先写后做，`callfacts.PARAM_RULE`）：只有声明给出「第 k 个形参在入口位于哪个寄存器/栈位置」时，才把调用点该寄存器的最后定义绑到第 k 个形参；声明必须能指到文件偏移/节/DIE/位置表达式，读不到即 abstain；导出表/COFF/ELF 符号表/`.pdata`/`.eh_frame` 只声明函数身份/范围（结构性），PDB 本轮未解码位置 → abstain；禁止按寄存器顺序/平台惯例补。
  - 来源与读法：DWARF 2–5（ELF `SHF_COMPRESSED` / PE `.zdebug_*` 的 `ZLIB` 头）逐条给节头索引 + `sh_offset/sh_size` 或 `rawptr` + 压缩头 + `CU@0x`/`DIE@0x` + 位置表达式字节；**修 `.zdebug_` 名称规范化（`name[7:]`→`name[8:]`）与 PE `ImageBase+RVA` 换算**；无 DWARF 样本 `available=false`，仍按站点计分母、每站一条 abstain。
  - 分母（18 样本 × 9 类）：DWARF **2/18 可读**（10338 个形参：5077/5261）；PDB **1/18 可定位、0/18 可读**；gnu_debuglink **1/18 可定位、外部文件缺失**；DWARF v2/v3 **0 条**（仅合成单测）。三者均明写「本轮无法验证」，不把 0 当结论；导出表/COFF/符号表/`.pdata`/`.eh_frame` 单列「结构性不含形参」；minidll 0 个调用点单列「无可绑定对象」。
  - 结果分列：形参 bound/partial/abstained = **5824/1696/6155**（linux）与 **6448/1834/6789**（exe），绑定寄存器段 8354/9152，partial 缺段 1813/2001；站点 11471/11980（bound 2057/2101、partial 3418/3777、zero_params 4903/4988、abstained 904/919、no_target 189/195、no_declaration 0）；对照样本 cli/bin_ls/dyn/rust 153/1154/3609/1029 站点全部 abstain、params_bound=0。
  - 独立复核：`readelf --debug-dump=info`（ELF）/ `objdump --dwarf=info`（PE）按 DIE 深度独立普查，CU/subprogram/带 low_pc/形参四项**逐项与模块 meta 相等**（59/2805/1794/5077；61/2880/1884/5261）；objdump -d 文本核对每条绑定定义，**8354+9152 段全部确认写入、未建模 0、矛盾 0**；`verify_paramdecl --selftest` 三类注入（声明外寄存器 / 删 declared 证据 / 无声明伪造绑定）全部检出，真实基线零失败。
  - 数字口径更正：站点状态原先「只要绑上一个形参就报 bound」，会把弃权说成结论；改为「有绑定且有未绑定 → partial」。站点 bound 3805→2057 / 4071→2101、partial 1670→3418 / 1807→3777；**形参级 5824/1696/6155、6448/1834/6789 与全部弃权原因一字未变**。
  - 返工 7 项：①`.zdebug_` 少一个下划线（PE 全查不到）；②PE 地址空间未换算；③无 DWARF 时不调 `bind_site` 吞分母；④站点状态把弃权说成绑定；⑤DWARF 2–4 CU 头把 `addr_size` 读在 `abbrev_off` 之前（无 v2/v3 样本，仅合成单测暴露）；⑥审计 `readable` 对不存在来源报 True；⑦测试期望自身错 3 处（regx 5=rdi、fbreg -8 的 SLEB=`0x78`、无定义应进 abstain 而非 partial）。
  - 回归：pytest **408 passed**（388→408，新增 20 项）+ **12 条验证命令 exit 0**（`verify_fingerprint` 需 `--all --matrix`，按该参数 132/132、误报 0）。
  - 规则：**R78** 判据的证据集合为空时只能当负向约束，不得输出肯定结论，文档须显式写「可判定证据集合为空」；**R79** 声明来源必须能定位到文件偏移与解析路径，读不到即 abstain，禁止用 ABI 惯例补齐；**R80** 分母先行：先报来源 present/readable/样本覆盖，0 覆盖只能报「本轮无法验证」，并区分结构性缺失/本轮缺失/真零；**R81** 站点级状态不得把部分绑定或弃权说成绑定，数字必须按形参级 bound/partial/abstained 分列。

- [x] 2026-11-16 M8-U3：字符串/数据引用交叉（数据节 → 引用点 → 函数）（交付 outputs/TASK_m8u3_strxref.md；证据 work/evidence_m8u3_numbers.log / evidence_m8u3_verify.log / evidence_m8u3_pytest.log / evidence_m8u3_scripts.log）
  - 口径先写后做（`strxref.CALIBER` 写死在模块头）：扫描范围只读数据节**白名单**（`.rodata`/`.rodata.str*`/PE `.rdata`，排除 `.rodata.cst*`/`.data*`/`.bss`/`.text`/`.edata`，NOBITS 与 RawSize==0 不扫）；编码只认可打印 ASCII `0x20..0x7E`，含高字节段一律不报；最短 4 字节；必须同节内 NUL 终止（节尾无 NUL 不报）；按 NUL 切分成**互不相交**段、只报整段、不做滑动窗口。引用点 = 已解出指令里的 rip 相对内存操作数（含 lea）+ 立即数（`≥ 0x100000`）；数据节 4/8 字节指针值不认作引用点，只当 no_site 归因证据。UTF-8、Go/Rust 长度分界字符串系统性不报，拒绝量（binary/short/high/no_nul_tail 及字节数）逐样本单列。
  - 分母（先分母后结果，18 样本全量无跳过）：字符串 **13829** = unique **2266** + multi **434** + no_site **11129**；no_site 归因 **跨界 262 / 未解出 0 / 间接 514 / 无证据 10353**。引用点 **3732**（rip 3729 + imm 3，全部有函数归属），引用落串内部（suffix，非起点）**556** 条、不计入唯一回指。
  - 「未解出」这一格不是 0 就完事：模块侧 no_site 里确实没有「已解出但未升格」的引用，但外部 objdump 证明**未解码代码里还有 5039 个引用点、涉及 276 条字符串**（busybox 覆盖率 0.1% 为主因），按 R83 单列为**下界外缺口**，并把 `refs` 声明为下界，不写成「没有引用」。
  - 期望值来源（不取被测实现）：`verify_strxref.py` 不 import `rekit.expr`/`rekit.elf`/`rekit.pe`，也不复用 `strxref` 中间结果。地址期望由外部 `objdump -d -M intel --insn-width=16` 的**原始字节列**给指令长度 + `[rip±disp]`/立即数文本，脚本自算 `addr+len+disp`；PE 用独立解析的节 RVA 归一化（`delta = objdump首址 − 节RVA`）。字符串期望用脚本自带的 struct 级 ELF/PE 节头解析重切一遍，与模块 addr/len/text 逐项相等。漏报三分：`已解出且 unlifted` 只计数、`不在已解出集合` 只计数（未解码缺口）、其余 FAIL。
  - 可失败自证：`--selftest` 五类注入全部检出——篡改 target、删除 objdump 可见站点、伪造字符串文本、同址站点函数归属改错（`layer_bug`）、站点函数换成域外种子（`function_range`/`layer_bug`）；注入前先验基线零失败，证明检查器不是空转。
  - 三层对账：本层引用点 ∩ callfacts 调用点 = **0**（`call [rip+槽]` 的槽是导入表不是字符串），结构上无非空对账对象，`crosscheck.note` 明写而不冒充通过；改用**函数域核对 3691 条**（声明 end 的种子 `start ≤ site < end`）冲突 **0**；反向语义核对（`call_kind == direct` 且目标落在字符串起点）**0**；三类归因 `layer_bug`/`caliber_difference`/`data_anomaly` 均为 0。
  - 返工 6 项：①口径单测期望自身错（`"bar"` 长 3 被最短 4 拒绝，改为 `quux`）；②status 与 reason 混用（原把归因名塞进 status）→ 拆 `status ∈ {unique,multi,no_site}` + 独立 `reason`；③verify 的 PE 地址基准错（独立侧用 `image_base+RVA`、模块用 RVA）→ 全 PE 样本「漏报」，改 `delta` 由 objdump 首址推出；④objdump 长指令换行导致长度算错 → 加 `--insn-width=16`；⑤`0x527e → 0x1d115` 被误判漏报（该指令不在 recdesc 已解出集合）→ 引入 `decoded` 集合，归入未解码覆盖缺口只计数，并加 CAVEATS/coverage 块；⑥无 `.text` 样本（upx×3、minipe_fakerich）崩溃 → `build` 先判 `no_code` 再用空 res，verify 要求给出 `no_code_reason`。
  - 零值三分（R85）：无白名单数据节 / 有白名单节但零字符串 / 无代码节，各有独立结构性原因字段（`strings_zero_reason`、`no_code_reason`），不共用一句 0。
  - 回归：pytest **426 passed**（408→426，新增 18 项）+ **13 条验证脚本 exit 0**（含新增 `verify_strxref.py`；`verify_fingerprint` 需 `--all --matrix`，按该参数 132/132、误报 0、违规 0）。
  - 规则：**R82** 字符串识别必须给「编码/最短长度/终止条件/重叠处理」四要素，默认只认 NUL 终止可打印 ASCII，UTF-8 与长度分界不报（宁可少报）；**R83** 引用点只在已解出指令集合内认定，必须同时报代码覆盖率与外部工具量化的未解码漏报数，`refs` 声明为下界；**R84** 引用点期望值须由外部工具独立算出（objdump 字节 + 地址算术），`--selftest` 必须注入五类错例并全部检出；**R85** 「无白名单数据节/有节无字符串/无代码节」三种零值必须分别给结构性原因；**R86** 三层对账交集为 0 必须写明「无非空对账对象」并给出非零替代核对项（本轮函数域 3691 条），不得把空交集当对账通过。

- [x] 2026-11-16 M8 收口：跨层事实收束（交付 outputs/TASK_m8_closeout.md；证据 work/evidence_m8close_pytest.log / evidence_m8close_scripts.log / evidence_m8close_snapshot.json / evidence_m8close_snapshot_run.log）
  - 逐条对账 4 个单元 × 共 22 条判据全部达标，每条「判据 → 实测 → 证据文件」成对（R87）。U0：独立写集合 501/602/6537 次查写、未建模 0、违规 0，五类注入可失败；两处口径扩展三样本数字不变（序言 1/1/25、thunk 28/0/0），cli-64 有 3 处 `48 ff 25`、dyn_static 有 2 处 `55 4c 89 e5` 是判据真正的差异点。U1：跨块事实 0/9/78、跨块弃权 0/22/75，槽事实 96→73 / 378→350 / 2951→2571。U2：形参 5824/1696/6155 与 6448/1834/6789，寄存器段 8354/9152，站点 11471/11980，外部 DWARF 普查四项逐项相等。U3：13829/2266/434/11129、引用点 3732、suffix 556、函数域 3691 冲突 0。
  - 能力增量（§2）：新增可回答 10 类问题（跳板/序言为何成立、校验器是否同源、跨块最后定义与缺什么、形参名与 DIE 偏移、声明来源真实可读面、字符串被谁引用、哪些字节不是字符串、引用归属一致性、"没引用"还是"没解出"）。仍答不了 11 项，二分归因：**信息不在文件里 5**（无调试信息的形参/局部、运行时间接目标、跨函数别名、调用约定契约）、**还没做 6**（长度分界串、未解码代码、跳转表确定边、PDB CodeView、DWARF v2/v3、跨块使用侧）。
  - 更正台账 6 条（§3，四列「旧/新/证据/以哪版为准」）：**A** U0 把 call 的 rsp 写判成暂态、把 431 条归因为独立侧口径错 → U1 §1.6 推翻：独立侧没判错，错在实现侧报出了不该报的槽事实；现版 `_NO_DEST_XFER` 只剩 `{jmp,ljmp}`，call 写 rsp 按持久写。**B** 私有符号"13 处"→ 逐行清点 14 符号/25 处。**C** 站点状态"绑上一个就报 bound"→ bound/partial/abstained 三分，站点级 3805→2057 / 1670→3418 与 4071→2101 / 1807→3777，形参级不变。**D** `0x527e` 判漏报 → 未解码覆盖缺口（`refs` 为下界）。**E** status 与 reason 混用 → 字段分开。**F** DWARF 2–4 CU 头字段顺序写反 → 按规范改并加单测。
  - 机器快照（R90）：`evidence_m8close_snapshot.json` 含 18 样本逐行 + 合计 + 被测代码 sha256（strxref/callfacts/callgraph/paramdecl/recdesc）；合计与各单元文档逐项一致（13829/2266/434/11129；引用点 2+3727+3=3732；函数域 3691 冲突 0；形参 12272/3530/37891；调用事实 48398 站点、before 167965 / after 135851 / abstain 83718、跨块事实 202 / 跨块弃权 388）。
  - 已知缺口（§5）：未解码代码 5039 引用点/276 串（busybox 覆盖率 0.1% 为主因）；16/18 无 declared 来源；PDB 0/18 可读；DWARF v2/v3 样本 0；长度分界串与数据节指针表按口径不计入。
  - 全量回归：pytest **426 passed**（`evidence_m8close_pytest.log`）；**13 个 verify 脚本 + 4 个 `--selftest` 共 17 条命令全 exit 0**，`FAILED_COUNT=0`（`evidence_m8close_scripts.log`）。环境前提：pytest 须把 binutils `bin/` 前置到 PATH，否则 `test_pe` 的 objdump 用例以 `FileNotFoundError` 失败（非代码缺陷）。
  - 下一里程碑建议（§6）：**M9-U1 覆盖缺口收敛（未解码代码与不可达函数）**——唯一同时满足"已量化 / 归因是还没做 / 不修则 U1–U3 全是下界"的缺口；候选切入点按代价：跳转表候选升格（外部 objdump 校验边界）→ 不可达函数补种 → 伪 VEX/EVEX abstain 归因。**18 样本不够定标**：需追加中型 stripped ELF 2–3（覆盖率 30–80% 区间）、中型 PE 1–2、跳转表密集 1、插件式 1；PDB 方向需 2 个未 strip MSVC x64 + 同目录 PDB（当前 0/18 可读），DWARF v2/v3 各 1。
  - 规则：**R87** 收口对账必须「判据 → 实测 → 证据文件」三列成对，无可复跑入口就写「无」，不得用「基本完成」代替结论；**R88** 更正台账独立成节，四列「旧结论/新结论/证据/以哪版为准」，被推翻的旧段落必须显式撤销；**R89** 「能/不能回答」不得合并成"暂不支持"，必须二分归因为「信息不在文件里」与「还没做」并给判定依据；**R90** 收口必须有机器快照（逐样本 + 合计 + 被测代码 sha256），文档数字与快照不一致即收口失败。

- [x] 2026-11-16 M9 收口：覆盖缺口收敛 + 样本面补齐（交付 outputs/TASK_m9_closeout.md；证据 work/evidence_m9_invariance.json / evidence_m9_coverage_oldsamples.json / evidence_m9_coverage_summary.json / evidence_m9_promotion.json / evidence_m9_vexaudit_old4.json / evidence_m9_pytest.log / evidence_m9_scripts.log）
  - 收敛线 C（覆盖率口径，不依赖新样本）：`coverage.py` 写死——分母 = 外部 GNU objdump 2.47 在同一节 `[VA, VA+size)` 列出的指令条数，分子 = recdesc 已解出且**同址同长**的条数；恒等式 `ours_total = matched + len_conflict + ours_only`、`denominator = matched + len_conflict + objdump_only`；汇总只允许 `full` / `sampled`，`sampled` 缺名单直接抛错。`verify_coverage.py` 不 import 计数逻辑，自解 ELF/PE 节头 + 自 parse objdump 复算分母，三个自证（篡改长度必须出 `len_conflict` / 伪造 objdump 少 10 条必须与独立复算不一致 / sampled 缺名单必须抛错）全部通过；`objdump` 不可用时 `ratio=None` 不写 0。
  - 收敛线 B（伪 VEX 弃权归因，不依赖新样本）：`vexaudit.py` 逐字节扫 C4/C5/62，每个位置独立试解，再用外部 objdump 同址结论裁成四类。旧 4 样本（cli-64 38 / bin_ls 313 / dyn_static 1,199 / avx_dense 0）+ 新 7 样本（cc1 68,395 / lto1 65,914 / python 10,166 / liblua 613 / gdb 27,392 / synth ELF 16,332 / synth PE 16,179）= **206,541 个弃权点，`decoder_defect=0`、`illegal_encoding=0`、`data_not_instruction=206,541`**。结论限这 11 个样本：不存在被误拒的真实 VEX/EVEX；笼统 abstain 全部落到「不在指令起点上的数据/错位字节」。另记两个合成 Go 样本各有 1 处「若当指令起点则长度不同」的候选（都不在指令流内，`len_conflict=0`）。
  - 收敛线 A（跳转表升格外部校验，不依赖新样本）：`switchcand.analyze_function(boundary=...)` 的边界只来自**外部 objdump 指令起点集合**，5 项检查全过才升格，升格仍不进确定集（R45）。旧三 fixture 由 `verify_switchcand.py` E 段逐候选独立复算（`promotion_audit`：应升格 == 实升格、空边界 0 升格、`res` 深比较不变）；新样本另跑 `evidence_m9_promotion.json`：liblua 21/30、python3.10 57/104，**不一致 0**、空边界 0、`res` 不变；合成 Go 0 候选（Go 分发不走 `cmp+ja` 表，只适用于 Go 样本）。
  - 样本线：`m9_sample_manifest.json` 登记 7 个新样本（sha256 现算、来源包身份取 deb control / `.PKGINFO`、许可、real/synthetic、可再分发/仅本地、结构事实、`.text` 范围）。选样标准测量前声明 R1–R6（尺寸带 10–50MB / stripped 判据 / 跳转表密集按程序性质先验 / 插件式为 ET_DYN 无 `.symtab` / 真实优先 / 禁止按覆盖率挑选），`violations: []`。槽位达标：中型 stripped ELF 2（cc1、lto1）、中型 PE 1（gdb.exe）、跳转表密集 1（python3.10）、插件式无符号 1（liblua5.4.so）；合成对照 2（Go ELF/PE）**未入尺寸带已标注**；M9 新增全部可再分发，`local_only` 为空（M2 的 cli-64.exe 仍仅本地）。
  - 分解（解码改进 vs 样本更换）：旧 18 样本重跑 recdesc，与 M8 收口快照的 `strxref.coverage` 逐样本比对 `decoded_instructions` / `decoded_bytes`——**18/18 相等、0 处不一致**（合计 638,926 条 / 2,574,299 字节）；交叉对账：覆盖率分子合计 638,883 与 638,926 恰差 43 = `ours_only`（putty 31 + dyn_static 8 + minidll 4）。⇒ **解码改进 = 0**；旧 62.13% → 新 76.88% 全由样本构成（busybox 305/245,678、minidll 1/9 拉低旧集）；且 M8 无同口径指标，故「M8→M9 的覆盖率提升」不可比较，只能比较同口径下不同样本集，或同批样本的解码输出。
  - 未完成 / 规模墙：`switchcand` 在 cc1（4.05M 指令，>30 分钟）、lto1、gdb（1.54M，**709 CPU 秒**）超时中止 → 这三样本记 `switchcand_skipped`，**不写 0**；Go ELF 8.24% vs Go PE 79.81% 只登记不归因；putty 31 条 `ours_only` 与 3,109 条 `(bad)` 分类单列未逐条追。
  - 回归：pytest **444 passed**（426→444）+ **19 条验证命令 exit 0**（原 17 + `verify_coverage.py` + `verify_vexaudit.py`），`FAILED_COUNT=0`。
  - 规则：**R91** 覆盖率分母必须由外部 objdump 独立计数、分子同址同长，报告必须同时给分子/分母/分母口径；**R92** 汇总必须声明 `full`/`sampled`，`sampled` 必须附名单，代码强制；**R93** 升格判据只能用外部 objdump 指令起点，被测实现自身解码不得作判据，空边界负控必须 0 升格；**R94** VEX/EVEX 弃权必须逐条归入四类计数，`decoder_defect>0` 必须修复或登记；**R95** 选样标准测量前以结构判据声明，禁止按覆盖率挑样本，合成/真实分栏且结论标注适用范围，sha256/许可/可再分发三栏入册；**R96** 超规模导致未跑完的层必须显式记 `skipped` 并给中止证据，不得写 0 或省略。
- [x] 2026-11-16 收口·M10：Go ELF/PE 十倍差归因 + switchcand 超时定因与预算（R97/R98）
  - 第一优先（十万差归因）：外部参照三件——objdump 2.47 指令边界、Go 1.27.3 `debug/gosym` 函数清单（ELF `.gopclntab` 8,908 个；PE `.rdata` 内 pcHeader 8,895 个）、PE `.pdata` 7,152 区间。逐函数分层：ELF matched 3（67/67）、partial 846（76,101/90,564）、**seed_missing 8,059（0/833,323）**、len_conflict 0；PE matched 6,388、partial 764、seed_missing 0、len_conflict 0。关键否证：8,059 个缺失函数被已解出代码直接 call/jmp 命中 = **0**，排除“该调度没调度”。
  - 自证（可失败）：仅用 objdump 边界与助记符、不调用 recdesc 解码/分类，从 `e_entry` 重做递归下降，得 **76,168 条 / 849 个函数 / 0.0824356**，与我方逐条相同（对称差 0）。解码缺陷与调度缺陷同时被排除。
  - 断链定位（具体函数）：① `runtime.main` ELF 0 条 / objdump 278 条（PE 252）：`0x48ecfd lea rax,[rip+0x2eebec] # 0x77d8f0` → `call 0x492e00(newproc)`，`0x77d8f0` 处 qword = `0x453520`（runtime.main 入口），`.text` 内无直接 call/jmp；② `main.main` 0/571（PE 559），直接调用者 0（`fn := main_main; fn()`）；③ `sha3.keccakF1600` 0/5,121（PE 5,119），3 个直接调用者自身不可达；④ `runtime.typesEqual` 171/721（PE 同 171），缺口紧跟 `0x47e912 jmp QWORD PTR [rcx+rdx*8]`（间接跳转，R45 不跟随）；⑤ `runtime.asminit` 1/32 是尾部 `int3` 填充造成的伪缺口。
  - 影响范围：M9 的分子/分母定义不变；凡把该样本数值叫“覆盖率”的地方必须加注“stripped Go ELF，entry 可达域，非全二进制域”；解码正确性类结论（同址同长、VEX 四分类）不受影响。
  - 第二优先（超时）：cProfile 定位 `_func_sets` 47.3s + `_decoded_index` 30.5s（417 × 627,658 ≈ 2.6 亿次 dict.get），修复后暴露每函数重读整文件（cc1 34MB × 1,974 ≈ 67GB）。`build_context(res)` 一次建 `by_origin/blocks_by_func/seeds/decoded/idx/reader/decoder`；`TableReader` 共享文件字节。修复前后：python3.10 77→0.89s、gdb 709 CPU 秒中止→2.67s、cc1 >30 分钟中止→8.11s，候选数不变。
  - 预算与降级：成本 = `len(insns)+len(blocks)`（确定性、不按墙钟）；`step_budget`/`max_functions`；三分法 `functions_analyzed / functions_skipped_budget / analysis_coverage`；每个跳过项进 `budget.skipped_detail`（原因 `step_budget_exhausted`/`function_batch_limit`）。自证：budget=50,000 → 384 analyzed/33 skipped/0.9209/candidates 57（全量 104 的子集），两次运行 JSON 逐字节相等；budget=0 → 0/417/0.0/0 且 `functions=[]`；空边界负控 0 升格；`res` 不变。
  - 回归：pytest **447 passed**（444+3）＋ **19/19 verify 命令 exit 0**（15 脚本 + 4 个 `--selftest`：coverage/vexaudit/recdesc/disasm），日志 `work/evidence_m10_verify.log`。
  - 规则：**R97** stripped Go ELF 的覆盖率必须标注种子源（仅 `e_entry`）与可达函数数/总数，写明“可达域”，函数清单必须来自外部工具；**R98** 超时类层必须给确定性预算（指令步数/函数批次，不按墙钟），`skipped` 作第三类单列，任何比率分母只含 `analyzed` 且并列 `analysis_coverage`。
- [x] 2026-11-16 收口·M11：`.gopclntab` 接入 declared 级种子（R99–R101）
  - 性质/版本：Go 链接器产出的**运行时必需表**（`-s -w` 不会移除），属 declared 级而非调试信息；支持 `0xFFFFFFF1`（go1.20+，本机 go1.27.3 实测并与 `debug/gosym` 对拍）、`0xFFFFFFF0`（1.18–1.19）、`0xFFFFFFFA`（1.16–1.17，ptrSize 宽 functab / 绝对 VA / 无 textStart）——后两者**无实测样本**，结果带「未验证」warning；`0xFFFFFFFB`（1.2–1.15）与未知 magic → `unknown` 并给 reason。header.textStart 实测为 0（未重定位），按官方 gosym 改用 `.text` 基址，不算猜。
  - 分源：ELF 8,908 条（标记 2：textfipsstart/end）、PE 8,895 条（标记 3：+go:buildid）；exclusive `gopclntab` 8,905 / 1,739（PE 与 `.pdata` 交集 7,152）。`declared_by_source`（inclusive）与 `declared_only_by_source`（exclusive）同时给，entry/symtab_func/pdata/gopclntab 各自计数不合并；标记排除并单列（objdump 侧占 ELF 33 条 / PE 98 条指令）。
  - 对拍：`tests/tools/gofunclist.go`（`debug/elf`+`debug/pe`+`debug/gosym`）独立取清单，与 `gopclntab.parse` 逐条比：entry/end/name **全等、0 差异**；entry/end 落在 objdump 指令边界的违规 **0**；5 项篡改（magic 0xFB / nfunc=0 / entry 非递增 / funcoff=0 / textStart 越界）全部 `unknown` 且 `funcs==[]`。另一类两源不一致：`.pdata` EndAddress vs gopclntab 下一入口在 PE 上 7,139/7,152 个差 1–31 字节（对齐填充），`end_conflicts` 单列，ELF 0。
  - 覆盖率（同口径 A/B）：ELF 76,168/923,970=**8.2436%** → 748,093/923,970=**80.9651%**（+72.7215pp，+671,925 条）；PE 738,852/925,712=**79.8145%** → 750,109/925,712=**81.0305%**（+1.2160pp，+11,257 条；真实 Go PE `hello_go.exe` 143,525→147,351，+2.0920pp；未 strip 的 `hello_go_linux` 仅 +68 条）。四样本 `matched_lost=0`、`same_addr_len_changed=0`、关闭开关时旧数字逐条复现 ⇒ 增量**全部来自可达域扩大**，解码贡献 **0**。
  - 余量归属：ELF 175,877 = 填充 `cc/90` 149,225（16.15%）+ 函数域内未静态达 26,652（2.88%）+ 范围外 0；PE 175,603 = 148,861 + 26,702 + **40（`go:buildid` 数据，反证标记排除生效）**；表尾对齐填充 16 字节；`ours_only` 各 1 条单字节 `ret`，`len_conflict=0`。
  - 下界清单：**升格** Go ELF/PE 覆盖率、M10 `seed_missing` 8,059 个函数、partial 边界 → definite（172,987 / 171,802）、speculative → 0/0、25 样本推算 **80.3734%**（未重跑全量，按 4 个 Go 样本实测增量推算）；**仍为下界** `strxref` 5,039 引用点/276 串、VEX 206,541 弃权、`switchcand` skipped、非 Go 样本、Go 函数域内 2.88% 间接目标。
  - 回归：pytest **463 passed**（447+16，69.84s）＋ **16/16 verify 命令 exit 0**（新增 `verify_gopclntab.py`）；规则 **R99** declared 来源逐源单列、**R100** 覆盖率变化必须拆分可达域 vs 解码、**R101** 新增 declared 源必须双源独立对拍、未验证版本不得冒充已验证。测算脚本 `evidence_m11_extra_go.json` 补齐 2 个未 strip Go 样本对照。
- [x] 2026-11-16 收口·M12：推算换实测（R102）+ 多源 end 缝隙量化（R103）
  - 第一件事（推算→实测）：25/25 样本全部重跑（gopclntab 开启、无跳过），总耗时 353.5s；逐样本落 sha256、耗时、旧/新分子分母。合并 25 **75.8866%（11,620,527/15,313,023）→ 80.3734%（12,307,603/15,313,023）**（+687,076 条 / +4.4869pp），与 M11 推算**差 0**；旧 18 **62.1329% → 62.5116%**（642,777/1,028,253，+0.3787pp）、新 7 **76.8766% → 81.6592%**（11,664,826/14,284,770，+4.7826pp）。变化仅 4 个 Go 样本：hello_go_linux +68（138,224→138,292）、hello_go.exe +3,826（143,525→147,351）、Go ELF 合成 +671,925（76,168→748,093）、Go PE 合成 +11,257（738,852→750,109）；其余 17 个可测样本 delta 全为 0 → M11 推算的前提（其余样本不变）被实测证实。
  - 代价与权重：未跳过任何样本，故不存在「按权重估算替代实测」；最贵的 3 个均实测——cc1 145.48s（权重 26.45%）、lto1 132.69s（25.54%）、gdb 30.32s（10.08%）；python310 10.2s、putty 3.0s，其余 <1s。分母三组逐条相同（同一 objdump 结果），变化全在分子。
  - M9/M10 下界升格（实测）：ELF 逐函数 gopclntab 范围 **seed_missing 8,059 → 0**、全覆盖 3→35、部分 846→8,871（obj 923,921 / matched 748,093）；PE `.pdata` 口径逐函数 **6,388/764/0 与 726,289 条完全不变**（证明 gopclntab 只新增不改已有）；PE gopclntab 范围 32/8,860/0、matched 750,109（「全覆盖」少是范围含尾部 `cc` 填充的口径差异）。
  - 第二件事（PE 缝隙量化，样本 `m9/pe_medium_synth_go_stripped.exe`）：**7,139/7,152** 个函数有双源，13 个 end 相同，**0 个** gopclntab end ≤ pdata end；缝隙总 **113,731 B = `.text` 的 3.2262%**（min 1 / max 31 / 均值 15.93；分布 1–3:609｜4–7:955｜8–15:1,871｜16–31:**3,704**）。缝隙内 objdump「指令」113,731 条（每字节 1 条）**全部是 `cc`/`90`**，占 M11 填充桶 148,861 的 **76.40%**；我方解出 **372 条**（全 `int3`，全在缝隙首字节 = pdata end），经 gopclntab end 归**前一函数**（例 `internal/abi.(*IntArgRegBitmap).Set` 0x13a0→缝隙 0x13e6、`runtime.mcall` 0x8b1e0、`runtime.badmorestackg0` 0x52b00、`runtime.(*mspan).typePointersOf` 0x25c60 delta 31）；跨 pdata end 的我方指令 **0**、跨 pdata end 的基本块 **372**（即 372 条单指令块）、目标落缝隙的 CFG 边 **0**（五类全 0）。
  - 换口径影响：改用 `.pdata` end 口径 → 372 条丢出函数域，分子 750,109→**749,737**、比率 81.0305%→**80.9903%（-0.0402pp）**、块 -372、CFG 边 0 变化 ⇒ **实质结论不变**：缝隙内无真实代码，无指令被截断，无边指向缝隙；差异只是 372 条填充字节（分子的 0.0496%）归属不同。当前实现取较大 end，是「宁可多算填充也不截断代码」。
  - 总账与「以哪份为准」：唯一权威 **`work/evidence_m12_ledger.json`**（含 25 行原始、A/B、逐函数、缝隙）；人读镜像 **`work/outputs/NUMBERS_LEDGER.md`**（冲突以 JSON 为准）；M11 收口文档 §8 的推算行已原地加 M12 补记并作废。
  - 回归：pytest **463 passed**（67.42s）＋ **16/16 verify 命令 exit 0**，日志 `work/evidence_m12_pytest.log` / `work/evidence_m12_verify.log`（PowerShell 读中文路径 .ps1 失败后改用 Python 驱动；前一版脚本输出 `DONE failed=0` 是假成功，未采信）。
  - 规则：**R102** 推算值不得进总账，总账只收实测（可复现命令 + 机器快照 + 逐样本 sha256），推算只能出现在过程文档且必须标注前提，实测出来立即替换；**R103** 多源 `end` 之间的缝隙必须量化到「字节数 / 指令数 / 归属 / 换口径后的分子与比率 / 边与块的影响」，缝隙若全是填充必须写明当前口径下多少填充被计入分子。
- [x] 2026-11-16 收口·M13：种子扩大后的下界重算（R104–R106）
  - 影响面判定：种子扩大只改 Go 的函数域。分母来源分四类——objdump 全节指令（不受影响）、只读数据节（不受影响）、recdesc 已解出指令集合（受影响）、声明函数域 `[entry,end)`（受影响）。六个下界条目中，真正需要“域”重算的是 Go 域内未达指令；strxref 的分子虽依赖已解出集合，但 18 样本只有 2 个 Go。
  - Go 域内未达指令（M11 三分法原判据）：复算 **ELF 26,652 / PE 26,702**，padding **149,225 / 148,861**、outside **0 / 40**，与旧值逐项相等（`match_old=true`）；declared_ranges 8,906 / 8,892。2.88% 是“域内未达的 objdump 指令（含对齐）”，不是漏解指令数。
  - VEX 206,541（11 样本）：分类器只读节字节 + objdump 指令起点 + 我方弃权类别，**不读 recdesc 种子**（结构不变性）。用同一 `classify_one` 复算 Go 两样本：lead 20,459 / 20,299、弃权 **16,332 / 16,179**、四分类全为 `data_not_instruction`、`decoder_defect=0`，与 M9 逐项相等；弃权地址与新可达域**已解出指令起点**的交集 **0 / 0**。故 206,541 不变——“种子扩大后有 0 个变成真实指令”。
  - VEX 措辞更正（C1）：Go ELF 弃权点 **16,332/16,332** 全部落在声明函数域内、PE **16,177/16,179**；它们是函数体内指令的操作数/立即数字节，不是“函数外数据区”。正确结论是“全部不是指令边界”，不是“全是数据”。
  - strxref 5,039/276：对两个 Go 样本做 `gopclntab` 关/开 A/B，未解码引用点 **0→0**、涉及字符串 **0→0**、我方引用点 2→2（两样本均如此）；M13 回归 `verify_strxref` 在新种子下仍输出 **5,039 / 276**，与 M8 相同，且全部来自 16 个非 Go 样本。旧总账“本轮未重跑该专项”不准确——M12 回归已重跑，M13 又做了 A/B 归因。
  - switchcand skipped（唯一失效项）：不是种子造成。M9 是整层**未运行**（超时），M10 性能修复后 cc1 **1,974/0 skipped/64 cands**、gdb **2,081/0/317**；M13 复测 gdb 2,081 / 0 skipped / 317 cands（13.0s）一致；lto1 至今**未运行**（应标 `no_run`，不是 skipped）。Go 两样本首次测量：各 **118** 个间接 jmp 函数、analyzed=118、**skipped=0**、candidates=0。
  - 非 Go 可达域：17 个可测非 Go 样本 `gopclntab=missing`、`unchanged=true`、`delta_numerator=0`（`evidence_m13_ledger.json.non_go_reach`）。M8 paramdecl 12,272/3,530/37,891 来自 DWARF，与种子无关，未重算。
  - 判据问题单列（不并入重算）：C1 VEX“数据”语义过宽；C2 skipped 混用「未运行」/「预算跳过」；C3 5,039 是补集度量且对 Go（非 NUL 终止字符串）近盲；C4 2.88% 含对齐字节；C5 skipped 不是候选数下界。
  - 总账与读者指引：唯一权威改为 **`work/evidence_m13_ledger.json`**（含 6 条判定、5 条判据问题、读者指引、代码 sha256；覆盖率等 M12 数字由 M13 回归复核后原样引用）；人读镜像 **`work/outputs/NUMBERS_LEDGER.md`** §6 改为 M13 判定表。旧文档**没有数字**过期，过期的是 3 处说法：`TASK_m10_closeout.md` 的 skipped、`TASK_m9_closeout.md` §3.2 的“全是数据”、旧总账“strxref 未重跑”；对照表见 `outputs/TASK_m13_lowerbounds.md` §5。
  - 回归：pytest **463 passed（69.45s）** ＋ **16/16 verify exit 0**，日志 `work/evidence_m13_pytest.log` / `work/evidence_m13_verify.log`。
  - 规则：**R104** 下界结论必须绑定分母来源，分母不随种子变的标 `seed_invariant` 并给结构证明，随种子变的必须用同一判据复算且逐项复现旧值（`match_old=true`）；**R105** 分类名不得替代判据，`data_not_instruction` 只能写“非 objdump 指令起点”且必须同时报域内比例；**R106** `skipped` 只用于分析覆盖率，未运行标 `no_run`、预算跳过标 `skipped_budget`，二者不混用且不进下界表。
- [x] 2026-11-16 收口·M13-patch：C1–C5 判据问题逐条修复（R107）
  - 方法：每条给出「现行判据原文 / 问题 / 改成什么 / 为什么不是放宽 / 可证伪测试」；先读 `TASK_m13_lowerbounds.md` §4 与 `evidence_m13_ledger.json.criterion_issues`，再改代码/字段，最后把状态从 `open` 改为 `fixed`（`criterion_issues[*].status` 全为 fixed）。
  - C1（VEX 语义）：`CAT_DATA="data_not_instruction"` → `CAT_NOT_START="not_objdump_insn_start"`；`audit(..., declared_ranges=)` 新增 `domain.abstain_in_domain/in_domain_ratio`，未给域时必须为 None 且渲染写明“不得据此写全是数据”。判据本身（只看 objdump 指令起点）未动；`classify_one` 不读域（测试 `test_classification_ignores_declared_domain` 反证）。`verify_vexaudit` 对 cli-64.exe 实报域内 **37/38（97.37%）**，206,541 计数不变。
  - C2（状态命名）：`switchcand.budget` 拆为 `run_status(ok/no_run)`、`functions_skipped_budget`、`functions_no_run`、`status_semantics`；`skipped_detail[].skip_type="skipped_budget"`；裸键 `skipped` 禁用。另修两处同类同名：`sitejoin` 的 `status:"skipped"` → `"no_decoded_instructions"`；`verify_switchcand` 快照与 baseline 的 expr 字段 → `skipped_undeclared_boundary`。全项目清单 10 项（3 项已改名、7 项按对象限定保留，含 `coverage.status`、`gopclntab.status`、`iat` 模块/槽两级、`callfacts.state/graph_state`），见 `status_field_inventory`。
  - C3（strxref 补集度量）：`lower_bounds.strxref` 标 `bound_type=complement_measure`、`is_lower_bound=false`、`complement_of="已解出指令里的引用点"`；`rekit/strxref.py` 头注与 `verify_strxref` 输出加补集口径行（对 Go 近乎盲）。5,039/276 不变。
  - C4（Go 2.88%）：新增测量 `evidence_m14_c4_alignment.json`——in_range_other 桶里 nop 族 **ELF 1,067/26,652=4.0034%、PE 1,066/26,702=3.9922%**（多字节 nop，如 0x40207C `0f 1f 40 00`），其余为 mov/lea/call/jmp/ret；故措辞定为“域内未达的 objdump 指令（含对齐）”，既不是“对齐桶”也不是“漏解指令数”。新增 `tests/verify_c4_alignment.py` 逐条复算（18.04s，pass）。
  - C5（类别错误）：switchcand 从 `lower_bounds` 移出，单列 `analysis_coverage`（lto1=`no_run`、cc1/gdb=`ok`）；新增 `bound_table_policy`（`bound_type` 白名单 + `analysis_coverage` 不得入表）。覆盖率数字完整保留，未删任何不利数据。
  - 逐条验证与数字变化：C1 `test_vexaudit`+`verify_vexaudit`（206,541 不变；新增域内 37/38）；C2 `test_switchcand`+`verify_switchcand`+`test_sitejoin`（cc1 1,974/0/64、gdb 2,081/0/317 不变）；C3 `verify_strxref`（5,039/276 不变）；C4 `verify_c4_alignment`（26,652/26,702 不变，新增 1,067/1,066）；C5 `test_ledger_criteria`（7 项，无数字变化）。变化分列见 `TASK_m13_lowerbounds.md` §7。
  - 回归：pytest **475 passed（68.54s，exit 0）** + **17/17 verify exit 0**（新增 `verify_c4_alignment.py`），日志 `work/evidence_m14_pytest.log` / `work/evidence_m14_verify.log`。
  - 规则：**R107** 结论措辞强度必须与证据强度匹配，不得用更强的说法替代——分类名不得暗示判据没证明的东西；补集度量不得称下界；含对齐的桶不得称“漏解指令数”；分析覆盖率不得进下界表。每条此类结论必须绑定 `bound_type/criterion/denominator/evidence`，由 `tests/test_ledger_criteria.py` 机器校验；找不到可证伪测试的结论不得写入总账。
- [x] 2026-11-16 收口·M15：单函数面向人报告层（`rekit funcreport`）
  - 方法：六层（recdesc/expr/callgraph/callfacts/strxref/paramdecl）按函数地址合成一份报告；每个可证伪条目带 `source={layer,field,text}`；每段给 `evidence_state/scope/reason`；`absence_summary` 逐条列全。本层不产生新推断、不新增反汇编、不改任何既有层判据。
  - 同源：`build()` 只跑一次，`--json` 打印同一 dict，人读走 `render(report)`（纯函数）；单测用 JSON roundtrip 断言 `render` 输出逐字节一致。
  - 缺失两栏：`absent_measured`（确实没有，有测量范围）/ `missing_source`·`missing_declaration`·`missing_decode`·`abstained`（缺证据）。渲染严格分离“确实没有：…”与“缺：…”。
  - 三类验收：完整声明 `add3`（12 指令、3 形参、`.pdata` 边界）、Go `0x401320`（25 指令、1 条表达式 abstain、无 DWARF）、`minidll.dll 0x1000`（1 指令、无结束声明、无 DWARF）；状态矩阵逐项一致。
  - 外部抽查：`tests/verify_funcreport.py` 16/16 PASS（块/调用目标为 objdump 起点、块内指令落域、`high_pc=0x1e`、DWARF 形参数 3、Go 25≤50、缺失语义含“缺：”）。
  - 层失败不静默：任何层异常进 `layer_errors`，对应段记 `missing_source`；注入的 `res/graph/facts/sxref` 在 build 前后哈希一致（只读）。
  - 回归：pytest **485 passed（73.58s，exit 0）** + **18/18 verify exit 0**，日志 `work/evidence_m15_pytest.log` / `work/evidence_m15_verify.log`。
  - 规则：**R108** 报告层只呈现不判断：任何结论必须带来源层与字段；缺失必须二分为「确实没有（有测量范围）」与「缺证据（缺来源/缺声明/缺解码/弃权并写缺什么）」；人读与机器可读必须同源生成，不得各自计算。

### 2026-11-16 M16 — 非字符串数据引用层（datarefs）

- 新增 `rekit/datarefs.py` + `rekit datarefs`：对象只认声明（ELF `STT_OBJECT.st_size`、DWARF 变量 + 类型链），引用点按 7 种寻址形态分列，归因三档不合并，指针槽首地址/内部值分列；分母先行（声明候选 = 接受 + 拒收 + 去重），PE COFF/导出表无尺寸字段单列 `format_rejections`、不进对象分母。
- 实测 `dyn_static`：539 = 483 + 41 + 15；形态 25,941（`seg_disp` 853 / `base_disp` 18,519 / `base_index` 2,695）；分档 `object_start=1709, inside_object=669, after_object=259, data_unattributed=1001, not_data=236`；有代码引用 417（86.3354%）；指针槽首地址 92、内部 30。
- 正样本 `tests/m16_fixtures/datarefs_full.exe`（PE，DWARF）：9 = 7 + 2 + 0；COFF 格式层拒收 720；`g_table` 内部命中 offset=4/12，`g_zero`（.bss，无文件字节）offset=8；指针槽 `0x4030→0x4010`、内部值 `0x4038→0x9084`。
- 修复四处会制造假归因的实现错误：ELF `shndx` 按节头 index 查（不是列表位置）；`fs:`/`gs:` 段前缀不按绝对地址归因（dyn 有 853 条栈保护）；算术文本的指令长度取指令而非操作数；TLS 节 VMA 与普通节重叠导致 `.data.rel.ro` 起点对象被误拒收。
- `funcreport` `SCHEMA=2`，七层白名单 + `data_refs` 真实来源：`funcreport_full` → `absent_measured`（确实没有可交叉对象），Go 0x401320 / minidll 0x1000 → `missing_source`（缺证据）；正样本 6 个用户函数 5 `present` + main `absent_measured`。
- 外部重算（`tests/verify_datarefs.py`）：readelf 对象 501 条、objdump DWARF 7 条、objdump -d 引用点 fix 207/207 与 dyn 3854/3855、objdump -s 指针槽 2/2；可失败自证（目标 +4、删 `g_table`）均 PASS。
- 回归：pytest **509 passed（70.33s）** + **18/18 verify exit 0** + fingerprint E9 PASS（132/132）；`verify_datarefs.py` 连续 12 次新鲜进程全 PASS。
- 规则：**R109** 对象分母与格式层拒收分账；**R110** 三档归因不合并、`after_object` 只表示邻接；**R111** “没有声明来源”与“声明存在但不可解析”分开报，且过程缓存不得以对象地址为键。
- 回归期修掉一个偶发失败（约 1/15）：`paramdecl._abbrev_table` 以 `id(data)` 作缓存键，两个 DWARF 样本的 `.debug_abbrev` 切片同为 512 B，`bytes` 大批释放后 `id` 复用导致命中别人的表 → `funcreport_full` 被误报 `missing_source`。缓存改按内容作键；同时把`no_declaration_source` 的 reason 拆成“无 DWARF 节”与“有节但解析失败”。护栏：`tests/test_datarefs.py` 新增 2 项。

### 2026-11-16 M17 — .NET 程序集结构层（dotnet）

- 新增 `rekit/dotnet.py` + `rekit dotnet`：只读声明回答「有哪些类型、哪些方法、方法体在文件哪里、IL 指令边界在哪」。链：PE `DataDirectory[14]` → CLI 头 → MetaData RVA/Size → BSJB 根 → 流头 → `#~` 表流（45 表 schema、HeapSizes/coded index 宽度）→ TypeDef/MethodDef；`MethodDef.RVA` 只用节表换算；tiny/fat 头、EH 附加节、ECMA-335 opcode 表、`#US` 原文。
- 样本来源如实分列：本机真实 Framework `mscorlib.dll`（3,356 TypeDef / 29,257 MethodDef）与 CoreCLR `System.Console.dll`（47 / 433）；受控样本由本机 `csc` 编译（6 / 18，含方法体/字符串/泛型/抽象/接口/PInvoke/EH）。受控样本只覆盖csc 实际生成的 IL 子集，**不能代表真实程序集**，局限写入 caveat。
- 分母先行（恒等式全部成立）：受控 18 = 15 + 3（abstract 2、pinvoke 1），体成功 15、IL 解出 15、指令 119；Console 433 = 396 + 37（pinvoke 33、runtime 4），体成功 396、指令 6,592；mscorlib 29,257 = 25,315 + 3,942（abstract 2,222、pinvoke 563、runtime 301、**unclassified 856**），体成功 25,315、指令 592,206。三样本 25,726 个方法体尾字节全为 0（IL 边界与 code_size 对齐）。
- 外部独立证伪：`dnfile` 表行数/TypeDef/MethodDef 逐行/RVA→文件偏移全部一致；`dncil` 逐条 IL 边界——受控 15/15 全量，真实样本另跑全量 **396/396、25,315/25,315**；`dnfile.user_strings` 逐条核对 #US（10/77/4,725），`ldstr` token 全部落在已知偏移；CLR 反射核对受控样本类型名/方法名/IL 长度。5 项可失败自证（IL 偏移+1、删一条、末字节 0xFF、RVA+1、表行数+1）全部检出。
- 跨层显式：`cross_layer` 列 19 项；`map` 部分适用，`pe`/`fingerprint` 适用，`disasm`/`recdesc`/`expr`/`callgraph`/`callfacts`/`sitejoin`/`strxref`/`datarefs`/`coverage`/`switchcand`/`vexaudit`/`paramdecl`/`struct`/`gopclntab`/`funcreport` 均 `not_applicable` 并写原因；`funcreport` 入口直接返回 `not_applicable`（8 行 absence），不跑六层、不返回空报告。
- 本轮读不出：签名语义（参数/返回/局部变量类型）、调用目标解析、字段/属性/事件/常量/特性语义、`FieldRVA` 静态数据内容、资源内容、嵌套类型全名、NativeAOT/ReadyToRun 原生代码、反编译/反混淆/壳识别；`FieldRVA`/`ENCLog`/`ENCMap` 因 dnfile 不实现而无外部重算。
- 回归：pytest **528 passed（70.64s）** + **20/20 verify PASS**（新增 `verify_dotnet.py` 27/27），日志 `work/evidence_m17_pytest.log` / `work/evidence_m17_verify_all.log` / `evidence_m17_il_full.log`。
- 规则：**R112** .NET 方法体不是 x86，x86 各层必须显式 `not_applicable`；**R113** .NET 分母逐级二分恒等式、RVA=0 原因逐类计数（`unclassified` 单列）；**R114** IL 边界必须由独立 opcode 表/解码器全量证伪并用尾字节对账。

### 2026-11-16 M18 — .NET IL 控制流与调用关系（ilflow）

- 接续执行（上一会话历史过大中断）。**盘点如实**：`ilflow.py` 实现已成型但从未被真实样本比对；`test_ilflow.py` 26 项通过但只覆盖受控样本；`verify_ilflow.py` 不可信——把方法摘要喂回分析函数导致「0 个方法 / 0 个目标；全部一致」的空对空 PASS、dncil 分支操作数漏减方法体头、dnfile 零行表直接 AttributeError。旧日志已改名 `work/evidence_m18_verify_broken.log` 保留。耗时未按基线计时（接续任务）；返工 2 次：校验器偏移/块规则对齐、`br` 假边修复。
- 实现（中断前主体保留）：token 解析 5 类原因分列（`method_missing`/`row_out_of_range`/`bad_parent`/`unsupported_parent`/`token_kind_mismatch`）；分支落点三分类 + switch 逐 case；基本块/四类边/可达；EH 单列结构 + `leave` 越区检查；分母恒等式；CLI `rekit ilflow`。
- 分母先行（四样本，恒等式全成立）：受控 Flow 19 有体/17 调用（internal 8、external 9）、Filter 5/2（1 internal、1 token_kind_mismatch）；Console 396 有体/1,133 调用（572/561）、mscorlib 25,315 有体/93,194 调用（93,174/0/20 `bad_parent`）。分支目标 6/5/599/52,837 全部落在指令边界（inside 0、outside 0、decode_error 0），switch 235 条 / 2,012 case；EH 子句 3/2/23/2,164。
- 本轮实现缺陷 1 处（独立切块对拍抓出）：`COND_BR` 含无条件 `br/br.s` → 每条 br 多一条假 fallthrough 边，并把 3 个不可达块误判可达。修复 `COND_BR=(SHORT_BR|LONG_BR)-UNCOND`，新增单测守卫。数字变化：Console 边 1,328→1,245、mscorlib 116,023→107,765、Flow 12→11；mscorlib 不可达 5,055→5,058；branch/call/EH/token 数字全部不变，未放宽任何判据（R72/R105）。
- 独立证伪（`verify_ilflow.py` 重写）：dncil 全量重算分支/块/边/可达 —— 25,735 个有体方法、94,346 条调用、109,684 块、109,029 条边、2,192 条 EH 子句全部一致；dnfile 独立核对存储方法每个调用点 token（行号/名/宿主/外部类型与程序集/MethodSpec 底层行与泛型个数），四样本零矛盾。可失败自证 7 项全部检出（目标 +1、外部名改字、删 EH 子句、删块、token 越界、MethodDef 行 1→2、空比对 FAIL）。
- EH 口径写死：**只单列结构、不建 CFG 边**（运行时异常传播不是静态转移），`leave` 单独建边并检查越区；四样本 `leave` 进保护区/出 finally/在 filter 均为 0，EH 边界/范围非法 0。
- 已知边界：mscorlib 20 条 `bad_parent` 是 TypeSpec 父为 `PTR/SZARRAY/VAR` 的结构边界；mscorlib external=0 仅因 TypeRef 表 0 行，不得外推；求值栈/类型推断/异常传播/反编译不在范围；真实样本逐条明细为前 2,000 个有体方法（全量聚合覆盖全部）。
- 回归：pytest **554 passed**；`verify_ilflow` **41 项全 PASS**；21 个 verify 脚本 20 个 exit 0 + `verify_fingerprint --all --matrix` exit 0。日志 `work/evidence_m18_pytest_all.log` / `work/evidence_m18_verify.log` / `work/evidence_m18_verify_all.log` / `evidence_m18_ilflow.json`，任务卡 `outputs/TASK_m18_ilflow.md`。
- 规则：**R115** 偏移基准写死且校验器不共用换算；**R116** IL 终结符分两层；**R117** EH 只单列、`leave` 建边并检查越区；**R118** 未解析原因可追问到表行，`bad_parent` 为必要补充；**R119** 空比对一律 FAIL + 可失败自证。

### 2026-11-16 O2-b — 数字总账链路 + 门禁语义统一（治理层，不改 rekit 源码）

- 总账权威迁移：新增 `pack\tools\ledger_check.py`（`--write` 重生成 / `--check` 漂移硬失败 / `--audit` 未登记清单）；唯一权威 = `work\evidence_numbers_ledger.json`（schema `numbers-ledger/1`，M13–M18，**8 小节 / 8 证据 / 67 个登记数字**），`evidence_m13_ledger.json` 降级为历史源。漂移判据：小节存在、标题一致、登记数字逐字出现在该节正文、证据 sha256 相等；任一不满足 exit 1。
- 插单盲区（R103 `pe_gap`）：113,731 / 3.2262% / -0.0402pp 已补登记，并用三个负例验证（3.2262%→3.2263%、113,731→113,733、-0.0402pp→-0.0403pp 均 FAIL，恢复 PASS）。同类盲区转显式清单：`--audit` 出 8 小节「已登记 67 / 未登记 105」，五类未登记原因（区间分布 / 派生百分比 / 旧值对照 / 地址与样例字节 / 逐样本细分格），落 `work\evidence_ledger_unprotected.json`。
- 新鲜度改用**字节判据**：证据 sha256 变化才 FAIL；证据被原样重写（`verify_ilflow` 每次运行重写同内容 `evidence_m18_ilflow.json`）只记 note。原 mtime 规则会在全量门禁跑完后把权威误判为「落后」；替换后覆盖不变（内容真变仍由 sha256 拦下）。
- M5 残差落盘：`verify_expr --oracle-only --json` 产 `work\evidence_m5_expr_residual.json`（objdump GNU 2.47.20260726；cli 1 条/1 函数、bin_ls 403 条/7、dyn_static 390 条/13，逐地址）；口径写入 ledger §14——objdump 整节线性扫描 vs expr 的 CFG 可达子集，残差单列、**不入任何已公布比率的分子分母**。
- 门禁语义统一：`verify_gate.py` 委托 `tests\vharness.py --json`（删本地 SUITE_ARGS 与第二套判定），pytest、`ledger_check --check` 为另两步硬检查；`run_id` 加随机后缀；summary schema `verify_summary/2` 带 `scope`；`--only` 单套跑在 `status.py` 里降级为 WARN（不能当发布证据）。
- vharness 三条收紧（只加不减）：① `MIN_DENOM` 21 套实测分母下限，低于下限 FAIL（`denominator_below_min`）；② 自证只认工件 dict（id/baseline/observed/fail_line），布尔值 FAIL、基线==观察值 FAIL、无失败行 FAIL；③ `REQUIRES` 15 套声明 objdump，缺工具 exit 2 `env_missing`，不静默跳过。`--selftest` **8/8**。
- 两套补「失败行」判据（不改被测数字）：`verify_gopclntab` 取篡改输入后的 `status=unknown funcs=0` 行为负控证据；`verify_vexaudit --selftest` 新增**故意写错期望**的负控行（必须报「不一致（已检出）」）。
- 全量实跑 `work\verification\20261117T001004-58f1`（vharness 383.6s + pytest 84.3s）：**21/21 套 PASS、pytest 554 passed / 0 failed / 0 skipped、ledger PASS 67 数字、VERDICT: PASS exit=0**；`status.py` 复跑 PASS（HANDOFF 6/6、latest PASS、ledger PASS、git WARN）。
- 判据变化汇总：mtime→sha256（删误报、真变仍拦）；自证「能跑」→「必须是工件且含失败行」；分母「非 0」→「≥实测下限」；缺外部工具「跳过」→ exit 2；gate 不再自建判定。
- 未动：`rekit\*.py` 0 处、样本 0 处、任何已公布数字 0 处改动；目录改名与 `git init` 未做。定标：**M19 = .NET 签名语义层（`#Blob` 解码）**，已写入章程，本轮不动工。

### 2026-11-17 M19 — .NET 签名语义层（sigblob）

- 新增 `rekit/sigblob.py` + `rekit sigblob`：只解 MethodDef / MemberRef / StandAloneSig 的 `#Blob` 签名（调用约定、泛型参数数、返回/参数类型）；`Field(0x04)` 与 `LOCAL_SIG`/字段签名只做长度与边界。上游 `dotnet.Tables.blob_span()`（`blob()` 复用同一实现，避免偏移逻辑漂移）与 `TypeResolver`（TypeDef/TypeRef 嵌套链）；TypeSpec 只写 `spec@0x1Bxxxxxx`，不解其 blob。
- **定标偏离（已向用户说明并继续）**：PyPI `dnfile` 0.5.0–0.18.0 全版本没有签名解码 API，定标②的字面「用 dnfile 的 Signature 解码」不存在。替代保持两条不让步：字节边界仍由 dnfile（`Signature_BlobIndex` + `Signature.value/raw_size/item_size/rva`）逐行比对；语义期望值改用微软 SRM `DecodeSignature`（`tests/sigref.ps1`，pwsh 7.6.6/.NET 10 `Add-Type` 编译 `ISignatureTypeProvider<string>`）。新增 `pwsh` 依赖，缺失 → `env_missing` exit 2（fail-closed）。
- 分母先行（四样本，恒等式全部成立）：方法签名 **32,518** 个（受控 18 + 20、Console 662、mscorlib 31,798）；字段签名 **911**、局部签名 **3,974** 只做长度；三张调用点表可读 blob **37,403**，解码率 **100.0000%**，undecoded 0、unknown 节点 0、`Field.non_field_signature=0`。mscorlib 四表 29,257 / 3,429 / 3,908 / 14,718；Console 433 / 237 / 73 / 277。
- 独立对拍（期望值不取被测实现）：dnfile 重算索引/文件偏移/长度/字节 **52,403** 行；SRM canonical 整串 **37,403** 行；M17 `signature_len`/签名 hex 前缀 **29,728** 行；三者 0 不一致。对拍抓到 3 处 `modreq` 渲染差异（SRM 原生带 `class` 前缀，spec §3 写死 `modreq([TR]X)`），在参考侧 formatter 按 spec 归一，未改被测实现与比较判据。
- 可失败自证（首版即带工件）：字节注入（`String`→`Int32`）→ `[FAIL] m19-drift token=0x06000003`；报告索引 +1 → `[FAIL] m19-bytes ... blob_index: dnfile=65 rekit=66`；长度前缀 +1 → `undecoded/trailing_bytes`；SRM 侧 canonical 改一字 → `[FAIL] m19-srm ... canonical 不一致`；空比对 → 拒绝 PASS。`verify_sigblob.py` **17 项全 PASS**。
- 未覆盖（如实登记，不换宽松样本）：本批四样本的方法签名中未出现多维数组（`ARRAY`）、`FNPTR`、`modopt`、内嵌 TypeSpec 引用；这些路径已实现但无证伪样本。`depth_exceeded`/`bad_compressed_int`/`truncated_signature` 同样无负样本。
- 回归：全量门禁 **22 套 PASS**、pytest **554 passed**、`ledger_check --check` PASS（run `20261117T010924-0a7b`）；总账新增 §15（9 小节 / 9 证据 / 82 数字），`evidence_m19_sigblob.json` 登记 sha256。
- 规则：**R120** 方法签名必须 `consumed == blob_len`，剩余字节记 `trailing_bytes` 且计 undecoded；**R121** `unknown`（结构已解、类型节点未知，计 `decoded_with_unknown`）与 `undecoded`（字节没解完）必须分开计数，两者都不得按名称猜；**R122** 参考实现与 spec 的 canonical 文本冲突时按 spec 归一，但必须在文档披露冲突点与处理方式，不得改被测实现或比较判据。

### 2026-11-17 M20 — .NET 类型布局与字段 RVA（.NET 纵切面封口）

- 定位：M17 到方法体位置、M18 到 IL 结构、M19 到签名语义，M20 收掉最后一块静态可证的类型布局，**不当作第四个 .NET 里程碑**。耗时未按基线计时（接续任务）；返工 3 次：`data_length` 返回值缺 `missing`、`--limit` 截断时从明细计数、运行期变量名覆盖分母。
- 实现：`rekit/layout.py`（726 行）+ `rekit layout`。静态只报三样——`FieldLayout.Offset`、`ClassLayout.PackingSize/ClassSize`、`FieldRVA` 的 RVA→文件偏移→数据字节；`FieldRVA` 数据长度按 `valuetype ClassSize` / 基元 / `unknown` 三源分列；`undecoded` 四类原因（`rva_zero`/`rva_not_in_any_section`/`data_truncated`/`field_index_zero`）逐类计数；sequential/auto 偏移单列 `runtime_derived` 且 `static_conclusion=false`。
- 分母先行（四样本，恒等式全成立）：`FieldLayout` **84**、`ClassLayout` **71**、`FieldRVA` **132**，合计 **287** = dnfile 独立读表行数。逐样本 mscorlib 78/63/128（数据 **64,421** 字节，长度来源 **120 / 8**）、System.Console 0/3/0、受控 IL 3/2/3（28 字节）、受控 C# 3/3/1（32 字节）。长度来源合计 **122 / 9 / 1**；数据解码率 **100.0000%**（131/131），unknown **0.7576%**（1/132，`valuetype_not_typedef`，IL 样本 `System.DateTime`，不拿 `.data` 的 8 字节反推）。
- 独立对拍（期望值不取被测实现）：dnfile 三表原始列值 **287** 行、dnfile `get_offset_from_rva` **131** 行（位置 + 字节）、源码真值 **16 项**（`.il` 的 `.pack`/`.size`/`.field [N]`/`.data`，`.cs` 的 `[FieldOffset]`/`[StructLayout]`/数组初始化器）、`__StaticArrayInitTypeSize=N` 与 ClassSize/推导长度 **121** 行，**全部 0 不一致**。dnfile 不实现 `FieldRVA`，故数据字节由源码数组初始化器独立作证，不把 dotnet 自家解析器当唯一裁判。
- 运行期 oracle（不进静态结论）：`tests/layoutref.ps1`（PowerShell 5.1 + CLR 反射）在受控样本给出 **14 个偏移 / 3 个 size**；显式布局的静态 `FieldLayout.Offset`/`ClassSize` 与运行期逐一相等（交叉印证）；`AutoStruct` 被 CLR 拒绝（`cannot be marshaled as an unmanaged structure`），记 **1 个 auto 边界不可得**，不写静态值。边界写入 `outputs/m20_layout/spec.md` §3。
- 可失败自证（首版即带，工件 = 注入 ID + 基线 + 观察到的失败行）：`FieldLayout.Offset` +4、`ClassLayout.ClassSize` +1、FieldRVA 文件字节翻转、`RVA` +1 四类全部检出（含 `[FAIL] m20-src selfproof FieldLayout A offset expected=0 actual=4`），空比对拒绝 PASS。`verify_layout.py` **28 项**（PASS 27 / SKIP 1；SKIP 是 System.Console 的 `FieldRVA=0` 无可复算行，由聚合分母兜底）。
- 回归：全量门禁 **23 套 PASS**、pytest **554 passed**、`ledger_check --check` PASS（收口 run `20261117T013424-1713`；文档定稿后复跑 `20261117T014558-2b7c` 同为 23/23 + 554 + ledger PASS，`VERDICT: PASS exit=0`）；总账新增 §16（10 小节 / 98 数字 / 未登记 127），`evidence_m20_layout.json` 登记 sha256，负例（`0.7576%`→`0.7577%`）exit 1 已验证后恢复。
- 文档漂移修正（本轮实测）：`HANDOFF.md` 补 M19/M20 并把过期态（git 未初始化、目录名 4/7、21 套、8 小节 67 数字）改为实测值；`pack/AGENTS.md` 规模改 **27 模块 / 18,600 行**（原 25 / 16,939）、23 套、23 个 verify；`CHARTER.md` 补 M20 行与转段触发器 T1–T5。
- 转段触发器实测：**T1 已命中**（验收 700 / 实现 730 = **0.96 ≥ 0.90**；该条曾被误读为「需同时满足两个条件」而写成未命中，已更正——判据是「比值 ≥0.90 **或** 连续 2 个里程碑验收新增 > 实现新增」，任一满足即命中；「连续 2 次验收 > 实现」不成立：M19 493 < 907、M20 700 < 730）；T2 计数 **1/2**；T3 未命中（429.4s < 10 分钟，新增证据 1 个）；**T4 已命中**（运行期 oracle 依赖 PowerShell + Windows CLR，别人无法直接复跑）；T5 未命中（未改任何既有 verify）。**T1 + T4 同时命中 ⇒ 停止纵深，转交付批次**。
- 规则：**R123** 类型布局的静态结论只到元数据写明的值（`FieldLayout.Offset`、`ClassLayout` 两列、`FieldRVA` 的 RVA 与字节），sequential/auto 偏移必须标运行期推导、不进静态分母；**R124** `FieldRVA` 数据长度不是元数据字段，按「valuetype ClassSize → 基元 → unknown」分源并逐类计数，推不出写 unknown 及缺什么，不得用 `.data` 字面量反推；**R125** 静态结论与运行期推导必须分栏（`static_conclusion.includes/excludes`），交叉印证不得反写成静态来源。

### 2026-11-17 U1-a — 交付批次（打包 / info / JSON 契约 / 示例 / tag，不占里程碑号）

- 打包：`04_rekit项目源码/pyproject.toml`（setuptools，`packages=["rekit"]`，console entry `rekit = rekit.cli:main`，`requires-python >= 3.8`，`dependencies = []`）。实测 `python -m pip install -e .` 后任意目录 `rekit info <file>` 可跑；未安装仍可 `python -m rekit.cli`。新增 `rekit/__main__.py` 支撑 `python -m rekit <cmd>`（既有 `test_ilflow` 用例一直在等这个入口，此前靠机器上残留的旧安装偶然通过）。
- `rekit info <file> [--json]`：章程承诺的命令补齐。字段 15 个（sha 无关），缺失写 `null` 不省键；ELF 带 `security`（沿用 `elf.parse`），PE 带 `image_base/subsystem/imports/exports` 与 `dotnet{is_cli,status,reason}`。失败语义与既有分诊一致（2=不存在/不可识别，3=解析失败）。
- JSON 契约冻结：`pack/03_路线图与章程/JSON_CONTRACT.md` 冻结 `info`/`map`/`ilflow`/`datarefs` 的 `--json` 顶层字段名；改名或删除按破坏性变更处理，新增字段须同步登记。`map` 无 `schema` 键（历史原因）已在契约里明写。
- 示例：`04_rekit项目源码/README.md` 给出 PE/ELF/.NET 各一条可复现命令与预期摘要（ELF 用 `bin_ls.elf` 的 info/map/datarefs；PE 用 `minipe.exe` 的 info/map；.NET 先跑 `work/outputs/m20_layout/gen.ps1` 再 info/ilflow）。**.NET 样本重新生成不是逐字节可复现**（编译期时间戳），可复现的是源码与元数据——README 已写明。
- 文档漂移修正（本轮实测）：`pack/README.md` 数字权威改 `evidence_numbers_ledger.json`、R33–R119 已有规范文件、目录名损坏提示改为「已改名」、21 套/4 分钟改 23 套/约 7.2 分钟、pytest 必须在 `work` 目录跑；`PATH_MAP.md` 规模改 27 模块/25 test/23 verify 并补 `pyproject.toml`、`README.md`、`JSON_CONTRACT`；`AGENTS.md` 规模 18,600→**18,720** 行、CLI 入口与 pytest 工作目录。
- 回归：全量门禁 23/23、pytest **554 passed**、ledger PASS（run 见收口提交说明）；`v0.1.0` tag。

