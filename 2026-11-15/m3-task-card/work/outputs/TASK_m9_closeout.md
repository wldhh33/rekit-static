# M9 收口：覆盖缺口收敛 + 样本面补齐

- 日期：2026-11-16
- 范围：M9 六条要求（样本线 3 条 + 收敛线 3 条）
- 工作根：`2026-11-15/m3-task-card/work`
- 机器快照与代码 sha256：`work/evidence_m9_coverage_summary.json`

## 0. 一句话结论

M9 建起了「分母先行」的覆盖率口径（分母由外部 objdump 独立计数），把伪 VEX 弃权从「笼统 abstain」拆成四类可对账计数，并把跳转表升格的判据全部移到外部 objdump 指令起点上；样本面补齐了 5 个真实样本 + 2 个合成对照。
**在同一批旧样本上，解码输出逐条未变（18/18 样本指令数与字节数完全相等），因此覆盖率的变化里「解码改进」为 0，全部来自样本更换与口径新建。** 这不是好消息也不是坏消息，是必须先把账说清的事实。

## 1. 口径与前置

### 1.1 覆盖率口径（收敛线 C，写死在代码里）

- **分母** = GNU objdump 2.47 对同一文件、同一节地址范围 `[VA, VA+size)` 用 `objdump -d -M intel` 列出的指令条数。**外部工具独立计数，不以 recdesc 自身解出的条数为分母。**
- **分子** = recdesc 已解出、且与 objdump **同起始地址、同长度**的指令条数。
- 恒等式（恒可对账）：

```
ours_total = matched + len_conflict + ours_only
denominator = matched + len_conflict + objdump_only
ratio       = matched / denominator
```

- 口径强制规则：汇总只允许 `scope=full`（清单全部样本都跑）或 `scope=sampled`（分层子集，**必须附样本名单**，否则代码直接抛错，不出数）。
- 实现：[coverage.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/2026-11-15/m3-task-card/work/rekit/coverage.py)；验收：[verify_coverage.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/2026-11-15/m3-task-card/work/tests/verify_coverage.py)、[test_coverage.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/2026-11-15/m3-task-card/work/tests/test_coverage.py)。

### 1.2 被测代码 sha256（R90：机器快照 + 代码指纹）

| 文件 | sha256 |
| --- | --- |
| rekit/recdesc.py | `f719a9793baaa06ae8728caac7c8952c1acc2f632532d54298fe934dc9ce561f` |
| rekit/disasm.py | `699d74abb80688d40d1ff65526b42024df3d0f44b2548c29022f3d7b7cd61b07` |
| rekit/coverage.py | `3d0c0272a14c66a25a5b455e274e9cb307554b9232e1cd6bbfd4af674f518156` |
| rekit/vexaudit.py | `e93072425193f2f41f91f31d5e8af81bdf1b85f3a256362f6e3d83f133c03167` |
| rekit/switchcand.py | `6645b091cc6aa52117d4a489b1a92722b5d0c22dfe50ac2d18a49fb1680379e7` |

## 2. 收敛线 C：覆盖率报告（分子 / 分母 / 口径 / 抽样）

### 2.1 可失败自证

`verify_coverage.py` 不 import `rekit.coverage` 的计数逻辑，自己用 struct 解析 ELF/PE 节头定位节窗口，自己解析 objdump 文本复算分母，并做 3 个自证：

1. 篡改一条我方指令长度 +1 → 必须出现 `len_conflict`（未出现即 FAIL）；
2. 伪造「objdump 少 10 条」→ 必须与独立复算不一致（一致即 FAIL）；
3. `scope=sampled` 缺样本名单 → 必须抛 `ValueError`（不抛即 FAIL）。

三个都通过；另有 5 个 pytest 覆盖恒等式、`len_conflict` 不进分子、objdump 不可用时 `ratio=None`（**不写 0**）、口径规则、无节表结构性结果。

### 2.2 数字（分子 / 分母 / 比例，均含分母口径）

旧 18 样本（M8 冻结清单）逐样本：

| 样本 | 分子 | 分母 | ratio | len_conflict | ours_only | objdump (bad) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| dyn_pie | 56 | 64 | 0.8750 | 0 | 0 | 0 |
| dyn_nopie | 53 | 65 | 0.8154 | 0 | 0 | 0 |
| dyn_static | 94,765 | 113,924 | 0.8318 | 0 | 8 | 0 |
| dyn_execstack | 59 | 67 | 0.8806 | 0 | 0 | 0 |
| dyn_norelro | 56 | 68 | 0.8235 | 0 | 0 | 0 |
| bin_ls.elf | 17,475 | 22,523 | 0.7759 | 0 | 0 | 0 |
| hello_go_linux | 138,224 | 171,832 | 0.8044 | 0 | 0 | 0 |
| busybox-1.35.0-musl | 305 | 245,678 | 0.0012 | 0 | 0 | 0 |
| cli-64.exe | 1,525 | 1,694 | 0.9002 | 0 | 0 | 0 |
| minipe.exe | 1 | 1 | 1.0000 | 0 | 0 | 0 |
| minidll.dll | 1 | 9 | 0.1111 | 0 | 4 | 0 |
| hello_go.exe | 143,525 | 182,854 | 0.7849 | 0 | 0 | 2 |
| hello_rust.exe | 22,582 | 26,353 | 0.8569 | 0 | 0 | 0 |
| putty-64bit.exe | 220,256 | 263,121 | 0.8371 | 0 | 31 | 3,109 |
| upx_dyn_pie / upx_cli-64.exe / upx_putty-64bit.exe / minipe_fakerich.exe | — | — | 不可测 | — | — | — |

- 4 个加壳样本节表被移除或无 `.text`，**记 `no_section`，不进分母**，不折算成 0。
- 旧样本合计：**638,883 / 1,028,253 = 62.13%**（14 个可测 + 4 个不可测）。
- busybox 的 0.12% 是真实事实不是 bug：入口只直接走到 305 条指令，其余 24.5 万条靠函数指针/表调用，递归下降从入口出发到不了。旧样本上就有，与 M9 无关。
- putty 的 31 条 `ours_only`、3,109 条 objdump `(bad)`：objdump 在 putty 上有大量无法解码的字节（多在 padding/数据区），双方都不完全干净；`ours_only` 的 31 条指我方解出但 objdump 未在起始地址列出，已单列、未计入分子。

新 7 样本逐样本：

| 样本 | .text 字节 | 我方指令 | 分子 | 分母 | ratio | len_conflict | ours_only | bad |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| elf_medium_cc1_stripped | 20,979,132 | 4,049,517 | 4,049,517 | 5,063,038 | 0.7998 | 0 | 0 | 0 |
| elf_medium_lto1_stripped | 20,165,308 | 3,910,063 | 3,910,063 | 4,863,491 | 0.8040 | 0 | 0 | 0 |
| elf_jumpdense_python310_stripped | 2,824,958 | 627,658 | 627,658 | 684,728 | 0.9167 | 0 | 0 | 0 |
| elf_plugin_liblua54_stripped.so | 176,630 | 36,574 | 36,574 | 47,339 | 0.7726 | 0 | 0 | 0 |
| pe_medium_gdb181.exe | 7,584,976 | 1,542,816 | 1,542,812 | 1,776,492 | 0.8685 | 2 | 2 | 1 |
| elf_medium_synth_go_stripped（合成） | 3,511,473 | 76,168 | 76,168 | 923,970 | 0.0824 | 0 | 0 | 1 |
| pe_medium_synth_go_stripped.exe（合成） | 3,525,201 | 738,853 | 738,852 | 925,712 | 0.7981 | 0 | 1 | 2 |

- 新样本合计：**10,981,644 / 14,284,770 = 76.88%**（7/7 可测）。
- 合并 25 样本（旧 18 + 新 7）：**11,620,527 / 15,313,023 = 75.89%**（21 可测 + 4 不可测）。
- 中型带 `scope=sampled`（cc1 + lto1 + gdb，10–50MB 的 3 个真实样本）：**9,502,392 / 11,703,021 = 81.20%**，样本名单随报告落盘（`evidence_m9_coverage_summary.json` 的 `aggregates.medium_band_sampled`）。

## 3. 收敛线 B：伪 VEX/EVEX 弃权逐条归因

### 3.1 方法

`vexaudit.py` 逐字节扫描节内每一个 C4 / C5 / 62 引导字节，对每个位置独立试解一次，再用外部 objdump 在同一地址的结论做裁决，分成四类：

| 分类 | 判据 |
| --- | --- |
| `decoder_defect` | objdump 在**同址**解出 `v*` 指令，我方却弃权 → 我方缺陷 |
| `illegal_encoding` | objdump 在同址给出 `(bad)` → 编码确实非法 |
| `data_not_instruction` | 该地址不是 objdump 的任何指令起点 → 是数据/错位字节，本就不该当指令 |
| `objdump_nonvex_at_addr` | objdump 在同址解出**非** VEX 指令 → 前缀字节属于上一条指令的立即数/位移 |

账目必须对平：`lead_bytes = abstain_sites + other_abstains + decoded + len_diff`。

### 3.2 分类计数

旧 4 样本（M8 已测过的 VEX 场景）：

| 样本 | C4/C5/62 引导字节 | 弃权点 | decoder_defect | illegal_encoding | data_not_instruction |
| --- | ---: | ---: | ---: | ---: | ---: |
| cli-64.exe | 39 | 38 | 0 | 0 | 38 |
| bin_ls.elf | 509 | 313 | 0 | 0 | 313 |
| dyn_static | 6,911 | 1,199 | 0 | 0 | 1,199 |
| avx_dense.exe | 25 | 0 | 0 | 0 | 0 |

新 7 样本：

| 样本 | 引导字节 | 弃权点 | decoder_defect | illegal_encoding | data_not_instruction |
| --- | ---: | ---: | ---: | ---: | ---: |
| cc1 | 123,963 | 68,395 | 0 | 0 | 68,395 |
| lto1 | 118,071 | 65,914 | 0 | 0 | 65,914 |
| python3.10 | 17,949 | 10,166 | 0 | 0 | 10,166 |
| liblua5.4.so | 853 | 613 | 0 | 0 | 613 |
| gdb.exe | 38,324 | 27,392 | 0 | 0 | 27,392 |
| synth Go ELF | 20,459 | 16,332 | 0 | 0 | 16,332 |
| synth Go PE | 20,299 | 16,179 | 0 | 0 | 16,179 |

**11 个样本、合计 206,541 个弃权点：`decoder_defect=0`、`illegal_encoding=0`、`data_not_instruction=206,541`。**
也就是说：这批样本上**不存在被解码器误拒的真实 VEX/EVEX**；所有被笼统记作「abstain」的 C4/C5/62 字节，逐条查证后全是「不在指令起点上的数据」。这个结论只覆盖被审计的 11 个样本，不外推为「解码器对所有 VEX 都正确」。

账目对平：`lead_bytes = decoded + decoded_len_differs + other_abstains + abstain_sites` 在 11 个样本上全部成立。新 7 样本的 `decoded` 数：cc1 55,568 / lto1 52,157 / python 7,783 / liblua 240 / gdb 10,932 / synth ELF 4,126 / synth PE 4,119；`other_abstains` 全为 0。

一处待解释但已分类：两个合成 Go 样本各出现 **1 个 `decoded_len_differs`**（若把该字节当成指令起点，我方解出的长度与 objdump 不同）。它们不在 recdesc 的指令流里（两样本 `len_conflict=0`），已登记为个别现象，不影响分子分母。

## 4. 收敛线 A：跳转表候选升格（外部 objdump 独立校验边界）

判据与实现：

- 边界 = **外部 objdump 的指令起点集合**（`objdump -d -M intel --insn-width=16`，脚本自己解析文本），`recdesc` 自身的解码结果**不参与**升格判断。
- 升格需同时满足 5 项：`guard_proven`（表长来自 cmp+ja/jae 守卫）、`table_complete`（无拒绝表项、未截断）、`min_targets >= 4`、`function_domain`（全部目标落在本函数区间内）、`external_boundary`（全部目标都是外部 objdump 的指令起点）。
- 升格后仍**不进确定边**（R45 不变），只单列在 `rep["promoted"]`，`res` 不改写。

对账结果：

| 样本 | 候选数 | 应升格（脚本独立算） | 实升格 | 不一致 | 空边界升格 | res 不变 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| liblua5.4.so | 30 | 21 | 21 | 0 | 0 | 是 |
| python3.10 | 104 | 57 | 57 | 0 | 0 | 是 |
| synth Go ELF | 0 | 0 | 0 | 0 | 0 | 是 |
| synth Go PE | 0 | 0 | 0 | 0 | 0 | 是 |

- 空边界负控：`{"starts": set()}` 时**一个都不许升格**——四个样本实测 0 升格。
- 旧三 fixture（cli-64.exe / bin_ls.elf / dyn_static）由 [verify_switchcand.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/2026-11-15/m3-task-card/work/tests/verify_switchcand.py) 的 E 段逐候选对账，`promotion.evidence` 落盘，PASS。
- python3.10 的 104 个候选里 47 个阻断：原因是 dtype/表长不可证、目标越函数域、或目标不是 objdump 指令起点（典型是落在数据/对齐填充上）。**阻断理由逐条可见，不是静默丢弃。**
- 合成 Go 样本 0 候选：Go 的类型 switch/接口分发不走 `cmp+ja` 表，属语言实现差异，**只适用于 Go 样本，不外推**。

## 5. 样本线：登记、选样标准、合成/真实分栏

登记表：[m9_sample_manifest.json](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/2026-11-15/m3-task-card/work/m9_sample_manifest.json)（M2 的 `sample_manifest.json` 与其 `e9_ground_truth` 冻结段未改动）。

### 5.1 选样标准（测量前声明，不看覆盖率）

- **R1 尺寸带**：中型 = 文件大小落在 `[10MB, 50MB]`。
- **R2 stripped**：ELF 需同时无 `.symtab` 且无 `.debug_info`；PE 记 COFF 符号数，`nsym=0` 才算完全 stripped，`nsym>0` 必须如实标注。
- **R3 跳转表密集**：按程序性质先验选取（解释器主循环 / 字节码分发器），**禁止**按「我方识别出多少候选」挑样本；候选计数只作结果记录。
- **R4 插件式无符号**：ELF `ET_DYN` 共享对象、无 `.symtab`、导出只看 `.dynsym`。
- **R5 来源**：优先真实发行版二进制（版本与许可可复核）；本地构造的标 `synthetic`。
- **R6 禁止项**：任何样本因覆盖率好看被选入/剔除即为违规，须在登记表记违规（本轮 `violations: []`）。

### 5.2 登记摘要

| ID | 文件 | 大小 | 类别 | 角色 | sha256 前 12 | 许可 | 可再分发 |
| --- | --- | ---: | --- | --- | --- | --- | --- |
| M9-S1 | elf_medium_cc1_stripped | 33.96MB | real | 中型 stripped ELF #1 | `873d5b58ae15` | GPL-3.0-or-later | 是（保留许可 + 源码获取方式） |
| M9-S2 | elf_medium_lto1_stripped | 32.56MB | real | 中型 stripped ELF #2 | `58ceb45aa02a` | GPL-3.0-or-later | 是（同上） |
| M9-S3 | elf_jumpdense_python310_stripped | 5.94MB | real | 跳转表密集 | `a2f33a6e0069` | PSF-2.0 | 是 |
| M9-S4 | elf_plugin_liblua54_stripped.so | 265KB | real | 插件式无符号 | `4b7546b6feae` | MIT | 是 |
| M9-S5 | pe_medium_gdb181.exe | 10.76MB | real | 中型 PE | `64dd0adf8749` | GPL-3.0-or-later | 是（同上） |
| M9-S6 | elf_medium_synth_go_stripped | 7.73MB | **synthetic** | 合成对照（ELF） | `5521c245c7e0` | 自有（Go 工具链 BSD-3） | 是 |
| M9-S7 | pe_medium_synth_go_stripped.exe | 7.93MB | **synthetic** | 合成对照（PE） | `1267a1ab1f65` | 自有 | 是 |

- 完整 sha256、来源包身份（deb control / `.PKGINFO` 的 Package-Version-Architecture）、构建命令、结构事实（节表、符号数、`.text` 范围）见登记表。
- **可再分发 / 仅本地回归**：M9 新增 7 个全部可再分发；`local_only: []`。M2 表中的 `cli-64.exe` 仍为仅本地回归，不因 M9 改变。
- **未达标项（如实记录）**：两个合成 Go 样本 7.73MB / 7.93MB，**未落入 10–50MB 带**。中型带由真实样本 cc1 / lto1 / gdb 满足，合成样本只承担 real/synthetic 对照，不计入中型带达标。
- **M9-S5 不是完全 stripped**：gdb.exe 仍有 1,019 个 COFF 符号，只满足「中型 PE」角色。

### 5.3 槽位达标

| 槽位 | 要求 | 满足 | real | synthetic |
| --- | --- | --- | ---: | ---: |
| 中型 stripped ELF | 2–3 | cc1, lto1 | 2 | 0 |
| 中型 PE | 1–2 | gdb.exe | 1 | 0 |
| 跳转表密集 | 1 | python3.10 | 1 | 0 |
| 插件式无符号 | 1 | liblua5.4.so | 1 | 0 |
| 合成对照 | 附加 | Go ELF / Go PE | — | 2（不在尺寸带） |

### 5.4 合成样本的适用边界（必须随结论带走的限制）

- 合成 Go 样本的结论**只适用于合成 Go 样本**，不得表述为真实二进制的普遍规律。
- 同一份 Go 源码，ELF 版覆盖率 **8.24%**、PE 版 **79.81%**，相差近 10 倍。本轮**不做解释性归因**（可能涉及 Go 运行时在两种链接方式下的间接跳转/代码布局差异），只登记为观察事实；正因为这个不对称，才更不能拿合成样本去代表真实二进制。
- 真实样本里同样存在反常值：busybox 0.12%（入口可达集极小），说明「低覆盖率」首先是**可达性问题**，不是解码能力问题；这两个数字放在一起看才能避免误读。

## 6. 覆盖率变化分解：解码改进 vs 样本更换

### 6.1 解码不变性证据（决定「解码改进 = 0」）

对 M8 冻结清单的 18 个样本重跑 recdesc，逐样本对比 M8 收口快照 `evidence_m8close_snapshot.json` 里 `strxref.coverage` 记录的 `decoded_instructions` 与 `decoded_bytes`：

- 结果：**18/18 全部相等，0 处不一致**，合计 638,926 条指令、2,574,299 字节逐样本相等（`evidence_m9_invariance.json`）。
- 交叉对账：旧 18 样本覆盖率分子合计 638,883，与解码总数 638,926 恰好相差 43 = `ours_only`（putty 31 + dyn_static 8 + minidll 4）。两个独立算出的数能对上，说明「分子定义」与「解码输出」没有暗账。
- 另有 3 个 fixture（cli-64.exe / bin_ls.elf / dyn_static）的 recdesc stats + 伪 C 文本 sha256 仍在 `tests/baselines/definite_baseline.json` 冻结值上逐项相等（pytest 断言）。
- M9 对 `disasm.py` / `recdesc.py` 的改动只新增了失败归因字段（`Unsupported.category`、`_Decoder.last_category`、abstain 记录的 `category`），**不改变任何解码判定**。sha256 变化只反映这些字段，不反映解码逻辑变化。

### 6.2 分解表

| 口径 / 样本集 | 分子 | 分母 | ratio | 说明 |
| --- | ---: | ---: | ---: | --- |
| 旧 18（M8 清单，full） | 638,883 | 1,028,253 | **62.13%** | 14 可测 + 4 无 `.text` |
| 新 7（M9 清单，full） | 10,981,644 | 14,284,770 | **76.88%** | 7/7 可测 |
| 合并 25（full） | 11,620,527 | 15,313,023 | **75.89%** | 21 可测 + 4 不可测 |
| 中型带 3 个真实样本（sampled，名单随报告） | 9,502,392 | 11,703,021 | **81.20%** | cc1 / lto1 / gdb |

结论：

1. **解码改进 = 0**：同一批旧样本上，我方解出的指令数与字节数与 M8 完全一致，没有任何一条「新增解出」。
2. **旧 → 新 的 62.13% → 76.88% 全部来自样本更换**：旧集里 busybox（305/245,678）与 minidll（1/9）这类极端低覆盖样本把加权比例压得很低；新集里中型 GCC 前端与 gdb 都在 80%–87%，python 到 91.67%。这是**样本构成**的效果，不是解码能力的变化。
3. **分母口径变化本身也是一次「账面变化」**：M8 没有指令级分母口径（只有 strxref 的字节口径），M9 是首次建立该口径。因此严格说，M8 与 M9 之间**不存在同口径的覆盖率提升可比较**；能比较的只有「同一口径下不同样本集」，以及「同一批样本的解码输出是否变化」。
4. **抽样与全样本的区别**：`full` 指清单内全部样本都跑（含不可测样本占用名额但不进分母）；`sampled` 是分层子集，必须附名单。中型带 81.20% 是 `sampled`，**不能**拿去和 `full` 的 76.88% 直接说「提升」，两者样本构成不同。

## 7. 未完成与限制（自证失败 / 规模墙）

1. **跳转表层在大型样本上未跑完**：`switchcand.analyze_binary` 在 cc1（4.05M 指令）、lto1（3.91M）、gdb（1.54M）上超出时间预算——gdb 实测累计 **709 CPU 秒仍未完成被中止**；cc1 在更早一次尝试中 **>30 分钟未完成被中止**。处理方式：
   - cc1 / lto1 / gdb 的候选层**记 `switchcand_skipped`**，不写 0、不伪造数字；
   - 升格验证改在有候选的样本上做（liblua 30、python 104），并由 verify 脚本逐候选对账；
   - 规模问题登记为待办（R96 候选），本轮不改实现。
2. **Go ELF 8.24% vs Go PE 79.81% 未归因**：只登记事实与「仅适用合成样本」的声明。
3. **合成样本未落尺寸带**：7.73MB / 7.93MB，已如实标注。
4. **putty 的 31 条 `ours_only` 与 3,109 条 objdump `(bad)`** 未逐条追到底：已分类单列，不影响分子分母定义。
5. **`ours_only_unlisted` 的 8 条（dyn_static）与 4 条（minidll）**：我方解出但 objdump 未在该地址列出的字节，单列未计分子；未逐条解释。

## 8. 回归

- pytest：**444 passed**（M8 基线 426 + M9 新增 18），日志 `work/evidence_m9_pytest.log`。
- verify 脚本：19 条命令（原 17 条 + `verify_coverage.py` + `verify_vexaudit.py`）**全部 exit=0**，日志 `work/evidence_m9_scripts.log`。
- 证据文件：`evidence_m9_invariance.json`（解码不变性）、`evidence_m9_coverage_oldsamples.json`（旧 18 逐样本）、`evidence_m9_coverage_summary.json`（聚合 + 代码 sha256）、`evidence_m9_promotion.json`（新样本升格对账）、`evidence_m9_vexaudit_old4.json`（旧 4 样本 VEX 分类）。

## 9. 规则回写

R91–R96 见 CHARTER「M9」行与 CHANGELOG R91 起的条目。
