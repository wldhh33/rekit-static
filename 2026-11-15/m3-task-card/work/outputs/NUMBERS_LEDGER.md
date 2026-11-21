# 数字总账（M13-patch → M20）

> 生成：2026-11-17 ｜ 覆盖：M13-patch 下界重算 → M20 .NET 类型布局与字段 RVA
> 本文件是**人读镜像**；机器快照 `work/evidence_numbers_ledger.json` 是**唯一权威数字源**（生效范围 M13–M20）。

## 0. 以哪一份为准

- **唯一权威**：`work/evidence_numbers_ledger.json`。它逐小节登记本文件的数字（`sections`）、
  逐证据登记 sha256（`sources`）与新鲜度规则，生效范围 **M13–M20**（含 M13-patch、M14–M20）。
- **漂移检查（硬失败）**：`python "pack\tools\ledger_check.py" --check`。以下任一情况 **exit 1**，不是提示：
  ① 本文件 §0 声明的权威路径与 JSON 不一致；② M14–M20 任一小节缺失；③ 任一登记数字在小节正文里找不到；
  ④ 任一证据文件 sha256 变化（权威落后于证据）。
  新鲜度**以字节为准**：证据被原样重写（sha256 相同、仅 mtime 变新）**不算**落后，只打印 note——时钟不作判据。
  重登记用 `--write`，重登记后必须复核数字。
- **历史权威快照**：`work/evidence_m13_ledger.json`。25 个样本逐行实测、4 个 Go 样本开关 A/B、逐函数分层、
  PE 缝隙量化、M13 的 6 条下界判定、5 条判据问题、代码 sha256 **仍然有效**，但**不再单独作为总账权威**；
  它与新权威的关系由 `evidence_numbers_ledger.json` 的 `sources` 条目（sha256）固定。
- **未受保护数字（显式清单，不是隐性漏洞）**：`python "pack\tools\ledger_check.py" --audit --audit-json "2026-11-15\m3-task-card\work\evidence_ledger_unprotected.json"`。
  审计只对小节正文（排除标题行）取数，逐节列出「已公布但未进 `numbers` 登记」的数值。当前 10 个小节、已登记 103 个、去重后未登记 141 个；
  不登记的原因分五类：①**区间/分布描述**（如 `1–3: 609`，登记的是区间端点与总数）②**派生百分比**（分子分母已登记，
  如 `0.0496%`、`76.40%`）③**旧值/对照值**（R102 禁止入账，只作 `match_old` 证据）④**地址与样例字节**
  ⑤**逐样本细分格**（登记表已保头部数字，细分格由证据 JSON 承担）。凡「可被单独改动且会改变结论」的数字必须登记。
- **人读镜像**：本文件。与 JSON 冲突时**以 JSON 为准**，并回头修正本文件。
- **M12 快照**：`work/evidence_m12_ledger.json` 的覆盖率 / A/B / 逐函数 / 缝隙数字**仍然有效**（M13 回归逐条复核）；
  只有它的 `still_lower_bounds` 列表被 §6 取代。
- **作废**：M11 收口文档 §8 里的「合并 25 样本 80.3734%」是**推算值**，现已被实测替换（见 §2，差值为 0）；
  M9/M10 文档中因种子缺失标为下界的 Go 数字，以 §3/§4 的实测值为准。
- **M13 更正**：`switchcand skipped（cc1/lto1/gdb）` 这条已失效（cc1/gdb 早已全量跑完，skipped_budget=0；lto1 是 `no_run`，不是 skipped）；
  VEX「全是数据」的措辞已更正为「非指令边界字节」。详见 `outputs/TASK_m13_lowerbounds.md` §2/§4。
- **M13-patch（C1–C5）**：5 条判据问题已全部落到代码/字段/校验，不再只是文档承诺：
  `strxref` 标为补集度量（不是下界）、VEX 分类名改 `not_objdump_insn_start` 并同报域内比例、
  Go 域内未达指令声明“含对齐”（实测 nop 族 1,067/1,066）、`switchcand` 拆出 `run_status`/`functions_skipped_budget`/`functions_no_run`、
  分析覆盖率移出下界表。机器校验：`tests/test_ledger_criteria.py`；规则 R107。
- 分母口径未变（R91）：GNU objdump 2.47 在同一节 `[VA, VA+size)` 列出的指令条数；分子 = 同址同长。

## 1. 25 个样本：旧值（推算前的 M9/M10）→ M12 实测

| 样本 | 旧值 | M12 实测 | 变化 | 原因 |
|---|---|---|---|---|
| dyn_pie | 87.5000%（56/64） | **87.5000%**（56/64） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| dyn_nopie | 81.5385%（53/65） | **81.5385%**（53/65） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| dyn_static | 83.1826%（94765/113924） | **83.1826%**（94765/113924） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| dyn_execstack | 88.0597%（59/67） | **88.0597%**（59/67） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| dyn_norelro | 82.3529%（56/68） | **82.3529%**（56/68） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| bin_ls.elf | 77.5874%（17475/22523） | **77.5874%**（17475/22523） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| hello_go_linux | 80.4414%（138224/171832） | **80.4809%**（138292/171832） | +68 条 / +0.0396pp | 已有 `.symtab` 1,797 个 STT_FUNC，仅补 68 条 |
| busybox-1.35.0-musl-x86_64 | 0.1241%（305/245678） | **0.1241%**（305/245678） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| upx_dyn_pie | 无 `.text` | 无 `.text` | — | 结构性，不进分母 |
| upx_cli-64.exe | 无 `.text` | 无 `.text` | — | 结构性，不进分母 |
| upx_putty-64bit.exe | 无 `.text` | 无 `.text` | — | 结构性，不进分母 |
| cli-64.exe | 90.0236%（1525/1694） | **90.0236%**（1525/1694） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| minipe.exe | 100.0000%（1/1） | **100.0000%**（1/1） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| minidll.dll | 11.1111%（1/9） | **11.1111%**（1/9） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| minipe_fakerich.exe | 无 `.text` | 无 `.text` | — | 结构性，不进分母 |
| hello_go.exe | 78.4916%（143525/182854） | **80.5840%**（147351/182854） | +3826 条 / +2.0924pp | `.pdata` 之外补 3,826 条 |
| hello_rust.exe | 85.6904%（22582/26353） | **85.6904%**（22582/26353） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| putty-64bit.exe | 83.7090%（220256/263121） | **83.7090%**（220256/263121） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| elf_plugin_liblua54_stripped.so | 77.2598%（36574/47339） | **77.2598%**（36574/47339） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| elf_jumpdense_python310_stripped | 91.6653%（627658/684728） | **91.6653%**（627658/684728） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| elf_medium_cc1_stripped | 79.9820%（4049517/5063038） | **79.9820%**（4049517/5063038） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| elf_medium_lto1_stripped | 80.3962%（3910063/4863491） | **80.3962%**（3910063/4863491） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |
| elf_medium_synth_go_stripped | 8.2436%（76168/923970） | **80.9651%**（748093/923970） | +671925 条 / +72.7215pp | gopclntab 补 8,906 个 Go 函数种子（可达域扩大） |
| pe_medium_synth_go_stripped.exe | 79.8145%（738852/925712） | **81.0305%**（750109/925712） | +11257 条 / +1.2160pp | gopclntab 补 1,739 个 `.pdata` 之外的函数 |
| pe_medium_gdb181.exe | 86.8460%（1542812/1776492） | **86.8460%**（1542812/1776492） | 0（逐条不变） | 无 pclntab（parse=missing），种子集不变 |

> 4 个无 `.text` 样本（UPX×3、`minipe_fakerich.exe`）结构性不适用，`status=no_section`，不进任何分母。
> 本轮 **25/25 全部重跑，无跳过**；总耗时 353.5s，其中最贵的 3 个：cc1 145.48s（权重 26.45%）、
> lto1 132.69s（25.54%）、gdb 30.32s（10.08%）——未跳过，故不存在「用权重估算替代实测」的情况。

## 2. 合并汇总（实测，替换 M11 推算）

| 口径 | 旧值 | M12 实测 | 差值 |
|---|---|---|---|
| 合并 25 样本（21 可测） | 75.8866%（11620527/15313023） | **80.3734%**（12307603/15313023） | +687076 条 / +4.4869pp |
| 旧 18 样本（14 可测） | 62.1329%（638883/1028253） | **62.5116%**（642777/1028253） | +3894 条 / +0.3787pp |
| 新 7 样本（7 可测） | 76.8766%（10981644/14284770） | **81.6592%**（11664826/14284770） | +683182 条 / +4.7826pp |

- 分母三组完全相同（同一个 objdump 计数结果），变化全部在分子，且只来自 4 个 Go 样本的种子新增。
- 与 M11 的推算值比对：M11 推算分子 12,307,603、比率 80.3734% → 实测 12,307,603 / 80.3734%，**差 0**。
  推算成立的前提（其余 21 个可测样本逐条不变）被实测证实：非 Go 样本本轮 delta 全为 0。
- 方向与原因：整体 +4.4869pp，**全部来自 Go 函数可达域扩大**（见 §3），不是解码规则变化
  （`matched_lost=0`、`same_addr_len_changed=0`、关闭开关时旧值逐条复现）。

## 3. Go 样本 A/B：种子新增 vs 解码本身（实测）

| 样本 | 关闭 gopclntab | 开启（M12） | 变化 | 归因 |
|---|---|---|---|---|
| Go ELF 合成（stripped） | 8.2436%（76168/923970） | **80.9651%**（748093/923970） | +671925 条 / +72.7215pp | 8,906 个函数入口（标记 2 已排除） |
| Go PE 合成（stripped） | 79.8145%（738852/925712） | **81.0305%**（750109/925712） | +11257 条 / +1.2160pp | `.pdata` 之外 1,739 个函数 |
| `hello_go_linux`（ELF 未 strip） | 80.4414%（138224/171832） | **80.4809%**（138292/171832） | +68 条 / +0.0396pp | `.symtab` 已覆盖，补 68 条 |
| `hello_go.exe`（PE 未 strip） | 78.4916%（143525/182854） | **80.5840%**（147351/182854） | +3826 条 / +2.0924pp | `.pdata` 之外补 3,826 条 |

- 解码贡献 **0**：四个样本 `matched_lost=0`、`same_addr_len_changed=0`，且关闭开关时数值与 M9/M10 逐条相等。
- 增量性质：**可达域扩大**。ELF 从 1 个入口扩到 8,906 个 Go 函数；PE 在 `.pdata` 7,152 个之外补 1,739 个；
  `hello_go_linux` 已有 `.symtab`，只多 68 条，说明增量大小取决于已有声明来源，不能跨样本套用。

## 4. 逐函数分层：M9/M10 的下界 → 实测

| 样本 / 范围口径 | M10 分类（下界） | M12 实测 | 匹配指令数 |
|---|---|---|---|
| ELF，gopclntab `[entry, next_entry)`（与 M10 的 gosym 范围同口径） | 全覆盖 3 / 部分 846 / **零种子 8,059** | **全覆盖 35 / 部分 8,871 / 零 0** | 748,093（= 总分子） |
| PE，`.pdata [begin,end)`（与 M10 的 7,152 行同口径） | 全覆盖 6,388 / 部分 764 / 零 0 | **全覆盖 6,388 / 部分 764 / 零 0（完全不变）** | 726,289（M10: 550,443+175,846） |
| PE，gopclntab 范围（当前实现的范围口径） | — | 全覆盖 32 / 部分 8,860 / 零 0 | 750,109（= 总分子） |

- **ELF 的 `seed_missing 8,059` 已归零**：每个 Go 函数都有声明入口；「全覆盖 3→35、部分 846→8,871」是
  **可达域扩大后重新分层**，不是同样的函数解码变强（解码贡献见 §3 为 0）。
- **PE 的 `.pdata` 口径逐函数数字与 M10 完全一致**（6,388 / 764 / 0，指令数 726,289 也一致）——
  说明接入 gopclntab 没有改变 `.pdata` 已覆盖函数的任何结果；PE 的增量全部在 `.pdata` 之外的 1,739 个函数里。
- PE 用 gopclntab 范围时「全覆盖」只有 32，是因为范围包含函数尾部的 `cc` 对齐填充（objdump 也把它当指令）；
  这是**范围口径**差异，不是解码退化，见 §5。

## 5. PE：`.pdata` end 与 gopclntab 下一入口之间 1–31 字节缝隙的量化

| 项 | 实测 |
|---|---|
| 有双源的函数 | 7,139 / 7,152（13 个 end 相同；**0 个** gopclntab end ≤ pdata end） |
| 缝隙总字节 | 113,731 B = `.text` 的 **3.2262%**（min 1 / max 31 / 均值 15.93） |
| 缝隙长度分布 | 1–3: 609 ｜ 4–7: 955 ｜ 8–15: 1,871 ｜ 16–31: **3,704** |
| 缝隙内 objdump 指令 | 113,731 条（= 每字节 1 条），**全部**是 `cc`/`90` 填充；占 M11 填充桶（148,861）的 **76.40%** |
| 缝隙内**被我方解出**的指令 | **372 条**，全部是 `int3`（`cc`），全部位于缝隙首字节（= pdata end） |
| 跨过 pdata end 的我方指令 | **0**（没有真实指令被 pdata end 截断） |
| 跨过 pdata end 的基本块 | **372**（即上面 372 条单指令块） |
| 目标落在缝隙内的 CFG 边 | **0**（definite/speculative/cross/undecoded 全 0） |
| 当前归属 | 372 条经 gopclntab end 归到**前一个函数**（例：`internal/abi.(*IntArgRegBitmap).Set` 0x13a0 → 缝隙 0x13e6；`runtime.mcall` 0x8b1e0；`runtime.badmorestackg0` 0x52b00） |
| 若改用 `.pdata` end 口径 | 这 372 条不再属于任何函数（丢出函数域）；分子 750,109 → **749,737**，比率 81.0305% → **80.9903%（-0.0402pp）**；基本块 -372；CFG 边 **0** 变化 |
| 实质结论 | **不改变**。缝隙内没有真实代码（100% `cc/90`），没有指令被截断，没有边指向缝隙；影响只是 372 条填充字节（分子的 0.0496%）在两种口径下归属不同。当前实现取两者较大 end，宁可多算填充也不截断代码；这 372 条是「与 objdump 在填充上的一致」，不是真实代码解码证据。 |

## 6. 下界结论：M13 重算后的状态

> 种子扩大（gopclntab）只改变 Go 的函数域；只有“以函数域为分母”的条目需要复算。
> 复算一律用原判据，且必须逐项复现旧值（`match_old=true`）才算判据未变。

| 结论 | 类别 | 旧值 | M13 复算 | 判定 | 说明 |
|---|---|---|---|---|---|
| `strxref` 未解码代码里可外部证实的引用点 / 涉及字符串 | `complement_measure`（**不是下界**） | 5,039 / 276 | **5,039 / 276** | 作为补集度量仍成立 | 18 样本中 2 个 Go 的贡献为 0→0；5,039 全部来自 16 个非 Go 样本；对 Go 近乎盲 |
| VEX/EVEX 弃权点（11 样本，**非指令边界**） | `seed_invariant_count` | 206,541（`decoder_defect=0`） | **206,541** | 仍成立 | 分类器不读取子；Go 两样本 16,332 / 16,179 逐项相等，成为新可达域指令起点的数量 = 0；域内占比 16,332/16,332、16,177/16,179 |
| Go 函数域内未达的 objdump 指令（含对齐） | `count_with_alignment` | ELF 26,652 / PE 26,702（2.88%） | **26,652 / 26,702** | 仍成立 | 三分法逐项复现；其中 nop 族 1,067（4.0034%）/ 1,066（3.9922%）；不是漏解指令数 |
| 非 Go 样本可达域（种子稳定性） | `stability_check` | 旧 18 / 新 7 其余样本 | **17 个可测样本 delta=0** | 仍成立 | 17 个样本 `gopclntab=missing`，种子逐条不变 |
| M8 `paramdecl` | `count` | 12,272 / 3,530 / 37,891 | 未重算 | 仍成立 | 形参来自 DWARF，不在 pclntab |

**分析覆盖率（不属于下界，单独列）**

| 条目 | 状态 | cc1 | lto1 | gdb | 说明 |
|---|---|---|---|---|---|
| `switchcand` 分析覆盖率 | `run_status` | analyzed 1,974 / skipped_budget 0 / candidates 64 | **`no_run`**（未运行，无统计量） | analyzed 2,081 / skipped_budget 0 / candidates 317 | 覆盖率不是候选数下界：`step_budget=0` 时候选=0、skipped_budget=417；不进下界表 |

- 判据问题的修复位置（不并入上表数字）：C1 `rekit/vexaudit.py`（`CAT_NOT_START` + `domain`）、
  C2 `rekit/switchcand.py` + `rekit/sitejoin.py`、C3 `rekit/strxref.py` 头注 + `verify_strxref` 口径行、
  C4 `tests/verify_c4_alignment.py` + `evidence_m14_c4_alignment.json`、C5 `lower_bounds`/`analysis_coverage` 分表。
  详见 `outputs/TASK_m13_lowerbounds.md` §4 与 `evidence_m13_ledger.json` 的 `status_field_inventory`。
- **读者指引**：旧文档中**没有数字**因种子扩大而过期；过期的是三处说法——`TASK_m10_closeout.md` 的 skipped 条目、
  `TASK_m9_closeout.md` §3.2 的“全是数据”、本总账旧版“strxref 本轮未重跑”。
  对照表见 `outputs/TASK_m13_lowerbounds.md` §5。

## 7. 复现与证据

```
cd 2026-11-15/m3-task-card/work
python -m pytest tests -q          # 全量回归
python tests/verify_*.py           # verify（含新增 verify_c4_alignment.py；verify_fingerprint.py 需 --all --matrix）
python %TEMP%/m13_recompute.py all # M13 下界重算，生成 evidence_m13_recompute.json
python %TEMP%/m14_c4_measure.py    # C4 对齐实测，生成 evidence_m14_c4_alignment.json
python %TEMP%/m13_ledger.py        # 汇总为 evidence_m13_ledger.json（M13 历史源，不再单独作权威）
python "pack\tools\ledger_check.py" --write  # 重生成 evidence_numbers_ledger.json（当前唯一权威）
python "pack\tools\ledger_check.py" --check  # 漂移检查，FAIL 即 exit 1
python %TEMP%/m12_union25.py     # 25 样本实测，生成 evidence_m12_union25.json
python %TEMP%/m12_gap.py         # PE 缝隙 + 逐函数分层，生成 evidence_m12_gap_and_funcclasses.json
python %TEMP%/m12_ledger.py      # 汇总为 evidence_m12_ledger.json（M12 快照）
```
（`%TEMP%` 下的脚本为中间脚本，未入库；所需参数与样本路径见各自文件头部的 `OLD`/`PE`/`ELF` 常量。）

- `evidence_numbers_ledger.json`：**唯一权威**（M13–M18 小节/数字登记 + 8 个证据文件 sha256 + 新鲜度规则）
- `evidence_m13_ledger.json`：M13 历史权威快照（判定表、C1–C5 修复状态、`status_field_inventory`、`analysis_coverage`、代码 sha256）
- `evidence_m5_expr_residual.json`：M5 表达式层 oracle 残差逐地址（样本/函数/地址/条数/objdump 版本）
- `evidence_m13_recompute.json`：M13 四组测量（`match_old`、Go 弃权点与域内比例、strxref 关/开 A/B、switchcand）
- `evidence_m14_c4_alignment.json`：C4 对齐实测（nop 族 1,067/1,066、样例地址与字节）
- `evidence_m12_union25.json` / `.log`：25 样本逐行实测（含 sha256、耗时）
- `evidence_m12_gap_and_funcclasses.json`：缝隙 7,139 条明细、372 条逐条地址/字节/归属、逐函数分层
- `evidence_m11_coverage.json`、`evidence_m11_extra_go.json`：4 个 Go 样本 A/B 与 `matched_lost` 判据
- `evidence_m14_pytest.log` / `evidence_m14_verify.log`：M13-patch 回归
  （pytest **475 passed** 68.54s exit 0；verify **17/17** exit 0）；`evidence_m13_*` 为上一轮，仅作对照

## 8. 累计规则（本轮新增 R104–R107）

- **R102**：任何**推算值**不得进入总账；总账只收实测（可复现命令 + 机器快照 + 逐样本 sha256）。
  推算只能在过程文档里出现，并必须标注「推算」与前提，一旦实测出来立即替换。
- **R103**：多源 `end` 之间的缝隙必须量化到「字节数 / 指令数 / 归属 / 换口径后的分子与比率 / 边与块的影响」，
  不能只说「差 1–31 字节」；缝隙内容若全是填充，必须写明当前口径下有多少填充被计入分子。
- **R104**：下界/比例结论必须绑定**分母来源**。分母不受种子影响的，标 `seed_invariant` 并给结构证明（判据不读种子）；
  分母随种子变化的，必须用同一判据复算，且复算必须**逐项复现旧值**（`match_old=true`）才可用于替换。
- **R105**：分类名不得替代判据。`data_not_instruction` 只能写成“非 objdump 指令起点”，不得简写为“数据/不在代码里”；
  此类结论必须同时报“落在声明域内的比例”。
- **R106**：`skipped` 只用于分析覆盖率；整层未运行标 `no_run`，预算跳过标 `skipped_budget`，二者不得混用，且都不得进入下界表。
- **R107**：结论的措辞强度必须与证据强度匹配，不得用更强的说法替代：
  分类名不得暗示判据没证明的东西（`not_objdump_insn_start` ≠“数据”）；补集度量不得称“下界”；
  含对齐的桶不得称“漏解指令数”；分析覆盖率不得进下界表。
  每条此类结论必须绑定 `bound_type`/`criterion`/`denominator`/`evidence`，由 `tests/test_ledger_criteria.py` 机器校验；
  找不到可证伪测试的结论不得写入总账。

## 9. M14 对齐实测（C4）

> 只回答一个问题：Go 域内未达的 objdump 指令里，对齐填充占多少、长什么样。
> 判据与分母不变（R91：同节 `[VA, VA+size)` 内 objdump 列出的指令条数）。

| 项 | 实测（`evidence_m14_c4_alignment.json`） |
|---|---|
| 声明范围数（ELF Go 合成，stripped） | 8,906 个函数范围 |
| objdump 指令总数 | 923,970 |
| 分类 | `padding_all_cc90`=**149,225** ｜ `in_range_other`=**26,652** ｜ `outside_range`=0 |
| 其中 nop 族 | 1,067 条（占 `in_range_other` 的 4.0034%） |
| PE 对照样本 nop 族 | 1,066 条（3.9922%）——与 ELF 侧同口径、不同样本，不合并 |
| 多字节 nop 样例 | `0f1f4000`（4B）、`0f1f440000`（5B）、`660f1f840000000000`（9B），地址与字节逐条留档 |

- 结论口径（R107）：这是「含对齐的未达桶」，**不是漏解指令数**；`26,652 / 26,702` 进 §6 的 `count_with_alignment`，不并入任何指令级比率。

## 10. M15 报告层不产生新数字

- `rekit funcreport` 只做六层结果的**同址合并**：报告中的每个计数都带
  `source={layer,field,text}`，是既有层字段的直读，不重算、不新增分母。
- 不修改 R91 / R102–R107 的任何比率与分母口径；`strxref` 5,039/276、
  Go 域内 26,652/26,702、VEX 206,541 等数字在本层不被重新计算或改写。
- `coverage`（objdump）只在 `tests/verify_funcreport.py` 作为外部校验工具，
  不进报告、不被 `rekit.funcreport` import。
- 缺失分类固定为两栏：`absent_measured` = 确实没有（有测量范围）；
  `missing_source` / `missing_declaration` / `missing_decode` / `abstained` = 缺证据。
- 回归：pytest **485 passed** 73.58s；verify **18/18** exit 0
  （日志 `evidence_m15_pytest.log` / `evidence_m15_verify.log`）。

## 11. M16 数据引用层（新分母：声明对象）

> 本层引入新分母，与 M13/M15 的任何比率无关；不复算、不改写任何旧数字。
> 对象只认声明（ELF `STT_OBJECT.st_size` / DWARF 变量），不按字节猜。

### 11.1 `dyn_static`（ELF，有 `.symtab`）

| 项 | 实测 |
|---|---|
| 声明候选 / 接受 / 拒收 / 去重 | 539 / **483** / 41 / 15（539 = 483+41+15 ✓） |
| 拒收逐类 | `type_not_object=12, size_zero=7, too_small=15, misaligned_start=4, overlaps_object=3` |
| 格式层拒收（不进分母） | `coff_symbols=0, export_table=0` |
| 有代码引用 / 有指针槽 / 无引用 | 417 / 51 / 39（分母 483） |
| 对象有代码引用比例 | **86.3354%**（417/483） |
| 引用形态 | `rip_mem=1700, lea_rip=2155, abs_mem=3, abs_imm=16, seg_disp=853, base_disp=18519, base_index=2695`（合计 25,941） |
| 归因分档（不合并） | `object_start=1709, inside_object=669, after_object=259, data_unattributed=1001, not_data=236` |
| 指针槽 | 首地址命中 92；落在对象内部 30（单列） |
| 未解出操作数 / 不可静态确定 | 8,853 / 22,067 |

### 11.2 `datarefs_full.exe`（PE，DWARF）

> **2026-11-21 重生成**：样本改由固定构建目录（`%TEMP%\rekit_m16_build`）+
> `-fdebug-prefix-map=<构建目录>=.` + PE 时间戳归零生成，产物不再含本机用户名/随机临时目录，
> 连续两次生成逐字节相同（`tests/test_repro.py`）。旧样本由另一套 MinGW（winlibs，本机已无）
> 编译且带 CRT 调试信息，无法复现；重生成后编译器与调试信息范围都变了，下表数字随样本重算。
> 判据、拒收分类代码与 `MIN_SIZE` 均未改。

下表为现行值；旧值仅作溯源。

| 项 | 实测 |
|---|---|
| 声明候选 / 接受 / 拒收 / 去重 | 5 / **5** / 0 / 0（5 = 5+0+0 ✓） |
| 拒收逐类 | 无（单 CU、无 CRT 调试信息；分类判据由 `test_static_addr_classification` 直接覆盖） |
| 格式层拒收（不进分母） | `coff_symbols=592, export_table=0` |
| 有代码引用 / 有指针槽 / 无引用 | 5 / 1 / 0；比例 **100.0000%**（5/5） |
| 归因分档 | `object_start=3, inside_object=3, after_object=8, data_unattributed=91, not_data=6` |
| 指针槽 | `0x2020→0x2000`；内部值 `0x2028→0x6024`（`g_zero+4`，单列） |
| `.bss` | `g_zero` 无文件字节、仍被引用与归因（`file_backed=false`） |

**变更对照（旧值已作废，勿引用）**

- 声明候选 ~~9~~ → 5；接受 ~~7~~ → 5；拒收 ~~2~~ → 0（旧的两条 `location_not_static` 来自 CRT 调试信息，新样本无）
- COFF 格式层拒收 ~~720~~ → 592；有引用/无引用 ~~5 / 2~~ → 5 / 0；比例 ~~71.4286%~~ → 100.0000%
- `after_object` ~~6~~ → 8；`data_unattributed` ~~190~~ → 91
- 指针槽 ~~0x4030~~/~~0x4010~~ → `0x2020`/`0x2000`；内部值 ~~0x4038~~/~~0x9084~~ → `0x2028`/`0x6024`

### 11.3 外部重算与可失败自证（`tests/verify_datarefs.py`）

| 检查 | 结果 |
|---|---|
| `readelf -sW` 对象对账 | 501 条符号对象，无不一致；2 条落在更大对象内部 |
| `objdump --dwarf=info` 对象对账（含类型链） | 5 条，`g_table=16` / `g_msg=11` / `g_zero=32` 一致（旧样本 ~~7~~ 条，多出的 ~~2~~ 条是无名 CRT 变量） |
| `objdump -d` 引用点目标 | fix **111/111**、dyn **3854/3855** 一致（fix 旧值 ~~207/207~~，随样本重算） |
| `objdump -s` 指针槽 | 2/2 一致 |
| 可失败自证 | 目标 +4 → FAIL、删 `g_table` → FAIL（干净输入 PASS） |

### 11.4 funcreport 三类样本

| 样本 | `data_refs` 状态 |
|---|---|
| `funcreport_full`（PE，DWARF 可读、无全局） | `absent_measured`（确实没有可交叉对象） |
| Go `0x401320`（stripped） | `missing_source`（缺证据） |
| `minidll.dll` `0x1000` | `missing_source`（缺证据） |

- 回归：pytest **509 passed** 70.33s；verify **18/18** exit 0 + fingerprint E9 PASS；
  `verify_datarefs.py` 连续 12 次新鲜进程全 PASS（修复前的偶发失败见下条）；
  日志 `evidence_m16_pytest.log` / `evidence_m16_verify.log`。
- **R109**：判别式对象分母必须写成 `声明候选 = 接受 + 拒收 + 去重`；格式层
  （无尺寸字段的 COFF/导出表）不得混入，且必须在比例之前单独打印。
- **R110**：引用点归因三档（首地址/内部/之后窗口）不得合并计数；`inside_object`
  必须带 offset（可能是数组元素/结构体成员），`after_object` 必须带 delta 且
  只表示邻接、不表示属于该对象。
- **R111**：“声明来源没有”与“声明来源存在但不可解析”不得合并成同一状态；
  过程缓存不得以对象地址（`id()`）为键。
  - 触发：`verify_datarefs.py` 的 `full-e` 约 1/15 概率把 `funcreport_full`
    报成 `missing_source`。根因是 `paramdecl._abbrev_table` 的缓存键为
    `(id(data), offset, len(data))`；两个 DWARF 样本的 `.debug_abbrev` 切片
    被 PE 文件对齐补齐成同长度（均 512 B），`bytes` 在大批释放后 `id` 会复用
    （实测 400 个 512 B 对象释放后重建，238/400 地址重叠），于是 `full` 的
    abbrev 切片可能命中 `datarefs_full.exe` 已缓存的表 → 解析失败 → DWARF
    被判不可读 → `no_declaration_source`。改为按内容（`bytes` 可哈希）作键。
  - 同时把 `datarefs` 的 `no_declaration_source` 拆两种 reason：无 DWARF 节
    （结构性没有）vs DWARF 节存在但解析失败（缺证据，附 paramdecl 审计原因），
    避免“解析失败”被读成“没有声明来源”。
  - 机器校验：`tests/test_datarefs.py::test_abbrev_cache_not_keyed_by_object_id`、
    `::test_dwarf_present_but_unreadable_not_reported_as_no_source`。

## 12. M17 .NET 程序集结构层（新对象：CLI 程序集）

> 本层引入新分母（TypeDef/MethodDef/方法体/IL 指令），与 M13/M15/M16 的任何
> 比率无关；不复算、不改写旧数字。全部来自声明：CLI 头、元数据表、MethodDef.RVA。

### 12.1 受控样本 `RekitSample.dll`（csc 编译）

| 项 | 实测 |
|---|---|
| TypeDef / 命名 / 嵌套 | **6** / 5 / 0（`<Module>` 1） |
| MethodDef / 有 RVA / 无 RVA | **18** / 15 / 3（`abstract=2, pinvoke=1`） |
| 可定位 / 体成功 / 头非法 / 截断 | 15 / **15** / 0 / 0（tiny 12、fat 3） |
| EH / IL | 方法 1、子句 2；解出 **15**、不可解 0、指令 **119**、尾字节非 0 方法 0 |
| `#US` / 泛型 | 条目 10（空 1 + 非空 9）、`ldstr` 9；GenericParam 1、TypeSpec 2、MethodSpec 0 |

### 12.2 真实 `System.Console.dll`（CoreCLR 7.0.20）

| 项 | 实测 |
|---|---|
| TypeDef / 命名 / 嵌套 | **47** / 46 / 18 |
| MethodDef / 有 RVA / 无 RVA | **433** / 396 / 37（`pinvoke=33, runtime=4`） |
| 体成功 / tiny / fat / EH | **396** / 256 / 140 / 23 方法 23 子句 |
| IL 指令 / 尾字节非 0 方法 | **6,592** / 0 |
| `#US` / 泛型 | 条目 77（非空 75）、`ldstr` 76；MethodSpec 19、TypeSpec 9 |

### 12.3 真实 `mscorlib.dll`（Framework 4.0）

| 项 | 实测 |
|---|---|
| TypeDef / 命名 / 嵌套 / 带方法 | **3,356** / 3,355 / 660 / 2,623 |
| MethodDef / 有 RVA / 无 RVA | **29,257** / 25,315 / 3,942 |
| 无 RVA 逐类 | `abstract=2,222, pinvoke=563, runtime=301, unclassified=856` |
| 可定位 / 体成功 / 头非法 / 截断 | 25,315 / **25,315** / 0 / 0（tiny 16,029、fat 9,286） |
| EH / IL | 1,651 方法 / 2,164 子句；解出 **25,315**、指令 **592,206** |
| 尾字节非 0 方法 | **0**（IL 边界与 code_size 全部对齐） |
| `#US` / 泛型 | 条目 4,725（非空 4,723）、`ldstr` 4,724；GenericParam 1,783、MethodSpec 656、TypeSpec 1,261、约束 98 |

### 12.4 外部重算与可失败自证（`tests/verify_dotnet.py`，27/27 PASS）

| 检查 | 结果 |
|---|---|
| `dnfile` 表行数 | 20 / 26 / 31 张，全部一致（`FieldRVA/ENCLog/ENCMap` dnfile 不实现，无外部重算） |
| `dnfile` TypeDef 逐行 | 6 / 47 / 3,356 行一致 |
| `dnfile` MethodDef 逐行 | 18 / 433 / 29,257 行一致 |
| `dnfile` RVA→文件偏移 | 15 / 396 / 25,315 个一致 |
| `dncil` IL 逐条 | 受控 15 方法全量；真实样本**另跑全量**：396/396、25,315/25,315 全部一致 |
| `dnfile` `#US` | 10 / 77 / 4,725 条文本一致；`ldstr` 9 / 76 / 4,724 个 token 全部落在已知偏移 |
| CLR 反射 | 5 类型（排除 `<Module>`）、排除 4 个构造方法后方法名与 IL 长度一致 |
| 可失败自证 | IL 偏移+1 / 删一条 / 末字节 `0xFF` / RVA+1 / 表行数+1，5 项全部检出 |

- 回归：pytest **528 passed** 70.64s；verify **20/20** PASS；日志
  `evidence_m17_pytest.log` / `evidence_m17_verify_all.log` /
  `evidence_m17_dotnet.json` / `evidence_m17_il_full.log`。
- **R112**：.NET 方法体不是 x86 指令。既有 x86 各层（disasm/recdesc/expr/
  callgraph/callfacts/sitejoin/strxref/datarefs/coverage 等）对 IL 必须显式
  `not_applicable` 并写原因，不得返回空列表或 0 让读者误读成“没有”；`funcreport`
  入口直接返回 `not_applicable`，不跑六层。
- **R113**：.NET 分母必须逐级二分并保持恒等式：`MethodDef = 有 RVA + 无 RVA`，
  `有 RVA = 可定位 + 不可定位`，`可定位 = 体成功 + 头非法 + 代码截断`，
  `体成功 = IL 解出 + IL 不可解`。RVA=0 的原因逐类计数（abstract/pinvoke/
  runtime/native/unclassified），`unclassified` 如实单列，不猜。
- **R114**：IL 指令边界必须由**独立** opcode 表/解码器逐条证伪（本轮 `dncil`），
  且在真实样本上全量比对；边界正确性同时用 `code_size - (末条 offset+size)`
  的尾字节数对账（三样本 25,726 个方法体尾字节全为 0）。

## 13. M18 .NET IL 控制流层（新分母：方法体/IL 指令）

> 本层在 M17 已声明的 MethodDef / 方法体 / IL 指令边界之上，回答四件事：
> 调用 token 指向谁、分支目标是否落在真实指令边界、基本块与块间边、EH 子句如何影响控制流。
> 分母全部来自声明（CLI 头、元数据表、MethodDef.RVA、方法体头），不复算、不改写 §6–§12 的任何数字。
> 权威证据：`work/evidence_m18_ilflow.json`（41 项检查全 PASS）。

### 13.1 四个样本的控制流分母（逐级恒等式见 R113 的 IL 版）

| 样本 | 方法总数 / 有体 / 已分析 | 分支指令 / 目标 | call 指令 | EH 子句 | 基本块 | 块间边 | 不可达块 |
|---|---|---|---|---|---|---|---|
| `FlowSample`（受控） | 20 / 19 / 19 | 6 / 6 | 17 | 3 | 30 | 11 | 3 |
| `FilterSample`（受控） | 5 / 5 / 5 | 5 / 5 | 2 | 2 | 15 | 8 | 6 |
| `System.Console.dll` | 433 / 396 / 396 | 596 / 599 | 1,133 | 23 | **1,372** | **1,245** | 63 |
| `mscorlib.dll` | 29,257 / 25,315 / 25,315 | 51,063 / 52,837 | 93,194 | 2,164 | **108,267** | **107,765** | 5,058 |

- `分支` 与 `目标` 口径不同：`switch` 的 N 个条目逐个计目标，故目标数 ≥ 分支数；两者不得互相替代。
- `已分析 = 有体 - partial - empty`，本轮四样本 `methods_partial=0`、`methods_empty=0`（恒等式逐样本成立）。
- 不可达块单列，不并入块总数解释，也不从边数里先行扣除。

### 13.2 token 解析与未解析原因

| 项 | 实测 |
|---|---|
| 未解析原因分类 | `method_missing` / `row_out_of_range` / `bad_parent` / `unsupported_parent` / `token_kind_mismatch`，逐类计数不合并 |
| `mscorlib` 的 `bad_parent` | 20 条，全部是 `TypeSpec` 父为 `PTR/SZARRAY/VAR`（签名前缀 `0x0F/0x13/0x1D`），不是缺被引程序集 |
| `calli`（`StandAloneSig`） | 归 `unresolved / token_kind_mismatch`，不当方法解析 |

### 13.3 外部重算与可失败自证（`tests/verify_ilflow.py`，41/41 PASS）

| 检查 | 结果 |
|---|---|
| `dncil` 分支目标（偏移按方法体切片起点校正） | 四样本全量一致；空比对一律 FAIL |
| `dnfile` token 行 / 名称 | 与 `ilflow` 解析逐条一致；缺表（0 行）按“无该表”处理并留原因 |
| EH 子句结构 | 与 `dnfile` 逐条一致（数量与范围） |
| 可失败自证 | 5 项注入（分支目标 +1 / token 表篡改 / EH 范围偏移 / 块边删除 / 分母恒等式破坏）全部检出 |

- 回归：pytest **554 passed**（`evidence_m18_pytest_all.log`）；21 套 verify 全 exit 0
  （`evidence_m18_verify_all.log`）；`evidence_m18_verify_broken.log` 是重写前空比对产物，**不作证据**。
- **R115–R119**：IL 不是 x86（R112 的延伸）；token 解析必须落状态与原因；分支目标必须由独立解码器复算；
  块与边不得照搬 x86 规则；EH 建模必须显式声明“建模成边还是单列结构”及理由。

## 14. M5 表达式层验收补强（补记，跨里程碑）

> 本节回填 M5-U1 验收洞的处置，不产生新分母，也不修改 §6–§13 的任何数字。
> 权威证据：`work/evidence_m5_expr_residual.json`、`work/evidence_o2a_expr.log`。

### 14.1 判据（外部 oracle，不依赖 Ghidra）

- 对 57 个抽样函数（cli 18 / bin_ls 18 / dyn_static 21）逐个做 **objdump 整节线性反汇编对照**：
  我方每条指令/abstain 必须是 objdump 指令起点；`call/branch/jmp` 站点助记符与直接目标逐条相等；
  间接形式必须是非直接操作数；`stats.insns` 必须等于下层 origin 归属指令数。
- `--selftest` 两类注入（直接调用目标 +1、`lifted` 账目 +1）均可检出；干净输入 0 失败。
- Ghidra 仍只作弱参照，不参与判据。

### 14.2 已知残差（单列，不入任何已公布比率的分子分母）

- 口径：**objdump 整节线性扫描 vs expr/recdesc 的 CFG 可达子集**。域内 objdump 多解出的指令即残差，
  **未逐指令归因**，因此本层**不表述为零分歧**。

| 样本 | 抽样函数 | 残差条数 | 涉及函数 |
|---|---|---|---|
| `cli-64.exe` | 18 | 1 | 1/18 |
| `bin_ls.elf` | 18 | 403 | 7/18 |
| `dyn_static` | 21 | 390 | 13/21 |

- 残差逐地址（样本 / 函数 / 地址 / 条数 / objdump 版本 `GNU objdump (GNU Binutils) 2.47.20260726`）
  落盘于 `evidence_m5_expr_residual.json`，不只存在于 stdout。
- 早先探针按“每样本前 40 个声明函数”统计为 cli 3 / bin_ls 3 / dyn 1 个函数，与本节 57 抽样口径不同，
  两组数字不得混用。



## 15. M19 .NET 签名语义层（#Blob 签名解码）

- 调用点分母（四样本，恒等式全部成立）：方法签名解出 **32,518** 个；字段签名 **911** 个、局部变量签名 **3,974** 个按口径只做长度与边界、不计类型语义；三者相加 = **37,403** = 三张调用点表的全部可读 blob，解码率 **100.0000%**，undecoded 0、unknown 节点 0。Field(0x04) 表只做长度/边界，`non_field_signature=0`。
- 逐样本分母：mscorlib（v4.0.30319）MethodDef **29,257** / MemberRef **3,429** / StandAloneSig **3,908** / Field **14,718**，三张调用点表可读 blob 合计 **36,594**；System.Console.dll（7.0.20）四张表可读 blob 共 **1,020** 行（MethodDef 433、MemberRef 237、StandAloneSig 73、Field 277）；受控 RekitSample 36 行、FlowSample 35 行。
- 独立对拍（期望值不取被测实现）：dnfile 逐行重算 #Blob 索引/文件偏移/长度/字节，四表四样本共 **52,403** 行，0 不一致；微软 SRM `DecodeSignature` 经 pwsh 编译参考 provider，逐行整串比 canonical 共 **37,403** 行，0 不一致；与 M17 的 `signature_len`/签名 hex 前缀逐行相等共 **29,728** 行，0 不一致。
- 可失败自证（首版即带，工件=注入 ID + 基线 + 观察到的失败行）：blob 字节注入（`String`→`Int32`）→ `[FAIL] m19-drift token=0x06000003`；rekit 报告 blob 索引 +1 → `[FAIL] m19-bytes ... blob_index: dnfile=65 rekit=66`；长度前缀 +1 → `undecoded/trailing_bytes`；SRM 侧 canonical 改一字 → `[FAIL] m19-srm ... canonical 不一致`；空比对 → 拒绝 PASS。
- 对拍抓到并处理的口径差异 1 处：SRM 原生把修饰类型渲染为 `modreq(class [TR]X)T`，spec §3 写死为 `modreq([TR]X)T`；在参考侧 formatter 按 spec 去掉 `class/valuetype` 前缀（System.Console 3 处），未放宽被测实现或比较判据。
- 补证（2026-11-17，补证样本单列、不并入上面四样本的分母）：受控 `SigSample.dll` 由 ilasm 汇编，5 个方法覆盖四类原缺口——`MArray(int32[0...,0...])` → `[r=2;lb=0,0]`（`ARRAY`）、`MFn(method unmanaged cdecl int32 *(int32))` → `fnptr(...)`（`FNPTR`）、`MMod` → `modopt([TR]System.Runtime.CompilerServices.IsConst)Int32`、`MOpt` → `modopt(spec@0x1B000001)Int32`（内嵌 TypeSpec 引用）；**4/4 路径命中**（`coverage` 检查按方法名逐条断言，canonical 与 SRM 整串全等）。`depth_exceeded` 由 `DeepSig63.dll` / `DeepSig.dll` 成对证伪：63 层解出 63 个 `[]`、64 层 `undecoded/depth_exceeded`，SRM 侧能解出 64 个 `[]`（边界在 64 层，不是“解不出嵌套”）。`bad_compressed_int` / `truncated_signature` 各由 `BadCompressed.dll` / `TruncatedSig.dll` 原位改 1 字节证伪；unknown 政策两条分支各由 `UnknownCodedTag.dll`（modopt 引用 tag=3）与 `UnknownElemType.dll`（返回类型 0x6F）证实为 `decoded` + `decoded_with_unknown`。每个负样本都断言：精确 reason、仅目标行 undecoded（其余 4 行仍 decoded）、blob 与正样本恰好差 1 字节、dnfile 索引/偏移/长度/字节 0 不一致、SRM 同一行报 error；空比对一律 FAIL。
- 补证过程中抓到并修复 2 处实现缺陷（都由新样本首次触发）：(1) `modopt`/`modreq` 的修饰类型引用解不出时只写了 canonical 前缀、没记 `ctx.unknown`，分母会把它算成 decoded_clean——改为记入 unknown 账本；(2) 未识别的元素类型字节让 `decode_method_sig` 读 `canonical` 时 `KeyError`——给 unknown 节点补 canonical。两处分别由 `UnknownCodedTag.dll` / `UnknownElemType.dll` 复现并回归（pytest 554 passed 不变）。
- 仍无样本（如实登记）：`sentinel`（vararg 调用点里的 0x41）与 `pinned`（0x45）两条解码分支——本批样本链只覆盖方法签名，这两条需要 vararg 调用点 / 局部变量签名样本，本批未造，未用近似样本冒充。`field`/`local` 签名只比 kind 不比类型是既定口径，不算缺口。
- 门禁：补证批次 `verify_sigblob.py` **27 项**全 PASS；全量 **23 套**、pytest **554 passed**、`ledger_check --check` PASS（run `20261117T040139-2ff9`，`GATE: PASS exit=0`，证据 `work\evidence_m19_sigblob.json`）。M19 首轮收口时为 17 项 / **22 套** / run `20261117T010924-0a7b`。

## 16. M20 .NET 类型布局与字段 RVA（.NET 纵切面封口）

- 静态可证分母（四样本，二分恒等式全部成立）：`FieldLayout` **84** 行、`ClassLayout` **71** 行、`FieldRVA` **132** 行，三者相加 = **287** 行，等于 dnfile 独立读同一批表的行数。`FieldLayout`/`ClassLayout` 解出 **84 / 71**（clean 84 / 71，unknown 0）；`FieldRVA` 的 `field_ref_ok=132`、`length_known=131`、`length_unknown=1`，`data_ok=131`、`rva_unmapped=0`、`data_truncated=0`，数据解码率 **100.0000%**（131/131），unknown 占比 **0.7576%**（1/132），逐项恒等式写在报告里而不是只写在文档里。
- 逐样本：mscorlib（v4.0.30319）`FieldLayout` **78** / `ClassLayout` **63** / `FieldRVA` **128**，数据字节 **64,421**，长度来源 **120 / 8**（valuetype ClassSize / 基元）；System.Console.dll（7.0.20）只有 `ClassLayout` **3** 行，另两表为 0；受控 IL 样本 3 / 2 / 3（28 字节，含 1 条 unknown），受控 C# 样本 3 / 3 / 1（32 字节）。
- 长度来源合计 **122 / 9 / 1**（valuetype ClassSize / 基元 / unknown）。唯一 unknown 是 IL 样本的 `System.DateTime` 静态字段：类型在别的程序集、本模块没有 ClassLayout，按 `valuetype_not_typedef` 记 unknown，不拿 `.data` 字面量的 8 字节反推。
- 独立对拍（期望值不取被测实现）：dnfile 逐行比较三表原始列值（Offset/Field、PackingSize/ClassSize/Parent、RVA/Field + 字段名）共 **287** 行，0 不一致；dnfile 的 PE RVA→文件偏移独立复算 **131** 行（位置与字节），0 不一致；源码真值（`.il` 的 `.pack`/`.size`/`.field [N]`/`.data`、`.cs` 的 `[FieldOffset]`/`[StructLayout]`/数组初始化器）共 **16 项**，0 不一致；`__StaticArrayInitTypeSize=N` 的 N、`ClassSize`、推导长度三者相等 **121** 行，0 不一致。
- 运行期推导（不进静态结论）：受控样本上 `Marshal.OffsetOf` / `Marshal.SizeOf(Type)` 给出 **14 个偏移 / 3 个 size / 1 个 auto 边界**。显式布局的静态 `FieldLayout.Offset` 与运行期逐一相等，`ClassSize` 与运行期 size 相等；sequential/auto 字段在报告里没有任何静态偏移；auto 类型被 CLR 拒绝（`cannot be marshaled as an unmanaged structure`），如实记为运行期不可得（仅指 `Marshal` 路径；非 `Marshal` 补证见下条），不写成静态值。
- 可失败自证（首版即带，工件=注入 ID + 基线 + 观察到的失败行）：`FieldLayout.Offset` +4 → `[FAIL] m20-src selfproof FieldLayout A offset expected=0 actual=4`；`ClassLayout.ClassSize` +1 → `[FAIL] ... expected=(1, 24) actual=(1, 25)`；FieldRVA 文件字节翻转 → `[FAIL] ... 数据 expected=0102… actual=fe02…`；RVA +1 → `[FAIL] m20-rva Blob24 file_off dnfile=593 rekit=592`；空比对 → 拒绝 PASS。
- 边界：sequential/auto 偏移、`ClassSize=0` 时的运行期 size、实例字段的引用布局都不在静态结论里（报告 `static_conclusion.excludes` 明列）；`PackingSize=0` / `ClassSize=0` 照抄“未指定”，不代换默认值。
- sequential/auto 运行期补证（2026-11-17，单列，`static_conclusion=false`）：`tests/layoutauto.ps1` 用编译期引用 + `/unsafe` 探针（清零后逐字段赋值、扫描首个非零字节，`sizeof(T)` 取 CLR 实际大小）量出 **10 个字段偏移**：IL `SeqStruct`（pack=2）X=0 / Y=2 / size=16、C# `SeqPack4`（pack=4）B=0 / L=4 / S=12，两例都与 ECMA-335 §II.10.1.2 从源码声明独立推导的期望一致；auto 两例 `AutoStruct` X=8 / Y=0 / size=16（CLR 重排，与声明顺序 X@0/Y@8 不同）与 `Plain` X=0 / Y=8 / Z=16 / size=24，只做运行期自洽（字段全量到、互不重叠、不越界），配负控（seq 偏移 +4、auto -1 / 越界 / 重叠四类注入均被检出）。运行期值不进静态结论，也不改上面的 14 / 3 / 1。
- 门禁：补证批次 `verify_layout.py` **33 项**（PASS 32 / SKIP 1；SKIP 是 System.Console 的 `FieldRVA=0` 无可复算行，由聚合分母兜底）；全量 **23 套**、pytest **554 passed**、`ledger_check --check` PASS（run `20261117T040139-2ff9`，`GATE: PASS exit=0`，证据 `work\evidence_m20_layout.json`）。M20 首轮收口时为 28 项（PASS 27 / SKIP 1）/ run `20261117T013424-1713`。
- **R123–R125**：类型布局的静态结论只到元数据写明的值（`FieldLayout.Offset`、`ClassLayout` 两列、`FieldRVA` 的 RVA 与字节）；sequential/auto 偏移必须标运行期推导，不得进静态分母；`FieldRVA` 数据长度不是元数据字段，推不出记 unknown 并写缺什么。

