# M13：种子扩大后的下界重算

> 生成：2026-11-16 ｜ 口径：**沿用 M9–M11 原判据，不改口径**
> 机器快照：`work/evidence_m13_ledger.json`（M13 起唯一权威）+ `work/evidence_m13_recompute.json`（本轮逐项测量）

## 0. 一句话结论

种子扩大（接入 gopclntab）只改变了 **Go 样本的函数域**，因此**只有以“函数域”为分母的结论需要复算**；
以 objdump 指令起点或数据节为分母的结论在结构上与种子无关。复算结果：**六个条目中没有数字变化**；
变化的是三条**措辞/状态**（switchcand 的 skipped 条目已失效、VEX「全是数据」措辞需修正、
总账里「strxref 本轮未重跑」的说法不准确）。

| # | 条目 | 类别 | 旧值 | M13 复算 | 判定 |
|---|---|---|---|---|---|
| 1 | strxref 未解码代码里可外部证实的引用点 / 字符串 | 补集度量 | 5,039 / 276 | **5,039 / 276** | 作为补集度量仍成立（**不是下界**） |
| 2 | VEX/EVEX 弃权点（11 样本，非指令边界） | 种子无关计数 | 206,541（defect=0） | **206,541**（Go 两样本逐项相等） | 仍成立（措辞已按 C1 修正） |
| 3 | Go 函数域内未达的 objdump 指令（含对齐） | 含对齐计数 | ELF 26,652 / PE 26,702 | **26,652 / 26,702** | 仍成立（含对齐 1,067 / 1,066） |
| 4 | 非 Go 样本可达域（种子稳定性） | 稳定性检查 | 旧 18 / 新 7 其余样本 | **17 个可测样本 delta=0** | 仍成立 |
| 5 | M8 paramdecl | DWARF 计数 | 12,272 / 3,530 / 37,891 | 未重算（无重算对象） | 仍成立 |

**分析覆盖率（不属于下界，单独列）**

| # | 条目 | 旧值 | M13 复算 | 判定 |
|---|---|---|---|---|
| 6 | switchcand 分析覆盖率（cc1/lto1/gdb） | 三者均 “skipped” | cc1/gdb **skipped_budget=0**；lto1 **`no_run`** | 条目已失效（不是种子造成） |

## 1. 方法与“判据未变”的证明

| 项 | 本轮做法 |
|---|---|
| 分母口径 | 未变（R91）：GNU objdump 2.47 同节 `[VA, VA+size)` 指令数；分子 = 同址同长 |
| 判据一致性 | 复算脚本必须**逐项复现旧值**才被接受（`match_old=true`）；复现不了就说明判据变了，不得替换 |
| VEX | 直接复用 `rekit.vexaudit.classify_one`（objdump 同址文本判四类），未改分类分支 |
| strxref | 直接复用 `tests/verify_strxref.py::check_sites`（未解码代码里的外部引用判定），只切换 `gopclntab=False/True` |
| Go 域内 | 复用 M11 的 objdump_only 三分法（全 `cc/90` / 域内其它 / 域外），逐项复现 149,225+26,652+0 与 148,861+26,702+40 |
| 代码指纹 | `evidence_m13_ledger.json.meta.code_sha256`（vexaudit / strxref / switchcand / coverage / recdesc / gopclntab / disasm） |

### 1.1 哪些分母受种子扩大影响

| 分母来源 | 受影响 | 原因 |
|---|---|---|
| objdump 线性扫描的全节指令 | 否 | 外部工具从节首顺序解码，与我们的种子无关 |
| 只读数据节（字符串识别） | 否 | 按节字节切分，与可达域无关 |
| recdesc **已解出指令集合**（strxref 分子、VEX 与“我方起点”的交集） | 是 | 种子多 → 解出多 |
| **声明函数域** `[entry, end)`（Go 域内分母、switchcand 函数集） | 是 | 域由种子决定 |

## 2. 逐项：旧值 → 新值 → 原因 → 判定

### 2.1 strxref：5,039 引用点 / 276 字符串（补集度量，不是下界）

- **分母性质**：`5,039` 是“只在我们**未解码**的代码里、由外部 objdump 可见的引用点”，分子随可达域变化 → 原理上受影响。
- **但 18 个样本里只有 2 个 Go**（`hello_go_linux`、`hello_go.exe`）。M13 对这两个样本做 `gopclntab` 关/开 A/B：

| 样本 | 关（旧） | 开（新） | 未解码引用点 | 未解码涉及字符串 | 我方引用点 |
|---|---|---|---|---|---|
| hello_go_linux | 2 串/2 引用点 | 2 串/2 引用点 | **0 → 0** | **0 → 0** | 2 → 2 |
| hello_go.exe | 2 串/2 引用点 | 2 串/2 引用点 | **0 → 0** | **0 → 0** | 2 → 2 |

- **聚合复算**：M12 回归中 `verify_strxref.py` 已在新种子下重跑，聚合仍 **5,039 / 276**（`evidence_m12_verify.log`）。
- **结论**：**作为补集度量仍成立**，且 5,039 全部来自 16 个非 Go 样本。它统计“只在我们未解码的代码里可见的引用点”，
  可达域变大它就变小，**不是**“至少还有 5,039 个引用点”的下界；对 Go（非 NUL 终止字符串）近乎盲。
  旧总账写“本轮未重跑该专项”不准确——那是 M12 的表述，实际上 M12 回归已经重跑过，M13 又做了关/开归因。
  M13-patch 已在 `rekit/strxref.py` 头注、`verify_strxref.py` 输出和 `lower_bounds` 的 `bound_type` 三处固化该口径（C3）。

### 2.2 VEX/EVEX：206,541 点（11 样本，非指令边界）

- **分母性质**：逐字节找节内 `C4/C5/62`，逐个位置试解；四分类的裁判是 **objdump 同址指令起点/文本**，不读 recdesc 种子 → **结构上与种子无关**。
- **受影响样本只有 2 个 Go**；用同一 `classify_one` 复算（`match_old=true`）：

| 样本 | lead 字节 | 弃权点 | 四分类（新名） | defect | 落在声明域内 | 成为**新可达域已解出指令起点** |
|---|---|---|---|---|---|---|
| Go ELF 合成 | 20,459 | **16,332**（旧 16,332） | `not_objdump_insn_start` 16,332 | **0** | 16,332 / 16,332（100%） | **0** |
| Go PE 合成 | 20,299 | **16,179**（旧 16,179） | `not_objdump_insn_start` 16,179 | **0** | 16,177 / 16,179（99.99%） | **0** |

- 其余 9 个样本无 gopclntab，种子集逐条不变（`evidence_m12_ledger.json` 的 `gopclntab=missing`），分类输入不变；
  合计 16,332+16,179+68,395+65,914+10,166+613+27,392+38+313+1,199 = **206,541**。
- **结论**：**仍成立**（数字、四分类、defect=0 全部不变）。**“全是数据”这个措辞已修正**，见 §4 C1：
  分类名改为 `not_objdump_insn_start`，并强制同报域内比例（上表两列）。

### 2.3 switchcand：分析覆盖率（cc1 / lto1 / gdb）——不属于下界

- **这不是种子问题，是标签问题**。历史文档把两件事都叫 skipped：
  (a) M9 因超时**整层未运行**；(b) M10 引入的**预算跳过** `functions_skipped_budget`。
- **M13 实测**：`gdb` analyzed 2,081 / **skipped_budget 0** / candidates 317（与 M10 一致，13.0s）；cc1 在 M10 已是 1,974 / 0 / 64。
  `lto1` 至今 **`run_status=no_run`**（没有统计量，不是 skipped_budget）。Go 两样本为本轮新增测量：各 118 个间接 jmp 函数，analyzed=118、skipped_budget=0、candidates=0。
- **结论**：该条目 **已失效**——不是因为种子扩大，而是 M10 性能修复后 cc1/gdb 早已全量跑完；`lto1` 标 `no_run`，不能标 skipped。
- **命名固化（C2）**：`budget` 现在同时给出 `run_status`（ok/no_run）、`functions_skipped_budget`、`functions_no_run` 与 `status_semantics`；
  `skipped_detail` 每条带 `skip_type=skipped_budget`；裸键 `skipped` 在预算报告中被禁用。全项目同名不同义清单见 §4.1。

### 2.4 Go 函数域内未达的 objdump 指令（含对齐）：26,652 / 26,702（各占 .text 2.88%）

- **分母性质**：objdump_only 指令是否落在 gopclntab 声明域内 → 受种子影响；但这组数字**本来就是 M11 种子扩大后的值**。
- **M13 用同一三分法复算**（当前种子，declared_ranges = 8,906 / 8,892）：

| 样本 | padding（全 cc/90） | 域内其它 | 域外 | 合计 | 与旧值 |
|---|---|---|---|---|---|
| Go ELF | 149,225 | **26,652** | 0 | 175,877 | 逐项相等 |
| Go PE | 148,861 | **26,702** | 40 | 175,603 | 逐项相等 |

- **结论**：**仍成立**。26,652/923,970 = 2.8843%，26,702/925,712 = 2.8845%；“2.88%”表述有效，但它是**域内未达的 objdump 指令（含对齐）**，不是“漏解的指令数”（§4 C4）。
- **对齐实测（M13-patch）**：`evidence_m14_c4_alignment.json` 逐条统计该桶里的 nop 族指令——
  ELF **1,067 / 26,652 = 4.0034%**，PE **1,066 / 26,702 = 3.9922%**。
  其余是 mov/lea/call/jmp/ret 等真实指令（例如函数尾部、间接跳转之后未被线性扫到的块）。
  因此措辞定为“含对齐”，既不能叫“对齐桶”，也不能叫“漏解指令数”。复核脚本：`tests/verify_c4_alignment.py`。

### 2.5 非 Go 样本可达域

- 17 个可测非 Go 样本：`gopclntab=missing`、`unchanged=true`、`delta_numerator=0`（`evidence_m13_ledger.json.non_go_reach`）。
- **结论**：**仍成立**；种子集逐条不变，覆盖率数字与 M9/M10 相同。

### 2.6 M8 paramdecl（12,272 / 3,530 / 37,891）

- 形参来自 DWARF，不是代码种子；本轮无重算对象，M12 回归 `verify_paramdecl` 仍 exit 0。**仍成立。**

## 3. 正面回答：VEX 那 20 万点，种子扩大后有多少变成真实指令？

**0 个。** 三层证据：

1. **结构证据**：`vexaudit` 的输入只有三项——节内原始字节、`objdump_instructions()` 给出的指令起点表、`disasm._decode_any()` 的弃权类别。
   它不接收 `res`（recdesc 结果），也不接收种子。种子扩大无法改变它的任何输入。
2. **实测证据**：两个 Go 样本在新种子下重算，弃权点数、四分类与 M9 逐项相等；把弃权地址与新可达域的**已解出指令起点**求交集，结果为 **0 / 0**。
3. **语义证据**：这些地址在 objdump 的线性扫描里不是指令起点，即它们落在**上一条指令的操作数/立即数内部**。
   种子只决定“从哪里开始解”，不决定“某个字节是不是某条指令的第一个字节”。

**但“全是数据”这句话是错的（数字对，话不对）**：Go ELF 的 16,332 个弃权点**全部**位于声明函数域内，PE 为 16,177/16,179。
它们不是“函数外的数据区”，而是**函数体内指令的非边界字节**。正确说法是“全部不是指令边界”，而不是“全是数据”。
这不是种子造成的，是原分类命名的语义过宽（§4 C1）。

## 4. 原判据本身的问题（单列，不并入上面的重算）——已全部修复

> 本轮（M13-patch）把 5 条从“文档承诺”落实为**代码/字段/测试**。每条给出：现行判据原文 → 问题 →
> 改成什么 → 为什么不是放宽 → 可证伪测试。

### C1 VEX `data_not_instruction`

- **判据原文**：`classify_one()`：`if ins is None: return "data_not_instruction", "objdump 未在该地址列指令（不是指令起点）"`。
- **问题**：判据只说明“不是 objdump 指令起点”，结论却写成“全是数据/不在代码里”。实测 Go ELF 16,332/16,332、
  PE 16,177/16,179 的弃权点落在声明函数域内——它们是函数体内指令的操作数字节，不是数据区。
- **改成什么**：类别名 `not_objdump_insn_start`；`audit(declared_ranges=)` 必须同报
  `domain.abstain_in_domain / in_domain_ratio`；未提供域时该比例为 `None`，并显式禁止“全是数据”的写法。
- **为什么不是放宽**：判据一字未改（仍只看 objdump 指令起点表，`classify_one` 不读域、不读种子）；
  改的是过强的结论表述，并新增了此前缺失的域内比例报告。要求更强。
- **可证伪测试**：
  - `tests/test_vexaudit.py::test_category_name_is_criterion_not_data_semantics`（名字里出现 `data` 即失败）
  - `tests/test_vexaudit.py::test_classification_ignores_declared_domain`（若有人把“域内=代码”写进判据即失败）
  - `tests/verify_vexaudit.py`：cli-64.exe 实报域内 37/38（97.37%），域内+域外必须等于 abstain_sites。

### C2 switchcand `skipped`

- **判据/字段原文**：预算报告只有 `functions_skipped_budget`，而历史文档把“M9 超时整层未运行”和
  “M10 预算跳过”都写成 `skipped`；`sitejoin` 的 `status` 也用 `"skipped"` 表示“没有已解出指令”。
- **问题**：三件不同的事共用一个词：(a) 整层未运行（没有分母）；(b) 预算跳过（有函数、有分母）；
  (c) 无可提升指令（结构层属性）。
- **改成什么**：`budget.run_status ∈ {ok, no_run}`、`functions_skipped_budget`、`functions_no_run`、
  `status_semantics`；`skipped_detail[].skip_type = "skipped_budget"`；裸键 `skipped` 禁用。
  `sitejoin` 的 `"skipped"` → `"no_decoded_instructions"`；测试快照的 expr 字段 → `skipped_undeclared_boundary`。
- **为什么不是放宽**：跳过条件、计数、分母全部没变；只是把同名不同义拆成不同名字，并加了机器可检的语义表。
- **可证伪测试**：
  - `tests/test_switchcand.py::test_status_names_distinguish_no_run_from_budget_skip`（断言 budget 无裸 `skipped`）
  - `tests/test_sitejoin.py::test_struct_index_status_names_are_self_describing`
  - `tests/verify_switchcand.py`（PASS）

### C3 strxref 5,039 的“下界”

- **判据原文**：`check_sites()` 统计“落在**我方未解码**的 objdump 指令里的引用点”，报告写成“引用点 5,039 个”。
- **问题**：这是**补集度量**：可达域越大它越小，不是某个稳定分母的下界；且 Go 字符串非 NUL 终止，对 Go 近乎盲。
- **改成什么**：`bound_type = "complement_measure"`、`is_lower_bound = false`、`complement_of = "已解出指令里的引用点"`；
  模块头注与 verify 输出都加补集口径行。
- **为什么不是放宽**：判定逻辑与数字一字未改；去掉的是更强的“下界”称呼，反而把适用边界写得更清楚。
- **可证伪测试**：`tests/test_ledger_criteria.py::test_strxref_is_complement_measure`（改回 `lower_bound` 即失败）。

### C4 Go 2.88% “域内未达指令”

- **判据原文**：三分法把 objdump_only 指令分成 padding（全 `cc/90`）/ `in_range_other` / 域外；
  文档把 `in_range_other` 简称为“域内未达指令”。
- **问题**：该桶**含对齐/填充指令**（多字节 nop），不全是真实代码目标；也不能反过来叫“对齐桶”。
- **改成什么**：`includes_alignment_bytes = true`、`not_equivalent_to = "漏解的指令数"`；
  措辞统一为“域内未达的 objdump 指令（含对齐）”，并给出对齐占比。
- **实测支撑**：ELF 1,067/26,652（4.0034%）、PE 1,066/26,702（3.9922%），其余为 mov/lea/call/jmp/ret。
- **为什么不是放宽**：三分法计数未变（26,652/26,702）；只是把“漏解指令数”降级为证据支持的说法。
- **可证伪测试**：`tests/test_ledger_criteria.py::test_go_domain_declares_alignment_share`（对齐数为 0 即失败）
  + `tests/verify_c4_alignment.py`（逐条复算，与存档不一致即失败）。

### C5 把 switchcand skipped 当下界

- **判据原文**：总账 §6 把 `switchcand skipped` 与真正的下界并列。
- **问题**：skipped 是分析覆盖率属性，不是候选数的下界；被跳过函数可能本来就没有候选。
- **改成什么**：从 `lower_bounds` 移出，单列 `analysis_coverage`；新增 `bound_table_policy`
  （`bound_type` 白名单 + `analysis_coverage` 不得入表）。
- **为什么不是放宽**：覆盖率数字完整保留（没有删掉不利数据），只是换了正确的类别；并新增白名单校验。
- **可证伪测试**：`tests/test_ledger_criteria.py::test_no_analysis_coverage_in_lower_bounds`
  （lower_bounds 里出现 switchcand 或 `skipped` 键即失败）。

### 4.1 全项目“同名不同义”状态字段清单

> 规则：状态名必须在自己的对象命名空间内自解释；同一份输出里不得让两个不同含义共用同一字段名。
> 机器快照：`evidence_m13_ledger.json.status_field_inventory`。

| 字段 | 含义 | 冲突 | 处理 |
|---|---|---|---|
| `expr.lift_binary()["skipped"]` / `["functions_skipped"]` | 边界未声明，拒绝提升 | 旧版与预算跳过同名 | 保留（expr 命名空间内由 reason 自解释）；测试快照改名 `skipped_undeclared_boundary` |
| `expr.lift_function()["skipped"]` | 该函数没有已解出指令 | 与“边界未声明”“预算跳过”均不同 | sitejoin 引用处改名 |
| `sitejoin.struct_index[fn]["status"]` | 旧值 `skipped` = 没有已解出指令 | 三者同名不同义 | **已改名** `no_decoded_instructions` |
| `switchcand.budget.*` | `run_status` / `functions_skipped_budget` / `functions_no_run` | 旧版都叫 skipped | **已拆分** + `status_semantics` |
| `switchcand.promotion["status"]` | `not_checked/promoted/blocked` | 升格状态，不是运行状态 | 不改（命名空间已限定） |
| `coverage["status"]` | `ok/unavailable/error/no_section`（objdump 可用性） | 与解码/运行状态不同对象 | 不改；禁止跨对象比较 |
| `gopclntab["status"]` | `ok/missing/unknown` | `missing`≠`unknown`，已分开 | 不改 |
| `disasm` 指令 `["status"]` | `ok/unsupported`（单条指令） | 与模块级 status 同名不同对象 | 不改；读取时必须带对象路径 |
| `iat["status"]` vs `iat.slots[]["status"]` | 模块 `ok/no_imports/invalid`；槽 `unresolved/repaired` | 同模块内两级对象共用字段名 | 不改；词表不相交，读取带对象路径 |
| `callfacts` 边 `["state"]/["graph_state"]` vs callgraph 边 `["state"]` | 两层各自的边状态词表 | 同名但来源不同 | 不改；`graph_state` + contradiction 检查显式列冲突 |

## 5. 读者指引：哪些旧文档的数字/说法已过期

| 旧位置 | 状态 | 现在看哪份 |
|---|---|---|
| `outputs/NUMBERS_LEDGER.md` | 已更新为 M13 版（§0 指向新权威） | 本文件 + `evidence_m13_ledger.json` |
| `work/evidence_m12_ledger.json` | 覆盖率 / Go A/B / 逐函数 / PE 缝隙数字**仍有效**（M13 回归复核）；仅其 `still_lower_bounds` 列表作废 | `evidence_m13_ledger.json` 的 `lower_bounds` |
| `outputs/TASK_m11_gopclntab.md` §8–§9 | 下界表被 M13 取代（数字多数不变，状态按 M13 读） | 本文件 §2 |
| `outputs/TASK_m10_closeout.md` | switchcand 的 cc1/gdb 数字有效；“skipped”措辞作废（C2） | 本文件 §2.3 |
| `outputs/TASK_m9_closeout.md` §3.2 | VEX 206,541 与四分类计数有效；“全是数据”措辞作废（C1） | 本文件 §2.2 |
| `outputs/TASK_m8u3_strxref.md` | **文件不存在**（只有 `evidence_m8u3_numbers.log` / `.verify.log`）；5,039/276 有效 | 本文件 §2.1 |
| `work/evidence_m11_coverage.json` | 26,652 / 26,702 三分法明细有效（M13 逐项复现） | `evidence_m13_recompute.json` 的 `go_domain` |
| `work/evidence_m13_ledger.json` 的 C1–C5 旧状态 | 已由 M13-patch 更新为 `status=fixed` | 本文件 §4 与 `status_field_inventory` |
| `work/evidence_m14_c4_alignment.json` | **新增**：C4 对齐占比的唯一出处 | 本文件 §2.4 / §4 C4 |

> 一句话：**没有数字因种子扩大而过期**；过期的是“说法”——switchcand 的 skipped 条目、VEX 的“全是数据”、
> Go 2.88% 的“漏解指令数”、strxref 的“下界”，以及总账里“strxref 本轮未重跑”的自我描述。
> 这些说法已在 M13-patch 按 C1–C5 全部改掉，并加了机器校验（见 §4、§8 R107）。

## 6. 复现

```
cd 2026-11-15/m3-task-card/work
# 环境：LC_ALL=C，PATH 前置 D:\msys64\ucrt64\bin（objdump 2.47），PYTHONIOENCODING=utf-8
python %TEMP%/m13_recompute.py all    # 生成 evidence_m13_recompute.json（domain/vex/strxref/switch）
python %TEMP%/m13_ledger.py           # 汇总 evidence_m13_ledger.json
python %TEMP%/m14_c4_measure.py       # C4：in_range_other 桶的 nop 族统计 → evidence_m14_c4_alignment.json
python -m pytest tests -q             # 全量回归
python tests/verify_*.py              # verify（含新增 verify_c4_alignment.py；verify_fingerprint.py 需 --all --matrix）
```

- `evidence_m13_recompute.json`：本轮四组测量（含 `match_old` 与逐条样例）
- `evidence_m14_c4_alignment.json`：C4 对齐实测（逐样本 nop 族计数、样例地址/字节、耗时）
- `evidence_m13_ledger.json`：唯一权威（含判定表、C1–C5 修复状态、`status_field_inventory`、代码 sha256）
- `tests/test_ledger_criteria.py`：C1/C3/C4/C5 的机器校验；`tests/verify_c4_alignment.py`：C4 逐条复算
- `evidence_m13_pytest.log` / `evidence_m13_verify.log`：M13 回归（M13-patch 的新日志见 §7）

## 7. 本轮回归

- pytest：**475 passed in 68.54s（exit 0；驱动耗时 72.01s）** — `evidence_m14_pytest.log`
- verify：**17 / 17 exit 0** — `evidence_m14_verify.log`
  （`verify_fingerprint.py` 用 `--all --matrix`；`verify_strxref.py` 仍输出
  “未解码代码里的引用点 5039 个，涉及字符串 276 条”，与 §2.1 一致；
  新增 `verify_c4_alignment.py` 逐条复算 Go 桶对齐，18.04s，pass）
- 逐条受影响的验证（数字变化均分列说明）：

| 修复 | 受影响的验证 | 数字变化 | 原因 |
|---|---|---|---|
| C1 | `test_vexaudit` + `verify_vexaudit` | 206,541 不变；新增 cli-64 域内 37/38（97.37%） | 只改名与新增域内比例，分类不计分 |
| C2 | `test_switchcand` + `verify_switchcand` + `test_sitejoin` | cc1 1,974/0/64、gdb 2,081/0/317 不变 | 只改字段名，不改跳过条件 |
| C3 | `verify_strxref` | 5,039 / 276 不变 | 只改类别与措辞 |
| C4 | `verify_c4_alignment`（新增） | 26,652 / 26,702 不变；新增 nop 族 1,067 / 1,066 | 新增对齐占比测量，不改三分法 |
| C5 | `test_ledger_criteria`（新增 7 项） | 无数字变化 | 只移动条目所在表并加白名单校验 |

## 8. 本轮新增规则

- **R104**：下界/比例结论必须绑定**分母来源**。分母不受种子影响的，标 `seed_invariant` 并给结构证明（判据不读取子）；
  分母随种子变化的，必须用同一判据复算，且复算必须**逐项复现旧值**（`match_old=true`）才可用于替换。
- **R105**：分类名不得替代判据。`data_not_instruction` 只能写成“非 objdump 指令起点”，不得简写为“数据/不在代码里”；
  此类结论必须同时报“落在声明域内的比例”。
- **R106**：`skipped` 只用于分析覆盖率；整层未运行标 `no_run`，预算跳过标 `skipped_budget`，二者不得混用，且都不得进入下界表。
- **R107（M13-patch）**：结论的措辞强度必须与证据强度匹配，**不得用更强的说法替代**。具体：
  (a) 分类名不得暗示判据没有证明的东西（`not_objdump_insn_start` ≠“数据”）；
  (b) 补集度量不得称“下界”（strxref）；
  (c) 含对齐的桶不得称“漏解指令数”（Go 域内）；
  (d) 分析覆盖率不得进入下界表（C5）。
  每条此类结论必须绑定：`bound_type`/`criterion`/`denominator`/`evidence`，并由 `tests/test_ledger_criteria.py` 机器校验；
  新增或修改这类结论时，若找不到可证伪测试，则不得写入总账。
