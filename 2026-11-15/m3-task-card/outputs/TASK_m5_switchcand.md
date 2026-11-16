# TASK M5-U2：跳转表候选层（默认关闭，严格隔离）

日期：2026-11-15　状态：✅ 完成（全部硬性条件已用可跑证据落地）

## 1. 背景与裁决

M4 按 R45 把间接 `jmp` 目标一律记为 `unresolved`（`target=None`）。这在"不猜"上是对的，
但把"有结构化证据的跳转表"也一起挡在门外：dyn_static 的 `0x401870` 我方 23 块，
Ghidra 55 块，差 32 块。

裁决：允许引入"跳转表候选 + 证据等级"，但必须严格隔离——把 **禁止"把猜测当已知"**
与 **允许"提出有证据的候选"** 分开写。

## 2. 硬性条件 → 落地位置

| # | 硬性条件 | 落地 |
|---|---|---|
| 1 | 候选层默认关闭，只在显式开关下输出；不进确定边/表达式/CFG 确定口径，单列并标注证据等级与依据 | `rekit/switchcand.py`（独立模块，不 import 进 recdesc/expr 的主路径）；CLI `--switch-candidates` 才调用；输出独立段"── 跳转表候选（非确定）──"，每条候选带 `evidence` + `basis`；块数另记 `blocks_candidate`，与 `blocks` 并列 |
| 2 | 负向测试：关闭候选层后所有既有确定数字逐项不变 | 冻结 `tests/baselines/definite_baseline.json`（3 样本 × recdesc 17 项 + expr 8 项 + `0x401870` 函数指标）；`tests/test_switchcand.py::test_definite_numbers_unchanged` 与 `tests/verify_switchcand.py` A 段双向断言；另有 `test_candidate_does_not_mutate_res` 直接比对同一 `res` 跑前/跑后 |
| 3 | R45 措辞同步，只增不删记入 CHANGELOG | `recdesc.py` 文件头新增"R45 措辞（裁决同步）"段；`recdesc.CAVEATS` / `expr.CAVEATS` 各加一条；CHANGELOG 追加"R45 措辞同步""新增 E9 负向基线""新增 R53–R55"三行；CHARTER M5 行与源码树、PROGRESS M5-U2 条目同步 |
| 4 | 用 dyn_static `0x401870` 量化收益：差的 32 块里补回多少、补错多少，两个数都报 | `tests/verify_switchcand.py` C 段（Ghidra 弱参照）：**补回 20 / 补错 0 / 剩余 12**，并列出剩余 12 个地址 |
| 5 | 候选被判错时要能看出被拒理由 | `_scan_entries` 四类拒绝理由（超出声明函数域 / 落在已解出指令内部 / 无法解出 / 表项越界）写入 `rejected_entries`，与整条被拒 `rejected` 一起由 `render_candidates` 打印；`test_scan_entries_*` 逐类断言 |
| 6 | 完成后再跑全量回归并汇报 | pytest **295 passed**（exit 0）；verify_disasm / verify_recdesc / verify_map / verify_iat / verify_expr / verify_switchcand 全部 exit 0；日志 `work/evidence_m5u2_*.log` |

## 3. 实现要点

- **两种形态**（都要求可回指的结构链，不是"看起来像"）：
  - `rel32`：`lea B,[rip+table]` → `movsxd R,[B+idx*4]` → `add R,B` → `jmp R`；目标 = `table + s32`
  - `abs64`：`jmp qword [rip+table+idx*8]`；目标 = 表内 `u64`（仅非 PIE 语义成立）
- **表长只认 guard**：`cmp idx,imm` + `ja` → `imm+1`；`+ jae` → `imm`。
  实测反例：`0x401870` 的表在第 8 项之后仍接着 `.rodata` 其它数据，第 9 项解出的目标
  仍落在函数域内——靠"首个越界项截断"会把数据当代码，因此无 guard 时表长记"未证明"，
  证据最多 medium 且扫描上限 64 项。
- **独立扩展**：`_extend` 用 `recdesc._Decoder` + `recdesc.classify` 做 BFS，leader 规则照抄
  M4，只在声明域内展开，**绝不写回 `res`**。
- **证据分级**：`high` = 有 guard + 全部表项有效 + 无截断 + 目标 ≥4；`medium` = 缺一项；
  `low` = 截断或目标 <3；函数边界未声明一律降为 `low`。

## 4. 验收结果

### 4.1 负向基线（E9）

`dyn_static`：块 21105、确定边 30202、指令 94773、表达式 1084/1089 函数、85464/94722 指令、
105342 语句、文本 sha256 `72cb6520…`；`0x401870`：23 块 / 80 指令 / 92 语句 / sha `608ed531…`。
候选层跑在同一 `res` 上前后：**28 项全等**，`res.blocks` / `res.instructions` 计数不变。

### 4.2 收益量化（Ghidra 弱参照，`0x401870`）

| 指标 | 数值 |
|---|---|
| 我方既有块 | 23 |
| 候选新增块起点 | 20 |
| 候选口径块数 | 43 |
| Ghidra 块数 | 55 |
| 差距 | 32 |
| **补回 recovered** | **20**（全部命中 Ghidra 块起点） |
| **补错 wrong** | **0**（体内非块起点 0；不在体内 0） |
| 剩余 | 12 个 Ghidra 块起点仍缺，候选层未覆盖 |

剩余 12 个：`0x40192b`（Ghidra 把 `jmp` 单独切块，我方把 `jmp` 放在块尾）+
`0x401a44/0x401a5c/0x401a93/0x401a9d/0x401aa7/0x401ab1/0x401abb/0x401ac5/0x401acf/0x401ad9/0x401aef`
（既有块末尾的细粒度切分差异）。我方多出 Ghidra 之外的块起点 **0** 个。

### 4.3 全量样本的候选概况

| 样本 | 有间接 jmp 的函数 | 间接 jmp | 候选 | high/medium/low | 未识别 | 整条被拒 |
|---|---|---|---|---|---|---|
| cli-64.exe | 33 | 33 | 0 | 0/0/0 | 33 | 0 |
| bin_ls.elf | 9 | 9 | 6 | 3/1/2 | 3 | 0 |
| dyn_static | 75 | 123 | 34 | 29/0/5 | 87 | 2 |

cli-64 的 33 处全是 IAT 尾跳转（`jmp qword [rip+disp]`，无 index），候选层不误判为跳转表
——这是负样本上的关键表现。

## 5. 已知边界

- 只覆盖两种特化形态；其它间接 jmp（寄存器来自函数指针表、嵌套索引等）一律进 `unmatched`。
- 表项"可解出指令"不能证明是代码（x86 字节稠密），因此证据等级依赖 guard 与函数域双重约束；
  `0x401870` 的 8 项之所以是 high，是因为 guard 上界 + 全部落在声明域内 + 无重复且 ≥4。
- 剩余 12 块不是候选层可修的：要动既有块切分口径，属于另一个判据变更，需单独裁决。
