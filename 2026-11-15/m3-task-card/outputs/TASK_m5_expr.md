# 青铜任务：rekit M5 第一单元 —— 函数内表达式恢复 + VEX/EVEX 长度表

日期：2026-11-15 ｜ 前置：M4 三单元（线性扫描 / 递归下降 / CFG 分级）已收口
用户口径：①复用 M4 函数域、基本块、确定边，不从零重做；只做函数内，不碰跨过程。
②验收 = 人工抽样 + Ghidra 对读；抽样规则写清（怎么选、覆盖哪几类函数）；Ghidra 是
弱参照，不一致必须归因。③恢复不出来必须显式 abstain 并说明缺什么信息，不得输出
"看起来合理"的表达式；已知不可判的间接目标不补。④补 VEX/EVEX 长度表，补完重新
量化 avx_dense 与 dyn_static 的弃权损失。⑤全量 pytest + 既有验证脚本零回归。

## 0. 输入复用（不重做）

- 函数域：`recdesc.collect_seeds` 的权威声明（PE `.pdata` / ELF FDE / `st_size`），
  只用有 `start..end` 的函数；无声明边界的 44 个 cli-64 派生函数默认跳过。
- 基本块与边：直接用 `recdesc.descend()` 已解边界与 `_build_blocks` 的块；
  `expr` 不重新切块、不重新判边，只把块内指令翻译成语句。
- 调用目标：只作为调用点显示，不内联、不跟参数、不推断返回值。

## 1. 抽样规则（写死在 `tests/verify_expr.py` 文件头）

**池**：三个样本里有权威声明边界的函数：cli-64.exe 41 个、bin_ls.elf 331 个、
dyn_static 1084 个。

**分层**（按该函数已解指令数）：S1 ≤10、S2 11–30、S3 31–100、S4 >100；
每层等距取 `min(4, n)` 个，第 k 个为 `idx_k = floor(k*n/m)`（k=0..m-1）。
不用随机数，任何人复跑得到同一批函数。

**强制覆盖**（5 类，判据只看我方 M4 事件与 abstain 原因，不看 Ghidra）：
`indirect_call`（有间接 call）、`loop`（有 loop/jrcxz）、`indirect_jmp`（有目标
未解析的 jmp）、`simd`（有 VEX 或 SIMD abstain）、`largest`（池内指令数最大）。

**去重结果**：41→**18**、331→**18**、1084→**21**，合计 **57** 个函数。
bin_ls 的 0x4c00 同时命中 loop / indirect_jmp / largest，去重后只算一次——分类
覆盖按"命中过"记，不虚增样本数。

## 2. 表达式恢复与 abstain 契约

支持的族（白名单）：`assign/binop/unop/shift/cmp/test/lea/call/jmp/jcc/loop/
push/pop/ret/leave/conv/setcc/cmov/bswap/xchg/int/nop/intrinsic`。

硬约束（代码即契约）：

- 表外 opcode、未建模语义 → `LiftError(reason, missing)`，`missing` 必须写
  "缺什么信息才能恢复"；不允许返回占位表达式。
- 间接 `jmp/call`：`target=None`，只渲染 `(*expr)();` 并注明"目标不可静态确定"；
  不构造 switch、不猜跳转表。
- 标志位只在同一基本块内跟踪；跨块标志、`OF/PF` 条件 → abstain。
- `fs:/gs:` 段覆盖保留段前缀（`*(u64 *)(fs:[0x28])`），不当作绝对地址 0x28。
- 无声明边界的函数默认 `skipped`；`--include-inferred` 强制提升时单独计数。

## 3. VEX/EVEX 长度表（上一轮定位为"还没做"，本轮补齐）

- VEX2(0xC5)：map 隐含 0F。VEX3(0xC4)：`mmmmm` 选 0F/0F38/0F3A，map 0 未定义
  → abstain。EVEX(0x62)：`P0[1:0]` 选 map，`P0[3:2]` 必须 0、`P1[2]` 必须 1，
  否则按非法编码 abstain。0F3A 一律带 imm8；0F 仅
  `{C2,C4,C5,C6,70,71,72,73}` 带 imm8；`0F 77`（vzeroupper/vzeroall）无 ModRM。
- 自纠：最初给 VEX3 也加了"P1[2]=0 非法"检查——VEX3 两个 payload 字节每位都有
  定义，没有保留位；该错误导致 dyn_static 在 `c4 c1 7a 7f 49 f0` 误弃权。移除后
  全节 113,924 条与 capstone 零长度分歧。
- 验证：`verify_disasm --all` 5 样本（含 avx_dense）与 objdump 长度不一致 **0**。

弃权损失变化：

| 指标 | 补表前（M4） | 补表后（M5-U1） |
|---|---|---|
| avx_dense 权威种子 | 2/5 | **5/5（100%）** |
| avx_dense abstain 点 | 3 | **0** |
| avx_dense 覆盖率 | <35% | **94.8%**（43/53 条可达，漏 0） |
| dyn_static abstain 点 | 107 | **0** |
| dyn_static 确定边 | 26,882 | **30,202** |
| dyn_static 目标未解出边 | 42 | **18** |
| dyn_static VEX 指令 | 4,367/113,924 未解 | 4,367 全部解出长度 |

（dyn_static 未解析 123 条不变——那是间接目标，按 R45 不猜，不是长度表能解决的。）

## 4. Ghidra 弱参照对读

`pyghidra 3.2.0` + Ghidra 12.2 headless，对同一 `.text` 只比三件可机械核对的事，
C 文本只供人工阅读：

1. 入口是否存在（`getFunctionAt`；不在起点时记录 `getFunctionContaining`）；
2. 基本块数（`BasicBlockModel`）；
3. 直接调用目标集合（`getCalledFunctions`，只判等 `.text` 内目标；`.plt/.got/`
   导入目标两边口径不同，单列计数不判等）。

结果（`verify_expr.py --manual 6`，共 57 个函数）：

| 样本 | 抽样 | 入口存在 | 重叠集块数相等 | 重叠集调用集相等 | 抽样内 abstain 指令 |
|---|---|---|---|---|---|
| cli-64.exe | 18 | 15 | 14/15 | 8/15 | 25 |
| bin_ls.elf | 18 | 8 | 8/8 | 5/8 | 35 |
| dyn_static | 21 | 18 | 15/18 | 12/18 | 190 |

**入口缺失不是判错**：bin_ls 是 stripped PIE，Ghidra 没有 symtab，只能从入口/
dynsym/流到达函数；我方边界来自 FDE。cli-64 的 0x1401/0x164c/0x199a 是 `.pdata`
里合法但非 16 字节对齐的条目，Ghidra 把整段并进 `FUN_1400012d0`（其函数 1790 字节
vs 我方 305 字节）。

分歧归因（脚本逐条打印，不静默归一化）：

| 类型 | 归因 | 实例 |
|---|---|---|
| 仅 Ghidra 有调用 | Ghidra 函数域明显更大（并入相邻/内联段） | cli-64 0x12d0 → 0x10a0/0x1200/0x19d0/0x1ac0 |
| 仅 Ghidra 有调用 | 尾跳转被反编译成 call | cli-64 0x1ac0 → 0x1d88；0x1d40 → 0x1bc4 |
| 仅我方有调用 | 目标是 PLT/代码中段，不是 Ghidra 认定的函数 | bin_ls 0x4040/0x4640 等 |
| 块数不一致 | 我方 1 处间接 jmp 未解析（R45 不猜），case 块不可达 | dyn_static 0x401870：23 块 vs 55 块（同 704 字节） |
| 块数不一致 | 函数域接近，差异来自块切分口径 | dyn_static 0x402b00（142/149）、0x44d710（384/385） |

**人工阅读抽查**（6 对/样本，C 文本全量在证据日志）：

- cli-64 `__security_check_cookie`：我方 `rol/ror` + `test` 与 Ghidra
  `(short)(_StackCookie >> 0x30) == 0` 一致；末尾尾跳转我方写 `goto L_0x1d88`，
  Ghidra 写 `FUN_140001d88()`——同一控制转移，呈现不同。
- bin_ls 0x483d：`rdx = addr(rax + 0x1); *(u8 *)(rax) = 0xa;` 为写换行 + 结束符，
  与 Ghidra 的 `*param_1 = 10` 语义一致；PLT 调用显示为 `sub_0x40a0()`。
- dyn_static 0x401e70：`rdi = *(u64 *)(fs:[0x28])`（stack canary）。
  **人工对读抓到真错**：修复前段前缀被静默丢弃，渲染成 `*(u64 *)(0x28)`，
  属"看起来合理但语义错误"。已修为保留 `fs:/gs:`，并加断言
  `test_fs_segment_is_not_rendered_as_absolute_address`。

## 5. 表达式恢复的量化（全二进制，仅声明边界域）

| 样本 | 函数域 | 已提升/跳过 | 指令 | 已提升 | abstain | 语句 |
|---|---|---|---|---|---|---|
| cli-64.exe | 85 | 41/44 | 1,463 | 1,433 | 30（2.05%） | 1,594 |
| bin_ls.elf | 331 | 331/0 | 17,475 | 16,867 | 608（3.48%） | 19,176 |
| dyn_static | 1,089 | 1,084/5 | 94,722 | 85,464 | 9,258（9.77%） | 105,342 |

弃权原因（抽样函数，按指令计）全部带 `missing`，主要是：SIMD/浮点（0F 28/29/
6F/74/7F/D7 等）、位操作（0F BC/BD/BA/A3）、x87（D9/DB/DD/DF）、
`mul/imul/div/idiv` 隐式 rax:rdx、跨块标志、`lock`、字符串指令。

## 6. 零回归

| 命令 | 结果 |
|---|---|
| `pytest -q`（挂 binutils PATH） | **280 passed**，exit 0 |
| `verify_disasm.py --all` | 5 样本长度不一致 **0**，PASS |
| `verify_disasm.py --selftest` | 注入 1 条长度错误被检出 |
| `verify_recdesc.py --all` | PASS（dyn_static 确定边 30,202 / 未解出 18 / abstain 0） |
| `verify_recdesc.py --selftest` | 注入 0x1000 长度 +1 被检出 |
| `verify_map.py --all --matrix` | 2,402/2,402 命中，失配 0，PASS |
| `verify_map.py --selftest` | 翻转 1 格真值后必须失败 → 已失败（检出成功） |
| `verify_iat.py --all --selftest` | 失配 0，故意改坏 1 字节被检出，PASS |
| `verify_expr.py`（本单元新增） | PASS，57 函数对读 + 弃权原因汇总 |

判据变更（已记 CHANGELOG）：`test_disasm` 旧断言"VEX/EVEX 必须 abstain"作废，
改为"合法 VEX/EVEX 必须解出长度，仅保留位非法的伪编码 abstain"；`test_recdesc`
的 AVX 两项从"必须弃权 3/5"改为"5/5 命中、abstain 0、覆盖 >0.9"。

## 7. 已知限制（不补、不猜）

- 跳转表/switch 不恢复：间接 jmp 目标 `None`，其后 case 块不可达（0x401870 即此）。
- SIMD/浮点/x87/字符串/`lock`/隐式双寄存器乘除未建模：abstain 且给 missing。
- 不做值编号/别名/类型推断：逐指令形态，同名变量不代表已合并。
- 只覆盖 `.text`、x86-64；调用约定与参数不恢复。
- Ghidra 未切出的函数不等于我方错；两者不一致均有归因，不做"谁对谁错"的默认裁定。

## 8. 交付物

- `work/rekit/expr.py`（新模块：操作数解码、白名单、abstain 契约、CLI `rekit expr`）
- `work/rekit/disasm.py`（VEX/EVEX 长度表）
- `work/rekit/recdesc.py`（CAVEATS 措辞同步）
- `work/tests/test_expr.py`（29 项）
- `work/tests/verify_expr.py`（抽样规则 + Ghidra 对读 + 归因）
- `work/tests/test_disasm.py` / `test_recdesc.py` / `verify_disasm.py`（判据同步）
- `work/evidence_expr_2026-11-15.log` / `.json`
- `work/evidence_m5_pytest.log`
- `work/evidence_disasm_2026-11-15.log` / `evidence_recdesc_2026-11-15.log` /
  `evidence_map_2026-11-15.log` / `evidence_iat_2026-11-15.log`
