# TASK M6-U2：跨函数参数传递的事实层（证据三级，不做 ABI 推断）

日期：2026-11-15　状态：✅ 完成（五条要求逐条落地，全量回归零回归）

## 1. 输入与边界

- 输入：M4 的已解出指令 / 基本块 / 函数域（`recdesc.descend`）+ M5-U1 的逐指令语义
  （`expr.decode`，只读）+ M6-U1 的调用图三态（`callgraph.build`，只读）+ M3 的导入/重定位结构。
- 新模块：`rekit/callfacts.py`（唯一新增文件）+ CLI 子命令 `rekit callfacts`。
  既有 `expr` / `recdesc` / `struct` / `callgraph` 的输出**逐字节不变**（未给它们加任何开关）。
- 这层回答的是「调用点前后哪些寄存器/栈槽在什么地址被写/被读、证据是什么等级、来自哪里」，
  **不回答「参数是什么」**：不猜参数个数、不给参数命名、不认定调用约定、不追跨块数据流。

## 2. 用户五条要求 → 落地位置

| # | 要求 | 落地 |
|---|---|---|
| 1 | 只给有证据的来源（`.pdata`/CFI/栈槽/调用点前后寄存器定义），逐条标来源与等级；**链接器声明与我方推导必须分开** | 每条证据是 `{level, source, text}`，只属一级；`LEVELS = declared / observed / derived`。`_target_provenance()` 与 `_func_declaration()` 都对「有声明」与「只有推导」走**不同分支**：函数域有 `end` 且来源 ∈ `{pdata, eh_frame_fde, symtab_func, dynsym_func, export, entry}` 才报 `declared`，否则报 `derived` 并在 `text` 里写明缺什么。`counts.evidence` 与 `counts.target_evidence` **分开计数**，不合并成一个"已确定" |
| 2 | 不做 ABI 推断、不猜参数个数与名称；证据不足 abstain 并写缺什么 | 本层没有 `parameters` 字段。每个站点固定带一条 `full_argument_set` abstain（"不判定哪些寄存器/栈槽是参数…缺调用约定证据"）。目标不可静态确定 → `target` abstain；窗口被未解码指令截断 → `window_before/window_after` abstain；栈槽基址被改写 → `slot:[…]` abstain。每条 abstain 都有 `missing` 文本，不写"未知"了事 |
| 3 | 跨块数据流暂不追；若开例外必须先给可验证判据、不许先做后补测 | `_operand_facts()` 只吃 `blk["insns"]`，before/after 都严格在同块内；每站点 `cross_block="not_traced"`，报告顶层 `cross_block={"traced": False, "rule": …本轮没有判据}`。**本轮没有开任何例外** |
| 4 | 调用图三态与新事实层不能互相矛盾；有矛盾单列说明 | `check_consistency()` 用**独立重算**的 `_target_provenance()` 与 `graph.edges` 的 `state` 逐点比对：直接站点必须两边都有且相等、间接站点在事实层不得有 `state`、站点总数必须等于调用图 `call_sites`。结果写进 `report["consistency"]`（`ok/checked/graph_sites/facts_sites/contradictions[]`），渲染头部同步显示。三样本 `checked == sites`、矛盾 **0** |
| 5 | 完成后跑全量 pytest 与九个验证脚本确认零回归 | 见第 7 节（10 个脚本，含新增 `verify_callfacts`） |

## 3. 三级证据的判据（谁能伪造什么）

| 级别 | 唯一来源 | 本层出现的字段 | 判据 |
|---|---|---|---|
| `declared` | 文件/链接器写死的声明 | `section`（目标落在 `.plt*` 节）、`reloc`（`r_offset` → 符号名）、`iat`（槽 RVA → `dll!name`）、`symbol`（`@plt` 后缀）、`function_decl`（`pdata`/FDE/符号表种子） | 只读文件结构，本工具不做任何推断。目标侧 `declared` 只出现在这两个位置：目标节表、目标名字回指 |
| `observed` | 字节事实 | `instruction`（`addr: bytes`）、`thunk_bytes`（单条 `jmp [槽]` 的字节）、`stub_bytes`（桩首 `FF25` 的字节）、`address`（目标地址不在指令集/PLT 节） | 读到字节，未解释语义。"call 目标是 `e8` 后 4 字节"属于地址算术，也记 observed |
| `derived` | 我方推导 | `last_def_in_block` / `first_use_in_block`（同块线性倒扫/顺序扫）、`thunk_shape`（"单条 jmp [导入槽] ⇒ 导入跳板"是形态判定）、`stub_parse`（槽无重定位时只报地址）、`function_start`（启发式种子）、`block_ownership`（按块归属判断函数中部目标） | 换个实现可能变，必须单独标注，不能冒充链接器声明 |

关键分界（实测都能看见）：

- **操作数事实里 `declared` 恒为 0**（三样本 0 / 759 / 759 等）。这是结构性的：一条"调用点前最后一次写 rdi"
  的**字节**是 `observed`，而"这是最后一次写"是 `derived`，不存在任何链接器声明能证明它。
- `cli-64` @`0x1061` → 目标 `0x1000`：目标有已解出指令（`observed`），但函数入口**只有启发式种子**
  → `decoded` 的补充证据是 `derived[function_start]`，**不写成"已声明函数"**。
- `dyn_static` 3 个站点的函数域是 `derived`（`.init` 附近无声明边界，`end` 未知），
  其余 3553 站是 `declared`（`eh_frame_fde`/`symtab_func` 给出 `start..end`）。

## 4. 实测（三样本全量，`rekit callfacts <file> --json`）

| 样本 | 站点 | 直接 | 间接 | before 事实 | after 事实 | abstain | 操作数证据 d/o/v | 目标证据 d/o/v | 函数域 declared/derived | 栈槽事实 | 槽 abstain | 窗口截断 b/a | 一致性 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cli-64.exe | 153 | 98 | 55 | 450 | 309 | 225 | 0 / 759 / 759 | 68 / 133 / 65 | 153 / 0 | 96 | 14 | 3 / 0 | checked 153，矛盾 0 |
| bin_ls.elf | 1141 | 1116 | 25 | 3771 | 2275 | 1230 | 0 / 6046 / 6046 | 1804 / 1116 / 0 | 1141 / 0 | 378 | 14 | 32 / 18 | checked 1141，矛盾 0 |
| dyn_static | 3556 | 3456 | 100 | 10847 | 6356 | 3905 | 0 / 17203 / 17203 | 3451 / 3456 / 402 | 3553 / 3 | 2898 | 81 | 77 / 86 | checked 3556，矛盾 0 |

- **账目对平**：`sites = direct + indirect`；每个直接站点在事实层与调用图层都有 `state` 且相等；
  事实层站点总数 == 调用图 `call_sites`（153/1141/3556）。间接站点在事实层 `state=None`（不冒充已分类）。
- **abstain 分布**（三样本）：

| 样本 | full_argument_set | target | slot:[…] | window_before | window_after | 合计 |
|---|---|---|---|---|---|---|
| cli-64.exe | 153 | 55 | 14 | 3 | 0 | 225 |
| bin_ls.elf | 1141 | 25 | 14 | 32 | 18 | 1230 |
| dyn_static | 3556 | 105 | 81 | 77 | 86 | 3905 |

  `target` 计数 = 间接站点 + 直接但 `unresolved` 的站点（dyn_static：100 + 5 = 105），每类都能对上，
  不存在"有个 abstain 但说不清为什么"。

## 5. 证据样例（逐条可复核）

**(a) PE 导入跳板：声明与推导分开写**　`cli-64.exe` @`0x1428`（`e8` 直接调用，函数域 `pdata` 0x1401..0x164c）

```
目标证据 observed [instruction]  目标 0x2738 有已解出指令（ff 25 d2 0a 00 00）
目标证据 observed [thunk_bytes] 目标函数体是单条 jmp [0x3210]（字节事实）
目标证据 declared [iat]         槽 0x3210 在导入表里 = api-ms-win-crt-stdio-l1-1-0.dll!_read
目标证据 derived  [thunk_shape] 「单条 jmp [导入槽] ⇒ 导入跳板」是我方形态判定
```

名字是链接器写的（`declared`），"这是跳板"是形态判定（`derived`），两者没有合并成一句"已确定"。

**(b) ELF 重定位回指**　`bin_ls.elf` @`0x475a` → `0x42f0`

```
declared [section]    目标 0x42f0 落在 .plt 节（节表声明）
observed [stub_bytes] 桩首指令按 FF25 解出 jmp [0x26d80]（字节事实）
declared [reloc]      槽 0x26d80 有导入重定位 → __assert_fail
```

名字来自 `.rela.plt` 的 JUMP_SLOT，不按节内序号猜。无重定位的静态 PLT 只报
`derived[stub_parse]`「槽 0x… 无重定位/导入名（不按节内序号猜名字）」。

**(c) 栈槽失效 → abstain（本单元唯一的口径升级）**　`cli-64.exe` @`0x1061`

```
abstain [slot:[rsp+16]] 基址 rsp 在 0x1052 被改写（晚于该槽定义 0x1040），
                        槽的实际位置不可判；缺：栈指针/帧基址的值追踪
```

M6-U1 在这里只打 `rsp_modified_before` 提示、仍把那三个槽当事实报出；
本单元改为**先判后报**：基址在"定义点之后、调用点之前"被改写，该槽就不再作为事实，
转 abstain 并写清缺什么。其余正常槽照常报（如 `0x1428` 的 `[rsp+1920] ← 0x1401`）。

**(d) 窗口被未解码指令截断**　`cli-64.exe` @`0x13d1`

```
window.barrier_before = {addr: 0x13bb, reason: "0F 11 SIMD/浮点指令未建模"}
abstain [window_before] 0x13bb 处指令无法给出读写事实（…）；缺：该指令的语义，
                        窗口在屏障处截断，不越过它声称「最后定义」
```

**(e) 目标未解析不猜**　`dyn_static` @`0x403cf8` → `0x0`

```
observed [address] 目标 0x0 不在已解出指令集合内，也不在任何 .plt* 节
abstain  [target]  目标地址既无已解出指令、也无 PLT/导入槽证据；
                   缺：该地址的数据/代码判别与该目标函数的链接器声明
```

## 6. 与调用图 / M6-U1 观察的对账

- **三态一致性**：事实层不复制调用图的结论，而是用同一份 `recdesc` 结果**独立重算**
  每条证据项，再逐点比对 `state` 与 `target`。三样本矛盾 0（`verify_callfacts` E 项）。
  为验证检测能力，`tests/test_callfacts.py` 里注入了两种不一致（篡改 `state`、
  删掉一个站点），都被如实检出——说明这个对账不是"必然通过"的空断言。
- **与 `--observe` 的差异是口径升级，不是回归**：
  - 寄存器结论**逐站点集合相等**（`verify_callfacts` 新增交叉核对：直接比对
    `callgraph --observe` 的 `before_defs/after_uses` 与事实层 `facts` 的寄存器集合）。
  - 槽结论**事实层 ⊆ 旧观察**：三样本 before 事实 464→450 / 3785→3771 / 10928→10847，
    差值 14 / 14 / 81 **恰好等于**各自 `slot:[…]` abstain 数；after 事实 309 / 2275 / 6356
    完全一致。即唯一变化就是"基址被改写的槽从事实降为 abstain"，未新增任何推断。

## 7. 全量回归

- pytest：**364 passed**（339 → 364，新增 `tests/test_callfacts.py` 25 项，exit 0）。
- 验证脚本 **10 个全部 exit 0**：
  `verify_disasm`（分歧 0/环境错误 0）/ `verify_recdesc` / `verify_expr` / `verify_map` /
  `verify_iat` / `verify_fingerprint --all --matrix` / `verify_switchcand` /
  `verify_struct` / `verify_callgraph` / `verify_callfacts`（三样本 PASS）。
- 负向基线不变：三样本 `recdesc` 17 项、`cli-64.exe` 表达式文本 sha256、
  `dyn_static` `0x401870` 文本 sha256 与 `tests/baselines/definite_baseline.json` 逐项相等；
  `build()` 前后 `res` 快照（指令数/块数/stats/cfg counts）完全一致（只读性）。
- 运行环境注记：本机 objdump 需 `LC_ALL=C` 才能打开含中文的绝对路径（否则
  `Illegal byte sequence`），这与本单元代码无关，是 shell 环境差异；日志已按该环境记录。
- 日志：`work/evidence_m6u2_callfacts.log`、`work/evidence_m6u2_pytest.log`。

## 8. 能力边界与不可判清单（如实列出）

1. **不产出参数列表**：本层只有"读写事实"，没有任何"第 N 个参数"的字段。
2. **跨块不追**：分支汇合处准备的参数不会出现；要开例外必须先写出可验证判据并先测后开，
   本轮判据为空（已写入报告 `cross_block.rule`）。
3. **栈槽位置可能不可判**：基址被改写即 abstain（14 / 14 / 81 站），不重算栈帧、
   不做值追踪。
4. **只报同块线性窗口**：窗口内出现未解码指令或未建模隐式读写即截断，
   不越界声称"最后定义"（3 / 50 / 163 处）。
5. **间接调用目标不猜**：目标侧 abstain；寄存器/栈槽的读写事实照常报，
   但**不**据此推断"这是函数指针参数"。
6. **`declared` 只覆盖文件里有的东西**：静态链接/无重定位的槽只有地址，没有名字
   （`derived[stub_parse]`），不作序号猜测；无 `.pdata`/FDE/符号的函数域只能报 `derived`。
