# TASK M6 收口：调用图与跨过程事实层

日期：2026-11-16　状态：✅ 收口（U1 / U2 逐条对账，全量回归零回归）

## 0. 结论摘要

- M6 两个单元（U1 调用图 + U2 参数事实层）**全部达标**，逐条对账见第 2 节。
- "操作数级 declared 证据 = 0" 是**结构性恒等式**，不是缺失也不是 bug，见第 3 节。
- 能力边界：调用图回答"谁调谁、目标属于哪一态"，事实层回答"调用点前后哪些位置被读写、
  证据几分级"；两者都**不回答**"参数是什么"。
- 最后一次全量回归：pytest **364 passed**，10 个验证脚本**全部 exit 0**（退出码见第 6 节）。
- 下一里程碑建议从"三层拼接"起步（还没做，纯拼装），不要直接跳 ABI 推断。

## 1. 输入与产出

| 单元 | 新增文件 | CLI | 交付文档 |
|---|---|---|---|
| M6-U1 | `rekit/callgraph.py` + `tests/test_callgraph.py`(23) + `tests/verify_callgraph.py` | `rekit callgraph`（`--observe` / `--indirect-candidates`） | `outputs/TASK_m6_callgraph.md` |
| M6-U2 | `rekit/callfacts.py` + `tests/test_callfacts.py`(25) + `tests/verify_callfacts.py` | `rekit callfacts`（`--json`） | `outputs/TASK_m6u2_callfacts.md` |

既有 `expr` / `recdesc` / `struct` / `callgraph` 输出**逐字节不变**（未加任何开关）。

## 2. M6 达标逐条对账

### 2.1 U1（调用图 + 保守跨过程观察）

| # | 要求 | 证据 | 结论 |
|---|---|---|---|
| 1 | 直接调用按确定边；间接调用走候选层（默认关闭、单列、带等级），不合并统计 | `counts.call_sites = direct + indirect`（153/1141/3556）；`edges[]` 只含直接边；候选层 `enabled=False` 默认 | ✅ |
| 2 | 观察只报事实，不做 ABI 推断 | 每条事实带 `at`+`bytes`；无参数列表字段；`observe_note` 写明禁止项 | ✅ |
| 3 | 三态区分且占比都报（分母 = 直接调用点） | decoded 63 (64.29%) / 428 (38.35%) / 3049 (88.22%)；plt_or_import 35 (35.71%) / 688 (61.65%) / 402 (11.63%)；unresolved 0 / 0 / 5 (0.14%) | ✅ |
| 4 | 递归与环可识别、渲染有界 | Tarjan SCC 自递归 0/2/15、互递归 0/0/2；渲染 visited + 节点上限 120 + 深度 12，两次逐字节一致 | ✅ |
| 5 | 全量回归零回归 | 见第 6 节 | ✅ |

### 2.2 U2（跨函数参数传递的事实层）

| # | 要求 | 证据 | 结论 |
|---|---|---|---|
| 1 | 只给有证据的来源，逐条标来源与等级；链接器声明与推导分开 | 每条证据 `{level, source, text}` 单级；`counts.evidence` 与 `counts.target_evidence` 分开；操作数 declared 0 / 目标 declared 68·1804·3451 | ✅ |
| 2 | 不做 ABI 推断；不足就 abstain 并写缺什么 | 无参数列表；每站固定 `full_argument_set` abstain；abstain 225/1230/3905 全部带 `missing` | ✅ |
| 3 | 跨块暂不追；例外须先给可验证判据 | `cross_block="not_traced"` + 顶层规则文本；本轮零例外 | ✅ |
| 4 | 与调用图三态不能矛盾，矛盾单列 | `consistency`：checked == sites（153/1141/3556）、矛盾 0；注入两种不一致均被检出 | ✅ |
| 5 | 全量回归零回归 | 见第 6 节 | ✅ |

### 2.3 本次收口（用户五条）

| # | 要求 | 落地 |
|---|---|---|
| 1 | 解释"操作数级 declared 为 0" | 第 3 节（为什么零 / 哪些结论必须 abstain / 怎么防止误读） |
| 2 | 最后一次全量回归，退出码入证 | 第 6 节 + `work/evidence_m6_closeout_pytest.log`、`work/evidence_m6_closeout_scripts.log` |
| 3 | CHARTER/PROGRESS/CHANGELOG 回写（状态/当日行/返工明细/规则编号） | 三个文档已回写；返工明细见第 7 节；M6 规则编号 R59–R65 |
| 4 | 收口汇报：达标、边界、下一里程碑、做不到 vs 还没做 | 第 2/5/8 节 |
| 5 | 环境怪癖写进环境记录 | 第 6.3 节 + PROGRESS 的"环境记录"条目 |

## 3. 为什么"操作数级 declared 证据恒为 0"

**先给结论：这是定义决定的恒等式，不是缺失、不是 bug、不是解析失败。**

### 3.1 declared 的定义与文件能声明什么

declared = "别人写进文件的声明，我们只是读出来"。文件里能被声明的对象只有：

- 节边界（节表）；
- 导入槽 → `dll!name`（PE 导入表 / ELF `.rela.plt` 的 JUMP_SLOT、`.rela.dyn` 的 GLOB_DAT）；
- 函数范围（`.pdata` RUNTIME_FUNCTION 的 Begin/End、FDE 的 initial_location+range、ELF `st_size`）；
- 符号（symtab/dynsym 的 STT_FUNC、导出表）；
- 栈展开规则（CFI/FDE 的 CFA 程序）。

**没有任何一种文件结构声明"这条指令在准备第 N 个参数"或"这是调用点前最后一次写 rdi"。**
`.pdata` / FDE / st_size 只声明函数范围；CFI 的 CFA 规则声明的是"栈帧相对位置怎么算"，
属于展开语义，不是参数身份；DWARF `.debug_info` 才可能声明变量位置，但本轮输入没有
调试段，而且即便有，那也属于"调试信息"，与"链接器声明"是两个来源，不能混为一谈。

### 3.2 一条操作数事实只有两个组成部分

| 组成部分 | 例子 | 等级 |
|---|---|---|
| 指令原始字节 + 地址 | `0x1056: 48 8b fa` | observed |
| "同块内倒扫的第一条写 / 顺序扫的第一条读" | 由本工具的扫描规则得出 | derived |

两者之外**不存在第三个可来自文件声明的部分**。所以 `counts.evidence.declared == 0`
在三样本（0/759/759、0/6046/6046、0/17203/17203）上是结构性的，换任何样本都会是 0。

### 3.3 这个 0 是可证伪的，不是"没实现所以是 0"

- `tests/test_callfacts.py` 有专门断言：任何 `facts[].evidence[]` 的 level 不得为 `declared`；
- `verify_callfacts.py` B 项独立重扫全部证据项，逐条校验来源与等级配对；
- 代码路径上，操作数事实的证据只由两处产生：`observed[instruction]` 与
  `derived[last_def_in_block/first_use_in_block]`，没有第三条分支能写 declared。

如果哪天出现非零，那才是 bug（说明有代码把目标侧证据串到了操作数上）。

### 3.4 因为 declared=0，哪些结论必须 abstain

凡是"身份 / 语义 / 归属"类判断，全部 abstain 并写 missing：

1. **不能说是第几个参数**——缺 ABI/调用约定声明；
2. **不能说这个值来自 caller 的形参**——缺跨过程数据流（本轮跨块不追）；
3. **不能说这个栈槽是参数溢出槽**——缺栈帧布局声明，且基址改写时槽位置本身不可判；
4. **不能说调用点有 N 个参数**——缺参数个数声明；
5. **不能说返回值/调用约定**——本轮完全未建模。

可以报的只有：某位置在什么地址被写/被读、字节是多少、扫描规则的命中位置。
这就是"参数传递的事实层"而不是"参数恢复"的原因。

### 3.5 为什么目标侧 declared 非零（68 / 1804 / 3451）

目标侧确实存在文件声明：目标落在 `.plt*` 节（节表）、槽有导入重定位（→ 名字）、
目标是声明函数入口（`.pdata`/FDE/symtab）。这些是链接器写的，报 declared 是正当的。
**两个计数器分开正是为了防止"把目标的声明当成操作数的声明"**——读者看到
`evidence.declared == 0` 时不应读成"这个样本没有声明信息"，而应读成
"声明信息只存在于目标侧与函数域，不存在于操作数读写事实里"。

## 4. M6 实测总表

### 4.1 U1 调用图三态（分母 = 直接调用点，括号内为占比）

| 样本 | 调用点 | 直接 | 间接 | decoded | plt_or_import | unresolved | 环（自/互） |
|---|---|---|---|---|---|---|---|
| cli-64.exe | 153 | 98 | 55 | 63 (64.29%) | 35 (35.71%) | 0 | 0 / 0 |
| bin_ls.elf | 1141 | 1116 | 25 | 428 (38.35%) | 688 (61.65%) | 0 | 2 / 0 |
| dyn_static | 3556 | 3456 | 100 | 3049 (88.22%) | 402 (11.63%) | 5 (0.14%) | 15 / 2 |

### 4.2 U2 事实层

| 样本 | 站点 | before | after | abstain | 操作数证据 d/o/v | 目标证据 d/o/v | 函数域 declared/derived | 一致性 |
|---|---|---|---|---|---|---|---|---|
| cli-64.exe | 153 | 450 | 309 | 225 | 0 / 759 / 759 | 68 / 133 / 65 | 153 / 0 | 矛盾 0 |
| bin_ls.elf | 1141 | 3771 | 2275 | 1230 | 0 / 6046 / 6046 | 1804 / 1116 / 0 | 1141 / 0 | 矛盾 0 |
| dyn_static | 3556 | 10847 | 6356 | 3905 | 0 / 17203 / 17203 | 3451 / 3456 / 402 | 3553 / 3 | 矛盾 0 |

abstain 构成（full_argument_set / target / slot / 窗口）：225 = 153+55+14+3；
1230 = 1141+25+14+50；3905 = 3556+105+81+163。`target` = 间接站点 + 直接但 unresolved
（dyn_static 100+5），每类都能对上。

## 5. 能力边界（两份，分开写）

### 5.1 调用图（callgraph）

能做：全部已解出 call 指令 → 函数级边；三态归因（每条边带证据文本）；函数级环；
有界渲染；`--observe` 同块窗口事实。

不能做：间接调用目标（只给候选层，且 high 只表示"操作数能静态定位到导入槽"）；
跳板之后的语义；跨节函数（非 `--section` 节）；候选层不并入确定统计。

### 5.2 参数事实层（callfacts）

能做：调用点前后同块内的寄存器/栈槽读写事实，逐条带等级与来源；声明与推导分开计数；
与调用图逐点对账；栈槽失效即 abstain；窗口截断可解释。

不能做：参数个数/名字/调用约定（ABI 推断，明确禁止）；跨块数据流；栈帧重算；
值来源链（无别名/值编号分析）；"这个操作数是不是参数"（统一 abstain）。

## 6. 最后一次全量回归（2026-11-16）

### 6.1 pytest

`python -m pytest -q` → **364 passed**（exit 0，28.89s）。
日志：`work/evidence_m6_closeout_pytest.log`（头部含 python/objdump 版本与环境变量）。

### 6.2 十个验证脚本（退出码入证）

| 脚本 | 参数 | 退出码 |
|---|---|---|
| verify_disasm.py | — | 0 |
| verify_recdesc.py | — | 0 |
| verify_expr.py | — | 0 |
| verify_map.py | — | 0 |
| verify_iat.py | — | 0 |
| verify_fingerprint.py | `--all --matrix` | 0 |
| verify_switchcand.py | — | 0 |
| verify_struct.py | — | 0 |
| verify_callgraph.py | — | 0 |
| verify_callfacts.py | — | 0 |

日志：`work/evidence_m6_closeout_scripts.log`（每个脚本的输出 + 逐行 exit + 汇总）。

负向基线不变：三样本 `recdesc` 17 项、`cli-64.exe` 表达式文本 sha256、`dyn_static`
`0x401870` 文本 sha256 与 `tests/baselines/definite_baseline.json` 逐项相等；
`build()` 前后 `res` 快照一致（只读性）。

### 6.3 环境记录（写进文档，不只留日志）

| 项 | 值 / 现象 | 处置 |
|---|---|---|
| Python | 3.14.0（MSC v.1944 64bit，`python -c "import sys;print(sys.version)"` 实测） | — |
| 控制台编码 | 不设 `PYTHONIOENCODING=utf-8` 时中文输出会 `UnicodeEncodeError` | 所有回归命令前置该变量 |
| objdump | GNU Binutils 2.47（项目内 `m2-task-card/work/tools/binutils-2.47/mingw64/bin`） | 回归前置该目录到 PATH |
| **objdump 中文路径怪癖** | 工程路径含中文，objdump 两个构建（msys64 ucrt64、项目 mingw64）在默认 locale 下报 `could not locate '…': Illegal byte sequence` / `No such file or directory`，**与本项目代码无关** | 运行时设 **`LC_ALL=C`** 后正常（已实测同命令 exit 0）；回归脚本统一带该变量 |
| 文档目录名 | `pack/03_…` 目录名在资源管理器中是 mojibake | 文档用 Python `open(encoding='utf-8')` 读写，不用 Edit 工具直连 |

## 7. 返工明细（M6 两单元合计 13 项：实现 9 / 验收器 2 / 文档 1 / 环境 1）

实现：

1. `recdesc.cfg.calls` 只记块末调用（cli-64 13 vs 实际 153）→ 调用点改为全量扫描
   `e8`/`FF` 并 `expr.decode` 判 family，两个口径单列且注明不合并。
2. ELF 非装载节 `.comment`（addr=0）导致 `section_of(0)` 误判 → `_Ctx` 只收 addr 非零的节。
3. `_symbol_of` 把 `fde@0x…` 当符号名 → 过滤 `fde@`/`range `/`0x` 前缀。
4. `_effects` 把 `lea` 的栈槽当"使用"、把 `mov rax, rbx` 的 rax 当使用 →
   assign 仅当 dst 是 mem 才取地址寄存器；`lea` 只取 `_mem_regs(src)` 不取槽。
5. 观察窗口字段名误导（`before_scanned` 实为窗口指令数）→ 拆为
   `before_insns/after_insns/before_decoded/after_decoded`。
6. 渲染树只从 entry 出发、几乎为空 → roots = entry（有出边）+ 所有 `in_calls==0 and
   out_calls>0`；重复节点文案改为"已展开过：不再重复展开"（DAG 复现不是环）。
7. `callfacts` 槽基址解析用 `rstrip` 脆弱 → 改为 `operand[1:].split("]")[0].split("+")[0]…`。
8. `facts` 计数只统计操作数证据 → 新增 `counts.target_evidence` 单独计数并渲染显示。
9. `_render_observations` 用 `.replace("DD","不")` 脏写法 → 直接写中文。

验收器：

10. `verify_callfacts.py` 里 `CG._Ctx(path, res, path and ".text")` 笔误 → `".text"`。
11. 旧 verify 未覆盖"槽口径升级"与"与 `--observe` 的寄存器结论一致" →
    新增交叉核对（寄存器集合相等、槽 ⊆）与独立基址改写扫描。

文档：

12. `TASK_m6_callgraph.md` 初稿凭记忆写样例（0x26de / 0x30c0 / 虚构观察）→
    实测核对后修正为 0x2690 / 槽 0x30c8 / 真实观察记录。

环境：

13. objdump 默认 locale 打不开中文绝对路径 → 见 6.3，统一 `LC_ALL=C`（不计代码返工）。

## 8. 下一里程碑建议起点

### 8.1 建议：M7-U1「三层拼接」——把图 / 事实 / 伪 C 接到同一调用点

- 输入：`callgraph.edges`（三态）+ `callfacts.sites`（读写事实）+ `struct` 的结构化文本。
- 产出：每个调用点一行——目标三态 + 调用前读写事实（带等级）+ 它落在哪条结构化语句。
- 硬约束：同一调用点在三处的结论必须一致；不一致单列（复用 `check_consistency` 的模式）。
- 意义：**纯拼装、零新推断**，能立刻暴露层间冲突；先把一致性做成机器可复核的，
  再谈数据流，避免"看起来像 C"先行的老问题。

### 8.2 之后（按顺序，不并做）

1. **M7-U2 跨块数据流**：必须先给可验证判据（候选：支配关系 + 块内单赋值 + 无别名写，
   且块入度=1），先写判据与反向测试，再开功能；
2. **M7-U3 参数绑定**：只有在存在调用约定声明来源（PDB / DWARF / 显式修饰名）时才可做，
   否则只能停在"位置事实"。

### 8.3 "结构上做不到" vs "还没做"

| 事项 | 归类 | 依据 |
|---|---|---|
| 无调试信息二进制的参数名/类型 | **结构上做不到** | 信息不在文件里；只能靠外部知识或运行期 |
| 虚表 / 运行期计算出的间接目标 | **结构上做不到（静态）** | 目标值依赖运行期内存内容 |
| 跨块数据流 | **还没做** | 技术上可做，但缺可验证判据与验收标准，按纪律先测后开 |
| 有声明来源时的参数个数/调用约定绑定 | **还没做** | 需要 PDB/DWARF 等 ABI 声明来源；本轮明确禁止 |
| 图 / 事实 / 伪 C 三层拼接 | **还没做** | 纯拼装，无推断，风险最低 |
| 跳转表目标识别 | 已做（候选层 high 才渲染） | `switchcand` + `struct` |
| 跨块窗口外的事实 | **还没做** | 属跨块数据流，同上 |

一句话：**M6 之后，"目标是谁、位置被怎么读写"已经有事实基础；"这些位置意味着什么"
要么缺证据（结构上做不到），要么需要先立判据（还没做）。下一步先拼三层，不碰 ABI。**
