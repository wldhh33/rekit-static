# M18 .NET IL 控制流与调用关系（ilflow）· 任务卡

- 日期：2026-11-16
- 上游：M17 `dotnet.py`（.NET 程序集结构层，声明可读）
- 本单元：在已声明的 MethodDef / 方法体 / IL 指令边界之上，回答四个问题
  ① 调用指令的 token 指向谁（本模块 / 外部程序集 / 未能解析且为什么）；
  ② 分支（短/长/switch）的目标是否落在真实指令边界；
  ③ 基本块与块间边是什么（不得照搬 x86 规则）；
  ④ 异常处理子句如何影响控制流（建模成边还是单列结构，并给理由）。
- 新增：`rekit/ilflow.py`、CLI `rekit ilflow`、`tests/test_ilflow.py`、`tests/verify_ilflow.py`
- 规则：R115–R119（见 §9）

---

## 1. 中断前已完成 / 本次补齐（如实分列）

### 1.1 中断前留下的三件半成品，逐件定性

| 文件 | 中断时状态 | 本次判定 | 处置 |
|---|---|---|---|
| `rekit/ilflow.py` | 实现已成型（token 解析、分支检查、块/边、EH 声明、分母恒等式、CLI），26 项单测通过 | **可用，但从未被真实比对过**：它的正确性只由受控样本的单测支撑，没有一条真实样本上的独立证伪 | 保留实现，不改口径；补真实样本全量证伪 |
| `tests/test_ilflow.py` | 26 项全部通过 | **可信但覆盖有限**：只覆盖 FlowSample/FilterSample 两个受控样本与 CLI 契约；未覆盖 switch、未覆盖真实程序集 token 解析 | 保留不动；真实样本比对交给 verify_ilflow |
| `tests/verify_ilflow.py` | 会崩溃/会空对空 PASS | **不可信，必须重写**：见下 1.2 三条硬伤 | 重写比较链路；旧日志改名保留 |

### 1.2 旧 verify_ilflow.py 的三条硬伤（逐条证据）

1. **空比对照样 PASS**：旧脚本把 `ilflow` 报告里的“方法摘要”直接喂回 `_analyze_method`，
   而该函数只认 `m["body"]["code_off"]`；摘要里没有 `body` 键 → 每个方法都被
   `if m.get("code_off") is None: continue` 跳过 → 分支比对打印
   `0 个方法 / 0 个目标（全量）；全部一致` 并判 PASS。EH、token 两段同理。
   **空对空不是通过**，这是本次重写的首要原因。
2. **dncil 分支目标基准算错**：dncil 的 `ins.offset` 与分支操作数**都相对方法体切片
   起点（含 tiny/fat 头）**，旧脚本只把 `ins.offset` 减了 `header_size`，没减操作数。
   FlowSample 的 `brfalse` 目标被算成 `31` 而不是 `19`，即便跑起来也会全量假失配。
   （实测：`Guarded`/`Loop` 的方法体头 12 B。）
3. **dnfile 缺表直接崩**：dnfile 对行数为 0 的表**不创建属性**。FilterSample 没有
   MethodSpec/MemberRef/TypeSpec 行，`md.MethodSpec` 抛 `AttributeError`，
   旧脚本在第一个真实样本上即退出，从未产生有效结论。

旧证据日志 `evidence_m18_verify.log` 里那些 `[PASS] ... 0 个方法 / 0 个目标`
就是上述空比对产物。**已改名 `evidence_m18_verify_broken.log` 保留**，不作为本单元证据；
权威证据为 `evidence_m18_verify.log`（重写后）与 `evidence_m18_ilflow.json`。

### 1.3 本次补齐

- 重写 `verify_ilflow.py`：全量聚合对账（分支形态/目标落点/EH/调用指令/token 表）
  + 存储方法逐条对账 + 五项可失败自证 + 空比对一律 FAIL。
- 用 dncil 全量对拍四样本，**未发现 `ilflow.py` 的实现缺陷**（见 §6）；
  期间修正的是校验器自身三处（偏移口径、缺表、空比对），按 R75 记为“校验器侧修复”。
- 重生成四样本证据日志，跑全量回归并回写 CHARTER/PROGRESS/CHANGELOG。

---

## 2. 口径（判据先写、实现照做）

### 2.1 token 解析（§8-1/§8-9）

| token 表 | 规则 | 结果状态 |
|---|---|---|
| `0x06` MethodDef | 行号 ∈ [1, MethodDef.rows] → 本模块方法，带 owner TypeDef 全名 | `internal` |
| `0x0A` MemberRef | 按父 `Class` 分派：TypeRef（外部声明）/ TypeDef（本模块）/ TypeSpec（解基类型再分派）/ MethodDef（不支持，明确报）/ 其它 | `internal` / `external(member,type,assembly)` / `unresolved` |
| `0x2B` MethodSpec | `Method` 列可指 MethodDef 或 MemberRef；泛型实参个数从 `Instantiation` blob 的 `0x0A GenArgCount` 读 | `internal` / 按底层 MemberRef 分派 |
| `0x11` StandAloneSig | `calli` 的签名 token，不是方法 | `unresolved / token_kind_mismatch` |
| 其它表 | 不认识的 token 表 | `unresolved / token_kind_mismatch` |

- 未解析原因**逐类计数、不合并**：`method_missing`（dnfile 无该行）、
  `row_out_of_range`（行号越过表行数）、`bad_parent`（TypeSpec 父不是名义类型，
  如 `PTR/SZARRAY/VAR`）、`unsupported_parent`（MemberRef 父为 MethodDef）、
  `token_kind_mismatch`（token 表不是方法表）。
- `bad_parent` 是**三类之外的必要补充**：规范只点名“缺被引程序集/签名不匹配/token
  类别不符”，但 `MemberRef` 的父可以是 `TypeSpec` 且其基是 `PTR/SZARRAY/VAR`，
  没有名义宿主可命名。归到“签名不匹配”是错误归因，故单列并在 §7 说明。
  本轮 mscorlib 20 条全部是该类（签名前缀 `0x0F/0x13/0x1D`），不是缺程序集。

### 2.2 分支目标（§8-2）

- 分支操作数是**相对下一条指令**的位移；`switch` 是 `N` 个 4 字节偏移，Base 为
  switch 指令之后。
- 落点三分类，互斥：
  - `instruction`：目标 ∈ 已解出指令起点集合；
  - `inside_instruction`：0 ≤ 目标 < code_size 但不是指令起点；
  - `outside_method`：目标 < 0 或 ≥ code_size。
- `inside_instruction` / `outside_method` **逐条单列**，不截断、不修正；
  本轮四样本 `targets_total = 52,837+599+6+5`，越界 **0**。
- switch：`switch_count` 与 `switch_cases` 分开报；mscorlib 234 条 switch / 2,008 个 case
  全部落在指令边界。

### 2.3 基本块划分（写死，§8-3）

Leader 集合：

1. 方法体第一条指令；
2. 所有**落在指令边界上的**分支目标（含 switch case）；越界目标不切块（已单列）；
3. 条件/无条件分支、`leave`、`switch` 的**下一条**指令（fallthrough）；
4. 每条 EH 子句的 `try_start / try_end / handler_start / handler_end / filter_start`
   若落在指令起点，则为 leader。

终结符分两层，写死：

- **不终结（仍有 fallthrough）**：条件跳转（`brtrue/brfalse/beq/...` 及其 `.s` 形式）、
  `switch`（switch 只把各 case 作为 switch 边，另补一条 fallthrough）；
- **终结（不再顺序连接）**：`br/br.s`、`leave/leave.s`、`ret`、`throw`、`rethrow`、
  `endfinally`、`endfilter`、`jmp`。
- `call/callvirt/newobj` 不终结块（IL 是栈式语义，本层不建模求值栈）。

边的种类只有四种：`fallthrough`、`branch`（条件/无条件的 taken 边）、`switch`、`leave`。
`leave` 的目标是指令地址而非 token，故单独成类，便于回答“离开保护区去了哪”。

### 2.4 与 x86 CFG 的本质差异（§8-3）

| 维度 | x86-64（recdesc） | IL（本层） |
|---|---|---|
| 指令语义 | 寄存器/内存操作数，长度由前缀+ModRM+SIB 决定 | 栈式，无寄存器；长度由 opcode + 内联操作数决定 |
| 分支目标 | 相对/绝对/RIP 相对，寄存器间接 jmp 目标不可判定 | **只有**相对位移与 switch 表；无寄存器间接跳转 → 不存在“目标不可判定” |
| 调用 | call 有绝对/相对/间接，需查导入/PLT | call 的 token 是元数据行号，直接查表；`calli` 才走签名 |
| 函数边界 | `.pdata`/FDE/`st_size`/`gopclntab`，可缺失 | MethodDef.RVA + 方法体头 `code_size`，**总是声明** |
| 异常 | SEH/C++ EH 在二进制里是数据+运行时约定，没有一等公民表示 | EH 子句是方法体头的正式结构（tiny 无、fat 附加节），有明确保护区/处理区 |
| 不可解码 | 数据被当指令、VEX 弃权等 | 仅当 opcode 未知/操作数被截断；本轮四样本 0 个部分方法 |

因此本层**没有**“间接目标不猜”“跨函数边”“疑似边”这些 x86 概念；对应位置换成
“token 不解析的原因分类”和“EH 子句声明”。

### 2.5 EH 的建模选择（§8-4，写死并给理由）

**选择：EH 单列为结构信息，不建模成 CFG 边。**

理由：

1. EH 子句声明的是“哪段代码（try）由哪段代码（handler/filter）接管”，接管发生在
   **运行时抛出异常**时，不是指令流里的静态转移；没有一条 IL 指令“跳到 handler”。
2. 若把 try→handler 连成边，会把“正常路径可达”与“异常路径可达”混为一谈，
   块的可达性、后支配、结构化输出全部失真（x86 侧正是因此把异常边单列）。
3. 例外是 `leave`：它是静态指令，必须建边，但要额外检查它是否**落进**保护区/
   handler/filter 内部或方法外——本轮四样本 `leave_into_region / leave_exits_finally /
   leave_in_filter = 0/0/0`，一旦非 0 会逐条单列。
4. EH 边界与范围非法（`try_end < try_start`、偏移不在指令边界）单列为
   `eh_bad_boundary / eh_bad_range`，本轮 0/0；不静默丢弃。

`filter` 子句的 filter 区起点（`filter_start`）单独保留，`filter` 与 `catch/finally/fault`
在 `eh_by_kind` 中分别计数。

---

## 3. 分母先行（§8-5，四样本实测）

| 样本 | 方法总数 | 有体 | 分析 | 部分 | 空体 | 方法错误 | 调用点 | internal | external | unresolved（原因） |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| FlowSample（csc 受控） | 20 | 19 | 19 | 0 | 0 | 0 | 17 | 8 | 9 | 0 |
| FilterSample（ilasm 受控，filter/fault/calli） | 5 | 5 | 5 | 0 | 0 | 0 | 2 | 1 | 0 | 1（`token_kind_mismatch`：`calli` 的 StandAloneSig） |
| System.Console.dll（CoreCLR 7.0.20） | 433 | 396 | 396 | 0 | 0 | 0 | 1,133 | 572 | 561 | 0 |
| mscorlib.dll（Framework 4.0.30319） | 29,257 | 25,315 | 25,315 | 0 | 0 | 0 | 93,194 | 93,174 | 0 | 20（`bad_parent`） |

| 样本 | 分支指令 | switch 条/case | 目标总数 | instruction | inside | outside | decode_error | EH 子句 | catch/filter/finally/fault |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| FlowSample | 6 | 0 / 0 | 6 | 6 | 0 | 0 | 0 | 3 | 2/0/1/0 |
| FilterSample | 5 | 0 / 0 | 5 | 5 | 0 | 0 | 0 | 2 | 0/1/0/1 |
| System.Console | 596 | 1 / 4 | 599 | 599 | 0 | 0 | 0 | 23 | 3/0/20/0 |
| mscorlib | 51,063 | 234 / 2,008 | 52,837 | 52,837 | 0 | 0 | 0 | 2,164 | 692/0/1,465/7 |

| 样本 | 块 | 边 | fallthrough/branch/leave/switch | 不可达块 | EH 边界/范围非法 | leave 进保护区/出 finally/在 filter |
|---|---:|---:|---|---:|---:|---:|
| FlowSample | 30 | 11 | 5 / 4 / 2 / 0 | 3 | 0 / 0 | 0 / 0 / 0 |
| FilterSample | 15 | 8 | 3 / 1 / 4 / 0 | 6 | 0 / 0 | 0 / 0 / 0 |
| System.Console | 1,372 | 1,245 | 646 / 569 / 26 / 4 | 63 | 0 / 0 | 0 / 0 / 0 |
| mscorlib | 108,267 | 107,765 | 54,928 / 47,972 / 2,857 / 2,008 | 5,058 | 0 / 0 | 0 / 0 / 0 |

- 方法级恒等式全部成立：`methods_total = with_body + 无体`；
  `with_body = analyzed + partial + empty + errors`；`call_total = internal + external
  + unresolved`；`branch_total = targets 条数（switch 按 case 展开）`；
  `targets_total = 三类落点之和 + decode_error`；`eh_clauses = eh_by_kind 之和`；
  `blocks_total = reachable + unreachable`；`edges_total = 四类边之和`。
- 不可达块来自 `ret/throw` 之后的对齐 `nop` 或 EH handler 只有入口可达的声明区，
  未做“删除”处理，原样计入并单列。

---

## 4. 独立来源证伪（§8-6）

期望值**不取自被测实现**：

- **分支 / EH / 调用指令 / 基本块**：`dncil` 独立解码方法体并**按写死规则独立重算块、边、
  可达性**（不调用被测实现）。全量聚合对账覆盖 **25,735 个有体方法**、
  **51,435 个非 switch 目标 + 2,012 个 switch case**、**2,192 条 EH 子句**、
  **94,346 条调用指令**、**109,684 块 / 109,029 条边**；逐条明细比对覆盖报告存储的方法
  （受控样本全量 24 个方法 / 45 块；真实样本各前 2,000 个有体方法，Console 全量 396 个）。
- **token**：`dnfile` 独立读表（MethodDef/MemberRef/MethodSpec/TypeRef/TypeDef/
  AssemblyRef），核对行号、名、宿主、外部类型与程序集、MethodSpec 底层行与泛型实参个数；
  对存储方法的**每个调用点**比对（去重按 token，因解析只依赖 token+模块表）。
- **未解析行号**：`row_out_of_range` 的 token 行号必须真的越过 dnfile 对应表行数。
- **口径修正（R115）**：dncil 的 `ins.offset` 与分支操作数都含方法体头，统一减
  `header_size`；EH 偏移已是 code-relative，`filter_start=-1 → None`。该换算只存在于
  校验器侧，被测实现自行从指令字节算相对位移，二者不共用函数。

### 4.1 可失败自证（verify `selfproof`，全部实测检出）

| 注入 | 期望 | 实测 |
|---|---|---|
| 干净输入分支 | 一致 | PASS |
| 分支目标 +1（落到指令内部） | 检出 `inside_instruction` | 检出 |
| 外部类型名改一字 | dnfile 比对失败 | 检出 |
| 删一条 EH 子句 | 结构不一致 | 检出 |
| 删一个基本块 | 块/边不一致 | 检出 |
| 调用 token 改越界行 `0x0AFFFFFF` | `row_out_of_range` | 检出 |
| MethodDef token 行 1→2 | 目标名必须随 dnfile 第 2 行变化，且 ≠ 第 1 行 | 检出 |
| 空比对（分母 0） | **判 FAIL** | 判 FAIL |

---

## 5. 声明可读 vs 依赖推断（§8-6 的边界回答）

- **声明可读**：类型/方法归属（TypeDef/MethodDef 表）、方法体位置与大小（M17 已证伪）、
  token 指向的表行、EH 子句声明、分支位移字节、指令边界（M17 已用 dncil 全量证伪）。
- **依赖规则推导（不是命名/类型推断）**：基本块与边、可达性、`leave` 去向、
  分支落点三分类。全部只由“已声明指令流 + ECMA-335 固定 opcode 表”机械推出，
  每条都可回指到具体 IL 偏移。
- **本轮明确不做**：求值栈/类型推断、参数与局部变量命名、`calli` 签名语义、
  异常传播路径、反编译 C#、反混淆/壳识别、NativeAOT/ReadyToRun。
  这些位置一律 `abstain` 或缺省，不用“看起来合理”的结论补齐。

---

## 6. 本轮发现与修复（只记真实发生的）

1. **实现侧修复 1 处（真实缺陷）**：`COND_BR` 把无条件 `br/br.s` 也算成条件跳转，
   导致每条 `br/br.s` 多出一条**虚假 fallthrough 边**，并可能把本不可达的块误判为可达。
   独立切块对拍在 Console（+83 条假边）与 mscorlib（+8,258 条假边、3 个块可达性反转）
   上把它抓出。修法：`COND_BR = (SHORT_BR | LONG_BR) - UNCOND`；
   新增单测守卫“从 `br.s` 块出发只能有 taken 边”。
2. **校验器侧修复 3 处**：
   ① 空比对 → 改为分母为 0 即 FAIL；
   ② dncil 分支操作数漏减 `header_size` → 修正后四样本零失配；
   ③ dnfile 缺表属性访问 → 全部 `getattr`，并对嵌套类型用 NestedClass 表独立拼全名。
3. **R75 的应用**：首次跑 verify 时 `eh_bad=False`（删子句没被抓到）不是实现错，
   而是自证脚本拿错了对比对象；按 R75 先怀疑校验器，修正后自证转 PASS。
4. **数字变化（R72/R105）**：修复后 `edges_total` 与 `unreachable_blocks` 变化，
   `branch/call/EH/token` 数字**全部不变**：
   Console 边 1,328 → 1,245（fallthrough 729 → 646），mscorlib 边 116,023 → 107,765
   （fallthrough 63,186 → 54,928），Flow 边 12 → 11；mscorlib 不可达块 5,055 → 5,058。
   变化原因**唯一**是无条件 `br` 的假 fallthrough 边被删除，判据没有放宽、阈值没有调整。

---

## 7. 已知边界（如实披露）

- **mscorlib 的 20 条 `bad_parent`**：TypeSpec 父为 `PTR/SZARRAY/VAR` 等非名义类型，
  没有类型名可报；这是结构边界，不是缺被引程序集。
- **mscorlib external = 0**：Framework mscorlib 的 TypeRef 表为 0 行，
  跨程序集调用在本样本上不存在；**不能**据此推断“本层不会报 external”——
  System.Console 的 561 条 external 是反例。
- **EH 不建边**：异常传播路径、finally 的重复执行语义、filter 的两阶段执行
  均不在静态指令流内，本层不回答；只回答“声明了哪些区、静态 `leave` 去了哪”。
- **求值栈未建模**：`dup/swap`、栈上类型、`calli` 的真实签名不在本单元范围。
- **真实样本逐条明细为抽样**：全量聚合对账覆盖全部有体方法，逐条目标/EH/token 明细
  覆盖前 2,000 个有体方法（受控样本全量）；抽样上限在输出中显式打印。
- **受控样本的局限**：FlowSample 由 csc 生成，FilterSample 由 ilasm 手工编写，
  只覆盖两套工具实际生成的子集，不代表任意程序集。

---

## 8. 回归（零失败）

- `python -m pytest -q` → **554 passed**（M17 528 + ilflow 26），日志 `evidence_m18_pytest_all.log`。
- `python tests/verify_ilflow.py` → **41 项检查全 PASS**（每样本 9 项 + 自证 1 项），
  退出码 0，日志 `evidence_m18_verify.log`、机器证据 `evidence_m18_ilflow.json`。
- 全部 `tests/verify_*.py`（21 个）逐脚本执行：20 个 exit 0；
  `verify_fingerprint.py` 需按 E9 口径带 `--all --matrix`（无参数 exit 2 是 argparse
  的用法错误，不是回归失败），带参重跑 exit 0。汇总 `evidence_m18_verify_all.log`。

---

## 9. 新增规则

- **R115**：IL 分支目标与指令偏移的基准必须写死——dncil 的 `offset`/操作数含方法体头，
  校验器统一减 `header_size`；EH 偏移本身 code-relative，`filter_start=-1 → None`。
  校验器与被测实现不得共用同一换算函数。
- **R116**：IL 基本块终结符必须分两层：条件跳转与 `switch` 不终结（保留 fallthrough）；
  `br/br.s`、`leave/leave.s`、`ret/throw/rethrow/endfinally/endfilter/jmp` 终结且无后继；
  `call/callvirt/newobj` 不终结；EH 边界必须切块；越界分支目标不切块但必须单列。
- **R117**：EH 只单列结构信息、不建 CFG 边（运行时异常传播不是静态转移）；
  `leave` 是静态转移必须建边，且必须检查是否落进保护区/handler/filter 或方法外，
  非 0 逐条单列；EH 边界/范围非法单列计数，不得静默。
- **R118**：token 未解析原因必须可追问到表行与原因分类（`method_missing` /
  `row_out_of_range` / `bad_parent` / `unsupported_parent` / `token_kind_mismatch`）。
  `bad_parent` 是三类规范分类之外的必要补充（TypeSpec 父非名义类型），
  不得为凑三类改归因为“签名不匹配”。
- **R119**：任何对拍的分母为 0 一律 FAIL（空对空不等于通过）；
  校验器的偏移/边界口径必须在文档与代码同时写死，并配可失败自证
  （空比对、目标+1、外部名改字、删 EH 子句、删基本块、token 越界、MethodDef 行变化）。
