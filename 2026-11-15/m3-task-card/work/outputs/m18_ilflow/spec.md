# M18 .NET IL 控制流与调用关系层（ilflow）口径规格

日期：2026-11-16
上游：M17 `rekit dotnet`（CLI 头 / 元数据表 / 方法体 / IL 边界）。
本层只做两件事：**把 IL 里的 token 解析成可核对的调用目标**，**把分支与异常处理
结构化成块和边**。不做反编译、不加载被引程序集、不反混淆、不碰 NativeAOT。

## 1. 输入与边界

- 输入：M17 报告（`dotnet.build(detail_methods=None, detail_insns=None)`）+
  同一文件的元数据表（`dotnet.open_tables(path)`）。
- 只分析 M17 判定 `status=ok` 且方法体成功、IL 已解出的方法；M17 的
  `undecodable_at` 之后不分析，方法记 `partial=true`。
- 不读目标程序集磁盘文件：即使 AssemblyRef 指向 `mscorlib`，也不加载它。
  外部方法只报“声明指向哪个程序集/类型/成员”，不把另一版本的同名方法当目标。

## 2. token 解析

### 2.1 参与解析的指令

`call`(0x28)、`callvirt`(0x6F)、`newobj`(0x73)、`ldftn`(0xFE06)、
`ldvirtftn`(0xFE07)、`jmp`(0x27)、`calli`(0x29)。

- 前六个的 token 是方法 token：MethodDef(0x06) / MemberRef(0x0A) / MethodSpec(0x2B)。
- `calli` 的 token 是 StandAloneSig(0x11)，是**签名**不是方法 → 未解析，
  原因 `token_kind_mismatch`（要按签名推断调用目标，本轮不推断）。

### 2.2 MethodDef(0x06)

行号在 `1..MethodDef 行数` 内 → `internal`，目标给出 row/name/owner type/RVA/是否有体。
行号越界 → `unresolved / row_out_of_range`。

### 2.3 MemberRef(0x0A)

父由 MemberRefParent coded index 决定：

| 父 | 规则 | 结果 |
|---|---|---|
| TypeDef(0x02) | 在本模块该类型的方法区间里按 `Name` + `Signature` 字节**精确**匹配 | 唯一命中 → internal；有同名但签名不同 → `signature_mismatch`；无同名 → `member_not_found` |
| TypeRef(0x01) | 先解析 ResolutionScope：Module / ModuleRef / AssemblyRef / TypeRef(嵌套) | 根作用域是**本模块**（Module，或 AssemblyRef 行 0）→ 按 TypeDef 规则在本模块找类型再匹配方法；根作用域是别的程序集/模块 → external |
| TypeSpec(0x1B) | 最小解析类型签名，取基类型：GENERICINST(0x15)/CLASS(0x12)/VALUETYPE(0x11) 后的 TypeDefOrRefOrSpec；SZARRAY/ARRAY/PTR/BYREF 递归元素 | 基类型是本模块 TypeDef → 按 TypeDef 规则匹配；基类型是 TypeRef → external；基类型是 VAR(0x13)/MVAR(0x1E) → `bad_parent`；blob 缺失/截断 → `no_signature` |
| ModuleRef(0x1A) | 另一模块的全局成员 | external（module 名） |
| MethodDef(0x06) | vararg 调用站点签名成员 | `unsupported_parent`（不展开） |
| 其它/坏 tag | — | `token_kind_mismatch` |

TypeRef 的 ResolutionScope：

- `Module`（tag 0，行 0）→ 本模块。
- `AssemblyRef`（tag 2，行 0）→ 本程序集（ECMA 约定），按本模块处理。
- `AssemblyRef` 行 > 行数，或名称缺失 → `missing_assembly`。
- `ModuleRef` 行 > 行数 / 名称缺失 → `missing_assembly`。
- `TypeRef`（tag 3）→ 嵌套类型：拼 `Outer+Inner` 后按根作用域判定；链深 > 8
  或成环 → `bad_parent`。

### 2.4 MethodSpec(0x2B)

`Method` 是 MethodDefOrRef coded index：

- 指向 MethodDef → internal（`generic=true`），并给 `generic_arg_count`
  （Instantiation blob 的 compressed 计数；blob 缺失则计数为 None，目标状态不变）。
- 指向 MemberRef → 按 2.3 解析，继承其状态。
- 其它 → `token_kind_mismatch`。

### 2.5 状态与原因（固定集合）

- `status`：`internal` / `external` / `unresolved`。
- `unresolved.reason`：
  `row_out_of_range`、`missing_assembly`、`signature_mismatch`、
  `token_kind_mismatch`、`member_not_found`、`bad_parent`、
  `unsupported_parent`、`no_signature`、`invalid_token`。
- **external 不是 unresolved**：声明已经说明“目标在哪个程序集/类型/成员”，
  只是本轮不加载那个程序集，所以没有 MethodDef 行号。
- 每个 token 结果都带 `resolution_path`（经过的表/行/作用域），便于复核。

## 3. 分支目标

形态：短跳转（br.s/brtrue.s/brfalse.s/比较跳转.s/leave.s，1 字节有符号位移）、
长跳转（同名无 .s，4 字节有符号位移）、`switch`（4 字节计数 + 4 字节/项，相对
switch 下一条指令）。

- 非 switch 目标 = `offset + size + delta`；switch 目标 = `offset + size + delta_i`。
- 目标分类（逐条单列）：
  - `instruction`：目标等于某条已解出指令的 offset；
  - `inside_instruction`：`0 <= target < code_size` 但落在某条指令内部；
  - `outside_method`：`target < 0`、`target >= code_size` 或 `target == code_size`。
- 恒等式：`分支目标总数 = instruction + inside_instruction + outside_method`。
- `leave` 额外检查：目标不得落在**包含该 leave 指令的任一 EH 保护区**内；
  违反记 `leave_target_inside_region`，逐条单列。

## 4. 基本块与边

### 4.1 规则（写死）

- **leader**：
  1. 方法入口 offset 0；
  2. 每个有效分支目标（含 leave、switch 每个 case）；
  3. 每个分支/switch 的下一条指令；
  4. 每个终结指令的下一条指令；
  5. 每个 EH 子句的 try 起止、handler 起止、filter 起点（落在指令边界上才算）。
- **终结指令**：`ret`、`throw`、`rethrow`、`endfinally`、`endfilter`、`jmp`、
  `br`、`br.s`、`leave`、`leave.s`。
- 块 = leader 到下一个 leader（含终结指令）；块尾是最后一条指令的
  `offset+size`。
- 边：
  - 条件分支：`branch`（目标）+ `fallthrough`（下一条）；
  - `switch`：每个 case 一条 `switch`（带 case 序号，重复目标不合并）+ `fallthrough`；
  - `br`/`br.s`：`branch`；`leave`/`leave.s`：`leave`；
  - 块因下一个 leader 而结束时：`fallthrough`；
  - `ret/throw/rethrow/endfinally/endfilter/jmp`：无后继边。
- 不可达块不丢弃：从入口 BFS，`reachable_from_entry` 逐块标注；handler/filter
  入口若只能由异常派发到达，标 `entry=eh_handler/eh_filter` 且
  `reachable_from_entry=false`。

### 4.2 与 x86 那套的差异（不能照搬）

- IL 是**栈式**：没有标志位、没有隐式寄存器；条件分支的操作数来自求值栈，
  块划分不依赖标志位活跃性。
- `switch` 是**绝对目标表**，不是 x86 的跳转表指针；表项直接是 IL offset。
- `leave` 不仅跳转，还**退出受保护区**并在运行时执行相应 finally；目标必须
  在保护区外。不能像 x86 `jmp` 那样只看目标。
- `endfinally`/`endfilter` **没有静态后继**：它们把控制权交回运行时（继续
  展开或回到派发器），不存在一条可声明的目标边。
- EH 区域是**声明**（子句表），不是从指令模式推断的；块必须在区域边界切开，
  否则一个块会同时属于 try 和 handler，`regions` 不唯一。

## 5. 异常处理建模决策

**建模成结构信息，不建模成边。** 理由：

1. handler 入口没有分支 token 指向它，它由运行时按异常类型/子句顺序派发；
2. finally/fault 在 `leave` 或异常展开时被运行时调用，IL 里没有 try→finally 的边；
3. filter 是否进入 handler 取决于 filter 代码的运行时返回值；
4. 若强行加 try→handler/finally 边，会把“运行时可能到达”伪装成“静态跳转”，
   污染可达性与块入度。

报告给出：子句 id、kind（catch/filter/finally/fault）、try/handler/filter 的
声明区间、catch 类型 token 的解析结果、嵌套深度、边界是否落在指令边界上；
并单列 `leave` 退出检查。边里只有 `branch/fallthrough/switch/leave` 四类。

## 6. 分母先行

所有比例都在分母之后；分母为 0 时比例写 `None`。恒等式：

```
有体方法 = analyzed + partial + empty
分支目标 = instruction + inside_instruction + outside_method
调用 token = internal + external + unresolved
EH 子句   = Σ(kind: catch/filter/finally/fault/unknown)
基本块    = reachable + unreachable
边        = Σ(kind: branch/fallthrough/switch/leave)
```

分母清单：方法数（M17 透传）、有体方法、已分析方法、部分分析（IL 不可解）、
分支指令数（按短/长/switch/leave 分）、分支目标数（按落点分）、switch 数与
case 数、调用指令数（按 opcode 分）、token 数（按表/状态/原因分）、TypeRef
父解析数、EH 方法数/子句数（按 kind 分）、块数/边数/不可达块数。

## 7. 报告结构

顶层：`schema/path/status/reason/assembly/denominators/scope/caliber/caveats/
cross_layer/limit/methods`。

每个存储方法：`row/token/name/owner_row/owner_type/code_size/instruction_count/
partial/undecodable_at/branches/branch_sites/call_sites/blocks/edges/eh/
reachability`。

- `branch_sites`：offset/opcode/form/next/targets（每项含 value、check、命中/包含指令）。
- `call_sites`：offset/opcode/token/token_table/status/reason/target/external/detail。
- `eh`：子句结构（见 §5）。
- `blocks`：start/end/insns/terminator/regions/entry/reachable_from_entry/partial。
- `edges`：from/to/kind/case。

`--limit N` 只控制**存储**的方法数，不影响任何分母。

## 8. 独立证伪与 DoD

1. `tests/verify_ilflow.py` 用 **dncil** 独立解码每条分支操作数、独立算目标，
   与 `branch_sites` 逐条比对；用 **dnfile** 独立读 MethodDef/MemberRef/TypeRef/
   AssemblyRef 行，核对 internal 目标名、external 程序集名、unresolved 行越界。
2. 字节级可失败自证：改分支位移 +1 → 必须出现 `inside_instruction`；改调用 token
   行号到越界 → 必须 `row_out_of_range`；改 MethodDef token 行 → 内部目标名变化
   必须被 dnfile 比对抓住。
3. 真实样本全量：`mscorlib.dll`（29,257 方法）与 `System.Console.dll`（433 方法）
   跑完整分母，不自证。
4. 回归：`pytest tests -q` 全绿；全部 `verify_*.py` PASS。

DoD：
- token 三态分母齐全且恒等式成立；未解析原因逐类计数，无“猜”；
- 分支目标四类落点（instruction/inside/outside/switch case）逐条可查；
- 块规则与 x86 差异写在报告 `caliber` 与本文；
- EH 建模选择有理由，`leave`/`endfinally` 语义明确；
- 外部来源能重算目标；自证能失败。
