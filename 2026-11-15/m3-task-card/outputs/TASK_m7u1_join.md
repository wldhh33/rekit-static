# TASK M7-U1：三层拼接（调用图 / 参数事实层 / 结构化文本）

日期：2026-11-16　状态：✅ 完成（用户五条要求逐条落地；全量回归零回归）

新增文件：`rekit/sitejoin.py`、`tests/test_sitejoin.py`（18 项）、`tests/verify_sitejoin.py`；
CLI：`python -m rekit.cli sitejoin <file> [--json]`。
**未修改任何既有模块**（callgraph / callfacts / struct / expr / recdesc 一行未动，见 §8 只读证明）。

---

## 1. 输入与边界

- 输入三层，全部只读：
  - `callgraph.build()` 的 `edges[]`（直接调用，带 `from / to / state`）；
  - `callfacts.build()` 的 `sites[]`（全部调用点，带 `from / bytes / call_kind / function / block / target / state`）；
  - `struct` 结构化文本（`structure_function` 的块节点：`block / lines / term`）。
- 本层不产生任何新判断：不推断 ABI、不猜参数个数与名称、不追跨块数据流、不补目标。
- 只拼接 + 对账 + 把不一致单列。间接调用在调用图里没有确定边（候选层默认关闭），图侧记 `indirect_no_edge`，不算冲突。

## 2. 对齐键：选什么、为什么（要求 1）

**主键 = 调用指令的虚拟地址（三层记录里的 `from`）。**

理由（可复算，不依赖任何一层的文本格式）：

1. 三层同源于同一份 `recdesc` 结果，指令边界按地址唯一确定；图与事实层都直接带 `from`，不需要任何换算。
2. 地址是字节事实（`observed`），不是某层的推导结论。选"层内序号"或"文本行号"都会把某一层的错位传染成键错位。
3. 唯一性可机械核账：`keys = |edges.from ∪ sites.from|`，重复即报（见下）。三样本实测 `keys = 153 / 1141 / 3556`，`duplicate_keys = 0`。

**结构化侧的特殊处理。** 结构化文本（`expr` 渲染的伪 C）**不带指令地址**，只有块号与行文本。因此结构化侧用
**(函数, 块起始地址) + 块内第 j 个调用** 回指主键：

- `j` 由**本块已解出 call 按地址排序**的顺序确定（与图/事实同源），**不用事实层站点顺序** ——
  否则下层漏 call 时会连带把文本行号错位，把"下层漏"误判成"文本定位错"；
- 行序 = 调用语句行 + 指向 call 指令的 `/* abstain @0x… */` 注释行（调用可以作为块终结指令，
  所以 `lines`（body）与 `term` 两段都要看，且记录 `slice` 标注行号属于哪一段）；
- 三重机械校验，任一不过就报冲突、不猜行号：
  ① 块内相关行数 == 块内应然调用数；② 直接调用的文本目标 `sub_0x…` == 事实层 `target`；
  ③ 行号能落回该块第 j 行的原文（`line_text` 与块内行逐字节相等，验证脚本 B 项复核）。

**键重复的处置。** `recdesc` 允许块重叠，同一地址便可能出现在两个块。此时**不合并、不取其一**，
报 `duplicate_key`（`data_anomaly`），要求回 recdesc 复核。三样本实测 0 例。

**键覆盖的独立账（本轮新增）。** 主键只覆盖"两层都记了的地址"，无法发现"两层都漏了"。
因此本层另从已解出指令里**独立枚举 call**（按"跳过前缀后的 opcode"判定，前缀含 REX `0x40-0x4f`、
地址长度 `0x67`、段前缀等），账目为：

```
decoded_calls == keys + 两层都漏(call_site_missing) + 0 多出
```

三样本实测 `153=153+0`、`1154=1141+13`、`3609=3556+53`（§6）。这条独立账是本轮唯一新增的判据来源，
它不复用 `callgraph._call_insns`，避免"用被检查者检查自己"。

## 3. 对账规则（要求 2）

逐键比对四组结论，**不一致一律单列**，不以任何一方为准：

| 维度 | 不一致时 | 
|---|---|
| 所属函数 | `function_mismatch` |
| 直接调用目标状态 | `state_mismatch` |
| 直接调用目标地址 | `target_mismatch` |
| 图有边/事实无站点，或反之 | `facts_site_missing` / `graph_edge_missing` |
| 操作数事实出现 declared 级证据 | `operand_declared`（M6-U2 的结构性恒等式被破坏） |
| 结构化侧定位失败/目标不符/行数不符 | `struct_block_missing` / `struct_line_unmatched` / `struct_line_target` / `struct_line_count_mismatch` |
| 已解出 call 两层都没记录 | `call_site_missing` |
| 站点/边对应的指令不是 call | `facts_site_not_call` / `graph_edge_not_call` |

每条冲突记录固定带 `{kind, attribution, key|(function,block), detail}`，`detail` 必须写出可比对的字段
（地址、字节、两个值），**不允许只写"疑似不一致"**。

归因只有三类：

- `layer_bug`：两层的同一事实结论不同，至少一层有误；单列待查，不取其一；
- `caliber_difference`：覆盖范围/粒度本就不同，不是错误（如结构化层只覆盖 declared 函数）；
- `data_anomaly`：输入数据异常（同一地址多块），需回 recdesc 复核。

## 4. 实测（三样本）

| 样本 | 键 | 唯一/重复 | 已解出 call | 两层都漏 | 覆盖 | 事实层站点 | 图直接边 | aligned | 函数未结构化 | 冲突（硬/口径） |
|---|---|---|---|---|---|---|---|---|---|---|
| cli-64.exe | 153 | 153 / 0 | 153 | 0 | 完整 | 153 | 98 | 153 | 0 | 0 / 0 |
| bin_ls.elf | 1141 | 1141 / 0 | 1154 | 13 | 有缺口 | 1141 | 1116 | 1141 | 0 | 13 / 0 |
| dyn_static | 3556 | 3556 / 0 | 3609 | 53 | 有缺口 | 3556 | 3456 | 3553 | 3 | 53 / 3 |

- **cli-64 全部 153 个调用点三层齐、零冲突**，是"对齐规则本身正确"的正样本。
- bin_ls / dyn_static 的硬冲突全部是 `call_site_missing`，且是**同一个下层根因**（§6），不是拼接层的定位错误：
  这两样本的 1141 / 3556 个已记录站点**全部 aligned，定位失败 0**。
- dyn_static 的 3 条 `struct_function_absent` 是口径差异：`0x403cf8 / 0x40453b / 0x421fde` 所属函数
  `not_declared`（结构化层默认只覆盖 declared 函数），不是 bug，也不静默丢弃。

样例（cli-64）：

```
0x001061  direct   graph=decoded        facts=decoded        struct=block:第 10 行
0x001167  direct   graph=plt_or_import  facts=plt_or_import  struct=label:第 3 行
0x001024  indirect graph=indirect_no_edge facts=None          struct=block:第 1 行
```

## 5. 冲突归因的实现纪律（要求 2 的"不许静默"）

- 冲突列表**不按种类去重**：同一根因影响多少个调用点就报多少条，每条带自己的地址。
- 硬冲突与口径差异**分开计数**（`hard_conflicts` / `caliber_differences`），汇报时分别给数。
- `links[]` 保留全部键的三层原样记录（含 `struct.line_text`），便于人工复核；冲突只是索引，不替换原文。
- 归因不由文本猜测决定：`call_site_missing` 的 `detail` 写出"该地址的原始字节、跳过多少前缀、opcode 是什么"，
  验证脚本再独立重算一次（§7-A），确保归因可复现。

## 6. 本轮发现的真实缺陷（下层，未在本单元修）

`callgraph._call_insns()` 用**首字节** `e8` / `ff` 判定 call，带前缀的 call 被整条漏掉：

| 样本 | 漏掉 | 形态 |
|---|---|---|
| bin_ls.elf | 13 | 全部 `41 ff d6`（REX.B + `call r14`） |
| dyn_static | 53 | 52 条 `43 ff 14 fe`（REX.XB + `call [r14+r15*8]`）；1 条 `67 e8 4f 26 00 00`（地址长度前缀 + 直接 call） |
| cli-64.exe | 0 | — |

影响：M6 公布的调用点计数在这两个样本上偏低（bin_ls 1141 → 应为 1154，其中间接 25 → 38；
dyn_static 3556 → 应为 3609，其中直接 3456 → 3457、间接 100 → 152）。`callfacts` 与 `callgraph` 共用同一套枚举，所以两层**同时**缺，
没有"两层互相矛盾"，只有"两层一起缺" —— 这正是必须靠 §2 的独立账才能发现的那一类。

**为什么不在本单元修：** 改 `_call_insns` 会改动 M6 已公布的全部计数、`expr` 文本 sha256 负向基线
以及 callgraph/callfacts 的既有断言，属于需要重新定标的独立单元（M7-U2），不能在"拼接层"里顺手改
（否则违反只读与口径单一变更原则）。本单元按"单列 + 归因 + 可复现"处理。

## 7. "能失败"的自证（要求 3）

四道，全部每次运行都执行，任一漏检即 FAIL：

1. **注入冲突**（`tests/verify_sitejoin.py` E 项 / `tests/test_sitejoin.py`）：
   改 `state`（期望 `state_mismatch`）、删图边（期望 `graph_edge_missing`）、破坏文本里的一行调用（期望 `struct_*`）。
2. **真实缺口**（E 项）：bin_ls 的 13 条 `call_site_missing` 必须存在，且逐条复核
   "该地址确实是一条 call、首字节确实不是 e8/ff"；若下层哪天修好了，这一项会变成 FAIL 并提示
   同步更新 `KNOWN_HARD`，不会悄悄变成空转。
3. **`--selftest`**：把行定位函数 `_slots` 打断，必须报出 `struct_line_count_mismatch` 硬冲突
   （实测 98 条，正好等于有调用块的块数）。
4. **账目自检**：`decoded_calls == keys + call_site_missing`、`keys == |union|`、
   `conflict_kinds` 与逐条重算一致；任何一条不平即 FAIL。

## 8. 只读证明（要求 4）

- `check()` 是纯函数：只读 `graph / facts / sidx`，返回新对象；`build()` 只把已经算好的报告传进去，不写回。
- 有三层证据：
  1. **深比较快照**：`json.dumps(..., sort_keys=True)` 在 `build()` 前后逐字段相等（graph / facts / sidx / res 四项，`verify_sitejoin.py` D 项与 `test_build_is_read_only`）；
  2. **注入对象复用**：验证脚本把外部建好的 graph/facts/sidx 传入 `build()`，跑完后原地对象不变；
  3. **既有模块未改**：本轮只新增 `rekit/sitejoin.py`、`tests/test_sitejoin.py`、`tests/verify_sitejoin.py`
     与 `cli.py` 的一处分派；`callgraph.py / callfacts.py / struct.py / expr.py / recdesc.py` 内容未改，
     旁证是负向基线（recdesc 17 项 + expr sha256）与既有 10 个验证脚本全部原样通过。
- **副作用：无。** 特殊说明：`struct_index()` 会调用既有 `structure_function()` 计算文本，这是"读输入、算新对象"，
  不是写回；其返回值从不被写进 res 或其它层的报告对象（快照已证）。

## 9. 全量回归（要求 5）

- pytest：**382 passed**（364 → 382，新增 `tests/test_sitejoin.py` 18 项），exit 0。
- 验证脚本 **11 个全部 exit 0**（既有 10 个 + 新增 `verify_sitejoin.py`），另跑 `verify_sitejoin.py --selftest` exit 0：
  `verify_disasm --all` / `verify_recdesc` / `verify_expr` / `verify_map` / `verify_iat` /
  `verify_fingerprint --all --matrix` / `verify_switchcand` / `verify_struct` / `verify_callgraph` /
  `verify_callfacts` / `verify_sitejoin`。
- 负向基线：三样本 recdesc 17 项与 `tests/baselines/definite_baseline.json` 逐项相等；
  cli-64 表达式文本 sha256 相等（改动只新增模块，未触碰既有输出，故基线不变，这也是"零回归"的直接证据）。
- 证据日志：`work/evidence_m7u1_join.log`（三样本报告）、`work/evidence_m7u1_pytest.log`、
  `work/evidence_m7u1_scripts.log`（12 条命令的退出码与全文）。

## 10. 能力边界（如实）

1. **只对齐已有记录**：拼接层不补齐任何一层的缺失；`call_site_missing` 只报不修。
2. **结构化侧仍是回指，不是寻址**：文本没有地址，只能靠"块 + 块内序号 + 三重校验"回指；
   若某天 `expr` 改了渲染顺序（如新增语句模板），三重校验会报 `struct_line_*`，不会静默错位。
3. **结构化层覆盖面小于另两层**：只覆盖 declared 函数；其余记口径差异。
4. **间接调用没有目标可比**：图侧无边，只能核"两层是否都知道这是间接调用"，不能核目标。
5. **不判"谁对"**：`layer_bug` 只说明"至少一层有误"，具体改哪层留给对应单元的复核（如 §6 已定位到 `_call_insns`）。

## 11. 下一单元建议（M7-U2）

1. 修 `callgraph._call_insns` 的前缀过滤（跳空前缀后再判 `e8`/`ff`），同步重跑 callgraph/callfacts/M6 报告，
   重新定标 `expr` sha256 与 M6 计数；修完后 `verify_sitejoin.py` 的 `KNOWN_HARD` 应变空，
   这会强制把本单元的 13/53 条冲突降为 0，等于给这次修复加了一道回归锁。
2. `sitejoin` 再处理"候选层开启（`--indirect-candidates`）"后的图侧对账：把候选层与事实层间接站点逐点比较，
   仍按三类归因，仍不进确定集。

---

## 12. 裁决落地一：M6 已公布数字的「已知偏低」就地标注（2026-11-16）

裁决原文：带前缀 call 被漏批准在 M7-U2 统一修 + 重定标，但**现在**就要把修正记录写进去；
CHARTER/PROGRESS 里 M6 已公布的调用点数（1141 / 3556）旁边必须标注"已知偏低，差额为带前缀 call，
修正见 M7-U2"，不能等 U2 做完才补，也不能让旧数字默默留着。

### 12.1 标注落点（全部为原地插入，旧数字保留可查）

| 文档 | 位置 | 插入内容 |
| --- | --- | --- |
| CHARTER.md | M6 里程碑行，U1 段"三样本 153/1141/3556 个调用点全部归因"之后 | `（1141/3556 已知偏低：分别漏 13/53 条带前缀 call … 修正见 M7-U2，三态占比分母同步受影响）` |
| CHARTER.md | M6 里程碑行，U2 段"三样本 153/1141/3556 站点"之后 | 同上口径的简注 |
| CHARTER.md | M7 里程碑行，U1 结论之后 | `U2 已批准待做`：修 `_call_insns` + 重定标，验收要求见本文件 §14 |
| PROGRESS.md | M6-U1 条目「口径」行 | 注明 `_call_insns` 首字节过滤已知漏 call，本行及以下数字均为旧口径 |
| PROGRESS.md | M6-U1 条目「三态（分母=直接调用点）」行 | 注明直接/间接分母的修正后口径（见 12.2） |
| PROGRESS.md | M6-U2 条目「实测」行 | 站点 1141/3556 后注明已知偏低与差额 |

### 12.2 差额明细（实测，与 `sitejoin` 的 `call_site_missing` 集合逐地址相等）

| 样本 | 已公布站点 | 实为 | 差额 | 构成 | 对三态分母的影响 |
| --- | --- | --- | --- | --- | --- |
| cli-64.exe | 153 | 153 | 0 | 无带前缀 call | 无 |
| bin_ls.elf | 1141 | 1154 | +13 | 全部间接：`41 ff d6`（call r14）、`41 ff 54 24 30` 等 | 直接 1116 不变；间接 25 → 38 |
| dyn_static | 3556 | 3609 | +53 | 52 间接（`43 ff 14 fe` 等）+ 1 直接（`67 e8`，地址长度前缀） | 直接 3456 → 3457；间接 100 → 152 |

集合相等的机械证据：用一次性审计脚本（不入库，方法见 §13）对三样本统计"带前缀 call"地址集合，
与 `sitejoin.check()` 报出的 `call_site_missing` 键集合**完全相等**（0 条多、0 条少）。

## 13. 裁决落地二：同类「按首字节过滤指令」审计清单（2026-11-16）

方法：对三样本逐条已解出指令，比较「raw 首字节」与「跳过 legacy 前缀 + REX 后的 opcode」，
按类别统计带前缀的 call / jmp / jcc / loop / ret / push-pop / FF-非控制流，并核对每个消费点
用的是 raw 字节还是 disasm 的 `opcode` 字段。实测总量：带前缀指令 686 / 8112 / 48032 条。

| # | 位置 | 判据 | 是否同类 | 实测命中 | 处置 |
| --- | --- | --- | --- | --- | --- |
| 1 | [callgraph.py](../../2026-11-15/m3-task-card/work/rekit/callgraph.py) `_call_insns`（L446-447） | `bytes` 串 `startswith("e8")/("ff")` | **同类，已确认漏检** | 带前缀 call 0 / 13 / 53；与 `call_site_missing` 集合相等 | **M7-U2 修**：跳前缀后判 opcode；`ff` 还须看 ModRM.reg ∈ {2,3} |
| 2 | [callfacts.py](../../2026-11-15/m3-task-card/work/rekit/callfacts.py) L283 | 直接调用 `CG._call_insns(ctx)` | **同类（继承）** | 同 #1 | 随 #1 一起修好，无独立代码 |
| 3 | [callgraph.py](../../2026-11-15/m3-task-card/work/rekit/callgraph.py) `rip_mem_target`（L143） | `b[0] != 0xFF or b[1] not in (0x15,0x25)` | **同类（判据）** | cli-64 有 3 条 `48 ff 25`（0x1d81 / 0x21e7 / 0x23ef）；但无调用边指向它们，且所在函数分别有 13 / 2 / 2 条指令（`thunk_of` 只认单条指令），故**本轮零影响**；PLT 节 `ff 25` 桩 111+4 / 22 条，带前缀 0 条 | 建议 U2 一并修：跳前缀取 opcode、再定位 ModRM 与 disp（disp 偏移不能写死 `+2`）；修后用计数断言锁住 |
| 4 | [callgraph.py](../../2026-11-15/m3-task-card/work/rekit/callgraph.py) `thunk_of`（L159-166） | `b[1] != 0x25` | **同类（判据）** | 单指令函数且带前缀 FF25：0 / 0 / 0 | 随 #3 一并修；注意「函数体仅 1 条指令」口径不覆盖 lea+jmp 尾跳（cli-64 那 3 条即此类），与本缺陷无关，不要混为一谈 |
| 5 | [callfacts.py](../../2026-11-15/m3-task-card/work/rekit/callfacts.py) L103 / L123 | `plt_stub_info` / `thunk_of` | **同类（继承）** | 同 #3 / #4 | 随 #3/#4 修好 |
| 6 | [recdesc.py](../../2026-11-15/m3-task-card/work/rekit/recdesc.py) `classify`（L377-411） | `ins["opcode"]`（disasm 已剥前缀） | **安全** | 带前缀 jmp 3 / 8 / 21 条照常分类；带前缀 ret 0 / 0 / 0 条 | 不动 |
| 7 | [recdesc.py](../../2026-11-15/m3-task-card/work/rekit/recdesc.py) `_modrm_byte`（L356-374） | 显式跳过 legacy 前缀 + REX 后再取 ModRM | **安全** | — | 不动 |
| 8 | [expr.py](../../2026-11-15/m3-task-card/work/rekit/expr.py) `decode`（L250-267）及 L409/431/471 | `_prefixes()` 先跳前缀再取 opcode（含 `f3 c3` = rep ret 特判） | **安全** | 带前缀 call 全部 `family == "call"`（0 例外） | 不动 |
| 9 | [struct.py](../../2026-11-15/m3-task-card/work/rekit/struct.py) / [switchcand.py](../../2026-11-15/m3-task-card/work/rekit/switchcand.py) | 只消费 recdesc 的 `kind`/`terminator`，不读字节 | **安全** | — | 不动 |
| 10 | [recdesc.py](../../2026-11-15/m3-task-card/work/rekit/recdesc.py) `PROLOGUE_PATTERNS`（L79）+ 扫描（L332-344） | 字面 4 字节模式 `55 48 89 e5` / `55 48 8b ec` 的 `blob.find` | **同类（弱）** | 命中 1 / 1 / 25 条；前一字节为前缀的 **0** 条 | 本轮无影响、不改（启发式种子默认关闭）。若将来扩到序言识别，须改成「按 opcode 判 push、再核后续字节」，不得只看字面模式 |
| 11 | 文件 magic：`cli.py` L26、`pe.py` L111、`iat.py` L37、`mapview.py` L90、`fingerprint.py` L73、`recdesc.py` L292、`disasm.py` L369、`expr.py` L769 | `MZ` / `\x7fELF` | 不适用（非指令过滤） | — | 不在审计范围 |

补充实测（用于约束修法）：

- **不能"跳前缀后见到 `ff` 就算 call"**：带前缀的 `ff` 非 call/jmp（inc/dec/push 等）有 28 / 5 / 112 条，
  例如 `48 ff c1`（inc rcx）、`41 ff 76 10`（push [r14+0x10]）。修法必须再看 ModRM.reg ∈ {2,3}。
- **disasm 前缀解析无遗漏**：非 VEX 单字节映射指令 1450 条中，`ins["opcode"]` 与"跳前缀后的首字节"
  不一致 **0** 条（初版脚本把 VEX2 `c5 xx` 误当无前缀、虚报 4716 条，剔除 VEX 后为 0）。
- **返回类**：三样本带前缀 ret 为 0；`ret` 判定走 `ins["opcode"]`，即使出现 `f3 c3` 也安全。

## 14. 裁决落地三：M7-U2 验收要求（前置写死，2026-11-16）

1. **修法**：`_call_insns` 改为「跳 legacy 前缀（0x26/2E/36/3E/64/65/66/67/F0/F2/F3）+ REX 0x40..4F
   后取 opcode」；`e8` 直接接受，`ff` 须 ModRM.reg ∈ {2,3}；最后仍交 `expr.decode` 复核
   `family == "call"`（双保险，防止表外编码混入）。
2. **重跑范围（受影响脚本，全部要跑）**：`verify_callgraph`、`verify_callfacts`、`verify_sitejoin`
   （`KNOWN_HARD` 应变空后仍须 exit 0）、`verify_struct`、`verify_expr`、`verify_recdesc`、
   `verify_disasm --all`、`verify_map`、`verify_iat`、`verify_fingerprint --all --matrix`、
   `verify_switchcand`，外加 `python -m pytest -q` 全量。
3. **修正前后对比表（必须列）**：每样本至少给 keys / 站点 / 直接 / 间接 / 三态分子分母与占比 /
   aligned / 冲突数 / `expr` 文本 sha256；并逐项说明"为什么更新、为什么不是放宽"：
   - 判据是**收紧/校正**（把真实 call 纳入），计数变大是事实修正，不是降低门槛；
   - 任何原本应报的冲突、abstain、截断**不得减少**（槽/窗口 abstain 只应不变或增加）；
   - 负向基线（`tests/baselines/definite_baseline.json`）若需改动，必须逐项给出旧值 → 新值 +
     字节级证据，禁止整表替换；
   - 某脚本数字若不变，也要显式写"不变"。
4. **零失败**：pytest 全绿 + 全部验证脚本 exit 0 + `verify_sitejoin --selftest` exit 0，日志入证
   （`work/evidence_m7u2_*.log`）。
