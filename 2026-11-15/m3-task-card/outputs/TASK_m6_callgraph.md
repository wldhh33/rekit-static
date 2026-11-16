# TASK M6-U1：调用图 + 保守的跨过程观察

日期：2026-11-15　状态：✅ 完成（五条要求逐条落地，全量回归零回归）

## 1. 输入与边界

- 输入：M4 的已解出指令 / 基本块 / 函数域（`recdesc.descend`）+ M5-U1 的指令语义
  （`expr.decode`，只读，逐操作数）+ M3 的导入结构（PE IAT、ELF `.rela.plt/.rela.dyn`）。
- 新模块：`rekit/callgraph.py`（唯一新增文件）+ CLI 子命令 `rekit callgraph`。
  既有 `expr` / `recdesc` / `struct` 的输出**逐字节不变**（未给它们加任何开关）。
- 不做的事：不做 ABI 推断、不猜参数个数、不给参数命名、不跨块传播、不猜间接目标、
  不把候选层数字并进确定统计。

## 2. 用户五条要求 → 落地位置

| # | 要求 | 落地 |
|---|---|---|
| 1 | 直接调用按"确定边"口径；间接调用走候选层（默认关闭、单列、带证据等级）；两者不合并统计 | `build()` 逐调用点分两路：`rec["target"] is not None` → `edges[]`（确定口径，三态计数）；否则 → `indirect.candidates[]`。候选层默认 `enabled=False`，加 `--indirect-candidates` 才输出，证据等级 high/medium/low；账目断言 `call_sites = direct + indirect`、`direct = decoded + plt_or_import + unresolved` |
| 2 | 参数观察只报事实：某寄存器/栈槽在调用点前后的定义与使用，不做 ABI 推断 | `_observe_call()`：同一基本块内倒序扫到调用点（before = 每个操作数**最后一次定义**）、顺序扫调用点之后（after = **第一次使用**）；输出 `{operand, kind, at, bytes}`，每个事实带回指地址与原始字节；`observe_note` 写明"不做 ABI 推断、不猜参数个数、不命名参数" |
| 3 | 调用图区分"目标已解出 / 目标在 PLT 或外部导入 / 目标未解析"三态，占比都要报 | `_classify()`：`decoded`（落点是已解出指令，并区分是否函数入口）；`plt_or_import`（落在 `.plt*` 节 / 符号 `@plt` / 目标函数体是单条 `jmp [导入槽]`）；`unresolved`（既不在已解出指令里，也不在 PLT/导入上）。`counts` + `ratios` 同时输出，分母写死为直接调用点 |
| 4 | 递归与环要能识别并标注，图递归渲染不能爆 | 函数级直接边做 Tarjan SCC（迭代版）：`cycles[{kind: self/mutual, members}]` + 节点 `recursion`/`scc` 标注；`_render_tree()` 用显式栈 + `visited` + 节点上限（默认 120）+ 深度上限 12，重复节点标 `[已展开过：不再重复展开]` |
| 5 | 完成后跑全量 pytest 与既有验证脚本确认零回归 | 见第 5 节 |

## 3. 实现要点（口径都可复核）

- **调用点必须全量扫描指令**：`recdesc.cfg.calls` 只统计**块末**调用（M4 的 CFG 只看
  块终结符）。实测 `cli-64.exe`：`cfg.calls` 13 条 vs 实际 call 指令 153 条
  （`e8` 98 + 间接 55）。若直接拿 `cfg.calls` 当调用图会漏 91% 的调用点。
  模块内两个口径**单列**并注明"不合并"。
- **PLT/导入名字只在能回指时给**：PE 走 `pe` 导入表（IAT 槽 RVA → `dll!name`）；
  ELF 走 `elf.parse()["relocations"]` 的 `JUMP_SLOT`/`GLOB_DAT`（`r_offset` → 符号名）。
  槽回指不到符号时**只报槽地址**（dyn_static 的静态 PLT 槽就是这样），不按节内顺序猜名字。
- **导入跳板**：函数体只有一条 `FF 25 disp32`（`jmp [rip+slot]`）且槽能回指导入 →
  该目标记为 `plt_or_import`，证据写"导入跳板：单条 jmp [0x…] = dll!name"。
  多指令跳板一律仍记 `decoded`（不推断）。
- **`unresolved` 不猜**：直接调用目标既不在已解出指令里、也不在任何 `.plt*` 节 →
  记未解析并写"目标 0x… 不在已解出指令内（节名），也不是 PLT/导入槽"。
- **间接候选层的证据边界**：`high` **只表示**"调用点的内存操作数静态定位到导入槽"
  这一事实（`call [IAT]` → 外部导入），**不表示**"被调函数已证明"；`medium` = 槽可定位
  但内容未解析（可能是函数指针表）；`low` = 寄存器/基址+索引间接。候选层不进 `edges`。
- **观察窗口截断可解释**：块内有未解码指令或未建模 intrinsic（隐式读写）→ 窗口在该处
  截断并记录 `before_barrier`/`after_barrier`（地址 + 原因），不越过屏障继续声称"最后定义"。
  栈槽按指令里**原样地址表达式**记录；窗口内 `rsp` 被改写时打 `rsp_modified_before`
  标记，显示时提示"未重算实际位置"。**不推断栈帧**。

## 4. 实测（三样本全量，`--indirect-candidates --observe`）

| 样本 | 调用点 | 直接 | 间接 | decoded | plt_or_import | unresolved | 候选 high/med/low | 函数节点 | 环（自/互） | 观察 before/after | 屏障 | rsp 改写 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cli-64.exe | 153 | 98 | 55 | 63 (64.29%) | 35 (35.71%) | 0 (0.00%) | 52 / 3 / 0 | 85 | 0 / 0 | 464 / 309 | 3 | 34 |
| bin_ls.elf | 1141 | 1116 | 25 | 428 (38.35%) | 688 (61.65%) | 0 (0.00%) | 1 / 2 / 22 | 331 | 2 / 0 | 3785 / 2275 | 50 | 166 |
| dyn_static | 3556 | 3456 | 100 | 3049 (88.22%) | 402 (11.63%) | 5 (0.14%) | 0 / 1 / 99 | 1089 | 15 / 2 | 10928 / 6356 | 163 | 368 |

- **账目对平**：`direct + indirect = call_sites`、`decoded + plt_or_import + unresolved
  = direct`、`len(edges) == direct`、占比和 = 1（三样本，verify_callgraph A 项）。
- **直接调用点集合 == E8 指令集合**（逐点一致，不漏不重）。
- **环**：bin_ls 自递归 2 例（`0x7990`、`0x13dd0`）；dyn_static 17 组（自递归 15、
  互递归 2：`{0x404760,0x411af0,0x411fd0,0x4120b0}`、`{0x447220,0x448800}`）。
  cli-64 无环（小样本，如实为 0，不解释成"环检测未实现"）。
- **三态样例**：
  - `cli-64` 0x1167 → 0x2690：`plt_or_import`，"目标是导入跳板：单条 jmp [0x30c8] =
    VCRUNTIME140.dll!memset"（`call 0x2690` 是 `e8` 直接边，跳板在内，目标属外部导入）。
  - `bin_ls` 0x475a → 0x42f0：`plt_or_import`，".plt 节；桩 jmp [0x26d80] → __assert_fail"
    （名字来自 `.rela.plt` 的 JUMP_SLOT，不靠节内序号推）。
  - `dyn_static` 的 5 条 `unresolved`：目标在 `.init`/`0x0`，证据逐条可见，不猜。

## 5. 全量回归

- pytest：**339 passed**（316 → 339，新增 `tests/test_callgraph.py` 23 项，exit 0）。
- 验证脚本 9 个全部 exit 0（8 个既有 + 新增 `verify_callgraph`）：
  `verify_disasm` / `verify_recdesc` / `verify_expr` / `verify_map` / `verify_iat` /
  `verify_fingerprint --all --matrix`（E9 132/132）/ `verify_switchcand` /
  `verify_struct` / `verify_callgraph`。
- 负向基线：三样本 recdesc 17 项、`cli-64.exe` 表达式文本 sha256、
  `dyn_static` 0x401870 文本 sha256 与 `tests/baselines/definite_baseline.json` 逐项相等；
  `build()` 前后 res 快照（指令数/块数/stats/cfg counts）完全一致（只读性）。
- 日志：`work/evidence_m6u1_callgraph.log`、`work/evidence_m6u1_pytest.log`。

## 6. 观察样例（只报事实，不做 ABI 推断）

`cli-64.exe` 调用点 `0x1061`（函数 0x1040 / 块 0x1040..0x1085；前 10 条已解码、后 11 条已解码）：

```
before  rbx ← 0x105e (48 8b d9)          ; 同块内最后一次写 rbx
before  rdi ← 0x1056 (48 8b fa)
before  rsi ← 0x1059 (48 8d 74 24 60)
before  rsp ← 0x1052 (48 83 ec 30)
before  [rsp+16] ← 0x1040 (48 89 54 24 10)   ; 栈槽定义（原样地址表达式）
before  [rsp+24] ← 0x1045 (4c 89 44 24 18)
before  [rsp+32] ← 0x104a (4c 89 4c 24 20)
after   r9d  → 0x1066 (45 33 c9)
after   rsi  → 0x1069 (48 89 74 24 20)
after   rsp  → 0x1069 (48 89 74 24 20)
after   rdi  → 0x106e (4c 8b c7)
after   rbx  → 0x1071 (48 8b d3)
after   rax  → 0x1074 (48 8b 08)
注: 窗口内 rsp 被改写；栈槽按指令里原样地址表达式记录，未重算实际位置
```

- 不出现"第 1 个参数/返回值类型/调用约定"之类推断；`before` 里 `rdi` 的定义不代表
  它被当参数使用，只是"本块内最后一次写 rdi"。
- `0x475a`（bin_ls）窗口里 `after_uses` 为空：调用点是块末，返回后没有同块指令可观察，
  如实输出 0，不跨块延伸。

## 7. 能力边界与不可判清单（如实列出）

1. **跨块数据流不报**：观察只限同一基本块；跨块（分支汇合后的参数准备）一律不出现，
   不是遗漏 0 条，而是本单元明确不做。
2. **间接调用目标不猜**：寄存器/基址+索引/虚表间接，目标不可静态确定；候选层只给
   "调用点操作数能定位到什么"，不给"被调函数是谁"。
3. **PLT 名字可能缺失**：静态链接/无 `JUMP_SLOT` 的 `.plt`（dyn_static 11.63% 的
   plt_or_import）只有槽地址，没有名字；不按序号猜。
4. **未解码指令会截断观察窗口**：三样本分别 3 / 50 / 163 处，原因逐条写在
   `before_barrier`/`after_barrier`。
5. **调用图节点只含被分析节内的已解出函数**：`--section` 之外的函数体不在节点集合里；
   跳板/PLT 作为"外部目标"出现，没有出边。
6. **环只对函数级直接边**：间接边不参与 SCC（目标未知，不能连边）。

## 8. 与后续里程碑的衔接

- 下一单元可做"跨函数参数传递的事实层"（例如仅在有 `.pdata`/CFI/栈槽证据时给出
  "调用点前 rdi 的定义来自 caller 的形参槽"），**前提仍是先定证据口径**，
  绝不能演变成 ABI 推断。
- 结构层（M5-U3）与调用图层目前独立：结构化文本里的 `call` 目标可直接映射到本模块
  的 `edges`（按 `from` 地址），但本轮未把两者拼成一份"带调用目标的伪 C"，
  以免混入候选层。
