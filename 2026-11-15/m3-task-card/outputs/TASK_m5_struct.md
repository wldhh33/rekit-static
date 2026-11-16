# TASK M5-U3：控制流结构化输出（可回溯的 if / loop / switch 分级）

日期：2026-11-15　状态：✅ 完成（四项要求逐条落地，全量回归零回归）

## 1. 输入与边界

- 输入：M4 的函数域 / 基本块 / 确定边（`recdesc.descend`）+ M5-U1 的逐语句伪 C
  （`expr.lift_function`，本次只新增 `body_lines` / `term_lines` 两个切片，**文本不变**）
  + M5-U2 的跳转表候选（`switchcand`，只读）。
- 新模块：`rekit/struct.py`（唯一新增文件），CLI 开关 `--structured`，默认关闭。
- 不做的事：不做类型推断、不做值编号、不做跨过程、不猜间接目标、不为了好看改写切块口径
  （剩余 12 块按裁决记为"已知差异：切块粒度差异"，不是能力缺失）。

## 2. 用户四项要求 → 落地位置

| # | 要求 | 落地 |
|---|---|---|
| 1 | 识别 if / loop；switch 仅在候选证据为 **high** 时渲染成 switch/case，等级不足保留 goto 并写明原因 | `_Builder._if`（if-then / if-else，含循环内 break/continue 判定）、`_loop`（while / do-while / for(;;)）、`_switch`：`c["evidence"] != "high"` → 不渲染 switch，输出 `unstructured` 节点，reason 写明"候选证据 medium（依据…），不渲染 switch，保留 goto"；无候选 → "间接 jmp 无候选：目标不可静态确定（R45），保留 goto" |
| 2 | 每处都能退回原始块与边，不允许"看着像 C 但回溯不到 CFG" | 每个节点带 `block` / `edges[{from,to,kind}]` / `join`；`check_traceable()` 校验：块引用存在、块不重复、**每个可达块必须出现且仅出现一次**、`edges` 必须是 recdesc 的真实后继、switch case 目标必须属于 high 候选集；`stats.violations` 与 `render_function` 头部同步输出 |
| 3 | 已知不可结构化形态单独统计、如实标注，不强行套 if/loop | `_irreducible`（Tarjan SCC 多入口）→ `unstructured` 节点 + "不可约循环（SCC 多入口），不强行套 if/loop"；条件标志跨块不可判 → `cond_unknown` 计数 + "条件不可判（跨块标志），不猜条件"；`goto_ratio > 30%` → `goto_dense`；不可达块单列 `blocks_unreachable` + 按块原样输出 |
| 4 | M5 收口 | 见第 4 节：全量回归 + 逐条对账 + 结构不可判清单 + 下一里程碑建议 |

## 3. 实现要点（都是"可回指"而不是"看起来对"）

- **支配/后支配**：迭代数据流求 `dom` / `postdom`；`NCP` 求汇合点。
- **循环**：回边 `h→b` 且 `h ∈ dom(b)` → 自然循环；按头块终结符分类：
  头块是条件块 → `while`；头块非条件、闩尾是条件块 → `do-while` / `for(;;)`。
- **join 不再一律塌到 exit**：编译器最常见形态是 `if (c) goto L; <fall 区域>; L:`。
  只要 taken 是**前向**目标，就取 `then = fall 区域、join = taken`，还原原形态；
  否则退回 NCP。修复前 0x401870 全是 `join=exit` + 巨型嵌套，修复后为 `join=0x40192d` 等真实汇合点。
- **顺序块必须续写**：非转移块（term=`next`）旧实现返回 `None`，导致其后的块全部掉进
  "tail label"（结构层覆盖不到，dyn_static 只认出 8 个 switch）。改为返回唯一后继后：
  while 8→425、do-while 1→21、switch 8→9（dyn_static 口径）。
- **switch 索引名**：候选只存 SIB 索引编号，渲染时从 `expr` 已渲染的块文本里取寄存器名
  （宽度由操作数宽度决定），取不到退化成 `reg#N`，**不猜 32/64 位**。
- **循环内的 break / continue**：条件必须对"去另一条边"的那支求，且 break 目标必须是
  循环外。旧实现把两者判反（`_IO_remove_marker` 里把"回边"标成 break，并把出口块
  渲染进循环体），已修正并加测试钉死。
- **switch 的 case 体**：只输出 `case N: goto L_0x…;` + "候选层口径：case 体不在确定集内"，
  不把候选目标当确定块展开。

## 4. 验收结果（三样本全量）

| 样本 | 函数 | 块 | if | else | while | do-while | for | switch | 降级 | 无候选 | goto | break | continue | 条件不可判 | 不可约块/函数 | 不可达 | goto 密集 | 可回溯违规 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| cli-64.exe | 41 | 294 | 88 | 17 | 20 | 2 | 0 | 0 | 0 | 3 | 60 | 3 | 1 | 3 | 0/0 | 0 | 9 | **0** |
| bin_ls.elf | 331 | 3821 | 1193 | 334 | 50 | 1 | 1 | 3 | 2 | 2 | 887 | 11 | 2 | 21 | 441/12 | 0 | 79 | **0** |
| dyn_static | 1084 | 21088 | 5905 | 1560 | 425 | 21 | 9 | 9 | 5 | 73 | 4347 | 85 | 27 | 206 | 2407/77 | 24 | 240 | **0** |

- **emitted == reachable 逐函数成立**（三样本全部函数，无一例外）。
- **候选账目对平**：dyn_static 29 个 high 候选 = 渲染 switch 9 + 落在未展开块（label）20
  + 降级 0 + 无去向 0；bin_ls 3 = 3 + 0。未展开块在文本里以 `L_0x…:` 原样出现并带
  "可达但未纳入嵌套结构（循环多出口/交叉边/共享块）"原因，**不存在"有候选但既没渲染也没解释"**。

### 4.1 代表样例（可回指）

`cli-64.exe` @ `0x1e5c`：

```
while (!((rax & rax) == 0)) {  // header=0x1e76 exit=0x1ec5 back=0x1e76
  … call RtlVirtualUnwind(…)
  if (!(edi < 0x2)) break;  // blk 0x1ebd → 0x1ec5（循环出口）
}
```

`dyn_static` @ `0x401870`（CPUID 分派）：

```
if (!(esi >u 0x7)) {
  L_0x40191d:  // blk 0x40191d term=jmp_ind
  switch (rsi) {  // jmp@0x40191d table=0x476020 evidence=high
    case 0: goto L_0x40198e;  … case 7: goto L_0x401cc1;
  }  // 候选层口径：case 体不在确定集内
}
```

## 5. 全量回归

- pytest：**316 passed**（新增 `tests/test_struct.py` 21 项，exit 0）。
- 8 个验证脚本全部 exit 0：`verify_disasm` / `verify_recdesc` / `verify_expr` /
  `verify_switchcand`（含 E9 负向基线 28 项全等）/ `verify_struct` / `verify_map` /
  `verify_iat` / `verify_fingerprint --all --matrix`（E9 VERDICT PASS，可判定格 132/132）。
- 日志：`work/evidence_m5u3_*.log`。

## 6. 结构不可判清单（如实列出，不强行结构化）

1. **不可约循环（SCC 多入口）**：bin_ls 441 块 / 12 函数，dyn_static 2407 块 / 77 函数。
   一律输出 `unstructured` + 显式 goto（两条边都列出），不套 if/loop。
2. **条件不可判**：跨块标志（OF/PF 或中间块改写标志）无法恢复条件文本 →
   `cond_unknown`（20/3/206），保留原始 `jcc` 与双 goto。
3. **循环多出口且无公共后支配点**：`while/do-while` 的 exit 记为 ∅，出口块在循环后
   按块原样输出（不猜汇合点）。
4. **候选证据不足或缺失的间接 jmp**：保留 goto 并写明证据等级/依据。
5. **高候选落在未展开区域**：dyn_static 20 处，按块原样输出（label），不计入 switch。

## 7. 已知差异（按裁决不改）

dyn_static `0x401870` 我方 23 块 vs Ghidra 55 块，剩余 12 块为**切块粒度差异**
（Ghidra 把块末尾的指令序列再切细），**不是能力缺失**，本轮未为对齐 Ghidra 显示习惯
改动核心切块口径。
