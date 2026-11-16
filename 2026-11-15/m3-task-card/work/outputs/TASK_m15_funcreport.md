# TASK M15 — 单函数面向人报告层（rekit funcreport）

日期：2026-11-16
定位：把 recdesc / expr / callgraph / callfacts / strxref / paramdecl 六层对
**同一个函数**的记录合成一份报告。**只呈现、不判断**：本层不产生任何新的目标、
参数、语义或置信度结论，也不新增反汇编。

## 1. 实现

| 文件 | 说明 |
|---|---|
| `rekit/funcreport.py` | 报告层主体：`build()` / `build_selection()` / `render()` / `main()` |
| `rekit/cli.py` | 唯一改动的既有文件：新增 `funcreport` 手动短路分支 |
| `tests/make_funcreport_full.py` | 用内联 C 生成“完整声明”样本到 `tests/m15_fixtures/`（不污染既有 10 样本） |
| `tests/test_funcreport.py` | 10 项单测：结构/来源白名单/导入白名单/缺失语义/同源/非 ok/确定性/CLI/层失败/注入只读 |
| `tests/verify_funcreport.py` | 三类样本 + objdump 外部抽查 16 项（exit 0/1） |

CLI：

```
rekit funcreport <file> [--func HEX] [--section NAME] [--json] [--limit N]
```

- 不给 `--func` 时返回 `function_not_specified` + 候选列表，**不猜默认函数**。
- 人读与 JSON 同源：`main()` 只 `build()` 一次，`--json` 打印同一 dict，
  人读走 `render(report)`（纯函数，只读 dict）。

## 2. 证据状态语义（字段级）

| 状态 | 含义 | 读者应理解为 |
|---|---|---|
| `present` | 该段至少一条带来源条目 | 有证据 |
| `absent_measured` | 测量范围明确、范围内确实为 0 | **确实没有** |
| `missing_source` | 该类来源整体不存在于本样本 | **缺证据** |
| `missing_declaration` | 来源存在但该函数无声明 | **缺证据** |
| `missing_decode` | 该函数无已解出指令，函数域内不可测量 | **缺证据** |
| `abstained` | 有来源但证据不足，已写缺什么 | **缺证据** |
| `not_applicable` | 不适用（仅占位） | 不适用 |

渲染时两种措辞严格分离：`absent_measured` 打 `确实没有：<测量结论>`，
其余非 `present` 打 `缺：<原因>`；`absence_summary` 逐条列全，不用省略号。

## 3. 三类验收样本（实测）

| 项 | 完整声明 `add3` | 部分证据 Go `0x401320` | 严重不足 `minidll.dll` `0x1000` |
|---|---|---|---|
| 文件 | `tests/m15_fixtures/funcreport_full`（PE，gcc `-g -O0`） | `samples/m9/elf_medium_synth_go_stripped` | `tests/fixtures/minidll.dll` |
| identity | present（RVA 0x14e0，12 条指令） | present（`internal/abi.(*IntArgRegBitmap).Set`，25 条指令） | present（`AddressOfEntryPoint`，1 条指令） |
| boundary | present（0x14e0..0x14fe，`.pdata` 声明） | present（gopclntab 声明） | **missing_source**（只有 `entry`，无结束声明） |
| blocks_and_edges | present（1 块，0 边） | present | present（1 块） |
| expressions | present（12/12 提升） | **abstained**（1 条指令缺位测试语义） | present（1/1 提升） |
| calls | **absent_measured**（0 个 call） | present | absent_measured（0 个 call） |
| strings_and_data | absent_measured（0 个字符串引用） | absent_measured（0 个） | absent_measured（0 个） |
| parameters | present（DWARF 3 个形参） | **missing_source**（无 DWARF） | **missing_source**（无 DWARF） |
| layer_errors | 0 | 0 | 0 |

三份报告都与 `spec.md` §6 状态矩阵逐项一致（verify 的 `*-matrix` 检查）。

## 4. “缺证据” vs “确实没有”（逐字段）

### 4.1 缺证据（`missing_source` / `missing_declaration` / `abstained`）

| 字段 | 样本 | 状态 | 具体缺什么 |
|---|---|---|---|
| `strings_and_data/data_refs` | ~~全部三份~~ | ~~missing_source~~ | **已被 M16 取代**：`rekit datarefs` 补上非字符串数据引用层。现状：`funcreport_full` → `absent_measured`（确实没有可交叉对象）；Go 0x401320 与 minidll 0x1000 → `missing_source`（无尺寸声明来源）。见 `TASK_m16_datarefs.md` §7 |
| `parameters/own_declaration` | Go 0x401320 | missing_source | 样本无 DWARF；**这不是 0 个参数**，也不按 ABI 补齐 |
| `parameters/own_declaration` | minidll 0x1000 | missing_source | 同上 |
| `boundary/end` | minidll 0x1000 | missing_source | 只有 `entry` 声明函数身份；`.pdata`/FDE/st_size/gopclntab 均未给结束地址 |
| `expressions/lifted` | Go 0x401320 | abstained | 1 条指令缺“位测试/扫描语义与 CF 输出”（M5-U1 白名单之外）；其余 24 条已提升 |

### 4.2 确实没有（`absent_measured`，有测量范围）

| 字段 | 样本 | 测量范围 | 结论 |
|---|---|---|---|
| `calls/call_sites` | add3 | 函数内全部 12 条已解出指令 | 没有 call 指令 |
| `calls/call_sites` | minidll 0x1000 | 函数内全部 1 条已解出指令 | 没有 call 指令 |
| `strings_and_data/strings` | add3 | 12 条已解出指令覆盖的字符串白名单引用点 | 0 个字符串引用 |
| `strings_and_data/strings` | Go 0x401320 | 25 条已解出指令覆盖的字符串白名单引用点 | 0 个 |
| `strings_and_data/strings` | minidll 0x1000 | 1 条已解出指令覆盖的字符串白名单引用点 | 0 个 |

注意：`strings=0` 只说明**本口径下没有可归属的指令引用**；`strxref` 的 caveat 明确
“没有引用点不等于字符串未使用”，本层原样引用该 caveat，不升级为语义结论。

## 5. 外部工具抽查（objdump，16/16 PASS）

| 检查 | 结果 | 证据 |
|---|---|---|
| full-matrix / go-matrix / scarce-matrix | PASS | 状态与 spec §6 一致 |
| *-absence | PASS | 每个非 present 字段都在 `absence_summary` |
| *-a | PASS | 块起点与 `state=decoded` 的直接调用目标都是 objdump 指令起点 |
| full-b | PASS | 12 条指令全部落在块 `[start,end)` 且是 objdump 起点 |
| go-b | PASS | 25 条指令全部通过 |
| scarce-b | PASS | 1 条指令通过 |
| full-c | PASS | `end-addr=0x1e` == `objdump --dwarf=info` 的 `high_pc` |
| full-d | PASS | 报告形参数 3 == objdump `DW_TAG_formal_parameter` 计数 3（DIE@0xc2） |
| go-e | PASS | 报告 25 条 ≤ objdump 在 `[0x401320,0x401380)` 的 50 条 |
| scarce-f | PASS | parameters=missing_source，人读含“缺：” |

探针日志：`work/evidence_m15_funcreport.log`；机器快照：
`work/evidence_m15_funcreport.json`。

## 6. 回归

- `python -m pytest tests -q` → **485 passed（73.58s，exit 0）**，
  日志 `work/evidence_m15_pytest.log`。
- 全部 `tests/verify_*.py`（Python subprocess 驱动）→ **18/18 exit 0**，
  日志 `work/evidence_m15_verify.log`。其中 `verify_fingerprint.py` 按脚本自身
  用法要求带 `--all --matrix`（不带参数时 exit 2 是用法错误，不是回归失败）。
- 既有层数字：未改任何判据/分母；`verify_*` 输出与 M14 一致（无变化）。

## 7. 数字口径

本层**不产生新数字**：

- 报告中的计数（指令数、块数、三态计数、形参数、字符串引用数）全部是对
  既有层字段的直读，每条带 `source={layer,field,text}`；
- 没有新增分母，不重算 R91 / R102–R107 的任何比率；
- `coverage`（objdump）只在 `verify_funcreport.py` 里作为**外部校验工具**，
  不进报告、不被 `funcreport` import。

## 8. 已知限制（不是“没有”，是本层不提供）

- ~~非字符串数据引用没有来源层 → 恒为 `missing_source`~~ → **M16 已补齐**
  （`rekit datarefs`）；现按声明对象/引用点给真实状态，见 `TASK_m16_datarefs.md`。
- `callgraph` 的间接候选层默认关闭；间接调用只在 `callfacts` 中以
  `unresolved` 单列，不并入确定集。
- 本层不提供“总结/建议/风险评级”；需要判断的读者应回看各层 caveats（报告末尾
  已按层原文附上，共 49 条）。
- `--limit` 只影响显示条数，计数始终完整；截断行写“显示 N / 共 M”。
