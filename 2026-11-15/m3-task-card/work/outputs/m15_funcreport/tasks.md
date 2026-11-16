# Tasks — M15 单函数面向人报告层（rekit funcreport）

> 依赖：`outputs/m15_funcreport/spec.md`（决策已定）。按序执行，每步有可验证产出。

## [x] T1 生成“完整声明”验收样本
- 新建 `tests/make_funcreport_full.py`：内联 C（`add3`/`twice`/`main`），
  `gcc -g -O0 -fno-pie -no-pie -o tests/m15_fixtures/funcreport_full`
  （独立目录，避免既有 `tests/fixtures/` 的 10 样本计数测试失败）。
- gcc 缺失打印 `SKIP`，退出 0。
- 验收：产物存在；`objdump -t` 能列出 `add3` 且 size>0。

## [x] T2 实现 `rekit/funcreport.py` 骨架与数据契约
- `SCHEMA=1`、`EVIDENCE_STATES`、`_src()`、`_section()` 统一构造器
  （强制 `evidence_state/scope/reason`）。
- `build(path, func_addr, section=".text", res=None, graph=None, facts=None,
  sxref=None, dwarf=None)`：一次 `recdesc.descend`，全流程复用。
- 四种非 ok：`function_not_found` / `not_a_function_start` /
  `no_decoded_instructions` / `function_not_specified`，均保留完整键结构。
- 层失败：每层 try/except → `layer_errors` + 对应段 `missing_source`，不静默。
- 验收：单测 7.1-1/6/9 通过。

## [x] T3 七段取数（只读既有层）
按 spec §3 逐段实现，字段清单按 §2.5：
- identity（expr.list_functions；内部地址判 `not_a_function_start`）
- boundary（seeds + end_by_source + end 冲突原文；无种子显式说明）
- blocks_and_edges（res.blocks / cfg.edges 五类 / cfg.calls 单列）
- expressions（lift_function，abstains 带 missing，body/term 不重排）
- calls（callgraph 三态 + facts 间接站点；`absent_measured` 必须写测量范围）
- strings_and_data（strxref 字符串站点；非字符串数据显式 `missing_source`）
- parameters（by_low_pc 命中规则 + bind_site 调用者绑定；无 DWARF 显式否定“0 个参数”）
- 验收：单测 7.1-2/4；三类报告可生成。

## [x] T4 人读渲染 + CLI 同源
- `render(report, limit)` 纯函数；段首行状态+范围；`absent_measured` 写
  “确实没有：”，其余非 present 写“缺：”；
  行尾 `[层:字段]`；截断写“显示 N / 共 M”，禁止 `…` 代替数量/缺失；
  禁止推断措辞（层原文引用豁免）。
- `main()`：`--func`（`int(v,0)`）、`--section`、`--json`、`--limit`；
  无 `--func` → `function_not_specified` + 候选。
- `rekit/cli.py` 增加 funcreport 分支（唯一改动的既有文件）。
- 验收：单测 7.1-5/8。

## [x] T5 只读性与层失败守卫
- 单测 7.1-3：AST import 白名单 + 禁止 `subprocess/disasm/coverage/struct`。
- 单测 7.1-10：`res/graph/facts/sxref` build 前后哈希一致。
- 单测 7.1-9：monkeypatch 层异常 → `layer_errors` 非空、其余段仍产出。
- 验收：临时插入违规 import 时测试变红，还原后变绿。

## [x] T6 外部抽查 `tests/verify_funcreport.py`
- 三类样本（spec §6 矩阵）：完整声明 / 部分证据 / 严重不足。
- 抽查 (a)–(f)：块与调用目标为 objdump 起点、指令落域、符号 size、
  DWARF 形参数、Go 指令数上界、严重不足样本的缺失语义。
- 实测状态与 §6 矩阵逐项核对；样本缺失记 SKIP 不算 PASS。
- 写 `evidence_m15_funcreport.json`；exit 0/1。

## [x] T7 文档
- `outputs/TASK_m15_funcreport.md`：三类报告摘要 +
  **“缺证据” vs “确实没有”逐字段清单** + 抽查结论 + 回归结果。
- `outputs/NUMBERS_LEDGER.md` 追加“M15 报告层不产生新数字”。
- `CHARTER.md`/`PROGRESS.md`/`CHANGELOG.md` 各追加一行 M15 里程碑
  （写前确认唯一目录）。

## [x] T8 全量回归
- `python -m pytest tests -q` → `evidence_m15_pytest.log`。
- 全部 `tests/verify_*.py`（Python subprocess 驱动）→ `evidence_m15_verify.log`。
- 验收：pytest 全绿；既有 verify 数字与 M14 一致（变化逐条归因）。

## [x] T9 汇报
- 三类报告 `evidence_state` 分布 vs §6 矩阵；
- “缺证据”字段清单 vs “确实没有”字段清单；
- 抽查 PASS/FAIL/SKIP；
- 回归是否改变既有数字（若有，逐条归因）。
