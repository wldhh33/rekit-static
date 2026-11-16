# HANDOFF · 会话交接

> 规则：每次会话结束前更新本文件；开工先读本文件 + `pack\AGENTS.md`，再跑 `python "pack\tools\status.py"`。
> 六段缺一不可、不得留空；全文 ≤150 行。历史进度看 `work\pack03\PROGRESS.md`，这里只写"当前"和"下一步"。

## 1. 当前进度

- **M18（.NET IL 控制流 ilflow）已收口（2026-11-16）**：pytest 554 passed；21 个 verify 脚本全部 exit 0（`verify_fingerprint` 用 `--all --matrix`）；`verify_ilflow` 41 项全 PASS。
- M18 收口证据：`work/evidence_m18_pytest_all.log`、`work/evidence_m18_verify.log`、`work/evidence_m18_verify_all.log`、`work/evidence_m18_ilflow.json`；任务卡 `outputs/TASK_m18_ilflow.md`。已断言的旧不可信日志保留为 `work/evidence_m18_verify_broken.log`。
- **本批（B1 / O3 交接协议，2026-11-16）已完成**：新增 `pack\AGENTS.md`、`pack\PATH_MAP.md`、`pack\tools\status.py`、本文件；从 `tmp\pack` 复制恢复 `pack\01_方法论文档`、`pack\02_规则库`（复制，未移动）。
- 本批**没有改动** `rekit\*.py`、`tests\*.py`、任何样本、任何已公布数字；回退依据见 `2026-11-16\vibe-coding-review\work\batch1\MANIFEST.sha256`。
- **O4（数字总账链路）已完成（2026-11-16）**：权威迁移到 `work\evidence_numbers_ledger.json`（M13–M18，8 小节 / 8 证据 / **67 个登记数字**，历史源 `evidence_m13_ledger.json` 降级）；新增 `pack\tools\ledger_check.py`（`--write` 重生成 / `--check` 漂移硬失败 / `--audit` 未登记数字清单）。R103 的 `pe_gap` 三数字（113,731 / 3.2262% / -0.0402pp）已补登记并用「改数字→FAIL」负例验证；未登记 105 个数字落 `work\evidence_ledger_unprotected.json`（五类原因）。新鲜度改**字节判据**（sha256 变才 FAIL，原样重写只记 note）。
- **O2-b（门禁语义统一）已完成（2026-11-16）**：`verify_gate.py` 改为委托 `tests\vharness.py --json`（不再留第二套判定）；vharness 收紧——分母下限 21 套、自证只认工件（布尔值 FAIL）、15 套缺 objdump 即 `env_missing` exit 2；`run_id` 加随机后缀；`status.py` 把「最近一次 verdict 非 PASS」「ledger 漂移」升为硬失败（git 未初始化仍 WARN）。
- **B2（O2 外部门禁）已完成（2026-11-16）**：新增 `pack\tools\verify_gate.py`，全量实跑 **21/21 verify PASS + pytest 554 passed**，`VERDICT: PASS exit=0`；产物 `work\verification\20261116T213155\`。跑前跑后 `work` 顶层 112 个 `*.json|*.log` 哈希零变化（`batch2\no_side_effects.json`）。
- **B3（O5 规则登记 + O4 数字总账）已完成（2026-11-16）**：新增 `pack\rules.json`（R01–R119 共 119 条，摘录+出处+互证状态）与缺口报告 `batch3\rules_gap_report.md`；O4 **不新建总账**——`work\outputs\NUMBERS_LEDGER.md` 已存在且以 `evidence_m13_ledger.json` 为唯一权威，只补了指针。
- **O2-a（vharness + 表达式层验收补强）已完成（2026-11-16）**：`tests\vharness.py` 已是严格模式（空比对 FAIL、缺自证 FAIL），`--all` **21/21 套 PASS、63 检查点零失败**（`work\evidence_o2a_vharness.json`；备份前后态 `evidence_o2a_vharness_before.json` 为 15/6）。
- `verify_expr` 的验收洞已补：**接入 objdump 外部 oracle**（全节线性反汇编对照 + 下层账目），`--selftest` 两处注入均可失败。M5-U1 已公布数字复跑**逐项相等**（抽样 57、入口 15/18·8/18·18/21、块数 14/15·8/8·15/18、调用集 8/15·5/8·12/18）。**已知残差**（不判失败、不表述为零分歧）：域内 objdump 比 expr 多解 cli 1 条(1/18 函数)、bin_ls 403 条(7/18)、dyn_static 390 条(13/21)，CFG 可达子集 vs 线性全扫，**未逐指令归因**，逐地址落 `work\evidence_m5_expr_residual.json`（objdump 2.47.20260726）。pytest **554 passed / 0 skipped / 0 failed**。
- **B4（规则史收敛 R33–R119）已完成（2026-11-16）**：新增 `pack\02_规则库\规则库_R33-R119.md`，87 条逐条给出「编号/原意/约束对象/判定方式/落地位置/依据/状态」；9 条「撞号」裁决（**0 条真撞号**，5 条属 R01–R32、4 条是摘要/提及行误判）+ 21 条多写法唯一化（6 条范围外 + 15 条 R33+）写入附录 A/B；**3 条标注「材料不足」**（R49/R93/R110），8 条标注「仅文档级」。`rules.json` 只新增 canonical 字段，mined 字段 0 处改动（`batch4\verify_merge.py` 自证）。

## 2. 未完成清单

以下条目会改 `rekit`/`tests` 源码，本会话只写改法，由源码会话执行：

| 编号 | 改法 | 提案位置 |
|---|---|---|
| ~~O2-a~~ | **已完成**：`tests\vharness.py` 已建（严格模式：空比对 FAIL、缺自证 FAIL，统一 exit 0/1/2），`--all` 21/21；6 个脚本已补可失败 `--selftest`，`verify_expr` 接入 objdump 外部 oracle。证据 `work\evidence_o2a_vharness.json`、`evidence_o2a_expr.log` | 提案 §4 O2 + 附录 A |
| O2-b | ~~新增 `tests\verify_all.py`~~ 已由 `pack\tools\verify_gate.py` 承担（外部门禁，不动 tests）；tests 内**不再**新建第二个总入口，避免两套 VERDICT 口径 | §4 O2 |
| O4 | ~~新建 `work\numbers.json`~~ **不新建**：总账已存在（`work\outputs\NUMBERS_LEDGER.md`）。**权威已于 2026-11-16 迁移到 `work\evidence_numbers_ledger.json`**（M13–M18，67 数字，`ledger_check.py --check` 硬校验；`evidence_m13_ledger.json` 为历史源）。新增数字必须先落 JSON 再改人读镜像，改后跑 `ledger_check --check` 与「改数字→FAIL」负例 | §4 O4 |
| O5 | `pack\rules.json` **已建**（119 条）；**规则史收敛已完成**：`02_规则库\规则库_R33-R119.md` 已建，`rules.json` 已回填 canonical 字段。**余 3 条材料不足**（R49 五类清单、R93 五项检查、R110 窗口大小）与 3 条口径需人定，见 `batch4\human_decisions.md` | §4 O5 + `batch4\human_decisions.md` |
| — | 修正 `pack\README.md` 过期内容："73 断言 / 5 模块 / `cd 04_rekit项目源码`" 均已失真（实为 554 passed / 25 模块 / 目录名 mojibake） | 提案 §4 O1 |

非源码类、尚未做：

- ~~**规则史缺口（最要紧）**：`02_规则库` 只到 R32，R33–R119 共 87 条没有规范文件~~ **已收敛（B4）**：`pack\02_规则库\规则库_R33-R119.md` 已建，87 条全部给出规范定义；3 条材料不足与 6 条待确认见 `batch4\human_decisions.md`。
- 顺带修正一个假事实：早期 `metrics.json` 报「缺 R9/R10/R11/R14/R17/R20/R26」，实为补零写法差异导致的假缺口，规则库原文一直有这 7 条（原文写 `R9` 不是 `R09`）。

- `pack` 下 4 个 mojibake 目录重命名（维护窗口，按 `pack\PATH_MAP.md` 手册逐个人工执行）。
- git 基线（**维护窗口执行，本会话不自行 `git init`**，改法如下）：
  1. 确认另一会话已停写 `rekit`（`work\rekit` 与 `pack\04_…\rekit` 是同一目录，不是副本）
  2. 先改名（4 个目录），再 init；否则 git 会把一次改名记成删+增
  3. `git init` 于 `pack\`；`git config core.autocrlf false`、`core.quotepath false`
  4. `.gitignore`：`work\samples\`、`work\verification\`、`tmp\`、`__pycache__\`、`*.pyc`、`cli-64.exe`（出处不明，不入库）
  5. 第一次提交只放治理文件（`AGENTS.md`/`PATH_MAP.md`/`tools\`/`README.md`/`rules.json`），源码与 tests 各单独一次
  6. 每次提交前必须 `python "pack\tools\verify_gate.py" --run` 全绿；回退就是删 `.git`

## 3. 已否决方案

1. **本批不 `git init`**：会把另一会话正在写的源码、99 MB 样本、junction 一并捕获；首次提交内容未定，回退成本高于收益。
2. **本批不重命名 mojibake 目录**：`work\rekit`、`work\tests` 是指向这些目录的 junction，改名即断链。
3. **不复制整个 `work` 开分支**：会复制 99 MB 样本并制造第 N 份副本。
4. **不用 `git mv` 批量改名**：当前无 git 基线，无法回滚。
5. **不把 `tmp\pack` 的 5 模块旧代码合并回 `pack`**：`pack` 已有 25 模块，旧副本并入会被误当最新（`tmp` 仅作 01/02 文档来源）。
6. **不为 `status.py` 引入第三方库**：纯标准库，避免给"开工第一条命令"增加环境依赖。

## 4. 待确认问题

1. ~~`pack\03_…\CHARTER|PROGRESS|CHANGELOG` 与 `work\pack03\` 哪份权威~~ **已定（2026-11-16 实测）**：`work\pack03` 是 junction 指向 `pack\03_…`，**同一份文件**，不存在双副本；改任一路径即改文件本身。
2. `01_方法论文档`、`02_规则库` 是否只存在于 `tmp\pack` 快照？已恢复，但需确认 RMS 是否还有其他目录只在 `tmp` 里。
3. `verify_fingerprint.py` 不带参数时是否等价于 `--all --matrix`？`verify_all.py` 的调用参数待定。
4. `tests\fixtures\cli-64.exe` 出处不明（AGENTS.md 已标"不可再分发"）。git 初始化前需决定是否入库。

## 5. 新增证据文件

- `2026-11-16\vibe-coding-review\work\batch1\status_output.txt` —— 本批 `status.py` 首跑输出（实测证据）
- `2026-11-16\vibe-coding-review\work\batch1\MANIFEST.sha256` —— 本批新增文件哈希 + 删除式回退步骤
- `2026-11-16\vibe-coding-review\work\batch2\gate_run.txt`、`no_side_effects.json`、`MANIFEST.sha256` —— B2 全量门禁结果与"零副作用"证明
- `2026-11-16\vibe-coding-review\work\batch3\rules_gap_report.md`、`rules_coverage.json`、`rules_extracted.json`、`mine_rules.py` —— B3 规则覆盖与缺口（含 9 条撞号明细）
- `pack\02_规则库\规则库_R33-R119.md` —— **B4 规则史收敛**：87 条规范定义 + 附录 A（9 条裁决）/ B（21 条唯一写法）/ C（需人定）
- `2026-11-16\vibe-coding-review\work\batch4\` —— `canonical_coverage.json`（机器可读镜像）、`human_decisions.md`（仍需人定）、`merge_canonical.py`、`verify_merge.py`、`rules.before_canonical.json`（回退基线）、`MANIFEST.sha256`
- `pack\rules.json` —— 119 条规则登记表（机器生成，可复跑）
- `2026-11-15\m3-task-card\work\verification\20261116T213155\` —— B2 门禁产物（21 套日志 + summary.json）
- `2026-11-16\vibe-coding-review\outputs\VIBE_CODING_OPTIMIZATION_PROPOSAL.md` —— 优化提案主文档（上一任务交付物，不属本批回滚范围）
- `2026-11-16\vibe-coding-review\work\metrics.json`、`project_survey.md`、`research_sources.md`、`collect_metrics.py` —— 提案采集材料（同上）

- `work\evidence_o2a_vharness.json`、`evidence_o2a_vharness_before.json` —— O2-a 全量 vharness（21/21、63 检查点）与接入前旧态（15/6）
- `work\evidence_o2a_expr.log`、`evidence_o2a_pytest_after_expr.log` —— verify_expr 外部 oracle 实跑输出（含 `[oracle]` 与残差行）与 pytest `554 passed`
- `work\evidence_numbers_ledger.json` —— **数字总账唯一权威**（M13–M18，8 小节/8 证据/67 数字，含 per-source sha256 与新鲜度规则）
- `work\evidence_ledger_unprotected.json` —— `ledger_check --audit` 未登记数字清单（105 个，五类原因）
- `work\evidence_m5_expr_residual.json` —— M5 表达式层残差逐地址（cli 1 / bin_ls 403 / dyn_static 390，objdump 2.47.20260726）
- `work\verification\20261117T001004-58f1\` —— O2-b 全量门禁产物（21 套日志 + vharness.json + pytest.log + summary.json）

## 6. 下一位第一条命令

```powershell
python "pack\tools\status.py"
python "pack\tools\verify_gate.py" --list
```

期望：`HANDOFF: 6/6 段非空`、`pack 目录名损坏 4/7`（已知，WARN 不算失败）、`verification/latest: PASS`（最近一次须为全量，否则 WARN）、`numbers ledger: PASS`、`git: 未初始化`（WARN），末行 `VERDICT: PASS exit=0`。
要跑全量再执行 `python "pack\tools\verify_gate.py" --run`（约 7 分钟，21 套 + pytest + ledger）。
若退出码为 1：先按本文件模板补齐 HANDOFF、修 ledger 漂移或重跑门禁，不要绕过。
