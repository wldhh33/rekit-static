# 8 项规则史存疑的裁决记录（2026-11-16）

| 项 | 内容 |
|---|---|
| 范围 | 8 项，覆盖 14 个规则号：R33 / R34 / R35 / R49 / R67 / R72 / R87 / R88 / R89 / R93 / R95 / R102 / R103 / R110 |
| 裁决方式 | 按证据自行定案，不逐条等人工拍板；证据不足的留显式缺口，不用反推当确证 |
| 结果落点 | `pack\rules.json`（canonical 字段）、`pack\02_规则库\规则库_R33-R119.md`（附录 C + 各条正文）、`work\batch4\canonical_coverage.json`（机器镜像） |
| 未做的事 | 未运行 rekit 验证套件；未改 `rekit\`、`tests\` 下任何代码；未改 `NUMBERS_LEDGER.md` |
| 复跑 | `python work\batch5\check_r95_manifest.py`；`python work\batch5\apply_adjudications.py`；`python work\batch5\sync_coverage.py`；`python work\batch4\verify_merge.py` |

## 0. 一页结论

| # | 规则 | 定案 | 类型 | 状态变化 |
|---|---|---|---|---|
| 1 | R49 | 五类强制覆盖 = 导入调用 / 回边 / 间接 jmp / SIMD abstain / 最大函数 | 可确证 | 材料不足 → 规范 |
| 2 | R93 | 五项检查 = guard_proven / table_complete / min_targets / function_domain / external_boundary | 可确证 | 材料不足 → 规范 |
| 3 | R110 | after_object 窗口 = 对象末尾后 0<Δ≤64 字节 | 可确证（实现口径常量） | 材料不足 → 规范 |
| 4 | R102 / R103 | 现行权威 = `evidence_numbers_ledger.json`（M13–M18）；`evidence_m13_ledger.json` 降为 M13 历史快照 | 可确证 | 引用链改三层 |
| 5 | R95 | 规则成立；登记落地 18/25，7 个 fixture 缺三栏 | 规则可确证 + 落地缺口 | 规范 + 显式缺口 |
| 6 | R67 | 运行环境记录节存在，保留为强制回归前置 | 可确证（文档级执行） | 表述补实 |
| 7 | R72 / R87 / R88 / R89 | 不引入自动检查，保持文档级 | 决策 | 理由入册 |
| 8 | R33 / R34 / R35 | 判定方式由 E9 载体源码与 manifest 修正记录确证，不再是反推 | 可确证 | 三条升为规范 |

裁决后 `材料不足` 计数：**3 → 0**（R49 / R93 / R110 全部结案）。
`规范·判定方式为文档级` 仍为 8 条（R67、R72、R87、R88、R89 及另外 3 条原有文档级规则）。

---

## 1. R49 · 「5 类强制覆盖」未列五类

- **原状**：`CHANGELOG.md:28,29` 只写「分层等距 + 5 类强制覆盖，无随机数」；`work\pack03` 全目录检索无枚举，故标 `材料不足`。
- **证据**：`tests\verify_expr.py` 是 R49 的实施载体，其文件头把抽样规则逐条写死（`:12-17`），并在 `:48` 定义 `CATS` 五类：`indirect_call` / `loop` / `indirect_jmp` / `simd` / `largest`；`:92-104` 的 `sample()` 对每一类做强制覆盖并对不存在的类别显式记「该二进制无此类」。
- **定案**：五类 = ①含导入调用（IAT/GOT 槽间接 call）②含回边（循环）③含间接 jmp（switch/跳转表形态，我方 abstain）④含 SIMD abstain（VEX/EVEX 或 SSE）⑤该二进制最大函数。分层边界同脚本：S1 ≤10、S2 11–30、S3 31–100、S4 >100，层内按地址升序等距取 min(4,n)。
- **为何不是反推**：这段是脚本**先于抽样结果写死的规则**（文件头注释 + 常量 + 抽样函数），不是从结果回推的口径；它约束的正是 R49 的约束对象（验收方法）。
- **影响范围**：R49 从 `材料不足` 升为 `规范`；后续任何重新抽样必须沿用同一五类与同一分层，改类别或层界属口径变更，须在任务卡声明并同步 `verify_expr.py`。
- **仍存疑**：五类的**命名**在脚本与文档中不完全一致（文档写「含导入调用」，脚本字段为 `indirect_call`）；已按语义对齐，未改代码。

## 2. R93 · 「5 项检查」未具名

- **原状**：`CHANGELOG.md:87` 只写「5 项检查全过才升格」，未列五项，故标 `材料不足`。
- **证据**：`rekit\switchcand.py:486-492` 构造 `checks` 字典，键即五项；`:495-505` 把未过项写入 `reasons` 并把状态置 `blocked`；`tests\verify_switchcand.py` 用外部边界独立复算并做空边界负控。
- **定案**：五项 = ①`guard_proven`（表长由 `cmp idx,imm` + `ja/jae` 证明）②`table_complete`（无被拒项、未触发扫描截断）③`min_targets`（有效目标 ≥4）④`function_domain`（全部目标在声明函数域内）⑤`external_boundary`（全部目标出现在外部 objdump 指令起点集合）。
- **影响范围**：R93 升为 `规范`；升格判据以源码为准，文档不再有「五项未具名」的缺口。若新增第六项检查，必须先改规则库再改代码。
- **仍存疑**：`min_targets=4` 这个阈值是源码常量，文档未给取值依据；性质与 R110 的 64 相同，属既定口径而非规则缺口。

## 3. R110 · 「对象之后窗口」无大小

- **原状**：`CHANGELOG.md:103` 与 `PROGRESS.md:306` 只说 `after_object` 带 `delta` 且只表示邻接，未给窗口上限，故标 `材料不足`。
- **证据**：`rekit\datarefs.py:38` `AFTER_WINDOW = 64`（注释：对象末尾后 0<Δ≤64 记 after_object，超窗不归因）；`:63`、`:77` 的 `CALIBER` 行已明写「这个窗口是口径，不是『紧邻对象』的推断」；`:503-504` 实际使用该常量。
- **定案**：窗口 = 对象末尾后 **0 < Δ ≤ 64 字节**；超过 64 字节不归因到任何对象。
- **影响范围**：R110 升为 `规范`。改动 `AFTER_WINDOW` 属口径变更，必须同步三处：`CALIBER` 文本、`tests\verify_datarefs.py` 的三档核对、总账里 `after_object` 的计数（否则历史数字与新口径不可比）。
- **仍存疑**：64 只说明「当前口径」，**没有取值依据**（为何不是 8/16/32）。建议下次改 `datarefs` 时在 `CALIBER` 补一句理由；本次不擅自补。

## 4. R102 / R103 · 权威总账是 M12 还是 M13

> **2026-11-16 第二轮修正**：裁决期间另一路已把权威切到 `evidence_numbers_ledger.json`（M13–M18），并加了硬校验。本节的结论已按新事实改写，旧版「M13 为现行权威」作废。

- **原状**：裁决时（当天早些时候）`NUMBERS_LEDGER.md` §0 指向 `evidence_m13_ledger.json`，两份快照的 `meta.note` 都自称「唯一权威」，规则库的 `enforced_at` 指向 M12。
- **现行事实**（已核实）：
  - `work\evidence_numbers_ledger.json` 是**现行权威**，`scope` = 「M13 收口（含 M13-patch）至 M18 收口」，`effective_from` = `M13-patch`，`mirror` = `work\outputs\NUMBERS_LEDGER.md`。
  - `pack\tools\ledger_check.py --check` 做硬校验，六项任一命中即 **exit 1**：权威头部自指一致、镜像 §0 指向权威、已登记小节在镜像中存在且节号一致、登记数字逐字出现、证据文件 sha256 相等、证据 mtime 不晚于权威 JSON。
  - `evidence_m13_ledger.json` 已降级为**「M13 历史权威快照」**：它在 `evidence_numbers_ledger.json` 的 `sources` 里以 sha256 固定（角色写「M13 逐样本权威快照（历史源，判定表/代码 sha256）」），仍被引用，但不代表现行范围。
  - M12 及更早仍由 `evidence_m12_ledger.json` 承担（`scope` 字段明写）。
- **定案**：R102/R103 的引用链改为三层——`evidence_numbers_ledger.json`（现行权威，M13–M18）> `evidence_m13_ledger.json`（M13 历史快照，`sources` 引用）> `evidence_m12_ledger.json`（M12 及更早）。
- **如何区分「历史快照」与「现行权威」**（写进规则库附录 C，防止以后再按旧的单文件权威判断）：
  1. 看 `authority` + `scope`：现行权威的 `scope` 覆盖当前全部里程碑；历史快照只覆盖单个里程碑。
  2. 看是否被硬校验：只有进入 `ledger_check.py` 的 `SECTIONS` / `NUMBERS` 登记、并参与 sha256 与 mtime 校验的才是现行权威。
  3. 看镜像指向：`NUMBERS_LEDGER.md` §0 声明的路径即现行权威；镜像与权威不一致时以权威为准。
  4. **不对**的判断依据：文件名里的里程碑号；文件内「唯一权威」的自述（M12、M13 都曾这样自称）。
- **影响范围**：任何新文档引用覆盖率 / A/B / 逐函数 / 缝隙数字，先看该数字属于哪个里程碑小节，再引现行权威；引 M13 快照时必须写明「M13 历史快照，经现行权威引用」。M12/M13 证据文件本身不改（历史证据不动）。
- **仍存疑（新增，来自实测）**：R103 的 `pe_gap` 三个数字（113,731 / 3.2262% / -0.0402pp）**没有进入新权威 M13 小节的 `numbers` 登记**（该节只登记 §6 下界结论的 6 个数字：`5,039/276`、`206,541`、`26,652/26,702`、`12,272/3,530/37,891`、`1,974`、`2,081`）。因此 `ledger_check` 不校验它们，这三个数字被改动不会被门禁发现。补登记即可闭合，本次不代改总账。

## 5. R95 · 样本三栏未逐样本核

- **原状**：只确认 `m9_sample_manifest.json` 存在且 `violations: []`，未逐样本核 sha256 / 许可 / 可再分发三栏，也未核总账 25 个样本是否全覆盖。
- **证据**：`work\batch5\check_r95_manifest.py`（只读）实测：M2 `sample_manifest.json` 11 个样本、M9 `m9_sample_manifest.json` 7 个样本，三栏 **18/18 齐全**，`violations=[]`；但 `evidence_m13_ledger.json` 的 `coverage.rows` 有 25 个样本，另 7 个 `tests/fixtures` 不在任何 manifest 中。
- **缺的 7 个**：`dyn_nopie`、`dyn_static`、`dyn_execstack`、`dyn_norelro`、`minipe.exe`、`minidll.dll`、`minipe_fakerich.exe`。
- **定案**：R95 **规则本身成立且表述完整**（无需改写规则句）；落地状态为 **18/25**。缺口写成显式事实，不抹平。
- **影响范围**：在补登前，任何「25 样本全部合规登记」的表述都属于不实陈述，应写「18/25，另有 7 个回归 fixture 未登记三栏」。补登动作归样本线负责人，不在本次范围。
- **仍存疑**：这 7 个 fixture 是否本来就按「回归夹具」豁免登记（不需要许可栏）——现有材料没有这条豁免规则；在补规则或补登记之前，只能按 R95 原文判为缺口。

## 6. R67 · 环境记录是否长期作回归前置

- **原状**：标 `规范·判定方式为文档级`，但未核实节是否真实存在、是否自引 R67。
- **证据**：`CHARTER.md` 的「运行环境记录（回归前置）」节存在（`pack03\CHARTER.md:62` 一带），含 Python 版本、`PYTHONIOENCODING=utf-8`、objdump 路径、中文路径需 `LC_ALL=C`，节内自引 R67。
- **定案**：保留为**强制回归前置**；判定方式维持文档级（无脚本）。
- **影响范围**：换机器、换 Python、换 binutils、换 locale 时必须先更新该节；未更新的环境跑出的结果不得与旧结果直接对比。
- **仍存疑**：无自动校验，靠人执行；若要自动化，最小可行做法是在 `verify_gate.py` 启动时比对 `--version` 输出与该节记录，但这属于门禁改造，不在本次范围。

## 7. R72 / R87 / R88 / R89 · 纯文档规则是否引入自动检查

- **原状**：四条都是文档结构/措辞判据（旧数字原地更正、三列成对、四列台账、能力二分归因），当前只有人工流程。
- **证据**：M8 收口文档 `2026-11-15\m3-task-card\outputs\TASK_m8_closeout.md` 已有实例：§2 能力 11 项 = 信息不在文件里 5 + 还没做 6；§3 六条四列表；§2/§3 的 22 条判据成对。`PROGRESS.md:120` 的「1141/3556 已知偏低：分别漏 13/53 条」是 R72 的原地标注实例。另：原 `enforced_at` 把路径误写为 `work\outputs\`，实际在 `outputs\`，本次已更正。
- **定案**：**不引入自动检查，保持文档级**。
- **理由**：可自动化的只有「节是否存在、列数是否对、有没有禁用词」——这些能查出形式不齐，查不出「三列填的内容是否成立」。若把它做成门禁，会制造一种新的假 PASS：格式齐全但结论不实，正是本轮提案 §9.2 列出的反模式之一。
- **影响范围**：四条状态维持 `规范·判定方式为文档级`，但理由入册，不再作为「待办」挂起。触发重新评估的条件：收口频率上升，或出现「形式齐全但内容不成立」的实例。
- **仍存疑**：人工审查的质量取决于执行者；这是流程成本，不是可以通过工具消除的风险。

## 8. R33 / R34 / R35 · 原文仅一行摘要，判定方式是否属于反推

- **原状**：三条的判定方式原先取自 `PROGRESS.md:58` 同段实测描述，标注了「反推」，可信度存疑。
- **证据**：
  - R33：`2026-11-15\m2-task-card\work\sample_manifest.json` 的 `e9_ground_truth.corrections_before_freeze` 逐条记录了两处冻结前修正（S5 `hello_go_linux` 的 `nx`、S7 `busybox` 的 `relro`），并写明由 `readelf -lW` 复核发现——这同时确证了「用权威工具复核」的判定方式和「修正属标注、不属判据」的边界。
  - R34：`tests\verify_fingerprint.py:6-10` 写死四维度分别出矩阵、分母为可判定格、弃权格单列；`:187-194` 的 `confusion()` 只统计可判定格。
  - R35：`tests\verify_fingerprint.py:6-8` 写死三态纪律（unknown 只对 `undeterminable` 算命中；可判定格答 unknown 记 miss；不可判定格给确定值记 FP）。
- **定案**：三条不再是反推——判定方式与实例都有载体（源码写死的口径 + manifest 的修正记录）。三条状态从「摘要 + 反推」升为 `规范`。
- **影响范围**：R33 的执行仍是人工复核流程（没有脚本能证明「真的用 readelf 看过」），这一点在 `canonical_status` 与「仍存疑」里保留；R34/R35 有源码契约，可视为脚本级判据。
- **仍存疑**：R33 的复核质量无法自动验证；只能在收口时要求修正记录必填（当前 manifest 已这么做）。

---

## 9. 顺带核对：`NUMBERS_LEDGER.md` 的规则区间滞后（**已由总账链路修复**）

- **原状**（裁决当天早些时候）：`NUMBERS_LEDGER.md` 的规则引用停在 **R114**（当时 §11「M17 .NET 程序集结构层」的 `R112–R114` 汇总块），此后没有 M18 的 IL 控制流节，R115–R119 在总账中没有落点。
- **现状**（2026-11-16 第二轮核实）：**已修复**。镜像补入三节——M14 对齐实测（§9）、M18 .NET IL 控制流层（§13）、M5 表达式层验收补强（§14）；`R115–R119` 已在 §13 出现（`NUMBERS_LEDGER.md:399`）。
- **节号顺延副作用**：原 §9–§11（M15 报告层 / M16 数据引用层 / M17 .NET 结构层）顺延为 **§10 / §11 / §12**。任何仍按旧节号引用的文档（如「§11 M17」）都要改成新节号，否则会指到 M16。
- **归属**：属总账链路，由总账负责人随里程碑收口更新；本次只在规则库附录 C 与本文记录，不动 ledger。

## 10. 本次顺带发现（未越界修改）

1. **R87 / R88 / R89 的落地路径原写 `work\outputs\TASK_m8_closeout.md`，实际在 `2026-11-15\m3-task-card\outputs\`**（无 `work` 层）。已在规则库与 `rules.json` 更正。
2. **同一路径错误还存在于其它条目**（例如 R77 指向 `work\outputs\TASK_m8u0_*.md`，实际在 `outputs\`）。不在本次 8 项范围内，未改，留作下一轮清理。
3. **两份旧 ledger 都自称「唯一权威」的问题已由新权威的 `authority` / `scope` / `sources` 结构解决**；旧文件的自述不再作为判断依据（见第 4 节）。

## 11. 一致性自证

- `python work\batch4\verify_merge.py` → **0 mismatches**：本次只改 canonical 区字段，119 条 mined 字段（`statement`/`source`/`status`/`alternates`）逐条未变，`stats` 不变。
- `python work\batch5\sync_coverage.py` → 87 条镜像按 `rules.json` 重建，`material_insufficient` 由 3 条改为空，`doc_level_only` = 8。
- 规则库正文（各条五字段）与 `rules.json` / `canonical_coverage.json` 使用同一份文本，逐条对应。

## 12. 第二轮修正记录（2026-11-16，权威变更后）

只改两处，其余 7 项定案不动：

1. **R102/R103 引用链**：由「M13 为现行权威」改为「`evidence_numbers_ledger.json`（M13–M18）为现行权威，`evidence_m13_ledger.json` 降为 M13 历史快照」。同步更新 `pack\rules.json`、规则库 R102/R103 正文与附录 C 第 4 行，并补了四条「历史快照 vs 现行权威」的区分方法。
2. **总账滞后条**：由「待办/滞后」改为「已由总账链路修复」，注明新增 M14（§9）/ M18（§13）/ M5 补记（§14）三节，以及原 §9–§11 顺延为 §10–§12 的副作用。

未改动：R110 的 64 无取值依据、R95 的 7 个 fixture 登记缺口——仍是显式缺口。新增一条缺口：R103 的 `pe_gap` 三个数字未进新权威的 `numbers` 登记（见第 4 节「仍存疑」）。
