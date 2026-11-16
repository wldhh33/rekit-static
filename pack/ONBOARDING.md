# ONBOARDING.md · 新接手者入口（10 分钟版）

> 面向：第一次进入本项目的会话或人。目标：10 分钟内知道**这是什么、现在在哪、怎么跑、以谁为准、哪些话不能当结论**。
> 定位：**只指路，不复述**。CHARTER(44,548B) + PROGRESS(131,319B) + CHANGELOG(86,970B) = 262,837 B（2026-11-17 实测），本文不重抄。
> 维护：本文与 `AGENTS.md`（稳定事实）和 `HANDOFF.md`（当前态）分工不同——**本文是地图，那两份是手册与便签**。改本文时同步 §8 的过期信号。
> 出处约定：`文件:节/行` 行号为 2026-11-17 版；与标题冲突时**以标题为准**（行号会漂）。

## §0 十分钟路线

| 分钟 | 做什么 |
|---|---|
| 0–4 | 读 `pack\AGENTS.md`（约 109 行）：这是什么、硬约束、命令、目录地图、禁区别 |
| 4–6 | 读 `2026-11-15\m3-task-card\work\HANDOFF.md`（约 80 行，六段）：当前进度 / 未完成 / 已否决 / 待确认 |
| 6–7 | 跑 `python "pack\tools\status.py"`：一条命令给出 7 项状态与结论 |
| 7–10 | 读本文 §3（门禁）、§4（权威链）、§6（边界）；需要细节再按 §5 去查原文件 |

**不要**为了"了解现状"去读 PROGRESS/CHANGELOG 全文。它们是按日期累积的证据账，只按 §5 索引定点查。

## §1 这是什么

- `rekit`：纯 Python 标准库的二进制静态分诊/分析工具（PE / ELF / .NET），三种用法：CLI、Python 模块、MCP 服务器。出处：`AGENTS.md:8-10`、`pack\README.md:27-31`。
- 项目性质：每日逆向学习的**载体**；当天产出必须回流成模块/规则/测试才算达标。出处：`AGENTS.md:9`、`CHARTER.md:5-9`。
- 规模（`status.py` 现算）：**28 个模块（含 `__init__.py`/`__main__.py`）/ 18,734 行（非空 17,333）**；25 个 `test_*.py`（6,404 行）；23 个 `verify_*.py`（10,450 行）。⚠ `AGENTS.md:10` 写的是 27 模块 / 18,720 行：行数差 14 与 U1-a 新增的 `rekit\__main__.py` 相当，模块差 1 疑为 `__init__.py` 未计入，但两处口径都没有注明——**以 `status.py` 为准**（详见 §8 第 1 条）。

## §2 现在在哪

**LAST = M20 收口（2026-11-17），已转入交付轨；M1–M20 全线收口，无在研里程碑。**

| 段 | 里程碑 | 一句话 | 权威记录 |
|---|---|---|---|
| 加载/指纹 | M1 loader → M1.5 MCP → M2 fingerprint → M3 map&patch | 解析 PE/ELF、ELF/PE 指纹（UPX×3、GCC/MSVC/Go/Rust）、映射换算 + IAT 修复 | `CHARTER.md:20-23`；证据 `work\evidence_map_2026-11-15.log` 等 |
| 反汇编/控制流 | M4 cfg → M5 表达式(U1–U3) → M6 调用图 → M7 三层拼接 | 指令边界、CFG 五类边、表达式、调用图/参数事实、三层同址对齐 | `CHARTER.md:24-27` |
| 口径对齐 | M8 口径对齐(U0–U3) → M9 覆盖缺口+样本 → M10 归因与性能 → M11 gopclntab → M12 推算换实测 → M13 下界重算 → M13-patch → M14 | 判据独立化、覆盖率恒等式、Go 函数表、缝隙量化、下界逐项复算 | `CHARTER.md:28-36`；数字 `NUMBERS_LEDGER.md` §1–§9 |
| 报告/数据层 | M15 funcreport → M16 datarefs | 七层同址报告（只呈现不判断）、非字符串数据引用（对象只认声明） | `CHARTER.md:37-38`；LEDGER §10–§11 |
| .NET 纵切面 | M17 dotnet → M18 ilflow → M19 sigblob → **M20 layout（封口）** | 结构→IL 控制流→签名语义→类型布局与 FieldRVA | `CHARTER.md:39-42`；LEDGER §12/§13/§15/§16 |
| 交付轨（不占里程碑号） | U1-a 打包 → U1-b 证据索引/R95 → U1 收口（gate.ps1、R126）→ 干净克隆演练（v0.1.1） | `pyproject` + `rekit` 命令 + JSON 契约冻结 + 证据索引 + 一命令门禁 | `PROGRESS.md:383-419`；tag `v0.1.0`→`d63d244`、`v0.1.1` |

**当前门禁态（2026-11-17 实跑，run `20261117T040139-2ff9`）**：23/23 套 verify PASS、pytest **554 passed / 0 failed / 0 skipped**、ledger **10 小节 / 10 证据 / 103 数字** PASS、证据索引 **129/129**、`VERDICT: PASS`；vharness 361.2 s + pytest 75.6 s ≈ **436.8 s（7.3 分钟）**。出处：`work\verification\latest\summary.json`、`pack\tools\status.py` 输出。

**方向已定**：M20 是 .NET 纵切面的封口，不是"第四个 .NET 里程碑"。转段判据 T1–T5 已写进 `CHARTER.md:44-68`；**T1 与 T4 已命中**（T1 实现/验收新增行比 0.96 ≥ 0.90；T4 运行期 oracle 依赖 Windows CLR），T2 计数 1/2。所以后续是交付/发布工作，不是继续叠层。

## §3 怎么跑门禁

**一条命令**（在仓库根，约 7 分钟）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1"
```

- 只看计划：加 `-List`；跑子集：`-Only verify_map,verify_iat`。出处：`pack\README.md:75-77`、`AGENTS.md:34`。
- **前置**（`gate.ps1` 逐项硬检查，缺一项 **exit 2 且不跑任何验证**）：Python 3.8+；`work` 与 3 个 junction；`samples`（m9/m17/m18/m20）；M19 样本 manifest 逐条 sha256；binutils 2.47；`powershell` + `pwsh`；`dnfile`（`pefile` 建议装）。出处：`pack\README.md:35-53`、`HANDOFF.md:18-19`。
- **干净克隆**：`git clone` → `pack\tools\setup.ps1 -AssetsSource <原工作区根>` → `gate.ps1`。样本与工具链**不入库**，必须显式恢复，不下载、不猜来源。出处：`pack\README.md:55-73`。
- 退出码：`0` PASS / `1` 实质失败 / `2` 前置缺失（先恢复资产，不要绕过）。出处：`AGENTS.md:34`、`HANDOFF.md:78-80`。
- **pytest 必须在 `work` 目录跑**（`tests` 是 junction，fixture 按 cwd 解析）：`cd "2026-11-15\m3-task-card\work"; python -m pytest tests -q`。出处：`pack\README.md:85`。
- 手动等价：`python "pack\tools\verify_gate.py" --run` + `python "pack\tools\ledger_check.py" --check` + `python "pack\04_rekit项目源码\tests\evidence_index.py" --check`。

## §4 哪些文件是权威（含 ledger 的三层）

| 问题 | 最终权威 | 人读镜像 / 辅助 | 硬校验 |
|---|---|---|---|
| **任何数字** | `work\evidence_numbers_ledger.json`（覆盖 M13–M20，`sections` 逐节登记） | `work\outputs\NUMBERS_LEDGER.md`（§0–§16）；未登记清单 `work\evidence_ledger_unprotected.json` | `python "pack\tools\ledger_check.py" --check`（小节缺失/数字漂移/sha 变化/证据 mtime 晚于权威 → exit 1） |
| M13 及更早数字 | 仍有效，但只作**历史快照**：`work\evidence_m13_ledger.json`、`work\evidence_m12_ledger.json` | 同上镜像 §1–§6 | 由新权威的 `sources` 以 sha256 钉住 |
| 规则 R01–R119 | `pack\rules.json`（119 条机器登记，`mined` 只读 / `canonical` 可判） | `02_规则库\规则库_R01-R32.md`、`02_规则库\规则库_R33-R119.md`（87 条五字段 + 附录 A–E）；R120–R126 见附录 E | `status.py` 报 `rules registry: 119 条` |
| 里程碑定义与完成标准 | `03_路线图与章程\CHARTER.md`（M1–M20 表 + T1–T5 + 运行环境记录） | — | — |
| 当日怎么验的、数字怎么来 | `03_路线图与章程\PROGRESS.md`（按日期节，L36 起；最近七节 L298 之后） | `work\outputs\TASK_*.md`（任务卡/收口报告） | — |
| 标准何时改过、为什么 | `03_路线图与章程\CHANGELOG.md`（`日期｜旧→新｜原因｜影响`） | — | — |
| 当前进度/下一步/已否决 | `work\HANDOFF.md`（六段，≤150 行） | — | `status.py`：`HANDOFF: 6/6 段非空` |
| 稳定事实/硬约束/命令/目录 | `pack\AGENTS.md` | — | — |
| 程序接口字段名 | `03_路线图与章程\JSON_CONTRACT.md`（v0.1.0 冻结，改名/删字段=破坏性变更） | `pack\README.md`、`04_rekit项目源码\README.md` | — |
| 某条证据来自哪次运行 | `work\EVIDENCE_INDEX.json`（129 条：sha256/size/mtime/run_id/覆盖小节） | `work\verification\<run_id>\summary.json` | `tests\evidence_index.py --check` |
| 目录为什么叫这个名 | `pack\PATH_MAP.md`（mojibake 改名与旧名对照） | — | `status.py`：`pack 目录: 7 个均可访问` |

**三条链别混**：数字链（ledger JSON）＞规则链（rules.json）＞叙事链（CHARTER/PROGRESS/CHANGELOG）。叙事链里的数字**一律不权威**，遇到冲突以 JSON 为准。

## §5 索引：想了解 X 就看 Y 的哪一节

| 想了解 | 去看 |
|---|---|
| 项目为什么存在、长期目标、三阶段路线 | `CHARTER.md:5-14`；`RE-ROADMAP.md:21-59`（阶段一/二/三）、`:93`（长期项目 #1） |
| 每个里程碑的**完成标准原文** | `CHARTER.md` 里程碑表（M1 L20 → M20 L42），每行末有证据路径 |
| 某个数字的分子/分母/口径/旧值对照 | `NUMBERS_LEDGER.md` §0（以哪份为准）→ 对应小节：§1–§5 样本与缝隙、§6 下界结论、§9 M14、§11 M16、§13 M18、§15 M19、§16 M20 |
| "这个数为什么是下界/不是下界" | `NUMBERS_LEDGER.md` §6 的「类别」列（`complement_measure` / `seed_invariant_count` / `count_with_alignment` / `stability_check`）+ `CHANGELOG.md` R104–R107 |
| 某层为什么这么设计、否决了什么 | `HANDOFF.md` §3（已否决 7 条）、§4（待确认 5 条）；`work\outputs\TASK_m*_*.md` |
| 规则 R49/R93/R110 等存疑项的定案 | `02_规则库\规则库_R33-R119.md` 附录 C（L846）；裁决记录 `2026-11-16\vibe-coding-review\work\batch5\RULE_ADJUDICATIONS.md` |
| 规则编号撞号/多写法的裁决 | 同文件附录 A（L791）/ B（L809） |
| `R120`–`R126` 是什么 | 同文件附录 E（L889）；`CHANGELOG.md` 同日行 |
| 验收标准每次调整的理由 | `CHANGELOG.md` 表（一行一次变更，含"影响评估"） |
| 环境怪癖（LC_ALL、中文路径、垫片、不可再分发样本） | `AGENTS.md:68-81`；`CHARTER.md:93-100`（运行环境记录，R67） |
| 现在缺什么、下一步做什么 | `HANDOFF.md` §2（未完成）、§6（第一条命令） |
| 接口字段与退出码 | `JSON_CONTRACT.md`（info/map/ilflow/datarefs 四命令）；失败语义见各节末尾 |
| 证据文件的来源 run 与覆盖范围 | `work\EVIDENCE_INDEX.json`（`rules` 段写死归因规则）；缺口统计见 `PROGRESS.md:392` |
| 交付轨做到哪、tag 怎么定的 | `pack\README.md:120-131`（版本与 tag、release tag 规则）；`PROGRESS.md:383-419` |
| 治理批次（O2/批1–批5）做了什么 | `PROGRESS.md:333`（O2-b）；`2026-11-16\vibe-coding-review\work\batch1..batch5\` |

## §6 看起来是结论、其实有边界的 12 条

| 说法 | 真实边界 | 出处 |
|---|---|---|
| "覆盖率 80.37%" | 是**25 样本**合并口径；旧 18 = 62.51%、新 7 = 81.66%，不可跨样本集引用 | LEDGER §2 |
| "strxref 5,039 引用点 / 276 字符串" | **补集度量**，不是下界；对 Go 近乎盲（18 样本中 2 个 Go 贡献 0→0） | LEDGER §6；R104 |
| "VEX 弃权 206,541" | 是"非 objdump 指令边界"计数，**不是"数据"**；结论限 11 个样本 | LEDGER §6；R107（C1） |
| "Go 域内未达 26,652 / 26,702" | **含对齐字节**，不是"漏解指令数"；nop 族仅 1,067 / 1,066 | LEDGER §6/§9；R107（C4） |
| "switchcand 覆盖率 / candidates" | 是 `analysis_coverage`，**不是候选数下界**；`no_run` ≠ `skipped_budget` | LEDGER §6；R107（C2/C5） |
| "M20 字段偏移" | 只有 `FieldLayout.Offset` / `ClassLayout` / `FieldRVA` 是静态可证；sequential/auto 偏移单列 `runtime_derived`，`static_conclusion=false` | `CHARTER.md:42`；`HANDOFF.md:9` |
| "unknown 已归零" | `unknown`（不可知，如外部程序集 `valuetype`）与 `undecoded`（编码错误）**必须分开报**；M20 仍有 unknown 1/132 | R121；`HANDOFF.md:8` |
| "弃权/残差" | 一律**单列**，不并入成功率，且必须写 `missing`（缺什么）；`evidence_m5_expr_residual.json` 是残差账 | R40/R47/R51；`CHARTER.md:22-25` |
| "`sentinel` / `pinned` 签名" | **仍无样本**，没造、没冒充；`LOCAL_SIG` 只记长度/边界 | `HANDOFF.md:27`（§2 首行） |
| "M19 用 dnfile 对拍签名" | 定标②**已偏离**：dnfile 无 Signature API，改用 SRM（`tests\sigref.ps1`，缺 pwsh 即 `env_missing` exit 2） | `CHARTER.md:41`；`PROGRESS.md:346` |
| "tag `v0.1.0` 是最新交付" | `v0.1.0`→`d63d244`；收尾补件在 `v0.1.1`；release tag 规则见 README | `pack\README.md:120-131` |
| "有 CI" | **没有已启用的 CI**。`.github\workflows\gate.yml` 是未验证草稿（无远端、从未触发），只跑两项轻检查 | `pack\README.md:133-137`；`AGENTS.md:66` |

另两条口径纪律：证据里**不得写仓库内绝对路径**（会让 sha256 随克隆目录漂移，异地 clone 必 FAIL）；`122` 条历史 `null` run_id **不回填、不猜**。出处：`AGENTS.md:77-79,97`；`HANDOFF.md:30`。

## §7 不许做的事（只列最常被踩的）

1. 不改既公布数字的口径去"对齐结果"；偏低按 R72 就地标注（`AGENTS.md:85`）。
2. 不删证据文件；失败日志改名保留（`AGENTS.md:86`）。
3. 推算值（estimated）不进 CHARTER/PROGRESS/README/总账（`AGENTS.md:87`）。
4. 被测模块与校验器不得共用同一段判据（R73）；对拍分母为 0 不得判 PASS（R119）。
5. **本工作树可能另有会话在改 `rekit\*.py`**：非源码会话只读，改动需求写进 `HANDOFF.md` 未完成清单（`AGENTS.md:92`）。

## §8 这一版入口文档自觉的局限

**半年内大概率会过期（每次收口都会动）**

| 内容 | 过期信号（可观察） |
|---|---|
| §2 里程碑表 / 当前门禁态 / tag | `CHARTER.md` 里程碑末行不再是 M20；`git tag` 出现 `v0.2+`；`status.py` 的 `verification/latest` run_id 变化 |
| 套数 23 / pytest 554 / ledger 103 数字 / 索引 129 | `gate.ps1` 输出的套数或 `summary.json` 的 `total`/`passed` 与本文不符 |
| §1 规模数字 | `status.py` 的 `规模:` 行变化（它每次现算，**以它为准**） |
| §4 权威链 | `pack\tools\` 出现新脚本而 §4/§3 未提；ledger `sections` 数 ≠ 10 |
| §6 边界清单 | 任一里程碑新开一层、或 R12x 增加；`HANDOFF.md` §4 待确认项被裁决 |
| CI 状态 | `.github\workflows\gate.yml` 从"未验证草稿"变为有远端实跑记录（U2） |

**已知不一致 / 待核实（本文不掩盖）**

1. `AGENTS.md:10` 写 27 模块 / 18,720 行；`status.py` 现算 **28 模块 / 18,734 行（非空 17,333）**。行数差 14 与 `rekit\__main__.py` 体量相当（U1-a 新增），模块差 1 疑为 `__init__.py` 未计入；**两侧口径均未注明**——待核实，以 `status.py` 为准。
2. "曾因历史过大导致会话加载超时失败"是任务背景口述，**仓库内无次数/时间的书面记录**，本文只写结论不写细节。
3. 任务说明称三份主文档"约 240KB"，实测 **262,837 B**（CHARTER 44,548 + PROGRESS 131,319 + CHANGELOG 86,970），以实测为准。
4. `PROGRESS.md:412` 干净克隆演练记 `432.5 s`，本机最新 run 记 `436.8 s`——不是矛盾，是两次运行，引用时请带 run_id。

**本文明确不覆盖**：每日任务卡/日报流程（`05_每日日志`、`06_日报docx`）、R01–R32 的逐条语义（去规则库）、vibe-coding 治理批次的过程细节（去 `2026-11-16\vibe-coding-review\`）、M1–M14 的逐日数字（去 PROGRESS/LEDGER 定点查）。这些是"该指路"而不是"该复述"的部分。
