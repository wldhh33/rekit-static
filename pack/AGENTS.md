# AGENTS.md · rekit 项目工作入口

> 本文件是任何 AI 会话进入本项目的**第一份必读**。目标：让新会话在 5 分钟内知道"现在在哪、下一步做什么、什么不能做"，而不必加载 226 KB 历史文档。
> 维护规则：只写稳定事实与硬约束；进度与半成品写在 `2026-11-15\m3-task-card\work\HANDOFF.md`。本文件 ≤150 行。

## 1. 这是什么

- `rekit`：纯 Python 标准库实现的二进制静态分诊/分析工具（PE / ELF / .NET），提供 CLI、Python 模块、MCP 三种用法。
- 库接口只承诺 `rekit.api` 的导出符号，契约见 `pack\03_路线图与章程\LIBRARY_API.md`（其余模块是内部实现，不承诺稳定）。
- 项目性质：每日逆向学习的**载体**。当天没有回流成 `rekit` 模块/规则/测试，当天不算达标。
- 规模（模块数 / 行数 / 测试数 / verify 套数）：**一律现算，本文件不写数字**（R127）。看 `python "pack\tools\status.py"` 的“规模”三行；行数同时给“总行 / 非空行”，避免两种口径各写一个数。

## 2. 硬约束（不可协商）

1. **结论必须可核**：没有证据链的结论不写；不确定就写不确定。
2. **证据必须能复跑**：每个数字都要有命令、样本集、口径；推算值不得进入正式总账。
3. **不许为好看的数字放宽判据**：阈值、分母、口径一律不得迁就结果。
4. **不改原始样本**：写回必须生成新文件，二次执行幂等，并用 sha256 证明。

## 3. 当前状态与下一条命令

- 进度、未完成清单、已否决方案、待确认问题：**以 `work\HANDOFF.md` 为准**（每次会话结束必须更新）。
- 会话开工第一条命令：

```powershell
python "pack\tools\status.py"
```

## 4. 常用命令

| 目的 | 命令 |
|---|---|
| 状态摘要（≤20 行） | `python pack\tools\status.py` |
| 干净克隆恢复（junction + 样本/工具链） | `powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\setup.ps1" -AssetsSource <原工作区根>` |
| 单命令门禁（推荐，含前置检查） | `powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1"`（`-List` 只看计划；前置缺失 exit 2） |
| 全量门禁（全部 verify 套 + pytest） | `python pack\tools\verify_gate.py --run`（`--list` 只看计划；套数见 `status.py`） |
| 全量单测 | `cd "2026-11-15\m3-task-card\work"` 后 `python -m pytest tests -q`（fixture 路径按 cwd 解析，必须在 work 目录跑） |
| 单个验证脚本 | `python "2026-11-15\m3-task-card\work\tests\verify_disasm.py" --all` |
| 指纹混淆矩阵 | `python "...\tests\verify_fingerprint.py" --all --matrix` |
| 运行 CLI | `rekit info <file>`（已 `pip install -e .` 后任意目录）；未安装时 `python -m rekit.cli <file>`（在 `rekit` 父目录下） |
| 库接口示例（import，非 subprocess） | `python "pack\04_rekit项目源码\examples\pe_report.py" <pe>`（另见 `elf_report.py` / `dotnet_report.py`；契约 `pack\03_路线图与章程\LIBRARY_API.md`） |
| 库/CLI 一致性判据 | `python "2026-11-15\m3-task-card\work\tests\verify_api.py"`（已含在全量门禁；空比对 FAIL、篡改期望值须被检出） |

验证结果统一落在 `work\verification\<run_id>\`（每套一个日志 + `summary.json`，`latest\` 为副本）。

注意：各验证脚本的参数面不统一（多数零参数，部分需 `--all` / `--matrix` / `--selftest`），调用前先 `--help` 或读脚本头部。

## 5. 目录地图（真实路径）

根目录：`d:\数据\下载\逆向学习工作体系_2026-11-15`

| 逻辑名 | 真实路径 | 说明 |
|---|---|---|
| 项目包 | `pack\` | git 仓库根是**工作区根目录** `d:\数据\下载\逆向学习工作体系_2026-11-15`（2026-11-17 初始化，基线 tag `baseline-pre-rename`）；`pack\` 只是其中一目录 |
| 源码 | `pack\04_rekit项目源码\rekit\` | 2026-11-17 由 mojibake 名改回，见 `pack\PATH_MAP.md` |
| 测试/验证 | `pack\04_rekit项目源码\tests\` | `test_*.py` + `verify_*.py` + fixtures（文件数/行数见 `status.py` 现算） |
| 方法论 | `pack\01_方法论文档\` | 2026-11-16 从 `tmp\pack` 恢复 |
| 规则库（旧） | `pack\02_规则库\` | R01–R32，2026-11-16 恢复；R33–R119 只有日志出处 |
| 规则登记（机器） | `pack\rules.json` | R01–R119 摘录 + R120–R127 补录，含出处与互证状态；**条数以 `status.py` 的 `rules registry` 行为准**；缺口分析见 `2026-11-16\vibe-coding-review\work\batch3\rules_gap_report.md` |
| 数字总账（人读） | `work\outputs\NUMBERS_LEDGER.md` | **唯一权威是 `work\evidence_numbers_ledger.json`**（M13–M20，`ledger_check.py --check` 硬校验）；`evidence_m13_ledger.json` 已降级为历史源，冲突以新 JSON 为准 |
| 章程/进度 | `pack\03_路线图与章程\` | 内含 CHARTER/PROGRESS/CHANGELOG/RE-ROADMAP（2026-11-17 改名） |
| 每日日志 | `pack\05_每日日志\` | 2026-11-06 ~ 11-15 |
| 日报 | `pack\06_日报docx\` | 10 期 docx |
| 工作目录 | `2026-11-15\m3-task-card\work\` | 证据、样本、任务卡、`pack03` 文档的**权威副本** |
| 工作目录里的源码 | `work\rekit`、`work\tests` | 指向 `pack` 的目录联接（junction），不是副本 |
| 样本 | `work\samples\`（m2 + m3） | 约 170 MB；被 `.gitignore` 排除，新克隆用 `setup.ps1` 恢复；`tests\samples`、`tests\fixtures` 已入库 |

`pack` 与 `work\pack03` 的 CHARTER/PROGRESS/CHANGELOG：**内容相同**，编辑时先确认改哪一份，改完同步另一份。
`.github\workflows\repo-contract.yml` 是**已启用但只做契约层**的 CI（2026-11-22 由 `gate.yml` 改名）：只跑 `ledger_check --check`、`evidence_index --check` 与 `repo_contract.py`（10 个入库样本的解析契约 + 可失败自证），`permissions: contents: read`，不跑 pytest / 25 套 / `gate.ps1` / setup；**它的绿只代表账本、证据索引与样本契约一致，不代表工具正确性**，全量仍在本机跑 `gate.ps1`。`v0.1.0` 停在 `6593dea`（U1-a+U1-b；2026-11-21 历史改写后重建），`v0.1.1` 覆盖门禁脚本、`setup.ps1`、R126、去垫片等收尾补件。

## 6. 环境怪癖（已知，不是 bug）

- 本机 Python 3.14；`rekit` 运行时纯标准库。全量门禁另需 `dnfile`（M19/M20 对拍，缺则 `env_missing`）与 `pefile`（pytest 交叉断言，缺则 skip）。
- GNU binutils 2.47 在 `2026-11-15\m2-task-card\work\tools\binutils-2.47\`，未加入 PATH，测试脚本内临时注入。
- objdump 打开含中文的绝对路径会报 `Illegal byte sequence`：先设 `LC_ALL=C`。
- 系统策略拦截 MSI/安装器；外部工具只用免安装 zip，单包 <500 MB，来源与许可须清楚。
- `cli-64.exe` 出处不明，**不可再分发**，只在本机测试。
- 部分旧测试曾硬编码统一开发机上的仓库根（`/<用户>/<项目>/rekit`）；2026-11-17 已把 5 个测试与 3 个生成器
  改为按 `__file__` 定位，**垫片不再需要**（旧版在 C: 盘克隆时会解析到 `C:\home` 并报 31 个失败/错误）。
- **证据里不得写仓库内绝对路径**：`evidence_*` 被 `ledger_check` 按 sha256 登记，绝对路径会让 sha256
  随克隆目录变化，异地 clone 门禁必 FAIL。`verify_layout` / `verify_sigblob` 已改为写 work 相对路径；
  仓库外 oracle（`mscorlib` / `System.Console`）保留绝对路径。
- `pack` 下 4 个目录名已于 2026-11-17 由 mojibake 改回可读名（`03_路线图与章程` / `04_rekit项目源码` / `05_每日日志` / `06_日报docx`），`work` 下 6 个 junction 已同步重建；`2026-11-16\vibe-coding-review` 的调研快照保留旧名，作为当日记录。
- Windows 终端显示中文可能乱码；路径操作优先用 Python，不要依赖 PowerShell 的字符串编码。

## 7. 禁止事项

- 不得修改任何已公布数字的口径来"对齐结果"；发现偏低按 R72 就地标注。
- 不得删除证据文件；失败日志改名保留。
- 不得把推算值（estimated）写进 CHARTER/PROGRESS/README/NUMBERS_LEDGER。
- 不得在被测模块与校验器之间共用同一段判据实现（R73）。
- 不得让对拍分母为 0 却判 PASS（R119）。
- 不得并行跑多个会写同一日志的验证脚本。
- 不得复制整个 `work` 目录来"开分支"（会复制 99 MB 样本并制造第 N 份副本）。
- **本工作树另有会话在改 `rekit` 源码**：其他会话只能读、不能写 `rekit\*.py`；需要改源码时写进 `HANDOFF.md` 的"未完成清单"，由源码会话执行。

## 8. 证据与提交约定

- 证据命名：`work\evidence_<milestone>_<suite>.<log|json>`；全量验证结果放 `work\verification\<run_id>\`。
- **新证据必须带来源 run_id**（2026-11-17 起）：文件首行写 `run_id: <YYYYMMDDTHHMMSS-xxxx>`；没有来源时写 `run_id: none` + 一句原因。凡由 `verify_gate` / `vharness` 产生的证据，还必须出现在 `work\verification\<run_id>\summary.json` 的文件清单里。`tests\evidence_index.py` 只认证据（唯一 run 归因 / 多 run 记 `ambiguous` / 无则 `null`）；**历史 122 条 `null` 不猜、不回填**。
- 每次收口必须有：pytest 结果、全部验证脚本的 exit code、更新后的 `HANDOFF.md`。
- git 初始化后：一次提交只做一件事；提交信息格式 `[O2] verify_all: 包装 verify_map`。
- 代码风格：标准库优先，不引入运行时依赖；注释只在逻辑不自明处写。

## 9. 当前冻结条款（提案执行期）

- 提案执行期间**不改判据、不改期望值来源、不改已公布数字**。
- 发现提案与现有规则冲突：写入 `HANDOFF.md` 的"待确认问题"，停下来等人裁决。
- 任何"顺手优化"单独提交，并在提交信息里标明"非提案范围"。
