# PATH_MAP · pack 目录名映射

> 背景：`pack` 是在 Windows 上解包时产生的文件名编码损坏（UTF-8 字节被按 GBK 解码）。
> **2026-11-17：4 个 mojibake 目录已按本表改回可读名，`work` 下 6 个目录联接（junction）已同步重建。**
> 改名前的精确旧名（含控制字符）保存在 git 基线 tag `baseline-pre-rename` 里，需要逐字节对照时以该提交为准。

## 映射表（已执行）

| 磁盘上的旧名（mojibake） | 现用名 | 内容 | 状态 |
|---|---|---|---|
| `03_璺?嚎鍥句笌绔犵▼`（`?` 为私用区控制字符 U+E21C） | `03_路线图与章程` | CHARTER / PROGRESS / CHANGELOG / RE-ROADMAP / JSON_CONTRACT | 已改名 2026-11-17 |
| `04_rekit椤圭洰婧愮爜` | `04_rekit项目源码` | `rekit/`（27 模块）+ `tests/`（25 个 `test_*.py` + 23 个 `verify_*.py` + fixtures）+ `pyproject.toml` / `README.md` | 已改名 2026-11-17 |
| `05_姣忔棩鏃ュ織` | `05_每日日志` | 2026-11-06 ~ 11-15 | 已改名 2026-11-17 |
| `06_鏃ユ姤docx` | `06_日报docx` | 10 期 docx | 已改名 2026-11-17 |

注：`03_…` 的旧名中含有控制字符 `U+E21C`，任何按字符串匹配的工具都会失败——这也是必须改名的直接原因。

## 已恢复的目录（2026-11-16）

| 逻辑名 | 来源 | 处理 |
|---|---|---|
| `01_方法论文档` | `tmp\pack\01_方法论文档` | 复制（未移动），文件 1 个 |
| `02_规则库` | `tmp\pack\02_规则库` | 复制（未移动），文件 1 个 |

复制前后的 sha256 记录在 `2026-11-16\vibe-coding-review\work\batch1\MANIFEST.sha256`。

## 改名执行记录（2026-11-17）

1. 前置：git 基线提交 `a70a025` + tag `baseline-pre-rename`；确认无 python 进程在跑；最新全量门禁
   `20261117T001004-58f1` 全绿（21/21 套、pytest 554、ledger 67）。
2. 改名是路径级破坏性操作，`work` 下 6 个 junction 会指向旧名，因此按「拆联接 → 改名 → 重建联接 → 探针读取」执行：
   - 对联接：`m2/m3-task-card\work\{pack03,rekit,tests}`（共 6 个），以及**工作区外的路径垫片**
     `<旧仓库根>`（测试里硬编码 `<旧仓库根>` 依赖它）；
   - 第一次改名后只重建了 work 下 6 个，pytest 因此 39 项 fixture 失败（483 passed）；
     补重建 `D:\home` 垫片后 pytest 恢复 **554 passed**，再重跑全量门禁确认；
   - 每个目录单独 `os.rename`，逐个校验新名存在、旧名消失；
   - 改名后 `04_rekit项目源码` 下 **171 个文件** sha256 逐文件前后一致；
   - 重建联接后用目录列表探针确认可读（不再是悬空联接）。
3. 同步修正硬编码旧路径：`pack\AGENTS.md`、本文件。
4. **未改**的旧名引用：`2026-11-16\vibe-coding-review\{work\project_survey.md, work\metrics.json, outputs\VIBE_CODING_OPTIMIZATION_PROPOSAL.md}`、
   `work\outputs\m15_funcreport\spec.md`、`work\evidence_m13_ledger.json` 是带日期的调研/证据快照，
   改写会篡改当日记录，且 `evidence_m13_ledger.json` 的 sha256 被数字总账锁定；保留旧名并在本文件登记。
5. 回归：改名后重跑全量门禁与 `pack\tools\status.py`，结果记录在提交说明中。

## 禁止

- 不要再用 `git mv` 批量改名；每次改名必须单独提交，便于只回退该次提交。
- 不要"顺便"移动文件内容；改名与移内容必须是两次独立操作。
- 不要把历史证据/调研快照里的旧路径"修正"成新名——那是当日观测记录。
