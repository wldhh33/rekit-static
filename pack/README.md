# 逆向学习工作体系 · 导航

> 本文件只做导航。**最新状态**看 `pack\AGENTS.md`（稳定事实与硬约束）与 `2026-11-15\m3-task-card\work\HANDOFF.md`（当前进度与下一步）。
> **数字**以 `2026-11-15\m3-task-card\work\outputs\NUMBERS_LEDGER.md` 为准，其唯一权威是
> `work\evidence_numbers_ledger.json`（M13–M20，`pack\tools\ledger_check.py --check` 硬校验）。
> 本文件不写易失数字。

## 先读这两份

1. `01_方法论文档/工作逻辑与思考流程.md` —— 怎么想、怎么干：五步闭环、标准先行、三层错误防御、降档条款、中断应对
2. `02_规则库/规则库_R01-R32.md` —— R01–R32 规范定义；R33–R119 见 `02_规则库/规则库_R33-R119.md` 与机器登记 `pack\rules.json`

## 目录导览

```
01_方法论文档/          工作逻辑与思考流程（总纲）
02_规则库/              R01–R32 规范定义；R33–R119 规范 + rules.json 机器登记
03_路线图与章程/        RE-ROADMAP / CHARTER / PROGRESS / CHANGELOG / JSON_CONTRACT（★ PROGRESS 最详实）
04_rekit项目源码/       rekit 源码 + tests（模块数/测试数/verify 套数现算见 pack\tools\status.py）+ pyproject.toml
05_每日日志/            2026-11-06 ~ 11-15 每日任务卡/知识卡/验证脚本/执行证据
06_日报docx/            10 期排版日报
```

> `pack` 下 4 个中文目录名曾因解包编码损坏（mojibake），已于 2026-11-17 改回可读名；
> 旧名对照与改名记录见 `pack\PATH_MAP.md`。历史调研快照里的旧名保留不改（当日观测记录）。

## rekit 项目是什么（30 秒版）

自研二进制分诊工具：给一个程序文件（exe/elf/.NET），输出体检报告——格式/架构/类型/入口/
安全防护（NX·RELRO·PIE）/导入导出清单/编译器指纹/控制流与调用关系。纯手写解析，结果一律与
readelf/objdump/pefile/ildasm 等权威工具交叉验证。三种用法：CLI / Python 模块 / MCP 服务器。

## 安装与复现验收（干净克隆演练过，2026-11-17）

**前置（Windows 10/11）**

- Python 3.8+；安装交叉验证依赖：`python -m pip install dnfile pefile`。
  `dnfile` 是**必需**的：`verify_sigblob` / `verify_layout` 缺它即 `env_missing`（exit 2）→ 门禁 FAIL。
  `pefile` 只影响 pytest 里少量 pefile 交叉断言（缺了会 skip），建议一并装。
- `powershell`（Windows PowerShell 5.1）与 `pwsh`（PowerShell 7）：.NET 运行期 oracle 用。
- 原工作区的**样本与工具链**（仓库不入库，见下）：`2026-11-15\m3-task-card\work\samples`、
  `2026-11-15\m2-task-card\work\samples`、`2026-11-15\m2-task-card\work\tools`。
  M19 补证样本在 `samples\m19_sigblob\{_gen,_neg}`（7 个 DLL），随 m3 samples 一起恢复；
  `work\m19_sample_manifest.json` 登记其 sha256，`gate.ps1` preflight 逐条核对。

**仅重新生成 M19 受控样本时需要（门禁不需要）**

- `ilasm`（.NET Framework 4.x，默认 `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ilasm.exe`）。
  `gate.ps1` **不调用** `ilasm`：样本是恢复来的成品，preflight 只校验 sha256。
  缺 `ilasm` 时门禁照常跑；只有重跑 `work\outputs\m19_sigblob\gen.ps1` 会 `exit 2` 并打印缺失路径。
- 重建后 `gen.ps1` 自动重写 manifest：`ilasm` 的随机 MVID / 时间戳由 `determinize.py`
  固定，同版本 `ilasm` 重跑产出**逐字节相同**（sha256 不变，不会变成下一次门禁的随机红）；
  换 `ilasm` 版本仍可能漂，重跑 `gen.ps1` 重新登记即可。

**步骤（在克隆根执行；路径可含空格与中文）**

```powershell
# 1. 克隆
git clone <repo-url> rekit
cd rekit

# 2. 恢复仓库外资产 + 重建目录联接（必须有显式来源；不下载、不猜来源）
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\setup.ps1" `
    -AssetsSource "D:\path\to\original\workspace"

# 3. 单命令门禁
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1"
```

`setup.ps1` 只做两件事：把上列 samples / tools 从 `-AssetsSource` 复制进来；在
`2026-11-15\m2-task-card\work` 与 `...\m3-task-card\work` 下建 7 个 junction
（`rekit`/`tests`/`pack03`/`tools` → `pack\04_rekit项目源码\*`、`pack\03_路线图与章程`）。
来源不全时 exit 2；目标已存在时 SKIP，不覆盖、不删除。

`gate.ps1` 先做前置检查（缺样本 / M19 样本 manifest / 工具链 / junction / dnfile 直接 exit 2，不静默跳过），再按固定顺序执行：
`ledger_check.py --check` → `tests\evidence_index.py --check` → `verify_gate.py --run`
（全部 verify 套 + pytest + ledger；套数以 `pack\tools\status.py` 现算为准）。`-List` 只看计划，`-Only verify_map,verify_iat` 跑子集。

手动等价步骤：

```powershell
python -m pip install -e .          # 在 pack\04_rekit项目源码 内执行；之后任意目录可用 rekit 命令
python "pack\tools\verify_gate.py" --run

cd "2026-11-15\m3-task-card\work"   # pytest 必须在 work 目录执行：tests 是目录联接，fixture 路径按 cwd 解析
python -m pytest tests -q
```

依赖：Python 3.8+ 纯标准库即可跑全部功能（构建期需要 setuptools；pefile / dnfile / objdump
仅交叉验证用到；`ilasm` 仅重建 M19 受控样本时用到）。objdump 需要 GNU binutils，且含中文路径时必须 `LC_ALL=C`（`verify_gate.py` 已自动处理）。

**路径垫片（2026-11-17 起不再需要）**：旧测试曾硬编码 `<旧仓库根>`，
依赖 `<旧仓库根>\...` 目录联接；且 Windows 上 `/home/...` 按**当前盘符根**解析，克隆在 C: 时
需要 `<旧仓库根>\...`（普通用户通常无权限）。本次演练已把 5 个测试与 3 个生成器改为按
`__file__` 定位，垫片已可删除。**没有改路径前**的失败点是：pytest 报
`FileNotFoundError: '<旧仓库根>/.../tests/fixtures/bin_ls.elf'`（约 31 个失败/错误）。

### 干净克隆演练记录（2026-11-17）

严格按上一版 README 操作，第一次 `gate.ps1` 即 **exit 2**，preflight 报 9 项缺失：

| 文档当时写的 | 实际发生 | 缺的那一步 |
|---|---|---|
| “fresh clone 后必须先从原始副本恢复” | 没有给恢复命令 / 来源格式 | 新增 `pack\tools\setup.ps1`，把来源写成显式参数 |
| `gate.ps1` 报 “junction 见 README” | README 没有 junction 创建步骤 | 同上，setup 建 7 个 junction |
| 只提 m3 samples + binutils | pytest 的 `paramdecl`/`strxref` 还要 **m2 samples** | preflight 增加 m2 samples 检查，setup 一并复制 |
| “另需 Python 包 dnfile”，无安装命令 | 缺 dnfile 时两套 `env_missing` → 门禁 FAIL | 前置写明 `python -m pip install dnfile pefile`，preflight 硬检查 |
| “依赖 `<旧仓库根>` 垫片” | 克隆在 C: 时 `<旧仓库根>` 解析到 `C:\home`，31 个失败/错误 | 测试改 `__file__` 相对定位，垫片降级为历史说明 |
| 手动 pytest 步骤 | PATH 里的 objdump 非 2.47 且输出 GBK，`test_minidll_crosscheck_objdump` 报 UnicodeDecodeError→TypeError | 测试内优先用仓库 binutils 并设 `LC_ALL=C`；工具不可用时才 skip（gate 内仍执行断言） |
| “`gate.ps1` 全绿，可复跑” | 异地克隆跑完 23 套 verify 后，`verify_gate` 内部 `ledger_check` 报 `证据 sha256 变化：evidence_m20_layout.json` | `verify_layout.py` 把样本**绝对路径**写进证据；克隆换了目录，sha256 必然变。改为写 work 相对路径 |
| 同上（第 2 轮） | 修完 layout 后，同类问题又出现在 `evidence_m19_sigblob.json` | `verify_sigblob.py` 同样把绝对路径写进证据；按同一方式改为相对路径 |
| “证据路径只是展示信息” | 绝对路径进被 `sha256` 登记的证据 = 门禁只在本机同一目录下成立 | 改为：work 内样本写相对路径；仓库外 oracle（`mscorlib` / `System.Console`）保留绝对路径并在本表说明 |

修后从零复跑（2026-11-17，commit `26b0559`，克隆到 `%TEMP%\rekit_clean_20261117d`）：

- `setup.ps1`：**exit 0，0.9 s**（samples 16 + 11 文件、tools 376 文件、7 个 junction）。
- `gate.ps1`：**exit 0，432.5 s（7.2 分钟）**，run id `20261117T030415-70ee` —— 23/23 套 verify PASS、pytest **554 passed / 0 failed / 0 skipped**、`ledger_check` PASS、`VERDICT: PASS`。
- 结论：**按本 README 从空目录可跑通**；每一步失败点都在上表，未跳过步骤、未放宽判据。

## 版本与 tag

- `v0.1.0` → `d63d244`（U1-a 打包 + U1-b 证据索引 / R95 补登记的完整交付），**保持不动**。
- `v0.1.1` → 干净克隆演练后的补件提交，覆盖：`gate.ps1`（preflight）、`setup.ps1`（资产恢复 +
  junction）、R126、路径垫片去除、`verify_layout` / `verify_sigblob` 证据路径改为 work 相对路径、
  本 README 与 CHANGELOG / PROGRESS / HANDOFF 的演练记录。tag 说明写明覆盖范围。
  **该 tag 由演练验证：**从空目录按本 README 跑通（run `20261117T030415-70ee`）。
- **重定位记录（2026-11-17）**：`v0.1.0` 最初指向 `5fbb421`（仅 U1-a）；因证据索引与 R95 样本登记
  在其后的 `d63d244`，本次移至 `d63d244`。仓库无远端、未推送，无下游影响；原指向与原因保留在
  tag 说明、`CHANGELOG.md` 与 `PROGRESS.md`，未抹除。
- **release tag 规则（2026-11-17 起）**：`v*` tag 只在该批次**全部收口后**打，且只打在包含该批次
  全部补件的提交上；批次中途不打 tag，避免再次出现“tag 停在半成品、需要重定位”的情况。

## CI 状态

**没有已启用的 CI**。`.github/workflows/gate.yml` 是**未验证**草稿：本仓库无 git 远端、该文件
**从未被 GitHub Actions 实际触发过**。它只跑不依赖样本的两项（`ledger_check --check`、
`evidence_index --check`），全量门禁仍需本机按上面的命令执行。不要把该文件当成“CI 已绿”的证据。
