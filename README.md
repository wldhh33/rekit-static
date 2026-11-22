# rekit · 逆向学习工作体系

`rekit` 是一个纯 Python 标准库实现的二进制静态分诊/分析工具（PE / ELF / .NET），支持 CLI、Python 模块与 MCP 三种用法。
本仓库同时是它的每日演进工作区：源码、规则、验证脚本与证据账本都在这里，任何结论都要能按仓库内的命令复跑。
里程碑与当前状态以 `pack/03_路线图与章程/` 和 `2026-11-15/m3-task-card/work/HANDOFF.md` 为准，本文件只做入口。

> **本仓库是什么**：`rekit` 的**工作体系快照**——分析实现 + 里程碑证据链（M13–M20）+ 可复现 fixture + 门禁；
> 与发布态主库 [`rekit`](https://github.com/wldhh33/rekit) 同源、布局不同（本库含 `pack/` 里程碑与证据）。
> 本库 tag（`v0.1.0`–`v0.1.2`）属**快照批次**，与主库版本号无关，不代表回退。

## 十分钟上手

按 `pack/ONBOARDING.md` 的十分钟路线走：这是什么 → 现在在哪 → 怎么跑 → 以谁为准。
最短路径：

1. 读 `pack/ONBOARDING.md`（地图，只指路不复述）。
2. 读 `pack/AGENTS.md`（硬约束与常用命令）。
3. 跑 `python "pack\tools\status.py"` 看当前状态。
4. 跑门禁：`powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1"`（前置缺失时 exit 2）。

## 第一次 clone 后会看到什么

仓库只含分析实现、证据链、可复现 fixture 与门禁脚本；**样本与工具链不入库**（原因与自备方式见 `pack/SAMPLES.md`）。
干净 clone 的第一条状态命令会失败——这是缺资产，**不是仓库损坏**：

| 命令 | 未 setup 时 | 说明 |
|---|---|---|
| `cd pack\04_rekit项目源码` 后 `python -m rekit info tests\fixtures\dyn_pie` | exit 0 | 纯标准库，clone 即可跑 |
| `python "pack\tools\status.py"` | `VERDICT: NOT_INITIALIZED exit=1` + 下一步命令 | 明确提示“从未 setup” |
| `powershell … -File "pack\tools\gate.ps1"` | `GATE: NOT_INITIALIZED exit=2` + 下一步命令 | 不执行任何验证 |

要跑全量门禁，先准备含 `samples` 与 binutils 的原工作区，再执行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\setup.ps1" -AssetsSource <原工作区根>
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1"
```

`setup.ps1` 成功后会写 `work\.rekit_setup.json`。之后若再缺资产，`status.py` / `gate.ps1` 会按 **FAIL** 逐条报缺项——“已初始化”不等于健康。

## 许可

MIT，见根目录 `LICENSE`。包内 `pack/04_rekit项目源码/LICENSE` 必须与本文件**逐字相同**；
`verify_dist.py` 的 `license.root` 判据会机械校验这一点（并带可失败自证）。

## 需要自备样本与工具链

本仓库**不包含**验证所需的二进制样本与外部工具链（binutils / UPX 等）：它们体积大、来源或许可不明，或不可再分发，
已从 git 历史移除并被 `.gitignore` 排除。没有这些文件时，`python -m rekit` 与随仓库保留的样本仍可用；
全量 pytest / `gate.ps1` 需要先自备，清单与自行获取/构造方式见 `pack/SAMPLES.md`，恢复流程见 `pack/README.md` 的安装与分发一节。
