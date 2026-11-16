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
04_rekit项目源码/       rekit 源码 + tests（27 模块 / 25 个 test_*.py / 23 个 verify_*.py）+ pyproject.toml
05_每日日志/            2026-11-06 ~ 11-15 每日任务卡/知识卡/验证脚本/执行证据
06_日报docx/            10 期排版日报
```

> `pack` 下 4 个中文目录名曾因解包编码损坏（mojibake），已于 2026-11-17 改回可读名；
> 旧名对照与改名记录见 `pack\PATH_MAP.md`。历史调研快照里的旧名保留不改（当日观测记录）。

## rekit 项目是什么（30 秒版）

自研二进制分诊工具：给一个程序文件（exe/elf/.NET），输出体检报告——格式/架构/类型/入口/
安全防护（NX·RELRO·PIE）/导入导出清单/编译器指纹/控制流与调用关系。纯手写解析，结果一律与
readelf/objdump/pefile/ildasm 等权威工具交叉验证。三种用法：CLI / Python 模块 / MCP 服务器。

## 安装与复现验收

```powershell
# 安装（在 pack\04_rekit项目源码 目录内；之后任意目录可用 rekit 命令）
python -m pip install -e .

# 一条命令跑全部（23 套 verify + pytest），约 7.2 分钟
python "pack\tools\verify_gate.py" --run        # --list 只看计划

# 或单独跑（pytest 必须在 work 目录执行：tests 是目录联接，fixture 路径按 cwd 解析）
cd "2026-11-15\m3-task-card\work"
python -m pytest tests -q
python "tests\verify_disasm.py" --all
```

依赖：Python 3.8+ 纯标准库即可跑全部功能（构建期需要 setuptools；pefile/ildasm/objdump 仅交叉验证用到，缺失自动跳过）。
objdump 需要 GNU binutils，且含中文路径时必须 `LC_ALL=C`（`verify_gate.py` 已自动处理）。

**路径垫片**：部分老测试硬编码 `<旧仓库根>`，Windows 上依赖目录联接
`<旧仓库根> → pack\04_rekit项目源码`。没有垫片时 **pytest** 会大面积失败；
安装后的 `rekit` 命令与 `python -m rekit.cli` **不受影响**。移动 `04_rekit项目源码` 后必须重建该垫片。
