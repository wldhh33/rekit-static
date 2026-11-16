# 逆向学习工作体系 · 导航

> 本文件只做导航。**最新状态**看 `pack\AGENTS.md`（稳定事实与硬约束）与 `2026-11-15\m3-task-card\work\HANDOFF.md`（当前进度与下一步）。
> **数字**以 `2026-11-15\m3-task-card\work\outputs\NUMBERS_LEDGER.md` 为准，其唯一权威是 `work\evidence_m13_ledger.json`。本文件不写易失数字。

## 先读这两份

1. `01_方法论文档/工作逻辑与思考流程.md` —— 怎么想、怎么干：五步闭环、标准先行、三层错误防御、降档条款、中断应对
2. `02_规则库/规则库_R01-R32.md` —— R01–R32 规范定义；R33 以后没有规范文件，机器登记见 `pack\rules.json`

## 目录导览

```
01_方法论文档/          工作逻辑与思考流程（总纲）
02_规则库/              R01–R32 规范定义（R33–R119 仅存于日志，见 rules.json）
03_路线图与章程/        RE-ROADMAP / CHARTER / PROGRESS / CHANGELOG（★ PROGRESS 最详实）
04_rekit项目源码/       rekit 源码 + tests（25 模块 / 25 个 test_*.py / 21 个 verify_*.py）
05_每日日志/            2026-11-06 ~ 11-15 每日任务卡/知识卡/验证脚本/执行证据
06_日报docx/            10 期排版日报
```

> ⚠️ `pack` 下 4 个中文目录名的**磁盘名已损坏**（GBK/UTF-8 混淆）。不要在终端里按上面的中文名 `cd`，
> 真实路径与改名手册见 `pack\PATH_MAP.md`。用 Python 的 `os.listdir` 取真实名，或直接用 `work\` 下的联接。

## rekit 项目是什么（30 秒版）

自研二进制分诊工具：给一个程序文件（exe/elf/.NET），输出体检报告——格式/架构/类型/入口/
安全防护（NX·RELRO·PIE）/导入导出清单/编译器指纹/控制流与调用关系。纯手写解析，结果一律与
readelf/objdump/pefile/ildasm 等权威工具交叉验证。三种用法：CLI / Python 模块 / MCP 服务器。

## 复现验收

```powershell
# 一条命令跑全部（21 套 verify + pytest），约 4 分钟
python "pack\tools\verify_gate.py" --run        # --list 只看计划

# 或单独跑
python -m pytest "2026-11-15\m3-task-card\work\tests" -q
python "2026-11-15\m3-task-card\work\tests\verify_disasm.py" --all
```

依赖：Python 3.12+ 纯标准库即可跑全部功能（pefile/ildasm 仅交叉验证用到，缺失自动跳过）。
objdump 需要 GNU binutils，且含中文路径时必须 `LC_ALL=C`（`verify_gate.py` 已自动处理）。
