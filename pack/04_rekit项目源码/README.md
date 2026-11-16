# rekit

纯 Python 标准库实现的二进制静态分诊/分析工具（PE / ELF / .NET），**无运行时依赖**。
三种用法：命令行、Python 模块、MCP 服务器。

## 安装

在**本目录**（`pack\04_rekit项目源码`）执行：

```powershell
python -m pip install -e .
```

- 构建期需要 `setuptools`（pip 会自动装），运行期仍是纯标准库；要求 Python ≥ 3.8。
- 安装后生成 `rekit` 命令，**任意目录**可执行，不再依赖 `pack` 的目录位置或路径垫片。

不安装也能用（需在 `rekit` 的父目录下）：

```powershell
python -m rekit.cli <file>
```

## 命令

| 命令 | 用途 |
|---|---|
| `rekit info <file> [--json]` | 一条命令输出分诊报告（格式/架构/入口/节/保护/导入导出/.NET） |
| `rekit map <file> [--addr HEX] [--off HEX] [--section NAME] [--json]` | 内存映射视图与地址换算 |
| `rekit ilflow <file> [--json] [--limit N]` | .NET IL 控制流与调用关系 |
| `rekit datarefs <file> [--json]` | 非字符串数据引用层（声明对象 ↔ 指令引用点） |
| `rekit fingerprint` / `iat` / `disasm` / `recdesc` / `callgraph` / `callfacts` / `sitejoin` / `funcreport` / `dotnet` / `sigblob` / `layout` / `coverage` / `expr` | 各分层分析命令 |
| `rekit mcp` | 以 MCP stdio 服务器身份启动 |

`--json` 的字段名自 v0.1.0 起冻结，见
[`pack\03_路线图与章程\JSON_CONTRACT.md`](../03_路线图与章程/JSON_CONTRACT.md)。

## 三个示例（可复现）

以下命令均在**本目录**执行；样本都在仓库内。

### 1. ELF

```powershell
rekit info "tests\fixtures\bin_ls.elf"
```

预期摘要：

```
format   : ELF (x86-64, 64-bit, DYN)
entry    : 0x6760
sections : 30
security : NX enabled (GNU_STACK RW) | RELRO full | PIE yes | W+X segs 0
```

```powershell
rekit map "tests\fixtures\bin_ls.elf" --addr 0x6760 --json
```

预期：`queries.addr.status = "hit"`、`offset = 0x6760`、`unit = "LOAD#1"`。

```powershell
rekit datarefs "tests\fixtures\bin_ls.elf" --json
```

预期：`status = "ok"`、`objects` 11 条、`sites` 4282 条、`denominator.object_code_ref_ratio = 1.0`
（样本带完整符号表，声明对象全部有代码引用）。

### 2. PE

```powershell
rekit info "tests\fixtures\minipe.exe"
```

预期摘要：

```
format   : PE (AMD64, 64-bit, EXE)
entry    : 0x1000
sections : 2
imagebase: 0x140000000  subsystem: Console
imports  : 1 DLL
dotnet   : cli=False status=not_dotnet (...)
```

```powershell
rekit map "tests\fixtures\minipe.exe" --addr 0x1000 --json
```

预期：`queries.addr.status = "hit"`、`offset = 0x400`、`unit = ".text"`。

### 3. .NET

样本源码（`LayoutSample.il` / `LayoutCSharp.cs`）与生成脚本在仓库内，
生成的 DLL 不进 git，先重建：

```powershell
powershell -ExecutionPolicy Bypass -File "..\..\2026-11-15\m3-task-card\work\outputs\m20_layout\gen.ps1"
```

前置：Windows + .NET Framework 4.0 的 `ilasm.exe` / `csc.exe`
（脚本固定用 `C:\Windows\Microsoft.NET\Framework64\v4.0.30319`）。
注意：**重新生成不是逐字节可复现**——编译器会写入时间戳，sha256 每次不同；
可复现的是源码与元数据（类型布局、方法体），不是文件哈希。

```powershell
rekit info "..\..\2026-11-15\m3-task-card\work\samples\m20\_gen\LayoutCSharp.dll"
rekit ilflow "..\..\2026-11-15\m3-task-card\work\samples\m20\_gen\LayoutCSharp.dll" --json
```

预期摘要：

```
dotnet   : cli=True status=ok
status=ok  assembly=LayoutCSharp  methods_total=1  methods_with_body=1
call_total=1  blocks_total=1  edges_total=0
```

## 测试与门禁

- 全量门禁（仓库根执行）：`python "pack\tools\verify_gate.py" --run`
- 单测：在 `2026-11-15\m3-task-card\work` 目录执行 `python -m pytest tests -q`
  （`tests` 是指向本目录的联接；fixture 路径按 cwd 解析，不能从仓库根直接指定 tests 路径）

**路径垫片（只影响 pytest，不影响安装后的 CLI）**：部分老测试硬编码
`<旧仓库根>`，Windows 上靠目录联接
`<旧仓库根> → pack\04_rekit项目源码` 工作。
没有该垫片时 pytest 会大面积 `FileNotFoundError`；`rekit` 命令与 `python -m rekit.cli` 不受影响。
移动 `04_rekit项目源码` 目录后必须重建该垫片。

已知环境怪癖：objdump 打开含中文的绝对路径需 `LC_ALL=C`（`verify_gate.py` 已自动处理）。
