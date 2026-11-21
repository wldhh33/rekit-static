# LIBRARY_API.md · rekit 库接口契约

> **定位**：本文件冻结 `rekit` 作为 Python 库被 `import` 时**承诺稳定的那一小部分**。
> 与之配套的机械判据是 `04_rekit项目源码\tests\verify_api.py`（门禁内执行）：
> 三个示例用 `import` 调用库接口，输出与 `rekit <cmd> --json` 的对应字段**逐项相等**，
> 不相等即 FAIL；空比对判 FAIL。
> **规模数字不写进本文件**（R127），模块数/测试数/套数一律现算：`python "pack\tools\status.py"`。

## 1. 与 JSON_CONTRACT.md 的关系

| 契约 | 冻结什么 | 不冻结什么 | 载体 |
|---|---|---|---|
| `JSON_CONTRACT.md` | 命令行 `rekit info --json` 的**顶层字段名与失败语义** | Python 函数签名、返回对象内部结构 | CLI 输出 |
| 本文件（LIBRARY_API.md） | `rekit.api` 的**导出符号集合**，以及 `verify_api.py` 逐项对拍的那些返回字段 | 其余 `rekit.*` 模块、未列入第 2 节的字段 | `rekit\api.py` |

两者的关系是**同一批数字的两条消费路径**：库路径（`rekit.api`）与 CLI 路径
（`rekit <cmd> --json`）必须给出相同值。任何一边改了字段名/取值，`verify_api.py`
就会在对应项上报 FAIL；此时要么回退，要么**同时**更新本文件、示例与对拍项。

## 2. 公开接口（对外承诺稳定）

只承诺 `rekit.api` 的 `__all__`；`verify_api.py` 用集合相等固定它，
新增/删除导出必须同时改本文件，防止把整个包冻结成 API。

| 符号 | 输入 | 承诺的返回字段 |
|---|---|---|
| `detect_format(path)` | 文件路径 | 返回 `"elf"` / `"pe"` / `None` |
| `build_info(path)` | 文件路径 | `JSON_CONTRACT.md` 冻结的 `info` 顶层字段 |
| `parse_pe(path)` | PE 文件路径 | `machine` `magic` `entry` `image_base` `subsystem` `nsect` `sections` `imports` `exports` |
| `parse_elf(path)` | ELF 文件路径 | `machine` `type` `entry` `sections` `security` |
| `build_dotnet(path)` | 托管程序集路径 | `status` `assembly` `file` `denominators` `types` `methods` |
| `probe_dotnet(path)` | 任意 PE 路径 | `is_cli` `cli_rva` `reason` |

异常类型（同样在 `rekit.api.__all__` 里）：`RekitError` 基类、`FormatMismatch`
（输入不是该格式）、`MalformedBinary`（格式对但结构截断/损坏）。语义见下节。

返回结构约定（与实现一致，示例即按此取值）：

- `parse_pe().sections`：每项 5 元组 `(addr, vsize, offset, size, name)`（按节表顺序）；
  `imports`：`[[dll, [函数名...]], ...]`；`exports`：无导出为 `None`。
- `parse_elf().sections`：每项 `(name, sh_type, addr, offset, size)`；
  `security`：`{"nx": ..., "relro": ..., "pie": ...}`。
- `build_dotnet().file`：`format/machine/image_base/entry/cli_rva/cli_size/sections`
  （`sections` 每项含 `index/name/vaddr/vsize/rawptr/rawsize/chars`）。

**失败语义**（承诺的是**类型**，不承诺异常消息文本）：

| 情形 | 抛出 | 实现方式 |
|---|---|---|
| 路径读不了 / 不存在 / 是目录 | `OSError`（含 `FileNotFoundError`） | 标准库 |
| 输入不是该格式（`parse_pe` 收到 ELF、`parse_elf` 收到 PE 等） | `rekit.api.FormatMismatch` | 显式 `raise` |
| 签名对，但头部/表结构截断或损坏，底层解不下去 | `rekit.api.MalformedBinary` | 显式 `raise` |
| 调用方参数类型用错（路径不是 `str` / `os.PathLike`） | `TypeError` | 标准库 |

`FormatMismatch` / `MalformedBinary` 都继承 `RekitError`（`RekitError` 直接继承
`Exception`，**不继承 `ValueError`**）：仓内多处 `except ValueError` 表示"格式不认识 /
参数不合法"（CLI 退出码 2），旧实现抛的是 `AssertionError`，从不被它接住；新异常独立成族，
`except api.RekitError` 可一次兜住格式与结构两类失败，也不会改变既有退出码分类。

契约是**"解析函数在格式不符时抛出 `FormatMismatch`"**，不是"请你先自己检查"：
`parse_pe` / `parse_elf` 自己判签名并在不符时抛出，调用方不必先 `detect_format`。
`detect_format` 的既有语义不变（`"elf"` / `"pe"` / `None`，读不了抛 `OSError`）；
`build_info` 对未识别格式仍返回 `None`。

**不得用 `assert` 表达失败**：`python -O` 会把断言整体剥掉，失败退化为静默错值。
`verify_api.py` 用 `python -O -c` 实跑同一组错格式输入，要求仍抛 `FormatMismatch`、
`isinstance(e, AssertionError)` 为假；并自带"篡改期望值 / 未抛出 / 空期望"三种自证。

## 3. 不承诺的部分（内部实现）

- `rekit.cli` / `rekit.dotnet` / `rekit.pe` / `rekit.elf` 等模块的**其余函数与变量**：
  可改签名、改返回结构、合并或删除，不另行通知。请只经由 `rekit.api` 使用。
- `rekit.mcp`：MCP 服务端入口，不是库接口。
- `rekit.coverage`：**仅命令行**。它调用外部 `objdump`（`shutil.which` + `os.environ`
  注入 PATH，见 `coverage.py`），结果取决于机器上装没装、装的是哪版 binutils，
  天然不适合作为库承诺。
- 其余分析模块（反汇编、调用图、表达式/递归描述等）：当前**未登记**为公开接口，
  视为内部实现；需要公开时走第 5 节的变更流程。

## 4. 示例与样本前置

`04_rekit项目源码\examples\` 下三个示例全部**用 `import` 调用**（源码禁止出现
`subprocess` / `os.chdir` / `os.getcwd`，`verify_api.py` 会扫描），并通过
`__file__` 定位仓库源码，因此不需要 `pip install -e .`、不依赖原工作区垫片或固定盘符。

```powershell
python "pack\04_rekit项目源码\examples\pe_report.py"     "2026-11-15\m3-task-card\work\tests\fixtures\minipe.exe"
python "pack\04_rekit项目源码\examples\elf_report.py"    "2026-11-15\m3-task-card\work\tests\fixtures\bin_ls.elf"
python "pack\04_rekit项目源码\examples\dotnet_report.py" "2026-11-15\m3-task-card\work\samples\m17\_gen\RekitSample.dll"
```

样本前置：

- PE / ELF 用仓库内 `tests\fixtures\minipe.exe`、`tests\fixtures\bin_ls.elf`，**随克隆就有**。
- .NET 用 **m3 samples** 的 `samples\m17\_gen\RekitSample.dll`：fresh clone 需先跑
  `pack\tools\setup.ps1 -AssetsSource <原工作区根>` 恢复；缺失时 `verify_api.py`
  报 `env_missing`（exit 2），不静默跳过。

## 5. 变更政策

1. 新增公开能力：先在 `rekit\api.py` 导出 → 在本文件登记 → 补示例/对拍项 →
   跑 `verify_api.py` 与全量门禁。
2. 破坏性变更（改符号名、改承诺字段、改返回结构）：视为 API 破坏，须在
   `CHANGELOG.md` 写明影响面，并按仓库版本规则处理（`v*` tag 批次收口后才打）。
3. 判据本身不得放宽：`verify_api.py` 的对拍项只增不减；确实无法对拍时标 `SKIP`
   并写明原因，不允许把 FAIL 改成"跳过"。

## 6. 分发形态（wheel / sdist）

`pyproject.toml` 的打包口径：`packages = ["rekit"]`、`dependencies = []`、
`requires-python = ">=3.8"`；`MANIFEST.in` 把 `tests` / `examples` prune 掉，
所以 wheel 与 sdist 都只含 `rekit/**`（+ 元数据）。构建产物（`dist/`、`build/`）
由 `.gitignore` 覆盖，不入库。

- **支持的 Python 版本**：3.8+（实测 CPython 3.8.20：wheel 安装 + `--help` / `info`
  （PE/ELF/.NET）/ `ilflow`（.NET）/ `import rekit.api` 全通；门禁与全量 pytest 在 3.14.0 上跑）。
  `requires-python` 的依据是这次实测，**不是静态扫描**；`tests\verify_dist.py` 把 pyproject、
  README、本文件的声明与 wheel 的 `Requires-Python` 逐字比对，不一致即 FAIL。
- **许可**：**MIT**（2026-11-21 用户裁决，已定案）。仓库根 `LICENSE` 为 MIT 正文，
  版权行 `Copyright (c) 2026 WLDHH33`（取自可核实的 git 身份）。`pyproject.toml` 按
  PEP 639：`license = "MIT"`、`license-files = ["LICENSE"]`（无自由文本 table、无弃用
  classifier）；wheel METADATA 出 `License-Expression: MIT` 与 `License-File: LICENSE`，
  wheel（`*.dist-info/licenses/LICENSE`）与 sdist（顶层 `LICENSE`）各含一份。
  收到 wheel 的人被授予使用、复制、修改、合并、发布、分发、再许可和/或销售本软件及副本的
  权利，条件是保留版权与许可声明；软件按“原样”提供，不附带担保。构建产物 `dist/`、`build/`
  不入库，**分发前必须重建**，旧的自定义文本 wheel 不得外发。

```powershell
cd pack\04_rekit项目源码
python -m pip install build setuptools
python -m build --no-isolation
# 仓库外：python -m venv <dir>; <dir>\Scripts\pip install --no-index --no-deps dist\*.whl
```

**只装 wheel 时可用**：`rekit --help`、全部分析命令（`info` / `dotnet` / `ilflow` /
`layout` / `sigblob` / `map` / `disasm` / `expr` / `recdesc` / `callgraph` / `callfacts` /
`funcreport` / `datarefs` / `sitejoin` / `iat` / `fingerprint` / `mcp`）——唯一例外是
`coverage`（见下）。`import rekit.api` 的 6 个函数 + 3 个异常类型同样可用。
分析 .NET 需要调用方**自带** .NET 文件。

**只装 wheel 时不可用**（缺的是仓库外资产，不是代码）：

- `examples\`：三份示例按 `__file__` 定位仓库源码，不是包内模块；
- `tests\` 与 `tests\fixtures`：pytest / verify 套随仓库发布，被 `MANIFEST.in` prune；
- `samples\`（含 m17 .NET 样本）：被 `.gitignore` 排除，不属于运行时资产；
- `gate.ps1` / `setup.ps1` / `work\` 脚本：仓库交付物，不随包分发；
- `coverage` 命令：运行期调用外部 `objdump`，不是 pip 依赖。

机械判据是 `tests\verify_dist.py`（门禁内执行）：在系统临时目录新建 venv、`--no-index`
安装 wheel（非 `-e`），然后在仓库外跑 `--help`、`info`（PE / ELF / .NET）、`ilflow`（.NET），
逐项检查：

1. wheel / sdist 内容只含包本体，无 tests / examples / samples / tools / fixtures；
2. METADATA 无 `Requires-Dist`、`Requires-Python` 与 pyproject 一致、console script 正确；
   `>=3.8` 另做静态扫描（3.9+ 专属语法 / 内置泛型注解 / PEP 604 / 3.9+ 专属 API）；
3. `import rekit` 的来源在 venv site-packages，不在仓库路径；
4. **同一输入下，仓库内 `python -m rekit` 与安装版 `rekit` 的 `--json` stdout 逐字节相同**，
   退出码相同；`--json` 唯一路径派生字段是 `path`，两边传入同一绝对路径，故不排除、也要求相等；
5. 安装版在两个不同 cwd 下输出相同（不读 cwd）；
6. 空比对判 FAIL；篡改一字节 / 改动 `path` 必须被检出，并给出首个差异位置（第 N 行第 M 字节）；
7. 许可：`LICENSE` 正文含 MIT 关键条款句与版权行；pyproject 的 `license` 是 SPDX 字符串
   （不是 table）且 `license-files` 含 `LICENSE`；wheel METADATA 的 `License-Expression`
   与 pyproject 逐字相等且有 `License-File: LICENSE`；wheel 与 sdist 各含一份 `LICENSE`。

这项判据可失败自证：比较器对篡改、路径变化、空比对三种输入都必须报不一致；许可四项另有
自证——篡改 SPDX 值、删除 `LICENSE`、伪造空声明都必须判 FAIL。项数现算见
`python "…\tests\verify_dist.py"` 的汇总行。
