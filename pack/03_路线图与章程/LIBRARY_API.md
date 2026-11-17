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

返回结构约定（与实现一致，示例即按此取值）：

- `parse_pe().sections`：每项 5 元组 `(addr, vsize, offset, size, name)`（按节表顺序）；
  `imports`：`[[dll, [函数名...]], ...]`；`exports`：无导出为 `None`。
- `parse_elf().sections`：每项 `(name, sh_type, addr, offset, size)`；
  `security`：`{"nx": ..., "relro": ..., "pie": ...}`。
- `build_dotnet().file`：`format/machine/image_base/entry/cli_rva/cli_size/sections`
  （`sections` 每项含 `index/name/vaddr/vsize/rawptr/rawsize/chars`）。

**失败语义**：读不了抛 `OSError`；格式不符时实现层可能用 `assert`（`python -O` 下断言
被移除），因此**先 `detect_format` 判格式再解析**。`build_info` 对未识别格式返回 `None`。

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
