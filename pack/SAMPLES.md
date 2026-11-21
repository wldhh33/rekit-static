# SAMPLES.md · 样本与工具链：为什么不入库、怎么自备

本仓库的验证依赖一批二进制样本与外部工具链。它们**不随 git 历史分发**（已从全部提交移除，并被 `.gitignore` 排除）。
原因只有两类：**许可不明/不可再分发**，或**体积大且可由外部获取**。

没有这些文件时，`python -m rekit`、随仓库保留的样本、`ledger_check`、`evidence_index` 仍可用；
全量 pytest / `gate.ps1` 需要先自备，恢复流程见 `pack/README.md`（`setup.ps1 -AssetsSource`）。
下表的"获取/构造"只写能核实的方式；不确定的一律标注**未经核实**。

## 1. 许可不明 / 不可再分发（本机保留，不入库）

| 文件 | 性质 | 许可状态 | 自行获取或构造 |
|---|---|---|---|
| `tests/fixtures/cli-64.exe` | MSVC 编译的真实 PE（Rich 头，MSVC 19.29） | 出处未留档；manifest 标 `redistributable=false`，**不可再分发** | 无法提供原件。自行用 MSVC 生成任意 PE（如 `cl /O2 hello.c`）替代；注意 `verify_fingerprint` / `verify_map` 对 MSVC 版本、节布局的期望值需按新样本重定标 |
| `tests/samples/fingerprint/upx/upx_cli-64.exe` | 由 `cli-64.exe` 经 UPX 压缩派生 | 随源样本：不可再分发 | 自备 PE 后 `upx --best -o upx_cli-64.exe <你的PE>`（UPX 自身 GPL-2.0+） |
| `tests/fixtures/dyn_nopie` | ELF64 ET_EXEC（非 PIE） | unknown（来源未留档） | 见 §3 的 gcc 命令；**与原件不保证逐字节相同** |
| `tests/fixtures/dyn_static` | ELF64 静态链接大样本 | unknown；内含 glibc 代码，整体来源未留档 | 见 §3；静态链接的 glibc 片段许可随 glibc（LGPL），但原文件来源不可考，故不推断 |
| `tests/fixtures/dyn_execstack` | ELF64 PIE，GNU_STACK 可执行（NX off） | unknown（来源未留档） | 见 §3 |
| `tests/fixtures/dyn_norelro` | ELF64 ET_EXEC，RELRO none | unknown（来源未留档） | 见 §3 |
| `tests/fixtures/minipe.exe` | 最小 PE32+ EXE（2 节） | unknown；非真实发行物 | `python tests/make_minipe.py`（仓库内纯标准库生成器） |
| `tests/fixtures/minidll.dll` | 最小 PE32+ DLL（导出桩） | unknown；非真实发行物 | `python tests/make_minidll.py` |
| `tests/fixtures/minipe_fakerich.exe` | 最小 PE32+ EXE，伪造 Rich 头（负样本） | unknown；非真实发行物 | `python tests/make_fakerich.py` |
| `tests/minipe.exe`、`tests/minidll.dll` | 与 `fixtures/` 重复的构建产物 | 同上 | 同上（生成器写 `tests/` 根，再复制到 `fixtures/`） |

> 三份 PE 最小样本由仓库内脚本直接写出字节（无随机数、无时间戳），**预计逐字节可复现**；请用脚本自带的输出核对大小与 sha256。

## 2. GPL 二进制（本机保留，不入库）

| 文件 | 许可 | 自行获取或构造 |
|---|---|---|
| `tests/fixtures/bin_ls.elf` | **GPL-3.0**（coreutils 的 `ls`） | 在 Linux 上 `cp /bin/ls tests/fixtures/bin_ls.elf`（发行版/版本不同则字节不同）；源码见 coreutils 发行包。原件来自哪一发行版**未经核实** |
| `tests/samples/fingerprint/busybox-1.35.0-musl-x86_64` | **GPL-2.0**（BusyBox） | 从 busybox.net 取得 1.35.0 源码，用 musl 静态编译（`make defconfig && make LDFLAGS=-static`）；或用同版本静态预编译包。原件对应的具体构建**未经核实** |

若要把这些二进制重新随仓库分发，必须同时满足 GPL 的源码提供义务（随附全文 + 书面要约或对应源码）；当前选择是不分发。

## 3. 用 gcc 构造 ELF 回归样本

`tests/hello.c` 是仓库内保留的最小源文件（`puts("hi")`）。按各样本名与 2026-11-10 任务卡记录的编译选项：

```bash
# 在 Linux（gcc + glibc）下，仓库根执行
gcc -fPIE -pie            tests/hello.c -o tests/fixtures/dyn_pie        # dyn_pie 仍随仓库保留，可作参照
gcc -no-pie               tests/hello.c -o tests/fixtures/dyn_nopie
gcc -no-pie -z norelro    tests/hello.c -o tests/fixtures/dyn_norelro
gcc -z execstack          tests/hello.c -o tests/fixtures/dyn_execstack
gcc -static               tests/hello.c -o tests/fixtures/dyn_static
```

注意：

- 源文件为 `hello.c` 属**推断**（fixtures 内没有当时的命令行记录），未逐字节验证。
- 不同 gcc/glibc 版本产出的节布局、地址、指令数都会变；`verify_map` 等脚本里钉死的期望值需要按新样本重定标，这不是零成本替换。

## 4. 工具链（从未入库，按需安装）

| 工具 | 用途 | 获取 | 许可 |
|---|---|---|---|
| GNU binutils 2.47（`objdump`） | 多套 verify 的权威对读 | 官方发布包，解压到 `2026-11-15/m2-task-card/work/tools/`（`.gitignore` 排除） | GPL-3.0 |
| UPX 5.3.0 | 生成/核对 UPX 指纹样本 | 官方 release zip | GPL-2.0+ |
| `pwsh` 7 | `verify_sigblob` 的 SRM oracle | `winget install --id Microsoft.PowerShell --source winget` | MIT |
| `dnfile`（Python 包） | .NET 元数据对拍 | `python -m pip install dnfile` | MIT |

## 5. 恢复本机验证环境

```powershell
# 从已有工作区恢复样本与工具链，并重建 work 下的 junction
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\setup.ps1" -AssetsSource <原工作区根>
```

`setup.ps1` 只做复制与建链，不下载、不猜来源、不伪造校验值；缺资产时 `gate.ps1` 会在 preflight 以 exit 2 停下。
