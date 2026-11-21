# 公开前体检报告（2026-11-21）

> 范围：工作树 472 个跟踪文件 + 全部 **23 个提交**（`git rev-list --all`，含历史 blob）的敏感信息、体积、可复现性、文件卫生、文档一致性与许可覆盖面。
> 方法：`git grep <pattern> $(git rev-list --all)`、`git cat-file --batch-check` 统计历史 blob、`git clone` 到 `%TEMP%\rekit_pubclone` 实走 README、`gate.ps1` / `ledger_check.py` / `evidence_index.py` 实跑。
> 未做：推送、创建远端、改写历史、删除任何文件（删除类仅建议）。本轮加固改动见 §7。

## 0. 结论

- **无 token / 私钥 / 内网 IP / 机器名**：常见密钥形态（`ghp_`、`github_pat_`、`AKIA`、`sk-`、`BEGIN … PRIVATE KEY`、`password/secret/api_key=…`）与 RFC1918 地址扫描均为 0 命中（`token` 的命中全是 .NET metadata token）。
- **必须处理 3 类阻断项**：① 全部提交的作者邮箱是个人 QQ 邮箱；② 仓库里固化了 9 个来源未知/明确不可再分发的样本；③ GPL 样本没有随附许可与源码获取说明。
- **已就地加固**：HEAD 中的 `C:\Users\<user>` 已清零；旧仓库路径 `<旧仓库根>`、`<旧仓库根>` 在**活文档与可用脚本**中已改为相对定位；README 过期许可措辞、ONBOARDING 门禁数字、CI 工作流套数已更新。
- **历史仍保留**上述路径与邮箱（含已删除内容的旧 blob）。按你的要求**只报告不改写**；因为还没有远端，现在改写历史成本最低（见 §8）。

## 1. 敏感与私人信息

### 1.1 已固化在提交元数据（仅报告，不改写）

| 项 | 位置 | 现状 | 干净移除? |
|---|---|---|---|
| 个人邮箱（已脱敏） | 全部 23 个提交的 author/committer email | 公开后会显示在每个 commit 与 GitHub 头像旁 | HEAD 文件里没有；要清除必须改写全部提交（`git filter-repo --mailmap` 或 `--email-callback`），退路是接受公开 |
| 作者名 `WLDHH33` / `rekit-baseline` | 提交元数据 + `LICENSE` 版权行 | 版权行是你已拍板的署名 | 可保留；不想暴露可改 `user.name` 后仅影响新提交 |

### 1.2 HEAD 中的用户名 / 私人路径（已在工作树修正，历史仍留）

| 文件 | 内容 | 已入库 | 处置 |
|---|---|---|---|
| `pack/04_rekit项目源码/tests/verify_datarefs.py` | 提示语里的 `C:\Users\<user>\Tools\...` | 是 | ✅ 已改为“加入 GNU binutils 的 bin 目录” |
| `2026-11-15/m2-task-card/work/verify_e3.py` | `.trae-cn\attachments\...upx-5.3.0-win64.zip` 完整路径 | 是 | ✅ 改为“见 evidence_e2e3_2026-11-15.log（原始上传包路径不随仓库公开）” |
| `2026-11-15/m2-task-card/work/sample_manifest.json` | `c:\Users\<user>\...\zip`、`D:\tools\go*`、`<旧仓库根>\...` | 是 | ✅ 改为工具链/克隆的通用描述 |
| `evidence_m12_pytest.log`（仓库根） | `At C:\Users\<user>\AppData\Local\Temp\...` | 是 | ✅ 改为 `<tmp>`；该文件本身建议归档（§4） |
| `pack/README.md`、`pack/AGENTS.md`、`pack/PATH_MAP.md`、`pack/04_rekit项目源码/README.md` | 旧开发机路径 `<旧仓库根>`、`<旧仓库根>` | 是 | ✅ 改为 `<旧仓库根>` / `/<用户>/<项目>` |
| `pack/05_每日日志/2026-11-07…15/verify_*.py`（6 个） | `sys.path.insert(0, "<旧仓库根>/...")`、fixtures 绝对路径 | 是 | ✅ 改为 `__file__` 相对定位 |
| `2026-11-15/m2-task-card/work/verify_objdump.py`、`run_pytest.ps1`、`2026-11-15/m3-task-card/work/collect_map_gt.py` | `<旧仓库根>\...` 默认仓库根 | 是 | ✅ 改为按 `__file__` 推导 `pack/04_rekit项目源码` |

> 说明：上述文件的历史版本仍在旧提交里（`git log -S` 可定位）。**只清理 HEAD 不会让历史消失**；彻底清除需改写历史。

### 1.3 仍然含有绝对路径、但无用户名（仅记录）

- 77 个跟踪文件含 `D:\…` / `C:\…`，绝大多数是**证据日志**里的运行路径（`D:\数据\下载\…`、`C:\Python314`）以及 `C:\Windows\…\mscorlib.dll` 这类标准 Windows 路径。
- `pack/03_路线图与章程/CHANGELOG.md`、`PROGRESS.md`、`HANDOFF.md` 的历史条目按纪律只追加，保留当时的 `<旧仓库根>…`、`23/23` 等记录（活文档 README/ONBOARDING 已更新）。
- 仓库内没有机器名（本机 `hostname` 为 `nb`，未在任何跟踪文件中出现）、没有内网 IP、没有凭据。

## 2. 体积

| 指标 | 数值 |
|---|---|
| `.git` 目录 | **10.48 MiB**（870 个对象，全为松散对象，尚未 `gc`） |
| HEAD 跟踪文件 | **472 个 / 17.40 MB** |
| 历史 blob 去重总字节 | ≈ 10.9 MB（最大单个 2.49 MB） |
| 历史中 `samples/`、`tools/`、`verification/`、`dist/`、`build/` 路径 | **0 个**（`.gitignore` 生效） |

HEAD 最大的文件：

| 大小 | 路径 | 性质 |
|---:|---|---|
| 2,494,464 | `tests/samples/fingerprint/hello_go.exe` | 自建 Go 样本 |
| 2,342,697 | `tests/samples/fingerprint/hello_go_linux` | 自建 Go 样本 |
| 1,706,136 | `tests/samples/fingerprint/putty-64bit.exe` | 第三方（MIT） |
| 1,131,168 | `tests/samples/fingerprint/busybox-1.35.0-musl-x86_64` | 第三方（GPL-2.0） |
| 960,664 | `tests/samples/fingerprint/upx/upx_putty-64bit.exe` | 第三方样本 + UPX 压缩 |
| 754,232 | `tests/fixtures/dyn_static` | 来源不明（见 §6） |
| 255,433 | `work/map_ground_truth.json` | 冻结真值 |
| 158,632 | `tests/fixtures/bin_ls.elf` | 第三方（GPL-3.0） |

结论：**没有“不该入库的二进制大件”被历史固化**；`pack/04_rekit项目源码/tests/samples/fingerprint` 的 5 个文件（合计约 7.5 MB）是有意提交的测试语料，但其中 3 个涉及第三方许可（§6）。

## 3. 可复现性（按 README 实际走一遍）

演练环境：`git clone --no-hardlinks` 到 `%TEMP%\rekit_pubclone`，不运行 `setup.ps1`，即“无样本、无工具链”。

| 步骤 | 实测结果 | 提示是否指向修复 |
|---|---|---|
| `git clone` | 成功，工作树干净 | — |
| `cd pack\04_rekit项目源码; python -m rekit --help` | **成功**（纯标准库，无任何资产） | — |
| `python examples\pe_report.py tests\fixtures\minipe.exe` | **成功**（fixtures 已入库） | — |
| `python examples\elf_report.py tests\fixtures\bin_ls.elf` | **成功** | — |
| `python examples\dotnet_report.py`（不带参数） | 打印用法后 exit 2 | 指向“传入 .NET 文件”，未提样本缺失 |
| `powershell -File pack\tools\gate.ps1` | **exit 2**，一次列出 **18 项前置缺失**（5 个 junction、6 组样本、objdump、pwsh、python 包） | ✅ 每项都指向 `setup.ps1 -AssetsSource <原工作区根>` 或 `pip install` |
| `powershell -File pack\tools\setup.ps1 -AssetsSource C:\NoSuchAssets` | exit 2，明确提示资产源不存在 | ✅ |
| 无 `pwsh`（裁剪 PATH 后跑 gate） | exit 2，报 `missing: pwsh (pwsh available) — gate 用 pwsh 调度 verify_gate` | ⚠️ 只说“缺什么”，**没给安装方法**（建议补一句 `winget install Microsoft.PowerShell`） |
| `python pack\tools\ledger_check.py --check` | **PASS**（纯 Python，无需资产） | — |
| `python pack\04_rekit项目源码\tests\evidence_index.py --check` | **PASS 131/131** | — |
| `python pack\tools\status.py` | 有 2 条 WARN（缺 junction/缺 verification），但最后 **VERDICT: PASS** | ⚠️ 会让人误以为“全绿”，建议把 WARN 计入非 PASS 或显式说明 |

**必然停点**：`gate.ps1` 需要 `setup.ps1 -AssetsSource <原工作区根>` 提供 `work\samples\` 与 `work\tools\binutils`。这两样都被 `.gitignore` 排除，**陌生人没有任何合法获取路径**。README 目前写了“样本不入库、需从原工作区恢复”，但没有明确说“没有原资产的人只能用到哪一步”。建议补一段“无资产可用范围”：可用 `python -m rekit`、PE/ELF fixtures、`ledger_check`、`evidence_index`；不可跑全量门禁/pytest。

## 4. 文件卫生（`work/` 及仓库根）

| 文件/目录 | 性质 | 已入库 | 建议 |
|---|---|---|---|
| `evidence_m12_pytest.log`、`evidence_m12_verify.log`（仓库根） | 一次性日志，位置异常（其余证据都在 `work/`） | 是 | **移到 `2026-11-15/m3-task-card/work/`（或 archive）并重写索引**；不删除（是 M12 证据） |
| `2026-11-15/m2-task-card/work/probe_fixtures.py/.json`、`probe_samples.py/.json` | 一次性探测脚本/快照 | 是 | **保留**：`outputs/TASK_m2_fingerprint.md` 明确引用为证据来源 |
| `2026-11-15/m3-task-card/work/evidence_m18_{leave_diag,filter,mscorlib,console}.txt` | 诊断转储 | 是 | **保留**：已在 `EVIDENCE_INDEX.json` 登记为 M18 证据 |
| `2026-11-15/m3-task-card/work/collect_map_gt.py` | 真值采集器（仍可用） | 是 | 保留；或移到 `pack/tools/`（需同步引用） |
| `2026-11-15/m2-task-card/work/{verify_objdump.py,verify_e3.py,run_pytest.ps1}` | M2 验证辅助 | 是 | 保留（本轮已改成路径无关） |
| `work/verification/<run>/`（27 个 run 目录，≈4.5 MB） | 门禁运行产物 | **否**（gitignore） | 不上传；本地可只留 `latest` |
| `pack/05_每日日志/*/evidence_*.log` | 历史日志 | 是 | 保留（历史记录）；含旧 `<旧仓库根>` 路径，见 §1.3 |
| `pack/06_日报docx/閫嗗悜…docx`（10 个） | 文件名乱码（原为中文） | 是 | **建议改名**为可读中文；无内容引用，风险低 |
| `tmp/`、`.screenshots/`、`dist/`、`build/` | 临时/构建产物 | **否**（gitignore） | 无需处理 |

## 5. 文档一致性

已改：

- `pack/README.md`：删除“旧版 wheel 的 `License: 内部学习项目，未声明开源许可`”原文引用，改为“自由文本许可声明”；“内部学习项目/未声明许可”在活文档中已无残留。
- `pack/04_rekit项目源码/README.md`：新增 **许可（MIT）** 小节，写明收到 wheel 被授予的权利。
- `pack/ONBOARDING.md`：门禁态从 `23/23、129/129、20261117…` 更新为 **25/25、131/131、20261121T163552-6067**。
- `.github/workflows/gate.yml`：`23 verify suites` → `25 verify suites（现算）`。
- `pack/AGENTS.md`、`pack/PATH_MAP.md`：`<旧仓库根>/...` 改为占位描述（保留“垫片已移除”的历史语义）。

仅记录（按纪律不改写）：

- `CHANGELOG.md`、`PROGRESS.md`、`HANDOFF.md` 的历史条目仍含旧路径、`23/23` 等当时数字。
- `pack/rules.json` 登记 127 条，部分文档写 119 条（既有漂移，与本次无关）。

## 6. 许可覆盖面

- **`LICENSE` 只在包根**：`pack/04_rekit项目源码/LICENSE`（MIT）。仓库根**没有** `LICENSE` / `README`。
  - GitHub 的许可证识别通常只看仓库根；若公开整仓，建议在根放一份同名 `LICENSE`（内容一致，`verify_dist` 可加“两处逐字相等”判据）或把仓库结构改成以包为根。
- README 许可小节：`pack/README.md`（安装/分发节）与 `pack/04_rekit项目源码/README.md` 均有，写明 MIT 与授予权利。
- 仓库内**没有** `NOTICE` / `THIRD_PARTY_LICENSES` / `COPYING`。

### 已入库、但不能/不宜随仓库公开的样本

| 文件 | 大小 | 许可/来源 | 结论 |
|---|---:|---|---|
| `tests/fixtures/cli-64.exe` | 14,336 | 来源不明，manifest 标 `redistributable=false` | **不能公开** |
| `tests/samples/fingerprint/upx/upx_cli-64.exe` | 9,728 | 由 `cli-64.exe` 经 UPX 压缩派生 | **不能公开** |
| `tests/fixtures/dyn_nopie` | 15,592 | FIX-01，许可未知 | **不能公开** |
| `tests/fixtures/dyn_static` | 754,232 | FIX-02，许可未知 | **不能公开** |
| `tests/fixtures/dyn_execstack` | 15,952 | FIX-03，许可未知 | **不能公开** |
| `tests/fixtures/dyn_norelro` | 12,456 | FIX-04，许可未知 | **不能公开** |
| `tests/fixtures/minipe.exe` | 2,048 | FIX-05，许可未知 | **不能公开** |
| `tests/fixtures/minidll.dll` | 2,048 | FIX-06，许可未知 | **不能公开** |
| `tests/fixtures/minipe_fakerich.exe` | 2,048 | FIX-07，许可未知 | **不能公开** |
| `tests/minidll.dll`、`tests/minipe.exe` | 2,048 / 2,048 | 与 fixtures 重复的构建产物 | 随 fixtures 一起处理 |

### 需要随附许可/源码获取说明（可保留）

| 文件 | 许可 | 要求 |
|---|---|---|
| `tests/fixtures/bin_ls.elf` | **GPL-3.0**（coreutils） | 随附 GPL-3.0 全文 + 源码获取方式（或书面要约） |
| `tests/samples/fingerprint/busybox-1.35.0-musl-x86_64` | **GPL-2.0** | 随附 GPL-2.0 全文 + 对应源码获取方式 |
| `tests/samples/fingerprint/putty-64bit.exe`、`upx/upx_putty-64bit.exe` | MIT（PuTTY） | 保留版权与许可声明 |
| `hello_go.exe`、`hello_go_linux`、`hello_rust*`、`dyn_pie`、`tests/samples/avx/*` | 自建/自著 | 可按 MIT 分发 |
| `tests/m16_fixtures/datarefs_full.exe` | 由仓库内 C 源码生成 | 可按 MIT 分发（建议保留生成脚本 provenance） |

> `work/samples/`（busybox、PuTTY、UPX 工具等）与 `work/tools/binutils` 未入库，公开后也不会随仓库分发；保持现状即可。

## 7. 已执行的加固改动（工作树，待提交）

- 敏感路径清理：`tests/verify_datarefs.py`、`work/verify_e3.py`、`work/sample_manifest.json`、`evidence_m12_pytest.log`、`pack/README.md`、`pack/AGENTS.md`、`pack/PATH_MAP.md`、`pack/04_rekit项目源码/README.md`。
- 脚本路径改为 `__file__` 相对定位：`pack/05_每日日志/2026-11-07…15/verify_*.py`（6 个）、`work/verify_objdump.py`、`work/run_pytest.ps1`、`work/collect_map_gt.py`。
- 可选工具链路径改为环境变量/通用提示：`tests/make_datarefs_full.py`、`tests/make_funcreport_full.py`、`tests/verify_funcreport.py`、`tests/verify_expr.py`、`tests/verify_switchcand.py`（Ghidra 改读 `GHIDRA_INSTALL_DIR`）。
- 文档：`pack/04_rekit项目源码/README.md` 新增许可小节；`pack/ONBOARDING.md` 更新门禁数字；`.github/workflows/gate.yml` 更新套数；`pack/README.md` 去除过期许可原文。
- 证据索引：因 `evidence_m12_pytest.log` 内容变化，已重写 `EVIDENCE_INDEX.json` 并 `--check` PASS。
- 全量门禁：本轮结束后重跑，结果见 §9。

## 8. 推公开仓库前需要你拍板的决定

1. **公开范围**：整仓（含 `pack/05_每日日志`、`2026-11-16/vibe-coding-review`、全部证据）还是只公开 `pack/` + `2026-11-15/`？当前 470+ 文件里相当一部分是学习过程记录。
2. **邮箱与历史**：接受原个人邮箱公开；还是趁没有远端时用 `git filter-repo` 改写 23 个提交的邮箱（并把作者名统一为 `WLDHH33`/noreply）。改写会改变所有 commit id。
3. **不可再分发样本**（§6 表）：删除这些文件并改写历史；或替换为自建 fixtures；或保持仓库私有、只分发 wheel；或公开时保留但接受许可风险（不建议）。
4. **GPL 样本**：保留 `bin_ls.elf` 与 busybox 并新增 `THIRD_PARTY_LICENSES.md` + 源码获取说明；还是从公开仓库移除、改用自建 ELF。
5. **根目录落地页**：是否新增根 `README.md`（指向 `pack/README.md`）与根 `LICENSE`（与包根逐字一致，并在 `verify_dist` 加一致性判据）。
6. **乱码文件名**：是否把 `pack/06_日报docx/閫嗗悜…docx` 改回可读中文（无引用，可安全 `git mv`）。
7. **远端与可见性**：本轮未创建远端、未推送；公开/私有、组织归属、是否启用 CI secrets 需要你确认后再做。

## 9. 门禁复跑（本轮加固后）

`powershell -NoProfile -ExecutionPolicy Bypass -File pack\tools\gate.ps1`，run `20261121T165722-8eec`：

- verify 套 **25/25 PASS**（`verify_dist` 43 项）
- pytest **554 passed / 0 failed / 0 skipped**
- `ledger_check --check` **PASS**（10 小节 / 10 证据 / 103 数字）
- `evidence_index --check` **131/131 PASS**
- `VERDICT: PASS suites=25 pass=25 fail=0 pytest=554 ledger=PASS exit=0`
- `GATE: PASS exit=0`

说明：本轮只改了扫描脚本/文档/路径解析，未改样本与工具链分发策略；`dist/`、`build/`、`samples/`、`tools/`、`verification/` 仍在 `.gitignore` 内。
