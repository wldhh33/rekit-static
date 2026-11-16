# HANDOFF · 会话交接

> 规则：每次会话结束前更新本文件；开工先读本文件 + `pack\AGENTS.md`，再跑 `python "pack\tools\status.py"`。
> 六段缺一不可、不得留空；全文 ≤150 行。历史进度看 `pack\03_路线图与章程\PROGRESS.md`，这里只写"当前"和"下一步"。

## 1. 当前进度

- **M20（.NET 类型布局与字段 RVA，.NET 纵切面封口）已收口（2026-11-17）**。实现 `rekit\layout.py` + `rekit layout`；分母四样本 `FieldLayout` 84 / `ClassLayout` 71 / `FieldRVA` 132 = 287 行，二分恒等式全部成立；数据解码率 100.0000%（131/131），unknown 0.7576%（1/132）。
- 静态只报元数据写明的三样：`FieldLayout.Offset`、`ClassLayout.PackingSize/ClassSize`、`FieldRVA` 的 RVA→文件偏移→字节。sequential/auto 偏移单列 `runtime_derived`（14 个偏移 / 3 个 size / 1 个 auto 不可得），`static_conclusion=false`，不进静态结论。
- 独立对拍（期望值不取被测实现）：dnfile 三表原始列值 287 行、dnfile RVA→文件偏移 131 行、源码真值 16 项（`.il` 的 `.pack/.size/.field [N]/.data`、`.cs` 的 `[FieldOffset]/[StructLayout]`/数组初始化器）、`__StaticArrayInitTypeSize=N` 与 ClassSize/推导长度 121 行，**全部 0 不一致**。
- `tests\verify_layout.py` 首版即带可失败自证（工件=注入 ID + 基线 + 观察到失败行），5 类注入全检出 + 空比对判 FAIL；**28 项（PASS 27 / SKIP 1）**。证据 `work\evidence_m20_layout.json`。
- **M19（.NET 签名语义层 `sigblob`）已收口（2026-11-17）**：方法签名 32,518 / 字段 911 / 局部 3,974；可读 blob 37,403，解码率 100.0000%，unknown 0；dnfile 字节边界 52,403 行、SRM canonical 37,403 行、M17 交叉 29,728 行全 0 不一致。定标②偏离已登记：dnfile 无签名 API，改 SRM（`tests\sigref.ps1`，pwsh 缺失即 `env_missing` exit 2）。证据 `work\evidence_m19_sigblob.json`。
- **门禁当前态**：全量 **23 套 PASS**、pytest **554 passed**、`ledger_check --check` PASS（干净克隆演练 run `20261117T030415-70ee`，`GATE: PASS exit=0`，432.5 s）。总账 **10 小节 / 98 个登记数字 / 去重后未登记 127 个**（五类原因），权威 `work\evidence_numbers_ledger.json`。
- **治理当前态**：`pack\` 已 git 初始化（基线 tag `baseline-pre-rename`）；4 个 mojibake 目录已改名、`work` 下 junction 已重建（`pack` 7 个目录均可访问）；`pack\rules.json` 119 条；`pack\tools\status.py` 硬判 HANDOFF/verification/ledger。
- 文档漂移已修（本轮实测）：`pack\AGENTS.md` 规模改 **27 模块 / 18,600 行**；`CHARTER.md` 补 M20 行与转段触发器 T1–T5（**T1/T4 已命中**，T1 曾被误读为需两个条件同时满足，已更正并留记录）。
- **U1 收口（2026-11-17）**：`v0.1.0` 由 `5fbb421` 移至 `d63d244`（含 U1-a + U1-b；worktree 检出该提交后 ledger/evidence_index 双 PASS）；新增单命令门禁 `pack\tools\gate.ps1`（preflight fail-fast + ledger → evidence_index → verify_gate）；`.github\workflows\gate.yml` 为**未验证**草稿（仅手动触发，从未运行）；新增规则 **R126**；`evidence_index.repo_root()` 修掉 junction 入口多算一级目录的 bug。
- **干净克隆演练（2026-11-17，`v0.1.1`）**：仓库外空目录按 `pack\README.md` 从零操作，第一次 `gate.ps1` 即 exit 2（9 项前置缺失）。新增 `pack\tools\setup.ps1`（显式 `-AssetsSource`、先复制后 junction、幂等）；去掉 5 个测试 + 3 个生成器的 `<旧仓库根>` 硬编码；`verify_layout`/`verify_sigblob` 证据路径改 work 相对路径（绝对路径会让 sha256 随克隆目录漂移）。修后：setup 0.9 s、gate **432.5 s**、23/23 + 554 passed + ledger PASS、exit 0。详见 `CHANGELOG.md` / `PROGRESS.md` 同日条目。

## 2. 未完成清单

U1 交付批次已全部收口（打包 / console entry / 示例 / 证据索引 / R95 7 样本 / 干净克隆演练 / `v0.1.1`）。仍未做：

| 项 | 状态 / 前置 |
|---|---|
| 真 CI | `.github\workflows\gate.yml` 只是未验证草稿（无远端、从未触发）；启用与远端推送留 U2 |
| 122 条 null run_id | **不回填**（不猜来源）；新证据按 `AGENTS.md` §8 的 run_id 约定落盘，避免缺口扩大 |
| tag 覆盖范围 | `v0.1.0` 停在 `d63d244`（U1-a + U1-b）；**`v0.1.1` 覆盖门禁脚本、setup、R126、去垫片等收尾补件**；release tag 只在该批次全部收口后打 |
| 下一条命令 | 本文件 §6；全量用 `gate.ps1`（干净克隆实测 432.5 s） |

非源码类、尚未做：

- `pack\02_规则库\规则库_R33-R119.md` 余 3 条「材料不足」（R49/R93/R110）与 6 条待确认，见 `2026-11-16\vibe-coding-review\work\batch4\human_decisions.md`；R120–R126 已建索引（附录 E），尚未回填主表。
- 工作树有 4 个与本轮无关的既有改动（`2026-11-16\vibe-coding-review\...`），属 R103/B4 前序工作，**不要夹带进收口提交**。

## 3. 已否决方案

1. **把 sequential/auto 偏移写进静态结论**：CLR 的字段排序是运行期行为，元数据里只有 `FieldLayout` 显式偏移；写进去就是把推导冒充声明（R123）。
2. **用 `.data` 字面量长度反推 `FieldRVA` 数据长度**：唯一的 unknown（IL 样本 `System.DateTime`）就是反例；按 R121 记 unknown 并写缺什么。
3. **把 dotnet 自家解析器当唯一裁判**：dnfile 不实现 `FieldRVA`（M17 已记），只做列值与 RVA 换算对拍；数据字节另用源码数组初始化器对拍。
4. **为让 unknown 归零而把外部程序集类型当"已解析"**：外部类型的长度在本模块里不可知，归零等于按名称猜。
5. **M20 后继续叠下一层**：`.NET` 纵切面到此封口，再叠就是补 `out_of_scope`，触发 T2（见 CHARTER）。
6. **为 `status.py` 引入第三方库**：纯标准库，避免给"开工第一条命令"增加环境依赖。
7. **把整个 `work` 复制一份来"开分支"**：会复制 99 MB 样本并制造第 N 份副本。

## 4. 待确认问题

1. **T4 已命中**（CHARTER 转段触发器）：本轮已出现"要给别人一条可复现命令"的需求雏形——`verify_layout.py` 依赖 `powershell` 跑运行期 oracle，别人拿到仓库无法直接复跑；交付批次必须给出可复现命令或明确标注环境前置。
2. R95 七个样本的口径：**已定案**为 7 个具体 fixture（`dyn_nopie`/`dyn_static`/`dyn_execstack`/`dyn_norelro`/`minipe.exe`/`minidll.dll`/`minipe_fakerich.exe`），见 `work\fixtures_sample_manifest.json`；18/25 → 25/25。
3. v0.1.0 的"可分发"边界：`tests\fixtures\cli-64.exe` 出处不明（`AGENTS.md` 已标"不可再分发"），发布包必须排除，但仓库是否保留待定。
4. `verify_layout.py` 的 SKIP 1（System.Console 的 `FieldRVA=0`）是否需要在交付批次补一个"零行表"负样本，目前由聚合分母兜底。
5. tag 覆盖范围：`v0.1.0` 停在 `d63d244`，U1 收口补件（`gate.ps1`/文档/R126）在 tag 之后。若要把补件纳入发布，只能再移一次 tag（会覆盖本次重定位记录，不建议）；当前口径是"tag 标代码交付，收口补件单列"。

## 5. 新增证据文件

- `work\evidence_m20_layout.json` —— M20 三表逐行明细、分母恒等式、长度来源、运行期 oracle、静态结论边界。
- `work\evidence_m19_sigblob.json` —— M19 签名解码与三方对拍（dnfile 字节 / SRM canonical / M17 交叉）。
- `work\verification\20261117T013424-1713\`、`work\verification\20261117T014558-2b7c\` —— M20 收口与文档定稿后复跑的全量门禁（23 套日志 + vharness.json + pytest.log + summary.json）。
- `work\verification\20261117T023235-f180\` —— U1 收口后经 `pack\tools\gate.ps1` 实跑的全量门禁（23 套日志 + vharness.json + pytest.log + summary.json）。
- `work\outputs\NUMBERS_LEDGER.md` §15/§16 —— M19/M20 数字人读镜像；权威 `work\evidence_numbers_ledger.json`。
- `work\outputs\TASK_m18_ilflow.md`、`outputs\m19_sigblob\`、`outputs\m20_layout\` —— 任务卡与受控样本源码（`.il`/`.cs`/`gen.ps1`）+ `spec.md`（静态/运行期边界）。
- `2026-11-16\vibe-coding-review\work\batch1..batch4\` —— 治理批次（HANDOFF 协议/门禁/规则/总账）证据，未受本轮影响。

## 6. 下一位第一条命令

```powershell
python "pack\tools\status.py"
powershell -NoProfile -ExecutionPolicy Bypass -File "pack\tools\gate.ps1" -List
```

期望：`HANDOFF: 6/6 段非空`、`pack 目录: 7 个均可访问`、`verification/latest: PASS scope=all`、`numbers ledger: PASS`、`git: 已初始化`、`GATE: PASS exit=0`。
要跑全量再执行不带 `-List` 的同一条命令（约 8 分钟，23 套 + pytest + ledger；preflight 缺项会 exit 2，先恢复样本/工具链，不要绕过）。
若退出码为 1：先按本文件模板补齐 HANDOFF、修 ledger 漂移或重跑门禁，不要绕过。
