# HANDOFF · 会话交接

> 规则：每次会话结束前更新本文件；开工先读本文件 + `pack\AGENTS.md`，再跑 `python "pack\tools\status.py"`。
> 六段缺一不可、不得留空；全文 ≤150 行。历史进度看 `pack\03_路线图与章程\PROGRESS.md`，这里只写"当前"和"下一步"。

## 1. 当前进度

- **M20（.NET 类型布局与字段 RVA，.NET 纵切面封口）已收口（2026-11-17）**。实现 `rekit\layout.py` + `rekit layout`；分母四样本 `FieldLayout` 84 / `ClassLayout` 71 / `FieldRVA` 132 = 287 行，二分恒等式全部成立；数据解码率 100.0000%（131/131），unknown 0.7576%（1/132）。
- 静态只报元数据写明的三样：`FieldLayout.Offset`、`ClassLayout.PackingSize/ClassSize`、`FieldRVA` 的 RVA→文件偏移→字节。sequential/auto 偏移单列 `runtime_derived`（14 个偏移 / 3 个 size / 1 个 auto 不可得），`static_conclusion=false`，不进静态结论。
- 独立对拍（期望值不取被测实现）：dnfile 三表原始列值 287 行、dnfile RVA→文件偏移 131 行、源码真值 16 项（`.il` 的 `.pack/.size/.field [N]/.data`、`.cs` 的 `[FieldOffset]/[StructLayout]`/数组初始化器）、`__StaticArrayInitTypeSize=N` 与 ClassSize/推导长度 121 行，**全部 0 不一致**。
- `tests\verify_layout.py` 首版即带可失败自证（工件=注入 ID + 基线 + 观察到失败行），5 类注入全检出 + 空比对判 FAIL；**28 项（PASS 27 / SKIP 1）**。证据 `work\evidence_m20_layout.json`。
- **M19（.NET 签名语义层 `sigblob`）已收口（2026-11-17）**：方法签名 32,518 / 字段 911 / 局部 3,974；可读 blob 37,403，解码率 100.0000%，unknown 0；dnfile 字节边界 52,403 行、SRM canonical 37,403 行、M17 交叉 29,728 行全 0 不一致。定标②偏离已登记：dnfile 无签名 API，改 SRM（`tests\sigref.ps1`，pwsh 缺失即 `env_missing` exit 2）。证据 `work\evidence_m19_sigblob.json`。
- **门禁当前态**：全量 **23 套 PASS**、pytest **554 passed**、`ledger_check --check` PASS（run `20261117T014558-2b7c`，`VERDICT: PASS exit=0`；收口 run 为 `20261117T013424-1713`）。总账 **10 小节 / 98 个登记数字 / 去重后未登记 127 个**（五类原因），权威 `work\evidence_numbers_ledger.json`。
- **治理当前态**：`pack\` 已 git 初始化（基线 tag `baseline-pre-rename`）；4 个 mojibake 目录已改名、`work` 下 junction 已重建（`pack` 7 个目录均可访问）；`pack\rules.json` 119 条；`pack\tools\status.py` 硬判 HANDOFF/verification/ledger。
- 文档漂移已修（本轮实测）：`pack\AGENTS.md` 规模改 **27 模块 / 18,600 行**；`CHARTER.md` 补 M20 行与转段触发器 T1–T5（**T1/T4 已命中**，T1 曾被误读为需两个条件同时满足，已更正并留记录）。

## 2. 未完成清单

M20 之后**不再开下一层**，下一步是交付型批次，由用户另排：

| 批次项 | 内容 | 前置 |
|---|---|---|
| 打包 | 可安装/可分发形态（纯标准库，不引运行时依赖） | 需先定"包子集"（`cli.py` 入口 + 被 import 的模块闭包） |
| console entry | 安装后 `rekit` 命令可用；当前只有 `python -m rekit.cli` | 同上 |
| 示例 | 命令行示例与输出样例（含 .NET 纵切面：`dotnet`/`ilflow`/`sigblob`/`layout`） | 交付形态定稿后 |
| 证据索引 | 把 `work\evidence_*.json|log` 按里程碑建索引，标明可复跑命令 | 无 |
| R95 七个样本登记 | R95 要求的 7 个样本补进 `m9_sample_manifest.json`（sha256/许可/可再分发） | 需确认样本来源 |
| 打 v0.1.0 | tag 与发布说明 | 以上完成且全量门禁绿 |

非源码类、尚未做：

- `pack\README.md` 过期内容（"73 断言 / 5 模块 / `cd 04_rekit项目源码`"）未修 —— 交付批次一并处理，避免与包结构改动打架。
- `pack\02_规则库\规则库_R33-R119.md` 余 3 条「材料不足」（R49/R93/R110）与 6 条待确认，见 `2026-11-16\vibe-coding-review\work\batch4\human_decisions.md`。
- 工作树有 5 个与本轮无关的既有改动（`2026-11-16\vibe-coding-review\...`、`pack\02_规则库\规则库_R33-R119.md`、`pack\rules.json`），属 R103/B4 前序工作，**不要夹带进 M20 提交**。

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
2. R95 七个样本的口径：是指定 7 个具体样本（哪 7 个？），还是 7 类样本（中型 ELF/PE/跳板密集/插件式/未 strip MSVC+PDB…）？登记前需确认。
3. v0.1.0 的"可分发"边界：`tests\fixtures\cli-64.exe` 出处不明（`AGENTS.md` 已标"不可再分发"），发布包必须排除，但仓库是否保留待定。
4. `verify_layout.py` 的 SKIP 1（System.Console 的 `FieldRVA=0`）是否需要在交付批次补一个"零行表"负样本，目前由聚合分母兜底。

## 5. 新增证据文件

- `work\evidence_m20_layout.json` —— M20 三表逐行明细、分母恒等式、长度来源、运行期 oracle、静态结论边界。
- `work\evidence_m19_sigblob.json` —— M19 签名解码与三方对拍（dnfile 字节 / SRM canonical / M17 交叉）。
- `work\verification\20261117T013424-1713\`、`work\verification\20261117T014558-2b7c\` —— M20 收口与文档定稿后复跑的全量门禁（23 套日志 + vharness.json + pytest.log + summary.json）。
- `work\outputs\NUMBERS_LEDGER.md` §15/§16 —— M19/M20 数字人读镜像；权威 `work\evidence_numbers_ledger.json`。
- `work\outputs\TASK_m18_ilflow.md`、`outputs\m19_sigblob\`、`outputs\m20_layout\` —— 任务卡与受控样本源码（`.il`/`.cs`/`gen.ps1`）+ `spec.md`（静态/运行期边界）。
- `2026-11-16\vibe-coding-review\work\batch1..batch4\` —— 治理批次（HANDOFF 协议/门禁/规则/总账）证据，未受本轮影响。

## 6. 下一位第一条命令

```powershell
python "pack\tools\status.py"
python "pack\tools\verify_gate.py" --list
```

期望：`HANDOFF: 6/6 段非空`、`pack 目录: 7 个均可访问`、`verification/latest: PASS scope=all`、`numbers ledger: PASS`、`git: 已初始化`、末行 `VERDICT: PASS exit=0`。
要跑全量再执行 `python "pack\tools\verify_gate.py" --run`（约 8 分钟，23 套 + pytest + ledger）。
若退出码为 1：先按本文件模板补齐 HANDOFF、修 ledger 漂移或重跑门禁，不要绕过。
