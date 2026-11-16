# 白银任务：rekit M2 fingerprint —— 壳 / 编译器 / 加固指纹（净室观察法）

日期：2026-11-15 ｜ 依据：CHARTER.md M2 + PROGRESS.md 尾行「下一子任务」｜ 任务类型：从零型（新模块）＋ 扩展型（复用 M1 解析结果）
本轮性质：任务卡 → **2026-11-15 同日追加：U1 已按本卡开工并落地**（见下方「执行口径」）

## 执行口径（2026-11-15 定档，覆盖本卡原「只做任务卡」的表述）

- **决策**：M2、M3 优先深度；产品化（多平台 CI、发行打包、许可材料、兼容矩阵、安装文档）整体推迟到 M3 收口后一次性做。已写入 pack/CHANGELOG.md（只增不删，含理由）。
- **当前执行范围**：**U1–U4 已完工**——骨架 + 静态维度（GCC/MSVC/Go/Rust 指纹、stripped、加固位）+ UPX 双格式正判 + E9 混淆矩阵，纯 stdlib，运行时不依赖任何外部下载；新增 19 条断言。
- **E2 / E3 已解挂（2026-11-15 同日）**：用户上传官方 `upx-5.3.0-win64.zip`（zip sha256 `d127996c…a9705`，`upx.exe` sha256 `ff30a651…d302b`，`upx --version` = `upx 5.3.0`），工具装在 `work/tools/upx-5.3.0-win64`（**不在 pack 内**）。正样本 ground truth 全部来自 upx 本体（`-l` 自报格式/原始大小、`-t` 完整性、`-d` 往返），不以本工具自证。**G3 关闭：`upx.exe` 交叉压缩 ELF 已验证可行**（`upx -l` 报 `linux/amd64`，15832 → 6124）。
- **不因产品化延后而降级的条目**（判定强度逐字保留）：
  - **E1** 接口契约 + 既有断言零回归 + CLI/模块输出等价；
  - **E4** 无 `.comment` 的样本必须 unknown（猜 GCC 即误报）；
  - **E5** 「有 Rich ⇒ MSVC」错误规则必须被 Rust 证据推翻；
  - **E6** Go 版本须与 `go version -m` 对齐；
  - **E7** stripped 只认 `.symtab`，PE 只报 COFF 符号表；
  - **E8** ELF 18 格 + PE 16 位逐格对表；
  - **E9** 混淆矩阵裁决，E2/E3 未 PASS 则整条不 PASS。
  - 产品化事项（CI/打包/许可矩阵/安装文档）**不是** M2 验收项，也不得用来替换或稀释任何 E 条目的证据。
- **权威对拍局限（如实标注）**：本机**原无** `readelf/objdump/file/upx/gcc`；**2026-11-15 已补装 upx 5.3.0 与 binutils 2.47（objdump/readelf/nm，见 §10 与 manifest `tools` 块）**。仍无 `file/strings/gcc/clang` 与 WSL，故 ELF 的通用节/段对拍仍以 **pyelftools + 2026-11-10 固化的 readelf 期望表**为主，涉及 UPX 的条目以 upx 本体对拍；`tests/test_elf.py` 中 4 条 readelf 交叉验证已由 skip 转为真跑（4 passed）。**E9 复核后的标注口径**：E8 的 ELF 18 格仍以 pyelftools + 2026-11-10 固化 readelf 期望表为准，属「实现独立、非进程独立」；4 条 readelf 交叉验证与 minidll 的 objdump 对拍属「进程独立」；不再笼统标注，按条目区分。
- **U1 实测状态**：新增 19 条断言全绿（含 E2/E3）。**2026-11-15 补装 binutils 后全量为 92 passed / 0 skipped / 0 failed**——原先因缺 `objdump` 报环境的 `test_minidll_crosscheck_objdump` 已真跑并通过（非 skip），另 4 条 `readelf not available` 的跳过也随 readelf 可用转为真跑并通过；证据见 `work/evidence_objdump_2026-11-15.log`。
- **E2/E3 验收结果**：E2 = 3/3 正样本判对（PE×2、ELF×1），证据均 2 条、`upx -t` 全 OK；E3 = 15 个未加壳负样本误报 0 / 异常 0。
- **E9 已裁决：PASS（2026-11-15 收口）**——载体 `tests/verify_fingerprint.py --all --matrix`（支持 `--selftest` 自证可失败），真值在执行前冻结于 manifest `e9_ground_truth`。**18 样本（3 UPX 正样本 + 15 未加壳负样本）/ 132 个可判定格 132 命中（100%）/ 12 个不可判定格全部正确弃权（100%）/ 误报 0 / 违规 0 / 异常 0**。证据：`work/evidence_e9_2026-11-15.log`。冻结前修正 2 处**样本标注错误**（S5 go_linux nx、S7 busybox relro，readelf 复核），非判据改动；矩阵首跑因验证器把 family/version 混表而重跑一次，原因与修正已记录在日志尾部。
- **判定强度未放宽**：unknown 只在真值为 undeterminable 时算命中；对不可判定格给确定结论直接记误报；强结论仍守 ≥2 条独立证据（脚本对 <2 条记 violation）。本轮零违规。

---

## 0. 一句话定义

给 rekit 增加第 4 类输出维度：拿到任意 ELF/PE，**只用文件里外部可见的字节特征**，回答四问——
`是否加壳 / 什么编译器 / 是否 stripped / 有哪些加固`，并对 ≥5 个已知样本做到 100% 命中、误报 0。

---

## 1. 现状勘察（本卡写定前的实测事实）

| 维度 | M1/M1.5 已具备 | M2 需要新增 |
|---|---|---|
| 格式分诊 | `cli.detect_format`（ELF magic / MZ+PE\0\0 双校验），退出码 2/3 分层 | 不变，fingerprint 复用 |
| 加固 | ELF：NX/RELRO/PIE/W+X（[elf.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/pack/04_rekit项目源码/rekit/elf.py) 183–214 行） | PE 侧：NX/DYNAMICBASE/HIGH_ENTROPY_VA/CFG（**全新**） |
| 编译器 | PE Rich 头（[pe.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/pack/04_rekit项目源码/rekit/pe.py) `parse_rich_header`） | ELF `.comment`、Go、Rust 指纹；Rich→MSVC 的**误判防线** |
| 壳 | 无 | 全新（UPX 强判 + 常见壳信号级提示） |
| stripped | 有 `.symtab`/`.dynsym` 解析能力，但未落成结论 | 全新（判定 + 口径定义） |

实测（2026-11-15，pyelftools 0.33 / pefile 2024.8.26 / Go 1.27.3 / rustc 1.99.1，见 `work/probe_*.json`）：

- 10 个既有 fixtures **全部无壳**；`dyn_*` 的 `.comment` 均为 `GCC: (Debian 14.2.0-19) 14.2.0`；
- `bin_ls.elf` 与 busybox 官方二进制**无 `.comment`、无 `.symtab`** → 编译器维度**必须答 unknown**，猜 GCC 即为误报；
- **`hello_rust.exe` 带 Rich 头**（rustc 走 MSVC 链接器）→ 「有 Rich ⇒ MSVC」是**错误规则**，M2 必须防这个假阳性；
- `hello_go.exe` 的节名是 `/4`、`/19`…（COFF 长节名偏移）+ 非零 COFF 符号表；Go ELF 带 `.go.buildinfo`/`.note.go.buildid`/`.gopclntab`；
- PuTTY 官方 w64 二进制**无 Rich 头**，节名含 `.00cfg`/`.gxfg`/`_RDATA`。

**环境硬约束（影响权威对拍选型）**【实测 2026-11-15 更新】：本机**原无** `readelf`/`objdump`/`nm`/`file`/`strings`/`upx`/`gcc`/`clang`，无 WSL；当日补装 **upx 5.3.0**（`work/tools/upx-5.3.0-win64`）与 **GNU binutils 2.47**（`work/tools/binutils-2.47`，提供 `objdump/readelf/nm`，免安装 MSYS2 包解压，已登记 sha256/许可）。**仍缺** `file`/`strings`/`gcc`/`clang`。
→ M2 的「权威来源」改为：**pyelftools / pefile（独立第三方实现）＋ 既有 readelf 期望表（2026-11-10 已固化 18 格）＋ 构造命令本身 ＋ `go version -m`**。
局限如实声明：pyelftools 与 rekit 同为 Python 解析同格式，属「实现独立」而非「进程独立」；涉及 UPX 的条目必须用 upx 本体对拍，不得用同源启发式自证。

---

## 2. 范围

### 2.1 做

1. **壳识别（强判）**：UPX（PE/ELF），证据 = 节名 `UPX0/UPX1/UPX2`、`UPX!` 魔数及其偏移、入口跳板形态；输出 `packer.name/confidence/evidence[]`。
2. **壳识别（弱提示）**：ASPack/ASProtect（节名 `.aspack`/`.adata`）、MPRESS（`.MPRESS1/.MPRESS2`）、Themida/WinLicense（节名/版本串）——只输出 `hint` + 命中证据，**不参与达标计数**，且必须能与「none」区分置信度。
3. **编译器指纹**：GCC（`.comment` 逐字 + 版本抽取）、MSVC（Rich `comp.id`→版本映射）、Go（buildinfo/节名/COFF 符号表）、Rust（rustc 路径串/panic 路径/PDB 名）、以及多指纹并存时的仲裁规则（Rust/MSVC、Go/CGO）。
4. **stripped 判定**：ELF = 无 `.symtab`（`.dynsym` 存在不算未 stripped）；PE 明确**不叫 stripped**，输出 `coff_symbols: present/absent`。
5. **加固检测**：ELF 复用现有三态；PE 新增 DllCharacteristics 位 + 导入表特征（GS/CFG 仅作 observed，不做推断）。
6. **统一输出**：`rekit fingerprint <file>`（JSON）+ MCP 工具 `rekit_fingerprint`，与既有 CLI/MCP 双身份一致。

### 2.2 明确不做（写死的边界）

- **不脱壳、不修复、不运行样本**（纯静态；`upx -d` 只在验证脚本里用于生成 ground truth，不进 rekit 代码路径）。
- **不做商业壳家族判定**（VMProtect/Themida 的变种/版本/配置）→ 只到「疑似壳」层级。
- **不做基于熵的单独结论**：熵只作辅助证据，单靠熵不得输出任何 `packer != none`。
- **不做 .NET/CLR、Go/Rust 的深度语义识别**（CLR 头、pclntab 解析属阶段四）→ M2 只做"是否 Go/Rust 编译"的指纹级判定。
- **不引用/搬运 DIE、PEiD、capa 的签名库与规则文件**（净室红线，见 §7）。
- **不改** M1 既有输出格式与 73 条断言；不引入第三方运行时依赖（仍纯 stdlib，pyelftools/pefile 只用于**测试**对拍）。

---

## 3. 子单元拆分、顺序与依赖

| 单元 | 内容 | 覆盖验收 | 依赖 | 粒度/预估 |
|---|---|---|---|---|
| **U0 样本与基准** | 取 upx 5.3.0 → 生成 S9/S10；`upx -d` 往返 sha256 校验；补全 `manifest.json` 全部 sha256；把 7 个达标样本固化进 `tests/fixtures/fingerprint/`（>1MB 的 busybox/go 走 `tests/fixtures/large/` + 下载脚本） | E2/E3 的前置 | 网络（**当前阻塞**） | 从零型 5–8 min（不含下载等待） |
| **U1 骨架与静态维度** | `rekit/fingerprint.py`（纯 stdlib）+ ELF stripped + PE 缓解位 + CLI `fingerprint` 子命令 + MCP 工具注册；输出 schema 冻结 | E1/E7/E8 | 无（现有 10 fixtures 即可） | 扩展型 2–4 min |
| **U2 编译器指纹** | GCC/MSVC/Go/Rust 四条规则 + 仲裁（Rich 假阳性防线） | E4/E5/E6 | U1；样本 S4–S7 本地已就绪 | 扩展型 3–5 min |
| **U3 壳识别** | UPX 强判（签名 + 节名 + 入口跳板，≥2 证据）+ 常见壳弱提示 + 负控 | E2/E3 | U0、U1 | 从零型 5–8 min（风险最高） |
| **U4 汇总与归档** | E9 指标脚本、pytest 扩展、CLI≡模块逐字节、PROGRESS/CHANGELOG 回写、evidence 日志 | E9 | U1–U3 | 扩展型 2–3 min |

**顺序**：`U0（可并行启动，取到 upx 前先做 U1）→ U1 → U2 → U3 → U4`。
依赖图：U1 独立；U2 依赖 U1 的输出 schema；U3 依赖 U1 + U0；U4 收口。
若 U0 长期受阻：**允许先完成 U1/U2/U4（E1、E4–E9）并如实记为「M2 部分完成」，E2/E3 挂起**——不得把无 UPX 样本的 E2/E3 记为达成。

---

## 4. 验收条目（先行写定，全部可证伪）

> 通用口径：**strong 结论（壳/编译器）须 ≥2 条独立证据**；`unknown` 是合法答案但只在 ground truth 为 `undeterminable` 时算命中；ground truth 写在 `work/sample_manifest.json`，**执行前冻结**。

> 验证载体现状（2026-11-15 收口）：E1–E8 的实际载体是 `tests/test_fingerprint.py`（19 条断言）+ `python -m pytest tests -q`；`work/verify_e3.py` 打印 E2/E3 对拍证据表；**E9 载体 `tests/verify_fingerprint.py --all --matrix` 已建立并裁决 PASS**（见 `work/evidence_e9_2026-11-15.log`）。下方各条 `验证` 行中的 `tests/verify_fingerprint.py --case …` 为早期设想的拆分子命令，**实际执行一律以本行给出的 pytest 选择器或 `--all --matrix` 为准**。

### E1 接口契约与零回归
- 判据：`python -m rekit.cli fingerprint <file> --json` 输出含 6 个顶层键 `format/packer/compiler/stripped/mitigations/evidence`；`packer` 必备 `name/confidence/evidence[]`；MCP `tools/list` 出现 `rekit_fingerprint`。
- 验证：`python -m pytest tests -q`（**实测 92 passed / 0 skipped**）；`python -m pytest tests/test_fingerprint.py -q -k "schema or cli_json or mcp_tool_registered"`；10 个 fixtures 的 `python -m rekit.cli <f>` 与模块直调逐字节一致已固化为 `test_cli.py` 断言（无需另跑 cmp）。
- 对拍：改造前快照（执行日先 `git stash` 或复制基线输出到 `evidence/cli_baseline/`）。

### E2 壳识别·UPX 正判（≥2 样本）
- 判据：S9（PE）、S10（ELF）均判 `packer.name == "upx"`，且 `evidence[]` 至少含 2 项且可定位（节名 / 魔数文件偏移 / 入口跳板）。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k upx`（3 条断言），并 `python work/verify_e3.py <work>` 打印 `upx -l` 原始大小/格式、`upx -t` 与 rekit 判定三列对照。
- 对拍：`upx -l -v <sample>` 自报格式与**原始文件大小**（PE 解包不逐字节回原文，故 PE 以 `-l` 原始大小 + `-t` 完整性为准）；**ELF 必须 `upx -d` 往返 sha256 全等**。实测：ELF 全等；PE 解包后大小相同、节表逐项全等、Rich 保留，但头部/对齐填充有 145/14336、1606/1706136 字节差异（UPX 规范化），已登记为 S9/S11 的 caveat。

### E3 壳识别·零误报 + 常见壳弱提示纪律
- 判据：**15 个**未加壳样本（S1–S7 + PuTTY + `minipe.exe`/`minidll.dll`/`minipe_fakerich.exe`/`hello_go`/`rust`/busybox）`packer.name == "none"`，FP = 0；对 UPX 样本不得输出 `aspack/themida/mpress` 等 hint；hint 命中时 `confidence < 0.5` 且 `evidence` 非空。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k packer_none`（含 `test_unknown_single_evidence_never_strong` 单证据不得强判），并 `python work/verify_e3.py <work>` 打印 15 行负样本分母表（逐样本判定 + 证据 + 独立 `bytes.find(b"UPX!")` 交叉扫描）。
- 对拍：发布者构建说明（busybox/PuTTY/Go/Rust 构建命令）+ 独立魔数扫描（脚本内 10 行 `bytes.find(b"UPX!")`，不复用 rekit 代码）。

### E4 编译器指纹·GCC
- 判据：`dyn_pie/dyn_nopie/dyn_static/dyn_execstack/dyn_norelro` → `compiler.family == "gcc"` 且 `version == "14.2.0"`；`bin_ls.elf`/busybox → `unknown`（不得猜 GCC）。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k "gcc"`（正判 + 无 `.comment` 必 unknown 两条）；脚本用 pyelftools 独立读 `.comment` 生成期望值，逐字比对。
- 对拍：pyelftools 读 `.comment`（独立实现）+ 11-10 已固化的 readelf 期望表（`evidence_readelf_authority.log`）。

### E5 编译器指纹·MSVC（含 Rich 假阳性防线）
- 判据：`cli-64.exe` → `msvc` 且 `rich.pairs == 11`、build 号映射与 11-12 结论一致；`hello_rust.exe`（带 Rich）→ `rust` **不得**为 `msvc`；`minipe.exe`/`minidll.dll`（自构造无 Rich）→ `unknown`。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k "msvc or rich"`（正判/仲裁/自造负控三组）。
- 对拍：pefile `PE.__data__` + 手工 Rich dump（11-12 evidence）+ rustc 构造命令。

### E6 编译器指纹·Go / Rust
- 判据：`hello_go.exe`/`hello_go_linux` → `go` 且 `version == "1.27.3"`；`hello_rust.exe` → `rust` 且证据含 rustc 标记（路径串或 `rustc`/`library/std` 字样），且 `compiler.family` 唯一不并列。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k "go_pe_and_elf_version or rich_is_not_msvc or family_is_single_valued"`。
- 对拍：`go version -m <file>`（Go 官方工具，权威）；Rust 侧以 `rustc --version` + 构造命令为权威（无官方 `-m` 等价物，属已知局限，须在产出中标注）。

### E7 stripped 判定
- 判据：ELF `bin_ls.elf`/busybox → `stripped=true`（reason 引用"无 .symtab"）；`dyn_*`/`hello_go_linux` → `false`；PE 一律输出 `stripped="n/a"` + `coff_symbols`（`cli-64.exe`=absent，`hello_go.exe`=present）。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k "stripped or coff_symbols"`；断言不得把 `.dynsym` 的缺席/存在当作 stripped 依据。
- 对拍：pyelftools 节表遍历（独立实现）；`hello_go.exe` 的 `PointerToSymbolTable != 0` 由 pefile 交叉确认。

### E8 加固检测（ELF 18 格 + PE 位）
- 判据：ELF 6 样本 × {NX, RELRO, PIE} = 18 格与 11-10 期望表全等；PE 4 样本（cli-64/minipe/minidll/putty）× {NX_COMPAT, DYNAMICBASE, HIGH_ENTROPY_VA, GUARD_CF} 逐位与 pefile 全等（实测均为 `0x8160`，CFG=0）。
- 验证：`python -m pytest tests/test_fingerprint.py -q -k "mitigations_match_readelf_table or pe_mitigation_bits"`（18 格 + PE 位）；E9 矩阵另按样本逐格复核（12 个加固弃权格亦计入）。
- 对拍：11-10 readelf 期望表 + pefile `DllCharacteristics`（WinNT.h 位定义）。

### E9 汇总指标与证据固化（完成标准裁决）
- 判据：以 `manifest.json` 全量为分母，输出混淆矩阵：`命中率 = 命中格 / 可判定格 = 100%`，`误报 = 0`（误报 = 输出非 none/non-unknown 结论但与 ground truth 不符）；**E2/E3 未达成则本条目不得判 PASS**。
- 验证：`python tests/verify_fingerprint.py --all --matrix --out work/evidence_e9_2026-11-15.log`，同时 `python -m pytest tests -q` 全绿。**实测：PASS**——18 样本 / 132 可判定格全中 / 12 弃权格全对 / 误报 0 / 违规 0 / 异常 0；`--selftest` 已验证翻转真值会使矩阵 FAIL。
- 对拍：矩阵内每格必须能追溯到对应 E 条目的证据行（脚本输出 `sample × dim → verdict → authority` 三列）。

---

## 5. 样本候选清单

> 「可获取」列为 2026-11-15 本机实测；`sha256` 见 `work/sample_manifest.json`。
> 达标集 = S1–S7（7 个，覆盖 GCC/MSVC/Go/Rust/undeterminable × 有壳无壳 × stripped/非 stripped）；S9/S10 是 **E2/E3 的必需项**（当前阻塞）。

| ID | 样本 | 来源 | 可获取 | 预期状态（实测/已知） | 权威判定方式 | 许可证 / 再分发 |
|---|---|---|---|---|---|---|
| S1 | `dyn_pie` | 自构造 `tests/hello.c` + gcc 14.2.0 | ✅ 已有 | 无壳 / gcc 14.2.0 / 未 stripped / PIE + **Partial RELRO**（gcc 默认无 now，U1 实测修正）+ NX | 构造命令 + `.comment` | 自有 / ✅ |
| S2 | `bin_ls.elf` | Ubuntu coreutils `/bin/ls` | ✅ 已有 | 无壳 / **compiler=undeterminable**（无 `.comment`）/ stripped / PIE+FullRELRO+NX | 发行版包 + pyelftools | GPL-3.0 / ✅ 保留许可 |
| S3 | `cli-64.exe` | 既有 fixture（MSVC） | ✅ 已有 | 无壳 / MSVC（Rich 11 对）/ 无 COFF 符号 / NX+ASLR+HEVA / 无 CFG | Rich 解码 vs pefile | **出处未明 / ❌ 仅本地** |
| S4 | `hello_go.exe` | 本机 `go build`（go1.27.3） | ✅ 已构造 | 无壳 / go 1.27.3 / COFF 符号 present / `/nn` 长节名 / TS=0 | `go version -m` | 自有 / ✅ |
| S5 | `hello_go_linux` | `GOOS=linux go build` | ✅ 已构造 | 无壳 / go 1.27.3 / 未 stripped / 静态无 interp | `go version -m` | 自有 / ✅ |
| S6 | `hello_rust.exe` | `rustc 1.99.1 -O` | ✅ 已构造 | 无壳 / rust（MSVC 后端，**带 Rich**）/ 无 COFF 符号 / NX+ASLR+HEVA / **version=None**（rustc 只嵌 `rustc/<40位commit>`，U1 实测） | `rustc --version` + commit 串 | 自有 / ✅ |
| S7 | busybox 1.35.0 musl | busybox.net 官方 binaries | ✅ 已下载（1,131,168 B） | 无壳 / **undeterminable** / stripped（10 节，无 `.symtab`）/ 静态 | 官方页 + pyelftools | GPL-2.0 / ✅ |
| S8 | PuTTY w64 | the.earth.li/latest/w64 | ✅ 已下载（1,706,136 B） | 无壳 / **无 Rich** / NX+ASLR+HEVA / `.00cfg`/`.gxfg` | 实测 + 构建说明【待核实】 | MIT / ✅ |
| S9 | `upx_cli-64.exe` | upx 5.3.0 压缩 S3 | ✅ 已生成（9,728 B） | **upx** / 原 MSVC 19.29（Rich 保留）/ packed / NX+ASLR+HEVA | `upx -l` 报 `win64/pe`+原始 14336；`-t` OK | UPX GPL-2.0+ / ❌ 派生自 S3，仅本地 |
| S10 | `upx_dyn_pie` | upx 5.3.0 交叉压缩 S1 | ✅ 已生成（6,124 B） | **upx** / 编译器 undeterminable / stripped unknown / 加固 unknown | `upx -l` 报 `linux/amd64`；`-t` OK；`-d` 往返 sha256 与 S1 全等 | 自有 / ✅ |
| S11 | `upx_putty-64bit.exe` | upx 5.3.0 压缩 S8 | ✅ 已生成（960,664 B） | **upx** / undeterminable（无 Rich）/ NX+ASLR+HEVA | `upx -l` 报 `win64/pe`+原始 1706136；`-t` OK | MIT / ✅ 可对外 |

**新增说明**
- 未纳入 7-Zip（`7-zip.org` 302 → GitHub release-assets，本机不可达；LGPL + unRAR 限制）、Notepad++（同为 GitHub 资产域，超时）。
- 不纳入任何恶意样本或来源不明样本（授权边界红线）。
- S3 出处未明 → 按「不可再分发」处理：只留在本地 fixtures，不进任何对外产物；若后续 M2 需要公开样本集，用 S9 派生自 S1 的路径替代。

---

## 6. 缺口与风险登记

| 编号 | 缺口/风险 | 影响 | 处置 |
|---|---|---|---|
| G1 | ~~无 upx 工具~~ **已关闭（2026-11-15）** | 用户上传官方包的 zip/exe sha256 与 `upx --version` 已登记（manifest.tools） | 装在 `work/tools/`，不进 pack |
| G2 | 无 `readelf/objdump/nm/strings/file`、无 gcc/clang | 无法做进程级独立对拍；无法本地造 ELF GCC 新样本 | 用 pyelftools/pefile + 既有 readelf 期望表；产出中如实标注「实现独立非进程独立」 |
| G3 | ~~upx.exe 能否交叉压缩 ELF~~ **已关闭（2026-11-15）** | — | 实测可：`upx -l upx_dyn_pie` → `linux/amd64`，`upx -d` 往返 sha256 与 S1 全等 |
| G8 | **upx.exe 不处理非 ASCII 路径**（本工作区路径含中文时读不到文件） | 自动化脚本若直接传中文路径会静默失败 | 一律在 ASCII 临时目录（`%TEMP%\rekit_upx`）内压缩/解包，再拷回 |
| G9 | **UPX ELF 移除节表（e_shnum=0）→ `elf.parse` 抛 IndexError** | M1 解析器不覆盖加壳态 | 指纹层已降级处理：`packer=upx` 仍可判（魔数 + 节表移除两条证据），`compiler/stripped/mitigations` 一律 unknown，不猜测；**未改 M1 解析器**，以免动既有断言 |
| G4 | Rust 无官方「版本自述」接口 | E6 的 Rust 版本只能靠字符串推断 | 只要求 `family=rust`，版本仅作 optional，不纳入达标格；构造命令留证 |
| G5 | PuTTY 构建工具链未核实（无 Rich） | 不能作为 MSVC 正样本 | 降级为「未加壳负控」，编译器维度标 undeterminable |
| G6 | 熵阈值易误伤（Go/Rust 静态二进制熵高） | E3 误报风险 | 硬规则：熵不得单独支撑强判；Go/Rust 指纹优先级高于熵 |
| G7 | 自构造 PE（minipe/minidll）DllChar 是伪造的 `0x8160` | 加固维度对自造样本不可信 | manifest 标注「构造器写入值」，E8 的 PE 格以 cli-64/putty 为准 |

---

## 7. 净室纪律（M2 的可证伪性保障）

1. **只看产物，不看实现**：不阅读 UPX/DIE/PEiD 的源码与签名库，不复制其规则表；规则来源限定为 PE/ELF 规范 + 公开格式文档 + 本卡登记的实测观察。
2. **每条强判 ≥2 独立证据**（例：UPX = 节名 + 魔数偏移；MSVC = Rich + 节表/导入风格；GCC = `.comment` + 符号表形态）。
3. **禁止「猜」**：证据不足输出 `unknown`，并在 `evidence` 里写明缺哪条证据；`unknown` 不算误报、也不算命中（除非 ground truth 为 undeterminable）。
4. **误报口径**：分母 = manifest 全量样本；任何 `packer != none` 或 `compiler != unknown` 的错误结论记 1 次误报。达标 = 误报 0 且 E2/E3 PASS。
5. **样本先冻结后执行**：`manifest.json` 的 dims 在执行前写定；执行中若发现 ground truth 写错，走 CHANGELOG 变更流程，不得直接改表。

---

## 8. 完成标准映射（CHARTER M2）

> 原文：对 ≥5 个已知样本识别率 100%，误报 0。

| 原文要素 | 由谁裁决 |
|---|---|
| ≥5 个已知样本 | S1–S7（7 个）→ E9 分母 |
| 识别率 100% | 4 维 × N 样本逐格比对 → E4–E8 + E9 矩阵 |
| 误报 0 | E3（无壳负控）+ E4/E7（undeterminable 不得猜）+ E9 |
| 「壳识别」要素 | E2/E3（**当前阻塞于 G1**） |

**结论前置**：G1 未解 → M2 不得宣布完成；可交付「U1/U2/U4 完成 + E2/E3 挂起」的部分完成报告。

---

## 9. 基线纪律与回写

- 粒度：U1 扩展型 2–4 min；U3 从零型 5–8 min；当日单白银。
- 返工计数：实现或验证脚本因缺陷修一次 = 1 返工；≥3 次 → 次日降档（沿用 11-13 条款）。
- 回写：PROGRESS 一行（完成项 + 耗时 + 返工 + 规则编号）；新规则续编 R33+；验收标准若变 → CHANGELOG（旧→新/原因/影响）。
- 证据归档：`learning/artifacts/<执行日>/`（TASK + verify 脚本 + `evidence_fingerprint_*.log` + matrix.json + 知识卡）。

---

## 10. 本卡的工作文件

| 文件 | 用途 |
|---|---|
| `work/probe_fixtures.py` / `probe_fixtures.json` | 10 个既有 fixtures 的 pyelftools/pefile 实测快照 |
| `work/probe_samples.py` / `probe_samples.json` | busybox/PuTTY/Go/Rust 样本实测快照 |
| `work/sample_manifest.json` | 样本登记表（sha256、来源、许可、ground truth、阻塞状态） |
| `work/samples/` | 已下载/已构造的候选样本与 `src/hello.go`、`src/hello.rs` |

### U1 落地清单（2026-11-15）

| 文件 | 内容 |
|---|---|
| `pack/04_rekit项目源码/rekit/fingerprint.py` | 指纹层实现：`detect_format/detect_packer/elf_compiler/pe_compiler/analyze/render_text/main`（纯 stdlib） |
| `pack/04_rekit项目源码/rekit/cli.py` | 新增 `fingerprint` 手动短路（既有位置参数路径不变） |
| `pack/04_rekit项目源码/rekit/mcp.py` | 新增工具 `rekit_fingerprint`，与 CLI 同源 |
| `pack/04_rekit项目源码/tests/test_fingerprint.py` | 19 条断言（E1 ×3、E3 负控 ×2、E2 ×3、E4–E8 ×11） |
| `pack/04_rekit项目源码/tests/samples/fingerprint/` | 固化样本：hello_go.exe / hello_go_linux / hello_rust.exe / busybox 1.35.0（约 6 MB；放 `samples/` 而非 `fixtures/`，以保持 `fixtures` 恰 10 文件的既有断言不变） |
| `pack/04_rekit项目源码/tests/samples/fingerprint/upx/` | UPX 正样本副本：upx_cli-64.exe（9,728 B）/ upx_putty-64bit.exe（960,664 B）/ upx_dyn_pie（6,124 B），sha256 见 manifest S9–S11 |
| `work/tools/upx-5.3.0-win64/` | UPX 5.3.0 工具（**不在 pack 内**）；zip sha256 `d127996c…a9705`、`upx.exe` sha256 `ff30a651…d302b` |
| `work/verify_e3.py` | E2/E3 证据生成器：打印 upx 版本/哈希、正样本 `-l`/`-t` 对拍表、15 负样本零误报表、往返验证结论 |
| `work/evidence_e2e3_2026-11-15.log` | E2/E3 实测证据日志（含 PE 往返 145/1606 字节差异的逐项说明） |
| `work/tools/binutils-2.47/` | GNU binutils 2.47（objdump/readelf/nm，MSYS2 mingw64 包解压，**不在 pack 内**）；objdump sha256 `c56162ea…473a8`，许可 GPL-3.0-or-later 等 5 项见 `share/licenses/` |
| `work/verify_objdump.py` | objdump 对拍证据生成器：打印版本/路径、`objdump -p` 原始导出片段、EAT 与名字→ordinal 三列对照 |
| `work/evidence_objdump_2026-11-15.log` | 全量 pytest（92 passed / 0 skipped）、parser-only 17 passed、minidll 对拍全等的留档 |
| `work/run_pytest.ps1` | 注入 binutils PATH 后跑全量的封装脚本（已打开的终端未继承新 PATH 时用；不做 skip 降级） |
| `pack/04_rekit项目源码/tests/verify_fingerprint.py` | E9 一次性验收载体：读 manifest `e9_ground_truth`、跑四维矩阵、逐格裁决并归因；`--selftest` 自证可失败 |
| `work/evidence_e9_2026-11-15.log` | E9 矩阵完整输出（18 样本逐格矩阵 + packer/compiler/stripped/COFF/mitigations 分项混淆矩阵 + 汇总 + 首跑/重跑说明） |
