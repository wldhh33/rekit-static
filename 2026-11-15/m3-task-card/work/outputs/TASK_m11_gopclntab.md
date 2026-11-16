# M11 收口：`.gopclntab` 作为 Go 函数边界的 declared 级种子源

> 日期：2026-11-16 ｜ 对应要求：M11 六条（性质定位 / 种子分级 / 独立验证 / 覆盖率拆分 / ELF+PE 双侧 / 下界升格清单）
> 证据：`work/evidence_m11_coverage.json`、`work/evidence_m11_extra_go.json`、
> `work/evidence_m11_pytest.log`、`work/evidence_m11_verify.log`
> 代码：`rekit/gopclntab.py`（新）、`rekit/recdesc.py`（`_add_gopclntab` / `_seed_add(end=)` /
> `seed_stats`）、`tests/tools/gofunclist.go`（独立参照）、`tests/verify_gopclntab.py`、`tests/test_gopclntab.py`

---

## 1. 性质：declared 级，不是调试信息

| 判断 | 依据 |
|---|---|
| 运行时必需表 | `runtime` 用 pclntab 做 PC→函数/行号查询与栈展开；条目缺失会使 `runtime.findfunc` 失效，程序不可正常运行 |
| 不是调试信息 | `-ldflags "-s -w"`（stripped）删除 `.symtab`/`.debug_*`，**不会**删除 pclntab；本仓库 2 个 stripped Go 样本仍带完整表（8,908 / 8,895 条） |
| declared 级 | 入口地址与函数结束由链接器写死进文件，不是字节模式推断；因此与 `entry` / `symtab_func` / `eh_frame_fde` / `pdata` / `export` 同级，不进 heuristic |
| 覆盖边界（必须一起说） | **只覆盖 Go 函数**：汇编 stub、C 代码、外部目标文件函数不保证在内；缺失≠不存在 |

链接器在表内写入了 3 个**非函数**条目，一律标记并排除（不参与种子、不参与入口/结束对拍）：
`go:buildid`（PE 把 build id 数据放 `.text` 开头）、`go:textfipsstart`、`go:textfipsend`。
`type:.eq.*` / `type:.hash.*` / `go:struct{...}.*` 是编译器/链接器生成的**真实代码**，仍按函数处理。

---

## 2. 版本支持范围（不支持的答 unknown，不猜）

| magic | Go 版本 | header 字段 | functab 布局 | `_func` nameOff 位置 | 本仓库状态 |
|---|---|---|---|---|---|
| `0xFFFFFFF1` | go1.20+ | magic+pad×2+minLC+ptrSize，然后 `nfunc,nfiles,textStart,funcname,cu,filetab,pctab,pcln`（后五项为相对表头的偏移，宽 ptrSize） | `(2·nfunc+1)` 个 **uint32**：nfunc 条 `{entryoff,funcoff}` + 1 个 endoff 哨兵；entry VA = textStart + entryoff；**funcoff 相对 pclnOffset** | `funcoff+4` | **实测 go1.27.3**，与 `debug/gosym` 对拍 entry/end/name 全等 |
| `0xFFFFFFF0` | go1.18–1.19 | 同 go1.20+ | 同（uint32 偏移） | `funcoff+4` | **无实测样本**：按规范同构实现，未经 `debug/gosym` 对拍 → 结果带「未验证」warning |
| `0xFFFFFFFA` | go1.16–1.17 | **无 textStart**（`nfunc,nfiles,funcname,cu,filetab,pctab,pcln`） | `(2·nfunc+1)` 个 **ptrSize** 宽字段，entry 为**绝对 VA** | `funcoff+ptrSize`（首字段是 uintptr entry） | **无实测样本**：同上，带「未验证」warning |
| `0xFFFFFFFB` | go1.2–1.15 | 旧布局（functab 紧接 header、无 funcnametab 偏移语义） | — | — | **未实现** → `status="unknown"`，`reason` 明写版本与原因 |
| 其它 magic | — | — | — | — | `status="unknown"` + 具体错误 |

两处与「按规范猜」不同、必须写清的细节：

- **textStart 可能未重定位**：本机 go1.27.3 实测 header.textStart = 0。Go 官方 `debug/gosym/pclntab.go`
  的做法是不读该字段、用调用方给的 `.text` 起点（原文 *"use the start PC instead of reading from the table,
  which may be unrelocated"*）。本模块同此：为 0 或不在 `.text` 内 → 取 `.text` 基址并记 warning；
  这是**与官方一致**的行为，不算猜。
- **「整表校验通过才采用」**：pad=0、ptrSize∈{4,8}、nfunc∈[1,2e6]、偏移链单调不越界、
  functab 不越界、入口严格递增且落在 `.text`、funcoff 落在 functab 之后、末条哨兵大于最后入口。
  任一不过 → 该候选**整表** unknown，不半信半疑地采用部分条目。

「没有表」与「表在但坏了」分开：无任何候选通过 pad/ptrSize 粗筛 → `missing`（普通 C/C++/Rust 二进制）；
有候选过粗筛但校验失败 → `unknown` + 具体 reason。15 个非 Go 样本复查：ok 4 / missing 11 / unknown 0。

文件头 `CAVEATS` 7 条（运行时必需表、只覆盖 Go、版本支持与未验证分支、textStart、整表校验、
funcoff 相对 pclnOffset、标记排除）+ `recdesc.CAVEATS` 第 8 条同步。

---

## 3. 种子来源分级：逐源单列，不合并、不当启发式

`recdesc` 的 declared 桶按来源分别计数（R99）：

```
authoritative: entry | symtab_func | dynsym_func | eh_frame_fde | pdata | export | gopclntab
heuristic    : prologue（仅字节/opcode 模式）
derived      : call 直接目标（不是种子）
```

两个口径同时给：
`declared_by_source`（**inclusive**：一个种子被多源声明则各源都计 1）与
`declared_only_by_source`（**exclusive**：仅被该源声明）。绝不汇总成「已声明 N 个」一个数。
`gopclntab` 的 count 已扣除标记条目（`is_marker` 跳过、不进 seeds）。

本轮 4 个 Go 样本（inclusive；剥离标记后）：

| 样本 | entry | symtab_func | pdata | gopclntab | 标记（排除） | 表内 nfunc |
|---|---|---|---|---|---|---|
| `elf_medium_synth_go_stripped`（ELF，stripped） | 1 | — | — | **8,906** | 2 | 8,908 |
| `pe_medium_synth_go_stripped.exe`（PE，stripped） | 1 | — | 7,152 | **8,892** | 3 | 8,895 |
| `hello_go_linux`（ELF，未 strip） | 1 | 1,797 | — | **1,794** | 0 | 1,794 |
| `hello_go.exe`（PE，未 strip） | 1 | — | 1,587 | **1,884** | 0 | 1,884 |

exclusive 口径（新增了多少**只有它能给**的种子）：ELF 合成样本 `gopclntab` 8,905 + `entry` 1；
PE 合成样本 `gopclntab` **1,739**（其余 7,152 已由 `.pdata` 声明、1 条与 entry 重合）。
未启用时（`gopclntab=False`）四个样本的 decode 输出与 M9/M10 逐条相同（见 §4 的 `repro`）。

---

## 4. 独立验证：官方解析器 + objdump 边界，两方对拍

不拿我方解析结果自证。参照实现 `tests/tools/gofunclist.go` 用 Go 标准库 `debug/elf`、`debug/pe`、
`debug/gosym` 独立取函数清单（PE 的 textAddr 从 `.text` 节算出 `ImageBase+VirtualAddress`），
`tests/verify_gopclntab.py` 逐条对拍：

| 样本 | 我方 nfunc | 官方 nfunc | entry 集合相同 | 仅我方 | 仅官方 | end 差 | name 差 | objdump 边界：entry 非边界 / end 非边界 |
|---|---|---|---|---|---|---|---|---|
| ELF 合成 | 8,908 | 8,908 | 是 | 0 | 0 | **0** | **0** | **0 / 0**（923,970 条指令、bad 1） |
| PE 合成 | 8,895 | 8,895 | 是 | 0 | 0 | **0** | **0** | **0 / 0**（925,712 条指令、bad 2） |

- **不一致分类桶已就位且为空**：`only_ours`（我方多解）/ `only_official`（我方漏解）/
  `end_diff`（结束地址分歧）/ `name_diff`（名字分歧）四类分别计数，本轮全 0。
- **标记区间单列**：objdump 在标记区间内的指令（ELF 33 条、PE 98 条）不计入 entry/end 边界统计；
  PE 的 `go:buildid` 数据确实被 objdump 当指令列出（见 §7 的 `outside_range` 40 条）。
- **另一类「两源不一致」单独归因（不是解析分歧）**：`.pdata` 的 `EndAddress` 与 gopclntab 的
  「下一入口」在 PE 合成样本上 **7,139/7,152 个函数不同**，全部是 `pdata < gopclntab`，
  差 1..31 字节，13 个一致 —— 归因为 MSVC/链接器在函数尾写的**对齐填充**，不是边界错误；
  `recdesc` 用 `end_by_source` 分别记两个 end、`end_conflicts` 单列（`by_pair` / `delta_hist`），
  ELF 侧无第二来源，冲突 0。
- **负控（可失败自证，5 项全部检出）**：篡改临时副本后必须 `status="unknown"` 且 `funcs==[]` ——
  magic→`0xFFFFFFFB`、`nfunc=0`、第 2 个 entryoff=0（非严格递增）、首个 funcoff=0（落在 functab 之前）、
  `textStart=0xDEADBEEF`（不在 .text）；未篡改副本仍 ok。

---

## 5. 覆盖率变化拆分：种子新增 vs 解码本身

口径不变（R91）：分母 = 外部 objdump 同节指令数；分子 = 同址同长。

| 样本 | 关闭 gopclntab | 启用 | 变化 | 分子增量 | `matched_lost` | `same_addr_len_changed` | 我方旧数字复现 |
|---|---|---|---|---|---|---|---|
| ELF 合成 | 76,168 / 923,970 = **8.2436%** | 748,093 / 923,970 = **80.9651%** | **+72.7215pp** | +671,925 | **0** | **0** | 是 |
| PE 合成 | 738,852 / 925,712 = **79.8145%** | 750,109 / 925,712 = **81.0305%** | **+1.2160pp** | +11,257 | **0** | **0** | 是 |
| `hello_go_linux`（ELF 未 strip） | 138,224 / 171,832 = 80.4414% | 138,292 / 171,832 = 80.4810% | +0.0396pp | +68 | **0** | **0** | 是（M9 行） |
| `hello_go.exe`（PE 未 strip） | 143,525 / 182,854 = 78.4916% | 147,351 / 182,854 = **80.5836%** | **+2.0920pp** | +3,826 | **0** | **0** | 是（M9 行） |

**拆开的两部分**

- **解码本身带来的：0。** 判据是（a）四个样本 `matched_lost = 0`（旧可达域内没有任何一条曾匹配的指令丢失）、
  （b）`same_addr_len_changed = 0`（旧可达域内没有任何一条同址指令长度变化）、
  （c）关闭 gopclntab 时四个样本的分子与 M9/M10 逐条相等（`repro=True`，含 ELF 76,168、PE 738,852、
  M9 行 138,224 / 143,525）。解码器对这些字节的行为没有变。
- **种子来源新增带来的：全部。** +671,925 / +11,257 / +68 / +3,826 全部是**新进入可达域**的指令；
  新增可达域由 gopclntab 声明的函数入口（及函数内顺序/分支可达指令）构成。

**措辞**：这是**可达域扩大**，不是「解码质量提升」。8.24% 那个数字从来不代表解码器对 Go ELF 只能解 8%，
而是「只有 `e_entry` 一个种子时能走到的范围」；现在 ELF 从 1 个入口扩到 8,906 个 Go 函数，
覆盖率随之上升，但**新增域内的解码质量并没有被独立度量过**——那里的正确性由 §4 的
objdump 同址同长对拍（`len_conflict=0`、`ours_only=1`）间接覆盖，不是被这组数字直接证明。

---

## 6. ELF 与 PE 两侧：PE 在已有 `.pdata` 时的真实增量

| 问题 | ELF | PE |
|---|---|---|
| 表如何定位 | 独立节 `.gopclntab`（`elf_section:.gopclntab`） | 无独立节名，`.rdata` 内按 magic 扫描并整表校验（`magic_scan@0x3a1180`） |
| 原声明来源 | 无（只有 `e_entry`；该样本 stripped，无 `.symtab/.dynsym/.eh_frame`） | `.pdata` 7,152 个 BeginAddress + entry |
| gopclntab 增量（函数） | 8,905 个独占种子 | **1,739** 个独占种子（∩ `.pdata` = 7,152） |
| gopclntab 增量（覆盖率） | **+72.7215pp** | **+1.2160pp**（+11,257 条；`.pdata` 之外的那 1,739 个函数） |
| 真实 Go PE（`hello_go.exe`） | — | `.pdata` 1,587 → gopclntab 1,884：**+3,826 条 / +2.0920pp** |

**直说**：PE 侧 `.pdata` 已经覆盖了绝大多数 Go 函数，gopclntab 带来的增量是
**1,739 个函数 / 11,257 条指令 / +1.22pp**（真实样本上 +2.09pp）——不是十倍级的改变，
但也不是零：`.pdata` 里没有、gopclntab 里有的那部分函数（闭包生成体、`type:.eq.*` 之类）此前整函数不可见。
反方向的对照同样有信息：`hello_go_linux` 未 strip、`.symtab` 已有 1,797 个 STT_FUNC，gopclntab 只多 +68 条（+0.04pp）
—— 说明增量大小由「已有哪些声明来源」决定，不能跨样本套用。

---

## 7. 剩余 19% 的归属（不是解码缺陷）

ELF：`objdump_only` 175,877 = **填充全 `cc`/`90` 149,225（16.15%）** + **函数范围内未静态达 26,652（2.88%）** + 范围外 0；
PE：175,603 = 148,861（16.08%） + 26,702（2.88%） + **范围外 40（0.004%）**。

- 范围外 40 条位于 `.text` 最前 40 字节，是 `go:buildid` 的数据被 objdump 当指令列出 —— 反证标记排除生效。
- 范围内未达的 26,652/26,702 条是函数内部**间接跳转目标/跳转表目标**（R45 不跟随、`switchcand` 默认关闭），
  以及紧随其后的对齐字节；因此**「Go 函数域内的指令覆盖率」仍是下界**，缺口 2.88pp。
- 表尾与节尾相差 16 字节对齐填充（两样本一致），末条函数 end 取表内哨兵（ELF `0x75a4a1`、PE `0x35da41`）。
- 我方多解 1 条/样本：ELF `0x55177f`、PE `0x152edf`，均为单字节 `ret`（`c3`）落在 objdump 某条指令内部，
  计 `ours_only` 不进分子；`len_conflict = 0`。

---

## 8. M9/M10 因种子缺失标为下界的数字：升格 / 仍为下界

### 可以升格（给出新数与依据）

| M9/M10 数字 | 原口径 | 现在 | 依据 |
|---|---|---|---|
| Go ELF 覆盖率 **8.24%**（76,168/923,970） | entry 可达域，下界 | **80.9651%**（748,093/923,970） | gopclntab 提供 8,906 个函数入口；仍是「可达域」但域=Go 函数域 |
| Go PE 覆盖率 **79.81%**（738,852/925,712） | `.pdata` 可达域 | **81.0305%**（750,109/925,712） | `.pdata` 之外补 1,739 函数 / +11,257 条 |
| M10「seed_missing 8,059 个函数（833,323 条）」 | 无种子 | 该批函数入口**全部由 gopclntab 声明**；`seed_missing` 类在本样本归零 | §3 exclusive 8,905 |
| M10「partial 846（ELF）/ 764（PE）」的函数结束不可判定 | 无声明 end | 有声明 end → **definite 边** ELF 0→172,987、PE 167,403→171,802 | `end_by_source`；`edges_definite` |
| M10「speculative 边 19,198 / 2,662」 | 无边界推断 | **0 / 0**（全部升为 definite） | 同上 |
| M9 合并 25 样本 **75.8866%**（11,620,527/15,313,023） | 含 2 个 8%/80% 的 Go 合成样本 | **推算 80.3734%**（12,307,603/15,313,023） | 4 个 Go 样本分子 +671,925/+11,257/+68/+3,826 实测；**其余 21 个可测样本与 4 个无 `.text` 样本沿用 M9 数据，未重跑全量**，故为推算值 |

> **M12 补记（2026-11-16）**：上表最后一行的「合并 25 样本 80.3734%」原为**推算值**。M12 已把 25/25 样本
> 全部重跑（无跳过，353.5s），实测 **12,307,603/15,313,023 = 80.3734%**，与推算**差 0**；推算前提
> （其余 21 个可测样本逐条不变）被实测证实——17 个非 Go 可测样本 delta 全为 0。**推算值就此作废**，
> 读者以 `work/evidence_m12_ledger.json`（唯一权威）与 `work/outputs/NUMBERS_LEDGER.md`（人读镜像）为准。

### 仍然是下界（gopclntab 帮不上或不适用）

| 数字 | 为什么仍是下界 |
|---|---|
| `strxref` unique 字符串 **2,266** / 引用点 **3,732** | 外部 objdump 证明未解码代码里还有 **5,039 个引用点 / 276 条字符串**；主因 busybox（0.12%）等**非 Go** 样本，gopclntab 不覆盖 |
| VEX/EVEX 弃权 **206,541** 点（11 样本，`decoder_defect=0`） | 非 Go 样本为主因；Go 样本本轮 `abstains=0`，不受益也不受损 |
| `switchcand` 的 `skipped`（cc1 / lto1 / gdb） | 预算问题，与种子无关；本轮未重测，函数域扩大后结果**未验证**，不宣称不变 |
| 旧 18 样本 **62.13%**、新 7 样本 **76.88%** | 其中 5 个真实新样本与多数旧样本是 C/C++/Rust，无 pclntab；Go 相关行已在 §5 列出 |
| M8 `paramdecl`（DWARF 形参 12,272/3,530/37,891） | 形参信息不在 pclntab 里，完全无关 |
| **Go 函数域内**指令覆盖（缺口 2.88%，26,652/26,702 条） | 间接跳转/跳转表目标不可静态跟随（R45）→ 函数域覆盖率仍是下界（例：`runtime.typesEqual` 171/721，缺口紧跟 `jmp [rcx+rdx*8]`） |

---

## 9. 回归与证据

- pytest：**463 passed**（M10 的 447 + `tests/test_gopclntab.py` 16），耗时 69.84s，0 failed/skipped
  → `work/evidence_m11_pytest.log`。
- verify：**16 个脚本全部 EXIT=0**（新增 `verify_gopclntab.py`；`verify_fingerprint.py` 需 `--all --matrix`），
  `FAILED_COUNT=0` → `work/evidence_m11_verify.log`。
- 本文件 §5–§7 数字来自 `evidence_m11_coverage.json`（A/B + 余量分类；其中 `objdump_only_breakdown.total`
  原字段误用 `len(obj)-len(ours)` 少算 1 条，已更正为 `sum(classes)` 并写 `total_note`），
  §5 后两行与 §8 的 25 样本推算来自 `evidence_m11_extra_go.json`。

## 10. 规则

- **R99**：declared 级来源必须**逐源单列**（inclusive + exclusive 两口径），不得合并成一个不区分的
  「已声明」计数；`gopclntab` 与 `entry`/`symtab_func`/`eh_frame_fde`/`pdata`/`export` 并列，不进 heuristic。
- **R100**：报告覆盖率变化必须拆成「种子来源新增（可达域扩大）」与「解码本身」两部分；
  「解码本身」用 `matched_lost` + `same_addr_len_changed` + 旧数字复现三项判据，任一非 0 不得声称 0。
- **R101**：新增 declared 来源必须双源独立对拍（官方解析器 + 外部 objdump 边界），不一致单列归因；
  未拿到样本的版本分支必须标「未验证」并在结果带 warning，未知版本必须答 `unknown`，不得按规范实现冒充已验证。
