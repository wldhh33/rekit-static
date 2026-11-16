# M16 Spec — 非字符串数据引用层（rekit/datarefs.py）

日期：2026-11-16
目标：补上 funcreport 唯一缺的来源层——**全局/静态数据对象及其指令引用点**。
本层只回答「文件里声明了哪些数据对象、哪些已解出指令点到了它们、凭什么这么归因」，
不推断语义（不猜类型名、不猜数组长度、不猜 ABI）。

## 1. 数据对象定义（先写后做，逐类拒收可计数）

### 1.1 可扫描节（数据节）

| 格式 | 条件 | 说明 |
|---|---|---|
| ELF | `SHF_ALLOC` 置位、`SHF_EXECINSTR` 未置位、`sh_size>0` | 含 `SHT_NOBITS`（`.bss`）；排除 `.text`、非 alloc 节（`.debug_*`/`.symtab`） |
| PE | `IMAGE_SCN_MEM_READ` 置位、`IMAGE_SCN_MEM_EXECUTE` 未置位、`vsize>0`，且 `IMAGE_SCN_MEM_DISCARDABLE` 未置位、节名不以 `.debug` 开头 | 含 `rawsize==0` 的 `.bss`；排除 `.text`、`.reloc`、`.debug_*` |

TLS 节（ELF `SHT_TLS`/节名 `.tdata`/`.tbss`，PE 节特征含 TLS 位）**不进数据节**：
TLS 地址是线程局部偏移，不是文件地址，归因会全错；声明落在 TLS 节记
`tls_section` 拒收类。

`.bss` 允许：地址范围可声明、文件字节为空；对象记 `file_backed=false`，
`content` 一律 `None`（这不是“内容为空”，是“无文件字节”）。

### 1.2 只有“声明”能造对象（拒绝反推）

对象必须来自下列声明之一，**不按字节形态猜**（禁止“看起来像指针/像表”）：

| 来源 | 声明字段 | 分级 |
|---|---|---|
| ELF `SHT_SYMTAB`/`SHT_DYNSYM` | `st_type==OBJECT`、`st_shndx` 为普通节号、`st_size>0` | `declared_symbol` |
| DWARF `DW_TAG_variable` | `DW_AT_location` 为静态地址（`DW_OP_addr` / `DW_OP_addrx`）+ 可解析尺寸（`DW_AT_byte_size` 或类型链） | `declared_dwarf` |
| PE COFF 符号 | 只有 节号+Value，**无 size 字段** | 拒收，记 `format_rejections.coff_symbols` |
| PE 导出表 | 只有 RVA+名字，**无 size 字段** | 拒收，记 `format_rejections.export_table` |

PE/ELF 差异必须写明：ELF 符号有 `st_size`；PE COFF/导出表都没有尺寸，
因此 PE 样本的对象只能来自 DWARF（`-g`）——没有 DWARF 时对象数=0 是
「确实没有可声明对象」，不是「确实没有数据」。

**格式层拒收不进对象分母**：COFF 符号/导出表在结构上不可能成为对象；若把它们
混进分母，PE 的 `.idata/.pdata` 标签会把比例淹没。它们单独计数，并在报告里紧接
分母之后打印，避免“比例看起来很差”的误读。

### 1.3 接受判据（全部满足）

1. `size >= MIN_SIZE(4)`；小于 4 记 `too_small`。
2. 对齐：`size>=8 → start%8==0`；`4<=size<8 → start%4==0`；否则 `misaligned_start`。
   （口径代价：可能拒收合法 `char[N]`，记入拒收类，不偷偷放宽。）
3. 完全落在**同一个数据节**内：`sec.va <= start` 且 `start+size <= sec.va+vsize`；
   不在任何数据节 → `outside_data_section`；跨节尾 → `overruns_section`。
4. 与已接受对象不重叠；起点+尺寸完全相同 → 记 `duplicate_declaration`（去重，
   不算拒收对象）；部分重叠 → 后者拒收 `overlaps_object`。
5. 声明位于可执行节 → `in_exec_section`；位于非 alloc 节 → `not_allocated`；
   `SHN_UNDEF`/`SHN_ABS`/负节号 → `undefined_or_absolute`。

拒收类固定为：
`type_not_object, size_zero, size_absent_in_format, too_small, misaligned_start,
outside_data_section, overruns_section, in_exec_section, not_allocated,
tls_section, undefined_or_absolute, location_not_static, location_unresolved,
size_unresolved, overlaps_object`
（`duplicate_declaration` 单列，不计入拒收对象）。

`location_not_static`（`DW_TAG_variable` 的 `DW_AT_location` 是 loclist/寄存器）
与 `location_unresolved`（是别的表达式形式，或地址换算失败）分开：前者是
“声明存在但非静态存储”（例如自动变量），后者是“我们没解出来”。

### 1.4 地址空间

统一用 recdesc 的地址空间：ELF=vaddr；PE=RVA（ImageBase 相减）。
DWARF 的 `DW_AT_location` 原文是 VA，按 `addr_base` 换算并在证据里写算式。

## 2. 引用点识别（每种形态单独计数）

来自 `recdesc` 已解出指令 + `expr.decode` 的结构化操作数，不解析 objdump 文本。

| form | 判据 | 目标 |
|---|---|---|
| `rip_mem` | mem 操作数 `rip=true` 且非 `lea` | 下一条指令地址 + disp |
| `lea_rip` | `lea` 的 mem 操作数 `rip=true` | 同上（取地址，非读内存） |
| `abs_mem` | mem 且 `base/index` 均 None、`rip=false`、无段前缀 | disp32（32 位地址；按 0xFFFFFFFF 截断） |
| `abs_imm` | 非控制流指令（排除 call/jmp/jcc/ret）的 imm 操作数 | 立即数值 |
| `seg_disp` | mem 有段前缀（`fs:`/`gs:`） | **无目标**（段基址运行时决定，`fs:0x28` 不是文件地址）；单列 |
| `base_disp` | mem 有 base、无 index、无段前缀 | 不可静态确定（寄存器） |
| `base_index` | mem 有 index、无段前缀 | 不可静态确定（基址+索引） |
| `unlifted` | `expr.decode` 失败 | 不可检查（单列原因） |

段前缀优先于 `abs_mem`：`fs:0x28` 的 disp=0x28 若按绝对地址解释会归因到
`.interp`/空地址，制造假引用。栈保护（`__stack_chk_fail` 配套的 `fs:0x28`）
在 dyn_static 上占 853 条，全部归 `seg_disp`、不参与对象归因。

`abs_imm` 只在其值落在某个数据节范围内时才成为候选（否则连候选都不是）；
控制流立即数是跳转目标，不是数据引用，排除。
目标不在数据节（如 `.text`）→ `not_data`，单列计数，不参与对象归因。

### 2.1 数据节自身的指针表（与引用点分开）

对每个有文件字节的数据节，按指针宽度（ELF64/PE32+=8，ELF32/PE32=4）**对齐**读取；
值**恰等于**某对象起点 → `pointer_edges` 单列（`from`=数据地址，`to`=对象，
无函数归属）。不做“列表识别”，不把连续指针猜成数组；非起点命中不计入。

## 3. 归因三档（不合并）

| tier | 判据 | 记录 |
|---|---|---|
| `object_start` | `target == obj.start` | 精确 |
| `inside_object` | `obj.start < target < obj.end` | `offset=target-start`；可能是数组元素/结构体成员，单列 |
| `after_object` | `obj.end <= target < obj.end+AFTER_WINDOW` | `delta=target-end`；窗口固定 64，超窗不归因 |
| `data_unattributed` | 目标在数据节内但不对应任何已接受对象 | 单列（含“声明被拒/未声明”） |
| `not_data` | 目标不在数据节 | 单列 |

每个 site 必须带：`arith`（算式文本）、`evidence`（observed：指令字节；
derived：算式与对象边界）。多对象命中 → `ambiguous=true`（正常不应发生，发生即数据异常）。

## 4. 分母先行

`denominator` 块先给：声明候选数、接受数、拒收总数+逐类、去重数；
再把接受对象分为 `with_code_ref`（任一档）/`with_pointer_edge`/`without_ref`
（三类不互斥，逐项计数，另给互斥的 `only_code_ref` 等不需要）。
比例只出现在分母之后：`object_ref_ratio = with_code_ref / accepted`（accepted=0 时 `None`，不写 0）。

恒等式（只在对象分母内成立，`format_rejections` 不参与）：
`declared_candidates == accepted + rejected_total + duplicates`。

`format_rejections`（`coff_symbols`/`export_table`）是**格式层**拒收，结构上
不可能成为对象，单列、不进上面的恒等式、也不进 `object_ref_ratio` 分母。
报告顺序：对象分母 → 格式层拒收 → 比例，确保读者先看到分母再看比例。

## 5. funcreport 接入（data_refs 变为真实来源）

`strings_and_data.data_refs` 结构：

```
{evidence_state, scope, reason,
 denominator{objects, accepted, rejected, by_rejection, with_code_ref, without_ref},
 objects[], sites[], tiers{}, forms{}, pointer_edges[],
 sources=[{layer:"datarefs",field,text}]}
```

状态判定：
- 层失败 → `missing_source`（reason 含“层调用失败”）；
- 函数无已解出指令 → `missing_decode`；
- 样本无可读声明来源 → `missing_source`，写清“这不是没有数据引用”；两种情形
  reason 必须分开：**没有**符号表/DWARF 节（结构性没有）vs **有 DWARF 节但不可
  解析**（缺证据，附 paramdecl 审计里的解析原因，R111）；
- 声明来源可读但接受对象 0 → `absent_measured`，写清“确实没有可交叉对象”，
  并把拒收分类原样列出；
- 对象 >0 且该函数无引用点 → `absent_measured`（范围=该函数 N 条已解出指令）；
- 否则 `present`。

`SCHEMA` 由 1 升为 2（数据契约变更）；`ALLOWED_LAYERS` 增加 `datarefs`。

## 6. 外部独立重算与可失败自证（verify_datarefs.py）

1. **对象表**：用 `readelf -sW`（ELF）或 `objdump --dwarf=info`（PE DWARF 变量）
   在本脚本内独立解析，按 §1.3 同一口径重算，与层输出逐项比对（start/size/name）。
2. **引用点**：对每个 `rip_mem/lea_rip/abs_mem` site，取 objdump 反汇编中同地址行，
   要求行文本含目标地址；同时用 objdump 的 `# 0x...` 目标集合做独立计数，
   报告 `ours ⊆ theirs` 与差集条数（差集必须有可解释来源：未解出/非数据目标）。
3. **指针表**：用 `objdump -s` 读 `from` 处字节，断言值 == `to`（外部字节证据）。
4. **可失败自证**：把某个真实 site 的目标 +4 后再跑同一比对，断言比对判 FAIL；
   同时断言该偏移不再落在 `object_start` 档。自证必须打印“改动后检测到失败”。
5. 三类样本（M15 的 full / Go / minidll）+ dyn_static（有 ELF 符号的真实样本）
   全部跑，输出 `evidence_m16_datarefs.json`。

## 7. DoD

- 全量 pytest 全绿；`verify_datarefs.py` 全部 PASS（SKIP 不算 PASS）。
- 三类样本 data_refs 状态与 §5 一致；「缺证据」与「确实没有」措辞分离。
- 数字全部可回溯：每个对象/站点带来源；本层不产生 R91/R102–R107 的任何比率。
