# TASK M16 — 非字符串数据引用层（rekit datarefs）与 funcreport 回接

日期：2026-11-16
定位：补上 M15 报告层暴露的缺失层——**非字符串数据引用（全局/静态对象）**。
本层只从**声明**造对象（ELF 符号 `st_size` / DWARF 变量），从**指令寻址形态**
造引用点，再按地址关系做三档归因。对象定义、接受/拒收、形态、归因全部写死，
可被外部工具逐条对账。

## 1. 实现

| 文件 | 说明 |
|---|---|
| `rekit/datarefs.py` | 本层主体：`_image` / `_data_sections` / `_from_elf` / `_from_dwarf` / `_accept` / `_classify` / `_attribute` / `_scan_sites` / `_scan_pointers` / `build` / `render` / `main` |
| `rekit/paramdecl.py` | 只扩展 DWARF 审计：保留 `DW_TAG_variable` 与类型 DIE（形参语义不变，`test_paramdecl` 全绿） |
| `rekit/funcreport.py` | `SCHEMA` 1→2；七层白名单加 `datarefs`；`data_refs` 段改由本层填充 |
| `rekit/cli.py` | 新增 `rekit datarefs <file>` 手动短路分支 |
| `tests/make_datarefs_full.py` | 用内联 C 生成 PE 正样本 `tests/m16_fixtures/datarefs_full.exe` |
| `tests/test_datarefs.py` | 21 项单测 |
| `tests/verify_datarefs.py` | readelf/objdump 外部重算 + 可失败自证，输出 `work/evidence_m16_datarefs.json` |

CLI：

```
rekit datarefs <file> [--section NAME] [--json] [--limit N]
```

## 2. 对象定义（写死，可追问）

### 2.1 数据节

| 格式 | 条件 | 说明 |
|---|---|---|
| ELF | `SHF_ALLOC` 置位、`SHF_EXECINSTR` 未置位、`sh_size>0`、`SHF_TLS` 未置位 | 含 `SHT_NOBITS`（`.bss`）；排除 `.text`、非 alloc 节 |
| PE | `MEM_READ` 置位、`MEM_EXECUTE` 未置位、`vsize>0`、`MEM_DISCARDABLE` 未置位、节名不以 `.debug` 开头 | 含 `rawsize==0` 的 `.bss`；排除 `.text`/`.reloc`/`.debug_*` |

TLS 节（`.tdata/.tbss`）**不进数据节**：TLS 地址与普通节 VMA 重叠（实测
`dyn_static` 的 `.tbss` 覆盖了 `.data.rel.ro` 起点），且 TLS 地址不是文件地址。
地址→节解析必须先跳过 TLS，否则 `rfv.0@0x49ee60` 会被误判为“越界”
（此错误由 verify 发现并修复）。

### 2.2 声明来源

| 来源 | 字段 | 能否给出尺寸 |
|---|---|---|
| ELF `SHT_SYMTAB` / `SHT_DYNSYM` | `STT_OBJECT` 的 `st_value/st_size/shndx` | 能 |
| DWARF `DW_TAG_variable` | `DW_OP_addr` + `DW_AT_byte_size` 或类型链 | 能 |
| PE COFF 符号表 | 只有 节号+Value，**无 size 字段** | 不能 → `format_rejections.coff_symbols` |
| PE 导出表 | 只有 RVA+名字，**无 size 字段** | 不能 → `format_rejections.export_table` |

**格式层拒收不进对象分母**。COFF 符号/导出表在结构上不可能成为对象；混进分母
会让 PE 的 `.idata/.pdata` 标签淹没比例。它们单独计数，报告里紧接分母之后打印。

### 2.3 接受判据（全部来自声明，不按字节猜）

1. 有明确尺寸且 `size >= MIN_SIZE(4)`；
2. 起始对齐：`size>=8` 按 8 字节，`4..7` 按 4 字节；
3. 落在数据节内且不越节尾；
4. 不与已接受对象重叠；同起点只留首个（其余计 `duplicates`）。

### 2.4 拒收类（逐类计数）

`type_not_object, size_zero, size_absent_in_format, too_small, misaligned_start,
outside_data_section, overruns_section, in_exec_section, not_allocated,
tls_section, undefined_or_absolute, location_not_static, location_unresolved,
size_unresolved, overlaps_object`

- `location_not_static`（DWARF 位置是 loclist/寄存器，例如自动变量）与
  `location_unresolved`（其它表达式/地址换算失败）分开：前者是“声明存在但非
  静态存储”，后者是“我们没解出来”。

## 3. 引用点识别（每种形态单独计数）

| 形态 | 判据 | 目标 |
|---|---|---|
| `rip_mem` | mem 且 `rip=true`（非 lea） | 指令尾 + disp |
| `lea_rip` | lea 的 rip 相对 mem | 指令尾 + disp |
| `abs_mem` | mem 且无 base/index/rip/段前缀 | disp32 |
| `abs_imm` | 非控制流指令的立即数 | 立即数值 |
| `seg_disp` | mem 带 `fs:`/`gs:` 前缀 | **无目标**（段基址运行时决定） |
| `base_disp` | mem 有 base、无 index | 不可静态确定 |
| `base_index` | mem 有 index | 不可静态确定 |

- 段前缀优先于绝对地址：`fs:0x28` 的 disp 若按绝对地址解释会归因到无效目标
  （实测 `dyn_static` 有 853 条栈保护）。
- 算术文本可被外部证伪，写成
  `insn_addr + instruction_length + disp = target`（长度取指令长度，不取操作数
  长度；此错误由 verify 的 objdump 对账暴露并修复）。
- `expr.decode` 失败的指令单列 `unlifted`（带原因），不当作“没有引用”。
- **数据节自身的指针表与代码引用点分列**：数据节按指针宽扫描，值恰等于对象
  首地址 → `pointer_edges`；落在对象内部 → `pointer_values_inside`（单列）。

## 4. 三档归因（不合并）

| 档 | 判据 | 额外字段 |
|---|---|---|
| `object_start` | 目标 == 对象首地址 | `offset=None` |
| `inside_object` | 目标落在对象内部（数组元素/结构体成员） | `offset>0` |
| `after_object` | 目标在对象尾之后 64 字节窗口内 | `offset` = 尾后偏移 |
| `data_unattributed` | 目标在数据节内但不属于任何声明对象 | — |
| `not_data` | 目标不在数据节 | — |

`inside_object` 单独报，因为它可能是数组元素或结构体成员；`after_object`
单独报，因为它是“邻接但未声明覆盖”，不能并入“精确命中”。

## 5. 分母先行（实测，先报分母再报比例）

### 5.1 `dyn_static`（ELF，有 `.symtab`）

| 项 | 值 |
|---|---|
| 声明候选 | 539 |
| 接受对象 | **483** |
| 拒收 | 41（`type_not_object=12, size_zero=7, too_small=15, misaligned_start=4, overlaps_object=3`） |
| 去重 | 15 |
| 恒等式 | 539 = 483 + 41 + 15 ✓ |
| 格式层拒收 | 0 / 0（ELF 无此结构） |
| 有代码引用 / 有指针槽 / 无引用 | 417 / 51 / 39 |
| 对象有代码引用比例（分母=483） | **86.3354%** |
| 形态 | `rip_mem=1700, lea_rip=2155, abs_mem=3, abs_imm=16, seg_disp=853, base_disp=18519, base_index=2695`（合计 25941） |
| 归因分档 | `object_start=1709, inside_object=669, after_object=259, data_unattributed=1001, not_data=236` |
| 指针槽 | 首地址命中 92 条；落在对象内部 30 条（单列） |
| 未解出操作数 / 不可静态确定 | 8853 / 22067（853+18519+2695） |

### 5.2 `datarefs_full.exe`（PE，DWARF）

| 项 | 值 |
|---|---|
| 声明候选 | 9 |
| 接受对象 | **7**（`g_counter=4, g_table=16, g_ptrs=16, g_msg=11, g_zero=32, 2 个匿名 16`） |
| 拒收 | 2（均为 `location_not_static`：`__CTOR_LIST__`/`__DTOR_LIST__`） |
| 去重 | 0；恒等式 9 = 7 + 2 + 0 ✓ |
| 格式层拒收 | `coff_symbols=720, export_table=0`（不进对象分母） |
| 有代码引用 / 有指针槽 / 无引用 | 5 / 1 / 2 |
| 比例（分母=7） | 71.4286% |
| 归因分档 | `object_start=3, inside_object=3, after_object=6, data_unattributed=190, not_data=6` |
| 指针槽 | `0x4030 → 0x4010`（`g_ptrs[0]=&g_counter`）；内部值 `0x4038 → 0x9084`（`g_zero+4`，单列） |
| `.bss` | `g_zero` 无文件字节（`file_backed=false`，`content_hex=null`），仍可被引用与归因 |
| 未解出 / 不可静态确定 | 22 / 746 |

## 6. 外部独立重算与可失败自证

期望值不取自被测实现（`tests/verify_datarefs.py`，12/12 PASS）：

| 检查 | 方法 | 结果 |
|---|---|---|
| dyn 对象表 | `readelf -sW` 重算 `OBJECT` 符号（值/尺寸/节），逐个对账；带尺寸符号不得凭空消失 | 对账 501 条；2 条落在更大对象内部（重叠已声明）；无不一致 |
| fix 对象表 | `objdump --dwarf=info` 重算 `DW_TAG_variable` 的 `DW_OP_addr` + 类型链尺寸 | 7 条；`g_table=16`、`g_msg=11`、`g_zero=32` 全部一致 |
| fix 引用点 | `objdump -d` 的 `# 目标` 注释（objdump 自己算的）逐点比对 | **207/207** 一致 |
| dyn 引用点 | 同上 | **3854/3855** 一致（1 条 objdump 未给注释，不计入核对） |
| fix 指针槽 | `objdump -s` 原始字节按指针宽解包，减 ImageBase | 2/2 一致 |
| 恒等式 / ELF 格式层 | 内建分母 + `format_rejections` 必须为 0 | PASS |
| **可失败自证（引用点）** | 期望目标 +4 后重跑同一检查器 | 干净=True，+4=False ✓ |
| **可失败自证（对象表）** | 从外部 DWARF 集合删掉 `g_table` 后重跑 | 完整=True，删除=False ✓ |

## 7. funcreport 回接（`data_refs` 从 missing_source 换成真实来源）

`SCHEMA=2`；`ALLOWED_LAYERS` 增加 `datarefs`；`build()` 调
`DR.build(path, section, res=res, dwarf=dwarf)`，异常进 `layer_errors` 且该段记
`missing_source`（写“层调用失败”，不静默）。

段落结构：`evidence_state / scope / reason / denominator / objects / sites /
tiers / forms / pointer_edges / function_scope / sources`。
口径分离：**denominator 是全文件对象口径；sites/forms/tiers 只含该函数已解出
指令；objects/pointer_edges 只列该函数引用到的对象**，`function_scope.note`
写明这一点。

状态映射：

| 条件 | 状态 |
|---|---|
| 层调用失败 | `missing_source`（缺证据：层失败） |
| 函数无已解出指令 | `missing_decode` |
| 本文件无可扫描数据节 | `absent_measured`（确实没有数据节） |
| 无任何能给出尺寸的声明来源 | `missing_source`（缺证据） |
| 声明来源可读但接受对象 0 | `absent_measured`（确实没有可交叉对象，列拒收分类） |
| 接受对象>0 且函数无数据节引用点 | `absent_measured`（确实没有；写明不可静态确定/未解出不在测量范围） |
| 否则 | `present` |

### 7.1 三类样本的结果

| 样本 | `data_refs` 状态 | 读者应理解为 |
|---|---|---|
| 完整声明 `funcreport_full`（PE，DWARF 可读、无全局变量） | **`absent_measured`** | 确实没有可交叉数据对象（接受 0/声明候选 0；COFF 720 条无尺寸字段，单列不进分母） |
| 部分证据 Go `0x401320`（stripped） | **`missing_source`** | 缺证据：无 `.symtab`、无 DWARF，不是“没有数据引用” |
| 严重不足 `minidll.dll` `0x1000` | **`missing_source`** | 缺证据：导出表/COFF 均无尺寸字段 |

M16 正样本（`datarefs_full.exe`）的 6 个用户函数：**5 个 `present` + 1 个
`absent_measured`**。`read_counter/table_sum/msg_addr/zero_two/ptr_zero` 各有
精确命中或内部命中：`g_table` 两处 `inside_object` 的 offset 分别为 4/12
（`g_table[1]`、`g_table[3]`，数组元素），`g_zero` 的 `inside_object` offset=8
（`&g_zero[2]`），`g_ptrs` 的指针槽给出 `→g_counter` 边，`g_zero`（`.bss`）
无文件字节但仍有引用并被归因。`main` 只做调用，本函数域内确实没有数据引用
（`absent_measured`，13 条已解出指令、0 个静态引用点，另有 1 条不可静态确定
形态不在测量范围）。

M15 文档里“非字符串数据引用没有来源层”的说法自本轮起失效，已在
`TASK_m15_funcreport.md` §4.1/§8 就地标注。

## 8. 回归

- `python -m pytest tests -q`（PATH 含 mingw64）→ **509 passed（70.33s，exit 0）**；
  新增 `test_datarefs.py` 23 项；`test_funcreport.py` 断言 `SCHEMA==2` 与七层白名单。
- 全部 `tests/verify_*.py` → **18/18 exit 0**；`verify_fingerprint.py --all --matrix`
  → E9 PASS（132/132 可判定格）。
- `verify_datarefs.py` 连续 **12 次新鲜进程**全 PASS（修复前约 1/15 失败，见下条）。
- 日志：`work/evidence_m16_datarefs.log`（本层 verify 输出）、
  `work/evidence_m16_pytest.log`、`work/evidence_m16_verify.log`。

### 8.1 回归期修掉的一个偶发失败（R111）

`full-e` 曾约 **1/15** 概率把 `funcreport_full` 报成 `data_refs=missing_source`
（期望 `absent_measured`），且 `layer_errors=无` —— 说明 DWARF 被当成“不存在”。

- 根因：`paramdecl._abbrev_table` 的缓存键是 `(id(data), offset, len(data))`。
  两个 DWARF 样本的 `.debug_abbrev` 切片被 PE 文件对齐补齐成**同一长度（512 B）**，
  而 `bytes` 在大批释放后 `id()` 会复用（实测 400 个 512 B 对象释放后重建，
  **238/400** 地址重叠）。于是 `full` 的切片可能命中 `datarefs_full.exe` 的表，
  解析报 `abbrev code` 缺失 → `readable=False` → `dwarf=None` → `no_declaration_source`。
- 修复：缓存键改为内容（`bytes` 可哈希，且缓存持有该对象，顺带杜绝地址复用）。
- 同时拆开两种“没有声明来源”的 wording：无 DWARF 节（结构性没有）vs DWARF 节
  存在但解析失败（缺证据，reason 带 paramdecl 审计原因），以后同类问题不会再
  被读成“没有声明来源”。
- 回归护栏：`test_abbrev_cache_not_keyed_by_object_id`（在 id 形状的键上放毒条目，
  正确实现必须无视）、`test_dwarf_present_but_unreadable_not_reported_as_no_source`。


## 9. 已知限制

- 对象只认声明：没有符号/DWARF 的二进制（stripped）无法交叉，状态是
  `missing_source`，不得读成“没有全局变量”。
- 基址+索引/基址+位移不可静态确定，单列计数，不猜目标；栈访问也在其中。
- `after_object` 是 64 字节窗口，不是“属于该对象”；窗口内若有未声明数据仍归
  `after_object` 并给出 delta。
- PE 的对象来源只有 DWARF；COFF/导出表只有格式层计数，不产生对象。
- 本层不判断“这次引用是读还是写”“是否是活代码路径”；只回答“地址为什么算
  指向那个对象”。
