# M17 Spec — .NET 程序集结构层（rekit/dotnet.py）

日期：2026-11-16
目标：回答「这个程序集里有哪些类型、哪些方法、方法体在文件哪里、IL 指令边界在哪」。
只做**声明可读的呈现**：不还原 C#、不做反混淆、不识别 .NET 壳/混淆器、不碰 NativeAOT。

## 0. 边界（先写死）

| 不做 | 原因 |
|---|---|
| 反编译为 C#/VB | 本层只到 IL 指令边界，不做控制流重建/表达式恢复 |
| 反混淆（名称/控制流/字符串加密） | 不属于结构层；读到什么声明就报什么 |
| .NET 壳/混淆器识别 | 不在本轮范围；不加启发式判据 |
| NativeAOT / ReadyToRun 原生代码 | 方法体不是 IL；RVA 指向原生代码时按「无 IL 方法体」记，不反解 |
| 语义（类型布局、字段偏移、调用目标解析） | 只给声明字段原值，不推断 |

## 1. 声明来源与读取链（缺一步就报缺，不按“常见布局”补）

```
PE 头（复用 rekit.pe）
 └─ OptionalHeader.DataDirectory[14] = CLI Header（RVA,Size）
     ├─ 目录不存在/为 0      → status=not_dotnet（这不是“没有类型”）
     ├─ RVA 映射不到文件      → status=cli_rva_unmapped
     └─ CLI Header（0x48 字节）
         ├─ cb 合法性（>=0x48）
         ├─ MetaData RVA/Size → 元数据根
         │   ├─ RVA 映射不到文件       → status=metadata_rva_unmapped
         │   ├─ Signature != 0x424A5342("BSJB") → status=no_metadata_root
         │   └─ Stream 头（#~ / #- / #Strings / #US / #GUID / #Blob）
         │       └─ 表流（#~ 或 #-）
         │           ├─ HeapSizes / Valid / Sorted / RowCount[]
         │           └─ 行数据（按列宽顺序读取）
         └─ EntryPointToken（0x06000000|x 方法 / 0x0A000000|x File）
```

口径：
- 所有 RVA→文件偏移只用节表（`vaddr <= rva < vaddr+vsize` 且 `delta < rawsize`），
  不假设节名、不假设 `.text`、不假设对齐后布局。
- 任一读取越界 → 该对象记 `missing_*`，**不补零、不跳到下一个候选**。
- 流可以缺失：`#~`/`#-` 缺失 → `status=no_table_stream`；`#Strings` 缺失时名字
  全部记 `missing_heap`（不是空字符串）。
- `#~` 与 `#-` 同时存在时优先 `#~`（未压缩流），并在报告里注明另一个被判为
  未使用，不合并两份。

## 2. 表流解析口径

- 行宽由声明决定：`HeapSizes` 决定 string/guid/blob 索引 2/4 字节；
  表索引按目标表行数 `< 65536 ? 2 : 4`；coded index 按
  `max(目标表行数) < (1 << (16 - tag_bits)) ? 2 : 4`。
- `Valid` 位图决定哪些表存在；未置位表的行数按 0，**不假设空表**。
- 表数据区从行数数组之后开始，按表号升序紧密排列；任何表行宽计算依赖的
  行数都取自声明，缺表按 0（这是 ECMA 定义，不是“常见布局”）。
- 本层实际解析行值的表：
  `Module, TypeRef, TypeDef, Field, MethodDef, Param, InterfaceImpl, MemberRef,
   Assembly, AssemblyRef, NestedClass, GenericParam, MethodSpec, TypeSpec`。
  其余表只报行数（分母的一部分），不解释语义。
- 名字只从 `#Strings` 堆按偏移取；偏移越界 → `missing_heap`，不返回空串。
- 签名只给 `#Blob` 的原始字节（前缀长度 + 十六进制预览），不解码签名类型。

## 3. 类型与方法的分母（先报分母）

类型分母：
- `TypeDef` 行数（含 `<Module>` 伪类型）。
- `<Module>` 单列（名字恰为 `<Module>` 且无命名空间），不算用户类型。
- 嵌套类型数（`NestedClass` 行数），嵌套关系只给声明（nested → enclosing）。
- 接口数（`InterfaceImpl` 行数）。

方法分母（恒等式必须成立）：
```
MethodDef 行数
 = RVA>0 的方法 + RVA==0 的方法
RVA>0 的方法
 = RVA 映射到文件 + RVA 映射不到文件
RVA 映射到文件
 = 方法体解析成功 + 方法体头非法 + 代码区超出文件
方法体解析成功
 = IL 解码成功 + IL 在某个偏移不可解
```
RVA==0 的无体方法按声明原因分类（逐类计数，不合并）：
`abstract`（Flags 0x0400）、`pinvoke`（Flags 0x2000 或 ImplMap）、
`runtime`（ImplFlags CodeType=Runtime）、`native`（CodeType=Native）、
`unclassified`（RVA=0 但上面都不是——如实记“未分类”，不猜）。

其它分母：tiny/fat 方法体数、带异常处理节的方法数、EH 子句总数、
`#US` 字符串字面量条数、泛型参数数（`GenericParam`）、泛型实例化数
（`MethodSpec`）、类型规格数（`TypeSpec`）。

比例一律放在分母之后；分母为 0 时比例写 `None`，不写 0。

## 4. 方法体定位与 IL 边界

### 4.1 方法体

- `MethodDef.RVA` 直接用声明值；RVA→文件偏移只用节表。
- 头格式：
  - tiny：`(byte0 & 3)==2`，`code_size = byte0 >> 2`（1..63），`max_stack=8`，
    无局部变量签名、无附加节。
  - fat：`(u16 & 3)==3`，`header_size = (u16 >> 12) * 4`（>=12），
    `code_size = u32@4`，`local_sig = u32@8`；`code_size` 必须落在文件内。
  - 其它低 2 位 → `body_bad_header`（如实报非法，不按 tiny 猜）。
- 代码区：`code_off = body_off + header_size(tiny 为 1)`，
  区间 `[code_off, code_off+code_size)`；越界 → `body_code_truncated`。
- 附加数据节（仅 fat 且 Flags.MoreSects）：从代码区末尾按 4 字节对齐；
  节头 = Kind(1) + DataSize(1 或 3，取决于 FatFormat) + Reserved(2)；
  Kind&0x3F==1（EHTable）时按 12 字节小子句 / 24 字节胖子句逐条读取
  try/handler 偏移与长度、catch token 或 filter 偏移。其它 Kind 只记大小，不解释。
- 附加节读取越界 → 该节记 `section_truncated`，已读出的子句保留。

### 4.2 IL 指令边界

- opcode 表按 ECMA-335 Partition III/VI 手写：单字节 0x00–0xE0 有效项 +
  `0xFE` 前缀的 0xFE00–0xFE1E 有效项；未列出的编码一律 `unknown_opcode`，
  在该偏移停止解码（`undecodable_at`），**不跳字节继续猜**。
- 操作数尺寸（字节）：`InlineNone=0, ShortInlineVar=1, InlineVar=2,
  ShortInlineI=1, InlineI=4, InlineI8=8, ShortInlineR=4, InlineR=8,
  InlineMethod/Field/Type/Tok/Sig/String=4, ShortInlineBrTarget=1,
  InlineBrTarget=4, InlineSwitch=4+4*n`（n 为紧随其后的 u32 计数）。
- 每条指令记：相对代码区起点的 `offset`、`size`、`opcode`、`operand_hex`；
  方法记 `instruction_count`、`undecodable_at`（若有）。
- 记录 `code_size` 与「最后一条指令 offset+size」的一致性：
  不相等单列 `tail_bytes`（可能是对齐/填充，也可能是解码错误，交给外部比对）。

## 5. 报告结构（JSON）

```
{schema, path, status, reason, caliber,
 file{format, sections[], cli_rva, cli_size},
 cli_header{...}, metadata{version, streams[]}, tables{row_counts, heap_sizes,
 valid_mask, sorted_mask, table_data_range},
 assembly{...}|null,
 types[{row, token, namespace, name, flags, extends, field_range,
        method_range, nested{enclosing}, kind}],
 methods[{row, token, owner, name, rva, impl_flags, flags, signature_hex,
          body{kind, header_off, code_off, code_size, max_stack, local_sig,
               sections[], eh_clauses[]}|null,
          body_status, body_reason,
          il{instruction_count, instructions[], stored, truncated,
             undecodable_at}}],
 strings_us{count, previews[]},
 generics{params[], method_specs, type_specs},
 denominators{...}, cross_layer{}, caveats[], limit}
```

`status` 取值：`ok / not_dotnet / cli_rva_unmapped / metadata_rva_unmapped /
no_metadata_root / no_table_stream / truncated / error`。
`status != ok` 时仍尽量给出已读到的部分，并逐项写 `reason`。

## 6. 与既有层的关系（显式，不静默返回空）

| 既有层 | 对 .NET 方法体 | 原因 |
|---|---|---|
| `map` | 部分适用 | RVA↔文件偏移仍成立；但只到节/方法体头，不解释 IL 指令 |
| `iat` | 不适用 | IL 调用是元数据 token（MethodDef/MemberRef）；P/Invoke 走 ImplMap 表，不是 IAT thunk |
| `disasm` / `recdesc` | 不适用 | IL 是字节码，不是 x86；按 x86 解码会得到假指令 |
| `expr` | 不适用 | 表达式恢复建立在 x86 指令上 |
| `callgraph` / `callfacts` / `sitejoin` | 不适用 | 调用目标是 token，不是代码地址；本层不产出 x86 调用图 |
| `strxref` | 不适用 | 字符串字面量在 `#US` 元数据堆，不在数据节；`ldstr` 是 token 引用 |
| `datarefs` | 不适用 | 数据对象声明来自 ELF 符号/DWARF；IL 引用是 token |
| `coverage` / `switchcand` / `vexaudit` | 不适用 | 均以 x86 指令为分母 |
| `paramdecl` / `struct` | 不适用 | DWARF 专用 |
| `gopclntab` | 不适用 | Go 专用 |
| `fingerprint` / `pe` | 适用 | 文件级；PE 头仍有效 |
| `funcreport` | 不适用 | 六层 x86 合成入口；对 .NET 文件返回 `not_applicable` 并指向 `rekit dotnet`，不返回空报告 |

## 7. 独立证伪（verify_dotnet.py）

1. **元数据独立重算**：`dnfile`（第三方独立实现）逐表比对行数；TypeDef/MethodDef
   逐行比对 name/namespace/flags/rva/impl_flags/signature 长度与哈希。
2. **方法体定位独立重算**：用 `dnfile.dnPE.get_offset_from_rva` 独立换算 RVA→文件
   偏移，与本层偏移比对；用 CLR 反射（PowerShell `Assembly.LoadFrom`）核对受控样本
   的类型名集合、每类型方法名集合、`GetMethodBody().GetILAsByteArray().Length`
   与 `code_size`。
3. **IL 边界独立重算**：`dncil`（独立 opcode 表/解码器）逐方法解码，比对
   `(offset,size,opcode)` 序列**完全相等**；不一致逐条列出。
4. **可失败自证**：把某方法真实 IL 的某条指令偏移 +1 / 删除一条后重跑比对，断言
   比对判 FAIL 且能列出差异；再把某方法 RVA +1 后断言方法体头/代码尺寸比对失败。
   自证必须打印「改动后检测到失败」。
5. 样本：受控编译样本（csc 产出，含方法体/字符串/泛型/抽象/接口/PInvoke/EH）、
   真实 Framework `mscorlib.dll`、真实 CoreCLR `System.Console.dll`；
   负样本由受控样本字节改动派生（清 CLI 目录、截断元数据、RVA 改坏），
   用于验证 `status` 与 `missing_*` 语义。

合成/受控样本的局限必须写在报告 caveat 里：编译产物只覆盖编译器实际生成的
IL 子集（无 mixed-mode、无 NativeAOT、无泛型实例化的全部形态、无混淆器变形），
不能代表真实世界程序集分布。

## 8. DoD

- `rekit dotnet <file> [--json]` 可跑；`status` 与 `missing_*` 语义符合 §1/§4。
- 分母恒等式在样本上成立；每个方法带 body 定位与 IL 边界。
- `verify_dotnet.py` 全部 PASS（含可失败自证），全量 pytest/verify 回归不变。
- 报告明确「声明可读 / 本轮读不出」两类清单。
