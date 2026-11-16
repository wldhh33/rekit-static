# M19 Spec — .NET 签名语义层（rekit/sigblob.py）

日期：2026-11-17
目标：回答「这条方法的签名说了什么类型」——只解 `#Blob` 内的签名 blob。
定标来源：`pack/03_路线图与章程/CHARTER.md` M19 行（2026-11-16 写死，本轮不改判据）。

## 0. 边界与分工（先写死）

| 层 | 回答什么 | 停止在哪 |
|---|---|---|
| M17 `dotnet` | 有哪些类型/方法、方法体在文件哪里、IL 指令边界 | 方法体位置与 IL 边界；签名只给原始字节预览 |
| M18 `ilflow` | IL 结构：分支/块/边/EH/调用目标 token | token 指向哪一行；不解该行的签名 |
| **M19 `sigblob`** | **签名说了什么类型**：调用约定/泛型参数数/返回类型/参数类型 | 类型**名字与形状**；不做类型布局、不算字段 RVA、不读特性、不反编译 |

不做（本轮明确不做，遇到就记 out_of_scope，不猜）：
- 类型布局（字段顺序/大小/对齐）、`ClassLayout`/`FieldLayout` 语义
- 字段 RVA / `FieldRVA` 数据、常量值
- 特性（CustomAttribute）解码、`Security` 权限集、`FieldMarshal` 原生类型
- 局部变量签名（`LOCAL_SIG`）与属性签名（`Property`）的类型语义：**只做长度与边界**
- 反编译为 C#/VB、类型名美化、按名称猜类型

## 1. 调用点与分母（分母先行）

三类调用点（每类各自二分，恒等式必须成立）：

```
MethodDef(0x06).Signature
MemberRef(0x0A).Signature
StandAloneSig(0x11).Signature
```

每张表：

```
rows = no_blob_index + has_blob_index                     (恒等式 1)
has_blob_index = blob_readable + blob_unreadable          (恒等式 2)
blob_readable  = decoded + undecoded                      (恒等式 3)
decoded = decoded_clean + decoded_with_unknown            (恒等式 4，仅诊断用，不并入 3)
```

- `no_blob_index`：该行 blob 索引 == 0。**这是「没有」，不是「没读到」**，单独计数。
- `blob_unreadable`：有索引但堆读不出来，按原因逐类：
  `no_blob_heap` / `blob_index_out_of_range` / `blob_length_invalid` / `blob_truncated`。
- `undecoded`：字节读出来了但签名解不下去，按原因逐类：
  `truncated_signature` / `bad_compressed_int` / `param_count_exceeded` /
  `depth_exceeded` / `not_method_signature` / `local_sig_out_of_scope` /
  `decode_error:<异常类>`。
- `decoded_with_unknown`：结构解完但有 ≥1 个 `unknown` 类型节点（见 §4）。不单列成
  「未解码」，它确实解出了结构；但必须能被数出来。

分流（按 blob 首字节低 6 位）：

| 表 | 首字节 | 处置 |
|---|---|---|
| MethodDef | 非 FIELD | 方法签名，解语义 |
| MemberRef | `0x06` FIELD | 字段签名：只记 kind/长度/边界，`field_sig_length_only`，**不并入 undecoded** |
| MemberRef | 其它 | 方法签名（可能是 vararg），解语义 |
| StandAloneSig | `0x07` LOCAL_SIG | 局部变量签名：只记 kind/长度/边界，`local_sig_length_only` |
| StandAloneSig | `0x06` FIELD | 字段签名：同上 |
| StandAloneSig | 其它 | **CallSite**，解方法签名 |

字段表 `Field(0x04).Signature`：只做长度与边界（`rows = no_blob_index +
has_blob_index`、`has_blob_index = readable + unreadable`），**不解类型**；首字节
不是 `0x06` 时记 `non_field_signature` 计数（不猜）。

范围外但带 blob 的表（Constant/CustomAttribute/FieldMarshal/DeclSecurity/Property/
TypeSpec/Assembly/AssemblyRef/File）只报「有 blob 引用的行数」，不解读——把它们显式
列出来，避免「没读」被当成「没有」。

## 2. 方法签名解码口径

按 ECMA-335 II.23.2：

```
MethodSig ::= CallConv GenericParamCount ParamCount RetType Param*
CallConv 低 6 位: 0x00 DEFAULT / 0x05 VARARG / 0x10 GENERIC / 0x20 HASTHIS / 0x40 EXPLICITTHIS
          高 2 位: 0x01 C / 0x02 STDCALL / 0x03 THISCALL / 0x04 FASTCALL
```

- `Param` 序列里允许出现 `0x41 SENTINEL`（vararg）：记录 `required_param_count`
  （sentinel 之前的参数数）。非 vararg 出现 sentinel → 记 anomaly `sentinel_in_nonvararg`，
  仍按 sentinel 处理（不丢字节）。
- 压缩整数（格式字节/泛型参数数/参数数/数组 rank/size/lbound）用 ECMA II.23.2 的
  1/2/4 字节编码；非法首字节 → `bad_compressed_int`。
- 每种元素类型至少消耗 1 字节，终止性由剩余字节数保证；参数数大于剩余字节数 →
  `truncated_signature`（不预分配、不按参数数继续读）。
- 递归深度上限 64，超过 → `depth_exceeded`（不是 unknown）。

## 3. 类型文法与 canonical 文本（两套实现共用的比较口径）

节点 → canonical 字符串（对拍时逐节点比较整串）：

| 元素 | 编码 | canonical |
|---|---|---|
| 基元 | 0x01–0x0E,0x16,0x18,0x19,0x1C | `Void/Boolean/Char/SByte/Byte/Int16/UInt16/Int32/UInt32/Int64/UInt64/Single/Double/String/TypedReference/IntPtr/UIntPtr/Object`（与 SRM `PrimitiveTypeCode` 同名） |
| class | 0x12 + TypeDefOrRef | `class [TD]Ns.Name` / `class [TR]Ns.Nested` |
| valuetype | 0x11 + TypeDefOrRef | `valuetype [TD]Ns.Name` |
| szarray | 0x1D T | `T[]` |
| array | 0x14 T rank [sizes] [lobounds] | `T[r=2;s=3,4;lb=0,0]`（缺省段省略为 `s=;` `lb=`） |
| ptr / byref | 0x0F / 0x10 T | `T*` / `T&` |
| genericinst | 0x15 (class\|valuetype) TypeDefOrRef count Arg* | `class [TR]Ns.List\`1<Int32>`（`G<A,B>`） |
| var / mvar | 0x13 / 0x1E N | `!0` / `!!0` |
| fnptr | 0x1B MethodSig | `fnptr(<MethodSig canonical>)` |
| modreq / modopt | 0x1F / 0x20 TypeDefOrRef T | `modreq([TR]Ns.X)T` / `modopt(...)T` |
| pinned | 0x45 T | `pinned(T)`（方法签名里不应出现；出现即记 anomaly） |
| typespec 引用 | TypeDefOrRef tag=0x1B | `spec@0x1Bxxxxxx`（**不解 TypeSpec 的 blob**，只写 token） |

方法签名整串：

```
sig cc=<Default|VarArgs|CDecl|StdCall|ThisCall|FastCall> hasthis=<0|1> explicit=<0|1>
    generic=<0|1> gpc=<N> req=<N> ret=<T> params=[<T>,...]
```

名字规则：TypeDef/TypeRef 的 `Ns.Name`；嵌套类型按 NestedClass 链拼成
`Outer+Inner`（与 SRM `GetDeclaringType` 链一致）。不带程序集名（同一行内比较，
不需要；跨程序集同名不是本层问题）。

## 4. unknown 政策（禁止按名称猜）

出现以下情况一律产出 `{"kind":"unknown","missing":<原因>,"raw":<已读字节hex>}` 节点，
**不**根据附近字节或表名补一个「看起来像」的类型：

| 情况 | missing |
|---|---|
| 元素类型字节不在上表 | `element_type_0xNN` |
| TypeDefOrRef tag 无对应表 | `coded_index_tag_<n>` |
| 行号 > 该表行数 | `row_out_of_range:<Table>` |
| 类型名读不出（#Strings 越界） | `name_missing`（名字置 null，不置空串） |

unknown 节点不影响签名整体 `decoded` 判定（结构解完），但整条签名计入
`decoded_with_unknown`，并按 missing 原因逐类计数。

## 5. 独立对拍（期望值不取被测实现）

**必须先说明的偏离**（见本轮汇报，已在此存档）：

1. 定标写的是「用 `dnfile` 的 `Signature` 解码」。事实：PyPI 上 `dnfile` 0.5.0–0.18.0
   的 wheel/sdist **都没有签名解码模块**（逐版本核对过文件清单；本机安装 0.18.0，
   `dnfile.signature` 不存在），因此该 API 不存在，无法照字面执行。
2. 替代方案（保持「第三方独立解码 + 逐 blob 逐字节边界」两条不让步）：
   - **字节边界层**：`dnfile` 逐行给 `row.struct.Signature_BlobIndex`（原始 #Blob 索引）
     与 `row.Signature`（dnfile 独立解出的 blob 字节）。与 rekit 的
     `{blob_index, blob_off, blob_len, blob_hex}` 逐行逐字节比对；索引/偏移/长度/内容
     任一不等即 FAIL。
   - **语义层**：微软官方 `System.Reflection.Metadata`（SRM）的 `DecodeSignature`
     ——ECMA-335 的参考实现，与 rekit 完全无关。经 `pwsh`（7.6.6，.NET 10）用
     `Add-Type` 编译一个 `ISignatureTypeProvider<string>` 输出同一套 canonical 文本，
     逐行整串比较。
   - 影响：语义期望值比原定方案更权威（微软自家解码器）；字节边界仍由 dnfile 覆盖。
     代价：verify 套新增 `pwsh` 外部依赖（缺 → env_missing exit 2，fail-closed），
     并在文档中登记。
3. SRM 的 `DecodeSignature` 无法回读消耗字节数（`BlobReader` 是值类型，按值传入），
   因此「消耗到哪」由 dnfile 的 blob 长度 + rekit 自己的 `consumed` 字段共同核对：
   rekit 必须 `consumed == blob_len` 才算 decoded，否则归入 `trailing_bytes` 并计数。

## 6. 检查器与自证（首版即带）

`tests/verify_sigblob.py`：
- 分母核对：四张表的恒等式逐条，与 dnfile 行数/索引为 0 的行数对拍。
- 逐行对拍：blob 索引/偏移/长度/字节 + canonical 整串（MethodDef/MemberRef 方法签名/
  StandAloneSig 方法签名）。空比对（分母 0 或无共同行）→ FAIL。
- 自证（工件形式，vharness 认的那种，首版就带）：
  1. 注入 ID：改样本副本里某个 MethodDef 签名的 blob 字节（例如把参数类型
     `string`→`int32`），检查器必须报出该行 canonical 不一致；
  2. 基线：干净样本该行 canonical；
  3. 观察到的失败行：注入后被报出的那一行（`FAIL ... token=0x06xxxxxx`）。
  另加：`#Blob` 索引 +1 注入（必须报 blob_index 不一致）、blob 长度前缀篡改
  （必须报 truncated/bad length）、空输入必须 FAIL。
- 样本：受控 `RekitSample.dll`、`FlowSample.dll`、真实 `System.Console.dll`、
  `mscorlib.dll`（沿用 M17/M18 同一批；读不出签名的样本如实 unknown 并单列）。

## 7. 输出 schema（草案）

```
{"schema":1,"path":...,"status":"ok|...","call_sites":{...},"denominators":{
   "MethodDef":{...},"MemberRef":{...},"StandAloneSig":{...},"Field":{...},
   "out_of_scope_tables":{...}},
 "methods":[{"row","token","name","impl_flags","flags","owner_row",
             "blob_index","blob_off","blob_len","blob_hex","kind","status",
             "reason","signature":{...},"unknown":[...]}],
 "memberrefs":[...],"standalonesigs":[...],"fields":[...],
 "counts":{...},"caliber":{...},"caveats":[...],"cross_layer":{...}}
```

`blob_hex` 默认全量（mscorlib 约 2.9 万行方法，预计 ~1–2 MB JSON）；`--limit` 只影响
列表条数，不影响分母（分母永远全量）。

## 8. 与既有层的显式关系（cross_layer）

- x86 各层（disasm/recdesc/expr/callgraph/funcreport…）：对 IL 方法体 `not_applicable`。
- `dotnet`：签名只到原始字节；M19 解出的 `signature_len` 必须与 M17 的
  `signature_len` 逐行相等（同源但独立重算的交叉核对）。
- `ilflow`：IL 里的 token 指向行，M19 说该行的签名；两者不互相覆盖，不做「按签名
  反推调用目标」。
