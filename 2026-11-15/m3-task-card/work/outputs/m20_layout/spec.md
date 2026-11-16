# M20 规格 · .NET 类型布局与字段 RVA（.NET 纵切面封口）

> 对应实现 `rekit/layout.py`（CLI `rekit layout`）、校验器 `tests/verify_layout.py`、证据 `work/evidence_m20_layout.json`。
> 本文件把**静态可证**与**运行期推导**的边界写死；两者混写即视为口径错误（R123）。

## 1. 范围

只做三张表的静态事实：

| 表 | 静态字段 | 含义 |
|---|---|---|
| `FieldLayout` (0x10) | `Offset` (u4) + `Field` (idx) | 显式布局下单个字段的声明偏移 |
| `ClassLayout` (0x0F) | `PackingSize` (u2) + `ClassSize` (u4) + `Parent` (idx) | 类型声明的打包粒度与总大小 |
| `FieldRVA` (0x1D) | `RVA` (u4) + `Field` (idx) | 静态字段初始化数据的位置，需换算到文件偏移再取字节 |

不做：特性、常量表、嵌套类型全名、序列化布局、`LayoutKind` 判定以外的运行期行为、反编译。

## 2. 静态结论只含三样

1. `FieldLayout.Offset` 原值（仅显式布局类型有行）；
2. `ClassLayout.PackingSize` / `ClassSize` 原值（`0` 照抄"未指定"，**不代换默认值**）；
3. `FieldRVA` 的 `RVA` → 文件偏移（`DN._rva_to_off`，只用节表 vaddr/vsize/rawsize，不假设节名）→ 数据字节。

`FieldRVA` 的数据长度**不是元数据字段**，按以下优先级推导，并逐条记来源：

| 来源 | 条件 | 计数（四样本） |
|---|---|---|
| `valuetype_classsize` | 字段类型是 TypeDef 且本模块有 `ClassLayout.ClassSize>0` | 122 |
| `primitive` | 类型是 ECMA-335 基元（`PRIM_SIZES`） | 9 |
| `unknown` | 其它（如外部程序集类型、无 ClassLayout） | 1 |

`unknown` 时**不得**用 `.data` 字面量长度反推——那会把"数据段里恰好有 8 字节"当成类型大小（唯一 unknown 即 IL 样本 `System.DateTime`，原因 `valuetype_not_typedef`）。

## 3. 运行期推导（不进静态结论）

sequential/auto 布局的字段偏移是 CLR 的运行时决定，元数据里没有。只在受控样本上给，且：

- 报告里放在 `runtime_derived`，字段 `static_conclusion=false`；
- 每条带 `boundary`：显式布局 → 「静态 `FieldLayout.Offset` 与运行期相等」；sequential → 「运行期顺序偏移，静态不可得」；auto → 「CLR 拒绝 marshal，运行期亦不可得」；
- 显式样本的静态/运行期吻合只作**交叉印证**，不作为静态结论的来源。

受控样本实测：`Marshal.OffsetOf` 给出 **14 个偏移**、`Marshal.SizeOf(Type)` 给出 **3 个 size**；`AutoStruct` 被 CLR 拒绝（`cannot be marshaled as an unmanaged structure`），记为 **1 个 auto 边界不可得**，不写任何静态值。

## 4. 分母与恒等式（先报分母）

四样本（受控 IL `LayoutSample.dll`、受控 C# `LayoutCSharp.dll`、mscorlib、System.Console.dll）：

- `FieldLayout` **84** 行 = 解码 clean **84** + unknown **0** + undecoded **0**；
- `ClassLayout` **71** = clean **71** + unknown **0** + undecoded **0**；
- `FieldRVA` **132** = `field_ref_ok` **132** = `length_known` **131** + `length_unknown` **1**；`data_ok` **131** + `rva_unmapped` **0** + `data_truncated` **0**；
- 三表合计 **287** 行 = dnfile 独立读同一批表的行数。

逐样本：mscorlib 78 / 63 / 128（数据 64,421 字节，长度来源 120 / 8）；System.Console 0 / 3 / 0；受控 IL 3 / 2 / 3（28 字节，1 unknown）；受控 C# 3 / 3 / 1（32 字节）。

## 5. 独立对拍来源（期望值不取被测实现）

1. **dnfile 原始列值**：`FieldLayout(Offset, Field)`、`ClassLayout(PackingSize, ClassSize, Parent)`、`FieldRva(Rva, Field)` + 字段名，**287 行** 0 不一致；
2. **dnfile RVA→文件偏移**：`get_offset_from_rva` 独立复算 **131 行**（位置 + 字节）0 不一致；
3. **源码即真值**：`.il` 的 `.pack` / `.size` / `.field [N]` / `.field ... at I_0001` 与 `.data cil`，`.cs` 的 `[StructLayout]` / `[FieldOffset]` / 数组初始化器，共 **16 项** 0 不一致；
4. **长度自洽**：`__StaticArrayInitTypeSize=N` 的 N、`ClassLayout.ClassSize`、推导长度三者相等 **121 行** 0 不一致；
5. **运行期 oracle**：`tests/layoutref.ps1`（PowerShell 5.1 + CLR 反射），只用于 §3。

dnfile 不实现 `FieldRVA`（M17 已记），因此**没有把 dotnet 自家解析器当唯一裁判**：列值与 RVA 换算来自 dnfile，数据字节来自源码数组初始化器，二者互不依赖。

## 6. unknown 与 undecoded 分离（R121）

- `decoded`：字节解完且长度来源明确；
- `decoded_with_unknown`：字节解完、长度来源 `unknown`（本次 1 条）；
- `undecoded`：`rva_zero` / `rva_not_in_any_section` / `data_truncated` / `field_index_zero`（本次 0 条）。

unknown 不得并入 undecoded，也不得为凑 100% 而按名称猜。

## 7. 可失败自证（首版即带）

工件 = 注入 ID + 基线 + 观察到的失败行；空比对一律 FAIL：

| 注入 | 观察到的失败行 |
|---|---|
| `FieldLayout.Offset` +4 | `[FAIL] m20-src selfproof FieldLayout A offset expected=0 actual=4` |
| `ClassLayout.ClassSize` +1 | `[FAIL] ... expected=(1, 24) actual=(1, 25)` |
| FieldRVA 文件字节翻转 | `[FAIL] ... 数据 expected=0102… actual=fe02…` |
| `RVA` +1 | `[FAIL] m20-rva Blob24 file_off dnfile=593 rekit=592` |
| 空比对 | 拒绝 PASS |

## 8. 已知边界

- sequential/auto 偏移、`ClassSize=0` 时的运行期 size、引用类型字段的实例布局不在静态结论内（`static_conclusion.excludes` 逐条列出）；
- 跨程序集类型大小不可知，记 unknown；
- 运行期 oracle 依赖 Windows + PowerShell/CLR，非 Windows 环境无法复跑运行期部分（静态部分不受影响）；
- `PackingSize=0` / `ClassSize=0` 照抄未指定，不代换默认值。

## 9. 复跑

```powershell
python "2026-11-15\m3-task-card\work\tests\verify_layout.py" --all
python -m rekit.cli layout "2026-11-15\m3-task-card\work\samples\m20\_gen\LayoutSample.dll"
```

受控样本生成：`work\outputs\m20_layout\gen.ps1`（ilasm/csc）。
