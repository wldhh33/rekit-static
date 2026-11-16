# TASK M17 — .NET 程序集结构层（rekit dotnet）

日期：2026-11-16
定位：rekit 第一次处理 **CLI 程序集**。目标只有四个问题：**有哪些类型、哪些方法、
方法体在文件哪里、IL 指令边界在哪**。全部答案来自声明（CLI 头 / 元数据表 /
MethodDef.RVA），缺一步就报缺；不还原 C#、不反混淆、不识别壳/混淆器、不碰 NativeAOT。

## 1. 实现

| 文件 | 说明 |
|---|---|
| `rekit/dotnet.py` | 本层主体：`probe` / `_read_metadata_root` / `Tables`（45 表 schema + coded index 宽度）/ `_rva_to_off` / `_parse_body`（tiny/fat + EH）/ `_decode_il`（手写 opcode 表）/ `_us_entries` / `build` / `render` / `main` |
| `rekit/cli.py` | 新增 `rekit dotnet <file>` 手动短路分支 |
| `rekit/funcreport.py` | 入口守卫：CLI 程序集 → `status=not_applicable` + 原因 + 指向 `rekit dotnet`（不返回空报告） |
| `samples/m17/_gen/RekitSample.cs` / `.dll` | 本机 `csc` 编译的受控样本（方法体/字符串/泛型/抽象/接口/PInvoke/EH） |
| `tests/test_dotnet.py` | 19 项单测 |
| `tests/verify_dotnet.py` | dnfile + dncil + CLR 反射外部重算、4 项可失败自证 → `work/evidence_m17_dotnet.json` |
| `outputs/m17_dotnet/spec.md` | 口径规格（8 节，含 DoD） |

CLI：

```
rekit dotnet <file> [--json] [--limit N]
                    [--detail-methods N] [--detail-insns N]
                    [--il-token 0x06000005]
```

`--detail-methods/--detail-insns` 只影响 JSON 里**存储**的 IL 指令条数，不影响任何分母。

## 2. 样本来源（先解决来源，再谈结论）

| 样本 | 路径 | 性质 | 用途 |
|---|---|---|---|
| `RekitSample.dll` | `samples/m17/_gen/` | 本机 `csc` 编译，6 TypeDef / 18 MethodDef | 受控对照（已知源码，可反向核名/核 IL） |
| `System.Console.dll` | `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\7.0.20\` | 真实 CoreCLR 程序集，47 / 433 | 真实样本（CoreCLR 布局） |
| `mscorlib.dll` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` | 真实 Framework 程序集，3356 / 29257 | 规模与覆盖率压力 |

受控样本源码覆盖：静态构造、实例方法、`switch`、循环、`long`/`double` 操作数、
字符串字面量、`List<T>` 泛型类型、泛型类型参数 `T`、抽象方法、接口方法、继承、
P/Invoke（`DllImport`）、`try/catch/finally`。编译命令：

```
csc.exe --% /nologo /target:library /optimize+ /out:RekitSample.dll RekitSample.cs
```

**合成样本的局限（不能代表真实程序集）**：只覆盖本机 csc 实际生成的 IL 子集；
没有 mixed-mode、没有 NativeAOT/ReadyToRun、没有混淆器变形、没有多模块程序集、
没有 `#-` 未压缩流、没有失败的方法体头。真实样本（mscorlib/System.Console）与受控
样本同跑，上述结论若只在受控样本成立，会在真实样本上暴露。

## 3. 声明读取链与缺失语义

```
PE 头（rekit.pe）
 └─ DataDirectory[14] = CLI Header
     ├─ 目录不存在/为 0        → not_dotnet（不是“没有类型”）
     ├─ RVA 映射不到            → cli_rva_unmapped
     └─ CLI Header(0x48)
         ├─ cb < 0x48           → truncated
         ├─ MetaData RVA/Size   → 元数据根
         │   ├─ RVA 映射不到         → metadata_rva_unmapped
         │   ├─ Signature != BSJB    → no_metadata_root
         │   └─ 流头 → #~ / #-
         │       ├─ 无表流            → no_table_stream
         │       ├─ 流范围越界        → truncated
         │       └─ 表流头不可解析    → truncated
         └─ EntryPointToken（只报原值，不解析目标）
```

- RVA→文件偏移只用节表：`vaddr <= rva < vaddr+vsize` 且 `delta < rawsize`；
  不假设节名、不假设 `.text`、不假设对齐后的布局。
- 任一读取越界即 `missing_*`，**不补零、不跳到下一个候选**。
- `#~` 与 `#-` 同时存在时优先 `#~`，报告中不合并两份。

## 4. 表流与堆

- 45 张表 schema 写死在 `TABLE_SCHEMAS`；行宽由声明决定：`HeapSizes` 决定
  string/guid/blob 索引 2/4 字节；表索引按目标表行数 `<65536 ? 2 : 4`；
  coded index 按 `max(目标表行数) < 1<<(16-tag_bits) ? 2 : 4`。
- 解析行值的表：`Module, TypeRef, TypeDef, Field, MethodDef, Param, InterfaceImpl,
  MemberRef, Assembly, AssemblyRef, NestedClass, GenericParam, MethodSpec, TypeSpec`。
  其余表**只报行数**（分母的一部分），不解语义。
- 名字只从 `#Strings` 按偏移取；越界记 `missing_heap`，不返回空串。
- 签名只给 `#Blob` 原始字节（长度 + 32 字节十六进制预览），**不解码参数/返回类型**。

## 5. 分母先行（实测）

恒等式（三样本全部成立）：

```
MethodDef = 有 RVA + 无 RVA
有 RVA    = 可定位 + 不可定位
可定位    = 体成功 + 头非法 + 代码截断
体成功    = IL 解出 + IL 不可解
```

### 5.1 受控样本 `RekitSample.dll`

| 项 | 值 |
|---|---|
| TypeDef | **6** = `<Module>` 1 + 命名类型 5；嵌套 0 |
| 类型（名字/继承） | `MathUtil:Object`、`Repository\`1:Object`、`Shape:Object`、`IWorker:—`、`Widget:Shape` |
| 接口实现 / 字段 / 参数 | 1 / 4 / 9 |
| MethodDef | **18** = 有 RVA 15 + 无 RVA 3 |
| 无 RVA 原因 | `abstract=2`（`Shape.Area`、`IWorker.Work`）+ `pinvoke=1`（`GetCurrentProcessId`） |
| 可定位 / 不可定位 | 15 / 0 |
| 体成功 / 头非法 / 代码截断 | **15 / 0 / 0** |
| tiny / fat | 12 / 3 |
| 带 EH 的方法 / EH 子句 | 1 / 2（`Widget.Area`：catch + finally） |
| IL 解出 / 不可解 / 指令总数 | **15 / 0 / 119** |
| 尾字节非 0 的方法 | **0**（119 条指令恰好铺满全部代码区） |
| `#US` | 条目 10（offset 0 保留空串 1 + 非空 9）；`ldstr` 9 个且全部指向已知偏移 |
| 泛型 | GenericParam 1（`Repository\`1` 的 `T`）；TypeSpec 2；MethodSpec 0；约束 0 |

### 5.2 真实 CoreCLR `System.Console.dll`

| 项 | 值 |
|---|---|
| TypeDef | **47**（命名 46，嵌套 18，带方法的类型 26） |
| MethodDef | **433** = 有 RVA 396 + 无 RVA 37 |
| 无 RVA 原因 | `pinvoke=33`、`runtime=4`、`abstract=0` |
| 可定位 / 体成功 / 头非法 / 截断 | 396 / **396** / 0 / 0 |
| tiny / fat | 256 / 140 |
| 带 EH 的方法 / 子句 | 23 / 23 |
| IL 解出 / 指令总数 | **396 / 6592**；尾字节非 0 的方法 0 |
| `#US` | 条目 77（保留空串 1 + 额外空串 1 + 非空 75）；`ldstr` 76 |
| 泛型 | GenericParam 0；MethodSpec 19；TypeSpec 9 |

### 5.3 真实 Framework `mscorlib.dll`

| 项 | 值 |
|---|---|
| TypeDef | **3356**（命名 3355，嵌套 660，带方法的类型 2623） |
| MethodDef | **29257** = 有 RVA 25315 + 无 RVA 3942 |
| 无 RVA 原因 | `abstract=2222, pinvoke=563, runtime=301, unclassified=856` |
| 可定位 / 体成功 / 头非法 / 截断 | 25315 / **25315** / 0 / 0 |
| tiny / fat | 16029 / 9286 |
| 带 EH 的方法 / 子句 | 1651 / 2164 |
| IL 解出 / 指令总数 | **25315 / 592,206**；尾字节非 0 的方法 **0** |
| `#US` | 条目 4725（保留空串 1 + 额外空串 1 + 非空 4723）；`ldstr` 4724 |
| 泛型 | GenericParam 1783；MethodSpec 656；TypeSpec 1261；约束 98 |

`unclassified=856`：RVA=0 且 `abstract`/`pinvoke`/`runtime`/`native` 都不成立。
这是**声明里看不出原因**，如实单列，不猜成“没有方法体”。

比例放在分母之后：方法体成功/MethodDef = 83.3333% / 91.4549% / 86.5263%；
IL 解出/有体 = 100% / 100% / 100%。

## 6. 方法体定位与 IL 边界（受控样本实例）

| 方法 | RVA | 头 | 文件偏移（头/代码） | code_size | 指令数 | 尾字节 |
|---|---|---|---|---|---|---|
| `MathUtil.Add` | 0x2058 | tiny | 600 / 601 | 16 | 8 | 0 |
| `MathUtil.Classify` | 0x206c | fat | 620 / 632 | 66 | 17 | 0 |
| `Widget.Area` | 0x2158 | fat | 856 / 868 | 68 | 25 | 0 |

- `Add` 的 8 条边界：
  `ldsfld(0,+5) ldc.i4.1(5,+1) add(6,+1) stsfld(7,+5) ldarg.0(12,+1)
   ldarg.1(13,+1) add(14,+1) ret(15,+1)`，`offset+size` 恰好等于 `code_size=16`。
- `Classify` 第 3 条 `switch` 的操作数是 `4 + 4*5 = 24` 字节（+1 字节 opcode = 25），
  5 个跳转目标按声明原值给出；11 条 `ldstr`/`ret` 分支的 `ldstr` token 指向 #US。
- `Widget.Area` 的 EH 两子句：
  `catch` try[0,40) handler[40,13) class_token=0x01000006；
  `finally` try[0,53) handler[53,13)。子句边界与 IL 偏移同一基准。

IL 解码口径：单字节 0x00–0xE0 + `0xFE` 前缀 0xFE00–0xFE1E；操作数尺寸按
`InlineNone/ShortInlineVar/InlineVar/ShortInlineI/InlineI/InlineI8/ShortInlineR/
InlineR/InlineMethod(-Field/-Type/-Tok/-Sig/-String)/ShortInlineBrTarget/
InlineBrTarget/InlineSwitch(4+4n)`。未列出的编码 → `unknown_opcode`，
在 `undecodable_at` **停止**，不跳字节继续猜。

## 7. 独立证伪（不自己证自己）

`tests/verify_dotnet.py` 27/27 PASS（`work/evidence_m17_dotnet.json`）：

| 检查 | 独立来源 | 结果 |
|---|---|---|
| 表行数 | `dnfile`（第三方元数据解析） | sample 20 张、console 26 张、mscorlib 31 张，全部一致 |
| TypeDef 逐行 | `dnfile`（name/namespace/flags/method range） | 6 / 47 / **3356** 行，全部一致 |
| MethodDef 逐行 | `dnfile`（rva/impl_flags/flags/name） | 18 / 433 / **29257** 行，全部一致 |
| 方法体文件偏移 | `dnfile.get_offset_from_rva` | 15 / 396 / **25315** 个，全部一致 |
| IL 边界逐条 | `dncil`（独立 opcode 表/解码器），归一化到方法体头基准 | sample 15/15 方法；真实样本默认各 120 个方法；**另跑全量：console 396/396、mscorlib 25315/25315 全部一致**（`work/evidence_m17_il_full.log`） |
| `#US` 逐条目 | `dnfile.user_strings.get(offset)` | 10 / 77 / 4725 条文本一致；`ldstr` token 9 / 76 / 4724 个全部指向已知偏移；受控样本字面量集合完全相等 |
| 类型/方法名与 IL 长度 | PowerShell CLR 反射 `Assembly.LoadFrom` | 5 个类型（排除 `<Module>`）、排除 4 个构造方法后逐名一致；`GetILAsByteArray().Length == code_size` |

可失败自证（4 项，全部 PASS）：

| 改动 | 期望 | 实测 |
|---|---|---|
| IL 偏移 +1 | 比对 FAIL | FAIL ✓ |
| 删掉一条指令 | 比对 FAIL | FAIL ✓ |
| 末字节改 `0xFF` | `unknown_opcode@15` | 命中 ✓ |
| MethodDef 行数 +1 | 表检查 FAIL | FAIL ✓ |
| 方法体 RVA/偏移 +1 | 偏移检查 FAIL | FAIL ✓ |

`dnfile` 不实现 `FieldRVA` / `ENCLog` / `ENCMap`，这三张表的行数**没有**外部重算
（mscorlib 的 `FieldRVA=128` 只是本层按声明读出），已在 verify 的 detail 里注明。

## 8. 与既有层的关系（显式，不静默返回空）

`cross_layer` 逐层列出 19 项。要点：

| 层 | 对 .NET | 原因 |
|---|---|---|
| `map` | 部分适用 | RVA↔文件偏移与节视图仍成立，用于方法体定位；不解释 IL |
| `pe` / `fingerprint` | 适用 | 文件级结构有效 |
| `iat` | 不适用 | IL 调用是元数据 token；P/Invoke 走 `ImplMap`，不是 IAT thunk |
| `disasm`/`recdesc`/`expr` | 不适用 | 方法体是 CLI 字节码，不是 x86；按 x86 解码会得到假指令 |
| `callgraph`/`callfacts`/`sitejoin` | 不适用 | 调用目标是 token，不是代码地址 |
| `strxref` | 不适用 | 字面量在 `#US`（`ldstr` 用 token），不在数据节 |
| `datarefs` | 不适用 | 对象声明来自 ELF 符号/DWARF；IL 引用是 token |
| `coverage`/`switchcand`/`vexaudit` | 不适用 | 分母是 x86 指令 |
| `paramdecl`/`struct`/`gopclntab` | 不适用 | DWARF/Go 专用 |
| `funcreport` | 不适用 | 返回 `status=not_applicable`，reason 写明“方法体是 CLI 字节码”，`absence_summary` 覆盖 8 行，并指向 `rekit dotnet` |

`funcreport` 守卫在 `build()`/`build_selection()` 入口做 `DN.probe(path)`，`is_cli`
时直接返回 `not_applicable`，**不会**让六个 x86 层各跑一遍再给出空列表。

## 9. 回归

- `python -X utf8 -m pytest tests -q`（PATH 含 mingw64）→ **528 passed（70.64s，exit 0）**；
  新增 `test_dotnet.py` 19 项；`test_funcreport.py` 白名单加 `dotnet`。
- 全部 `tests/verify_*.py` → **20/20 PASS**（含 `verify_dotnet.py` 27/27、fingerprint
  `--all --matrix` E9 PASS 132/132），日志 `work/evidence_m17_verify_all.log`。
- 日志：`work/evidence_m17_pytest.log`、`work/evidence_m17_dotnet.json`、
  `work/evidence_m17_il_full.log`。

## 10. 声明可读 / 本轮读不出

### 10.1 声明可读（本轮已给原值，可追问）

- CLI 头全部字段（cb / 版本 / MetaData RVA+Size / Flags / EntryPointToken /
  Resources / StrongName / ManagedNativeHeader）。
- 元数据根：签名 `BSJB`、版本串、6 个流头（`#~/#Strings/#US/#GUID/#Blob`）。
- 表流：HeapSizes/Valid/Sorted/RowCount、45 张表的行数、表数据区范围；
  14 张表逐行值（见 §4）。
- 类型：TypeDef 行、命名空间/名字、Flags、Extends（解到 TypeDef/TypeRef 名字）、
  字段/方法行范围、嵌套 encloser、`<Module>` 伪类型单列。
- 方法：MethodDef 行、RVA、ImplFlags/Flags、名字、签名字节长度与预览；
  无 RVA 的声明原因（abstract/pinvoke/runtime/native/unclassified）。
- 方法体：tiny/fat、头文件偏移、代码区文件偏移与 code_size、max_stack、
  local_sig token、附加节、EH 子句（try/handler 偏移与长度、catch token、
  filter 偏移）。
- IL：每条指令的 offset/size/opcode（名字+原始操作数字节）、方法指令数、
  不可解位置、尾字节数。
- `#US`：条目偏移与原文（UTF-16 解码，只给原文不解密）。
- 泛型：GenericParam 行（owner/number/name）、MethodSpec/TypeSpec/约束行数。
- Assembly 行：名字/版本/culture/flags/hash_alg/公钥长度。

### 10.2 本轮读不出（明确不在本轮）

- **签名语义**：参数类型、返回类型、局部变量类型——只给 `#Blob` 原始字节，
  不解码。因此“方法签名长什么样”本轮读不出。
- **调用目标**：`call/callvirt/newobj` 的 token 只给原始 4 字节，不解析
  MethodDef/MemberRef/MethodSpec 到具体方法名，不建调用关系。
- **字段/属性/事件/常量/自定义特性的语义**：只有行数，不列名字/类型/值。
- **`FieldRVA` 指向的静态数据**（如数组初始化 blob）：只有行数，不读内容。
- **资源内容**：`ManifestResource` 只有行数，不读。
- **嵌套类型全名拼装**：只给 enclosing row，不拼 `Outer+Inner` 全名。
- **`unclassified` 方法（mscorlib 856）**：RVA=0 且无声明原因，声明里就是看不出。
- **NativeAOT/ReadyToRun 原生方法体**：若 RVA 指向原生代码，本层按
  `body_bad_header` / `undecodable` 如实报，不反解原生指令。
- **反编译为 C#/VB、反混淆、壳/混淆器识别**：整块不做。
- **三张表的外部重算**：`FieldRVA`/`ENCLog`/`ENCMap` 因 `dnfile` 不实现，
  行数只有本层自报，没有独立来源复核。

## 11. 已知限制

- 只回答结构问题；“这段 IL 是否合法可执行”“是否可达”“是否被混淆”不在范围。
- IL 指令边界由 opcode 表切分；未知编码停止在 `undecodable_at`，不猜后续。
- 方法体只解析头/代码区/EH 节；不解析局部变量签名、不重建控制流。
- `#US` 只给原文；字符串加密/拼接不在本轮（会表现为原文看起来是乱码，但本层
  不判断是否加密）。
- 受控样本由本机 csc 生成，见 §2 的局限声明；真实样本结论以 mscorlib/
  System.Console 的行为为准。
