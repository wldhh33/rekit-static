# M8-U2：参数绑定，只认 declared 来源

日期：2026-11-16　｜　范围：`rekit/paramdecl.py`（新增）、`rekit/callfacts.py`（接线）、
`tests/test_paramdecl.py`（20 项）、`tests/verify_paramdecl.py`（18 样本矩阵 + 独立复核 + `--selftest`）
证据：`work/evidence_m8u2_numbers.log`（数字底稿）、`work/evidence_m8u2_verify.log`
（18 样本矩阵 PASS）、`work/evidence_m8u2_pytest.log`（408 passed）、
`work/evidence_m8u2_scripts.log`（12 条验证命令 exit 0）

---

## 0. 结论

| 用户要求 | 状态 | 一句话 |
|---|---|---|
| ① R76「暂态写」误判记入方法学，并给「定义成立但无法判定」自查清单 | ✅ | R76 的判据**说得通但可判定证据集合为空**：它只能当负向约束（call 的 rsp 写按持久写），不能产出任何「这是暂态写」的正向结论；§1 给出 10 条自查清单与本轮命中项 |
| ② 声明必须说出「文件哪一处、怎么读到的」，读不到就 abstain | ✅ | DWARF 证据逐条带 `CU@偏移`、`DIE@偏移`、位置表达式字节、节头/压缩头；PDB 只定位到 RSDS 但未解码位置记录 → 一律 abstain；导出表/符号表/COFF 结构性不含形参 |
| ③ 先报分母再报结果；0 条来源不得当结论 | ✅ | 18 样本 × 9 类来源先报 present/readable；DWARF 仅 **2/18** 可读、PDB **1/18 可定位但 0 可读**、gnu_debuglink **1/18 可定位但外部文件缺失**；v2/v3 样本 0 条 → 明写「本轮无法验证」 |
| ④ 数字分列：声明绑定 / 证据不足弃权 | ✅ | 形参级 `bound 5824 / partial 1696 / abstained 6155`（linux）与 `6448 / 1834 / 6789`（exe）分列，另列寄存器段 8354 / 9152；不合成净增量 |
| 回归 | ✅ | pytest **408 passed**；12 条验证脚本 exit 0（`verify_fingerprint` 需 `--all --matrix`，已按该参数跑出 PASS） |

本轮**修正了上一轮的一处口径**（不是放宽）：站点状态原先「只要绑上一个形参就报 bound」，
会把弃权说成结论；现改为「有绑定且有未绑定 → partial」。形参级数字不受影响，站点级
bound/partial 重排（§4.4）。

---

## 1. 方法学：R76 案例与「定义成立但无法判定」自查清单

### 1.1 案例：判据说得通，但可判定证据集合为空

R76 的定义（[callfacts.py](file:///d:/数据/下载/逆向学习工作体系_2026-11-15/2026-11-15/m3-task-card/work/rekit/callfacts.py#L71-L88)）是：

> w 对 (r, t) 是**暂态写** ⇔ 存在 b（a < b ≤ t）使
> (T1) b 是同一函数内**已解出**的指令，且把 r 写成 a 之前 r 的值；
> (T2) (a, b) 内没有对 r 的其它写；(T3) (b, t) 内没有对 r 的写。

三段都写得通，形式上也对。但本轮能承认的「复原证据」（T1 的 b）集合是**空**：

- `call` 的复原发生在**被调方体内**的 `ret`，不在本函数已解出的窗口里；
- `ret imm16` 的净效果取决于调用约定（callee-cleanup），净变化可能是 `+8+imm16`；
- 认定调用约定属于 ABI 推断，本层明令禁止。

所以 R76 **没有**输出任何「暂态写」结论。它唯一的产出是负向约束：**任何没有被判成
暂态的写，都按持久写处理**——包括 `call` 对 rsp 的写。如果文档写成「call 不算写 rsp」，
那是特例豁免，不是这条判据的结果；M8-U1 已把这点改对。

### 1.2 教训

1. **「判据成立」与「判据可判定」是两件事。** 定义再自洽，只要它能使用的证据集合为空，
   它就不能给出肯定结论；此时输出必须落在「持久/不可判定」，文档也不得声称判定了暂态。
2. **空证据集合必须显式写出来。** 不能只写「暂态写判据见 §x」——读者会以为工具真的在判暂态。
3. **负向约束也是成果，但要标成负向。** 「排除法」可以收紧输出（431 条槽事实转弃权），
   却不能反过来证明被排除项不存在。
4. **可证伪 ≠ 可证实。** `--selftest` 能证明「实现回到旧口径会失败」，不能证明
   「所有持久写都被正确识别」。两者在验收表里要分开写。

### 1.3 「定义成立但无法判定」自查清单

新判据/新来源落地前逐条过；任一命中就必须把结论降为 abstain，并写清缺什么。

| # | 自查项 | 不通过的表现 |
|---|---|---|
| 1 | 判据的每个肯定分支，是否都能在**当前输入**上指出一条可判定证据（地址/字节/偏移）？ | 证据集合为空却仍输出肯定结论 |
| 2 | 肯定结论是否依赖外部契约（调用约定、栈平衡、未解码流、运行时状态）？ | 用「通常如此」补齐，即 ABI 推断 |
| 3 | 能否构造反例？能构造但当前证据不足以排除，是否仍当成立？ | 把「没找到反例」当成「成立」 |
| 4 | 该来源在语料中有多少样本？分母是否先报？ | 直接报「0 个参数 / 不支持」，不报分母 |
| 5 | 声明能否定位到文件偏移与解析路径（节头/压缩头/CU/DIE/表达式字节）？ | 只说「有 DWARF/有 PDB」，指不出位置 |
| 6 | 声明存在但缺关键字段（`low_pc`、`location`）时，是否单列？ | 与「没有声明」混成一个桶 |
| 7 | 「结构性不含该信息」与「本轮读不出」是否分开？ | 把导出表不含形参说成「本轮缺失」 |
| 8 | 默认值是否落在保守侧（持久/不可判定/abstain）？ | 默认假设「暂态/可复原」 |
| 9 | 每个 0 是否有结构性原因？没有时是否先查分母被吞？ | 0 被当成结论 |
| 10 | 每条弃权是否写清「缺什么、补上什么就能判定」？ | 只报 `missing` 为空或占位文本 |

### 1.4 本轮命中项

| 情形 | 类别 | 处理 | 计数 |
|---|---|---|---|
| R76 暂态写 | 定义成立、证据集合空 | 只作负向约束；call 的 rsp 写按持久写 | 431 条槽事实转弃权（M8-U1） |
| PDB 形参位置 | 定义成立、本轮读不出 | RSDS/TPI 可定位，CodeView 位置记录未解码 → abstain | 1/18 样本，0 条绑定 |
| gnu_debuglink | 定义成立、外部文件缺失 | 只记引用，不作判据 → abstain | 1/18 样本（bin_ls） |
| DWARF 位置为空 | 声明存在、缺字段 | `params_without_location` 单列 → abstain | linux 1524 / exe 1505 个形参 |
| DWARF 栈/帧基址位置 | 需栈帧模型 | `DW_OP_fbreg/CFA` 不判定 → abstain | linux 99 / exe 155 条弃权 |
| DWARF 声明缺 `low_pc` | 声明存在、无法对齐 | 无法与站点地址对齐，计入 `no_declaration` | linux 1011 / exe 996 个 DIE（本样本无站点命中） |
| 间接调用目标 | 目标不可静态确定 | 目标侧 abstain | linux 189 / exe 195 站点 |
| DWARF v2/v3 | 解析路径成立、语料 0 条 | 仅合成单测；明写「真实样本无法验证」 | 0/18 样本 |
| 导出表/COFF/符号表/`.pdata`/`.eh_frame` | **结构性**不含形参 | 不是「读不到」，是声明本身没有该信息 | 见 §2 |

---

## 2. 分母先行

### 2.1 来源类别 × 18 样本（`verify_paramdecl.py` 实测）

| 来源类别 | present | readable | 形参声明数 | 语义 |
|---|---|---|---|---|
| dwarf | 2/18 | 2/18 | 10338 | `formal_parameters`（唯一携带入口位置） |
| pdb | 1/18 | **0/18** | 0 | `types_only_undecoded` |
| export_table | 1/18 | 1/18 | 0 | `function_identity_only` |
| coff_symbols | 1/18 | 1/18 | 0 | `function_identity_only` |
| elf_symtab | 6/18 | 6/18 | 0 | `function_identity_only` |
| elf_dynsym | 5/18 | 5/18 | 0 | `function_identity_only` |
| gnu_debuglink | 1/18 | **0/18** | 0 | `external_reference_only` |
| eh_frame | 7/18 | 7/18 | 0 | `function_range_only` |
| pdata | 6/18 | 6/18 | 0 | `function_range_only` |

分母结论：

- **只有 DWARF 能提供形参声明**：2/18 样本（`hello_go_linux`、`hello_go.exe`），共 10338 个
  `DW_TAG_formal_parameter`。
- **PDB：1/18 可定位、0/18 可读**。RSDS 与 MSF7.00 目录能读，但 CodeView 位置记录未解码
  → **这类来源本轮无法验证**，不是「PDB 不含形参」。
- **gnu_debuglink：1/18 可定位、外部 debug 文件缺失** → **本轮无法验证**。
- 其余六类**结构性不含形参位置**（CLASS_DECLARES 写明），不是「样本碰巧为 0」。
- **DWARF v2/v3：18 样本中 0 条** → 真实样本无法验证；仅有合成单测（§7.2 的 v2 头顺序用例）。
  不得写成「v2/v3 没有形参」。

### 2.2 「无法验证 / 结构性缺失 / 真零」三分

| 说法 | 含义 | 本轮实例 |
|---|---|---|
| 本轮无法验证 | 来源存在、读法或外部依赖缺失 | PDB（未解码）、gnu_debuglink（外部文件缺失）、DWARF v2/v3（无样本） |
| 结构性缺失 | 声明格式本身不含该信息 | 导出表/COFF/ELF 符号表/`.pdata`/`.eh_frame` |
| 真零（有分母） | 声明可读且确实为 0 个形参 | `zero_params` 4903 / 4988 个站点（声明明确 0 形参） |

`minidll.dll` 是第四种：**0 个调用点**（sites=0）。它不构成参数绑定的分母，不能读成
「0 个参数」；`verify_paramdecl.py` 单列 `[无可绑定对象]`。

---

## 3. 声明在文件哪一处、怎么读到的

### 3.1 ELF（hello_go_linux）

- 节：`.debug_info` / `.debug_abbrev` / `.debug_str` / `.debug_line_str` /
  `.debug_loclists` 等，`SHF_COMPRESSED`。
- 读法：节头索引 → `sh_offset/sh_size` → 压缩头 `Chdr{ch_type=1,ch_size}` → zlib 解压。
  审计串形如：`ELF 节头[29] .debug_info sh_offset=0x… sh_size=0x… sh_flags=0x800(SHF_COMPRESSED)；
  Chdr{ch_type=1,ch_size=0x…}；zlib 解压得 0x… 字节`。
- DIE：`CU@0x…；DIE@0x…`，形参位置给出 `DW_AT_location` 的表达式字节或 loclist 偏移。

### 3.2 PE（hello_go.exe）

- 节名：`.zdebug_info` 等（经 COFF 字符串表 `/4`、`/19` 解析）。
- 读法：PE 节头 `rawptr/rawsize` → 首 4 字节 `ZLIB` + u64(BE) 未压缩长度 → zlib 解压。
- **修过的 bug**：`_canon` 原用 `name[7:]`，把 `.zdebug_info` 映射成 `.debug__info`（多一个
  下划线），PE 全查不到。改为 `name[8:]` 后 61 个 CU 全部读出。
- **地址空间**：PE 的 `DW_AT_low_pc` 是 `ImageBase+RVA`（本例 0x140000000），站点目标按 RVA；
  绑定前显式换算 `lookup = target + image_base`，并在弃权文案里写出换算式。

### 3.3 位置表达式与位置列表

- `DW_OP_reg0..reg31` / `DW_OP_regx`：入口处的寄存器段；
- `DW_OP_piece`：多段（如结构体跨寄存器）逐段记录；
- `DW_OP_fbreg` / `DW_OP_call_frame_cfa`：栈位置 → 需要栈帧模型，本轮 abstain；
- 其它表达式（`bregx`、复合表达式）→ abstain，并报「未解释」；
- `DW_AT_location` 为空 → abstain，报「入口位置表达式为空」。

### 3.4 读不到就 abstain

`bind_site` 只有在「声明可读 + 形参有位置 + 位置能在入口解释 + 调用点有该寄存器的
可判定定义」四条同时成立时才绑定；缺任一条都进 `abstains`/`partial`，并写 `missing`。
代码里没有「按寄存器顺序/平台惯例补齐」的分支（单测 `test_no_declaration_and_no_dwarf_abstain`
与 `test_no_facts_abstains_without_abi_guess` 钉住）。

---

## 4. 判据与数字分列

### 4.1 判据（先于实现写进 `callfacts.PARAM_RULE`）

> 只有声明来源能给出「第 k 个形参在函数入口位于哪个寄存器/栈位置」时，才把调用点该寄存器的
> 最后定义绑定到第 k 个形参。声明必须能指到文件偏移/节/DIE/位置表达式；读不到即 abstain。
> 导出表、COFF/ELF 符号表、`.eh_frame`、`.pdata` 只声明函数身份/范围，不声明参数（结构性）；
> PDB 本轮只定位到 RSDS 与 TPI 流，未解码位置记录，因此一律 abstain。
> 禁止按寄存器顺序/平台惯例补参数。

### 4.2 数字（`build` 实测）

| 样本 | 站点 | bound | partial | zero_params | abstained | no_decl | no_target |
|---|---|---|---|---|---|---|---|
| hello_go_linux | 11471 | 2057 | 3418 | 4903 | 904 | 0 | 189 |
| hello_go.exe | 11980 | 2101 | 3777 | 4988 | 919 | 0 | 195 |
| cli-64.exe | 153 | 0 | 0 | 0 | 0 | 98 | 55 |
| bin_ls.elf | 1154 | 0 | 0 | 0 | 0 | 1116 | 38 |
| dyn_static | 3609 | 0 | 0 | 0 | 0 | 3457 | 152 |
| hello_rust.exe | 1029 | 0 | 0 | 0 | 0 | 836 | 193 |
| minidll.dll | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

形参级（只统计声明可读的样本）：

| 样本 | 因声明绑定 | 部分绑定 | 因证据不足弃权 | 绑定寄存器段 | partial 缺段 |
|---|---|---|---|---|---|
| hello_go_linux | **5824** | 1696 | **6155** | 8354 | 1813 |
| hello_go.exe | **6448** | 1834 | **6789** | 9152 | 2001 |

两列分开报：`bound` 是「声明给出位置且调用点有该寄存器定义」；`abstained` 是「声明不可读 /
位置为空 / 栈位置 / 调用点无定义」等证据不足。`partial` 单列（多段只绑到一部分），
`bound_pieces` 是实际绑定的寄存器段数，不等于形参个数。

### 4.3 弃权原因（hello_go_linux，形参级）

| 原因 | 条数 |
|---|---|
| 形参的入口位置表达式为空（DWARF 未给出位置） | 2358 |
| 调用点前没有寄存器 rax 的可判定定义 | 954 |
| 调用点前没有寄存器 rbx 的可判定定义 | 835 |
| 调用点前没有寄存器 rcx 的可判定定义 | 689 |
| 调用点前没有寄存器 rdi 的可判定定义 | 409 |
| 间接调用目标不可静态确定 | 189 |
| 调用点前没有寄存器 rsi 的可判定定义 | 157 |
| 调用点前没有寄存器 rax,rbx 的可判定定义 | 107 |
| 形参入口位置在栈/帧基址（DW_OP_fbreg/CFA） | 99 |
| 调用点前没有寄存器 rax,rbx,rcx 的可判定定义 | 84 |
| 调用点前没有寄存器 r8 的可判定定义 | 63 |
| 调用点前没有寄存器 r9 的可判定定义 | 40 |
| 调用点前没有寄存器 rdi,rsi,r8 的可判定定义 | 30 |
| 调用点前没有寄存器 reg17 的可判定定义 | 23 |
| 其余组合（多寄存器/reg17/r10+ 等） | 118 |

### 4.4 站点状态口径修正（返工项）

原实现：只要 `bound` 非空就报 `bound`，即使其它形参全部弃权。这会把「一个形参绑定 + 三个
形参缺定义」说成绑定结论，违反「分开报」。现改为：

- `partial`：有形参绑定，且存在未绑定形参（缺定义进 `abstains`，多段缺一段进 `partial`）；
- `bound`：全部形参绑定；
- `abstained`：一个也没绑上。

影响：hello_go_linux 站点 `bound 3805→2057`、`partial 1670→3418`；hello_go.exe
`4071→2101`、`1807→3777`。**形参级 5824/1696/6155 与 6448/1834/6789 一字未变**，
弃权原因也未变——修正只发生在「站点状态不得把弃权说成绑定」。

---

## 5. 独立复核

### 5.1 DWARF DIE 普查（外部工具，不经被测解析器）

`readelf --debug-dump=info`（ELF）/ `objdump --dwarf=info`（PE）按 `<depth><offset>` 与
`DW_TAG_*` 独立统计：

| 项 | hello_go_linux（readelf） | hello_go.exe（objdump） |
|---|---|---|
| CU 数 | 59 = 模块 59 | 61 = 模块 61 |
| subprogram 数 | 2805 = 模块 2805 | 2880 = 模块 2880 |
| subprogram 带 low_pc | 1794 = 模块 1794 | 1884 = 模块 1884 |
| subprogram 下 formal_parameter | 5077 = 模块 5077 | 5261 = 模块 5261 |

⚠ 普查里 `DW_TAG_formal_parameter` 的**总数**是 10354/10783，包含 `DW_TAG_inlined_subroutine`
下的形参；本层只把 `subprogram` 的直接子节点当声明，二者不是同一分母，不能直接比总数。

### 5.2 objdump 文本核对绑定定义

对每一条被绑定的寄存器段，取 `def_at` 的指令，用外部 `objdump -d -M intel` 文本判断该
指令是否真的写这个寄存器：

- hello_go_linux：核对 **8354** 段，未建模 **0**，矛盾 **0**；
- hello_go.exe：核对 **9152** 段，未建模 **0**，矛盾 **0**。

这是「只证伪」的判据：文本说没写 → FAIL；说写了不证明语义正确。

### 5.3 `--selftest`

三类注入全部被检出：

```
[selftest] 三类注入（声明外寄存器 / 缺 declared 证据 / 无声明伪造绑定）全部被检出 → 通过
[selftest] 基线（真实 hello_go_linux）零失败，检查器不是空转的
```

---

## 6. 总账

| 要求 | 可复核证据 |
|---|---|
| 只认 declared | `bind_site` 只在 `dwarf` 声明路径绑定；无 DWARF 样本 `available=false`、`params_bound=0`、每站一条 abstain |
| 声明可定位 | 每条绑定带 `CU@0x`/`DIE@0x`/位置表达式字节；审计串给节头/sh_offset/sh_size 或 rawptr + 压缩头 |
| 分母先行 | §2 表；`verify_paramdecl.py` 先打分母矩阵，再打结果；`minidll` 单列「无可绑定对象」 |
| 数字分列 | §4.2 两表；`params_bound/partial/abstained` 各自独立计数 |
| 禁止 ABI 补齐 | `PARAM_RULE` + 单测 + 弃权文案「禁止按 ABI 补」 |
| 回归 | 408 passed；12 条验证命令 exit 0 |

---

## 7. 回归与返工

### 7.1 返工与自纠

1. **`_canon` 少一个下划线**（实现）：`.zdebug_info → .debug__info`，PE 全部查不到声明；
   修为 `name[8:]` 后 PE 61 个 CU 可读。
2. **PE 地址空间未换算**（实现）：`low_pc=ImageBase+RVA` 与站点 RVA 不同域，原先全部
   `no_declaration`；新增 `addr_base` 换算并在文案写出算式。
3. **`by_low_pc` 缺声明吞分母**（实现）：原 `dwarf is None` 时不调用 `bind_site`，
   `counts.sites=0`；改为每站都调，无声明记 `no_declaration` 并计数。
4. **站点状态把弃权说成绑定**（实现，口径修正）：见 §4.4。
5. **DWARF 2–4 CU 头字段顺序写反**（实现）：`version < 4` 分支把 `addr_size` 读在
   `abbrev_off` 之前；语料无 v2/v3 样本，只有合成单测能暴露。按规范改正并留
   `test_dwarf2_cu_header_field_order` 钉住。
6. **审计 `readable` 默认值**（实现）：不存在的来源报 `readable=True`；改为默认等于
   `present`，避免「可读但没找到声明」的误读。
7. **测试期望值自身错 3 处**（验收器）：`DW_OP_regx 5` 是 rdi 不是 rsi；`DW_OP_fbreg -8`
   的 SLEB 编码是 `0x78` 不是 `0xf8`；「无定义」应进 abstain 而非 partial。

### 7.2 新增测试

- 合成 DWARF：abbrev/CU/DIE、exprloc、loclist、`regx`、`piece`、`fbreg`、未知 opcode、
  v2 头顺序、`.zdebug_` 名称规范化；
- 绑定纪律：声明绑定、缺定义 abstain、多段 partial、零形参、无声明、间接目标、PE 基址换算；
- 真实样本：两个 Go 样本的声明证据、PE/ELF 地址基、无声明样本分母守恒、审计结构。

### 7.3 回归

- `python -m pytest -q`：**408 passed**（含新增 20 项）；
- 12 个 `tests/verify_*.py`：exit 0。`verify_fingerprint.py` 不带参数会以 exit 2 提示
  「必须同时给 `--all --matrix`」，按该参数运行结果为 PASS（132/132，误报 0）。

---

## 8. 边界与下一步

- **PDB 形参位置**：RSDS/TPI 已定位，CodeView 位置记录未解码 → 本轮无法验证；补上后
  可把 hello_rust.exe 的 1029 个站点纳入绑定分母。
- **DWARF v2/v3**：v2/v3/v4 共用同一 CU 头分支，已有 v2 合成单测；语料 0 条，需要有
  v2/v3 的真实样本才能验证。
- **栈/帧基址形参**：需要栈帧模型（跨函数栈平衡、`push/pop` 配平），本轮 abstain；
  linux 99 / exe 155 条形参弃权属此类。
- **缺 `low_pc` 的声明**：linux 1011 / exe 996 个 DIE 无法与站点地址对齐；本样本无站点
  命中，但口径上计入 `no_declaration`，不是「声明不存在」。
- **运行时才能确定的间接目标**：结构上做不到，不列入后续承诺。
