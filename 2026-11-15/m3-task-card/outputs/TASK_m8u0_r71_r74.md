# M8-U0：R71/R74 落地与两处口径扩展

日期：2026-11-16　｜　范围：`rekit/callgraph.thunk_of`、`rekit/recdesc.collect_heuristic_seeds`、`tests/verify_callfacts.py`、`tests/verify_sitejoin.py`
证据：`work/evidence_m8u0_scripts.log`（13 条命令全 EXIT=0）、`work/evidence_m8u0_pytest.log`（383 passed）

---

## 0. 结论

| 用户要求 | 状态 | 一句话 |
|---|---|---|
| ① `verify_callfacts` 的 D 段按 R74 独立化，且"独立化后仍能失败" | ✅ | 写集合改由 objdump 文本重算，不再 import `callgraph._effects`/`_Ctx`；`--selftest` 正例检出、负例不误报；注入错误必 FAIL |
| ② M8-U0 两个口径扩展（`thunk_of` 按 R71、序言按 opcode） | ✅ | 代码已落；三样本实测**数字一个都没变**，属判据对齐而非修实测缺陷 |
| ③ 其余私有符号引用逐个给结论 | ✅ | 清点得 14 个不同符号（25 处代码行）；本轮独立化 3 个、消除 2 个，其余 9 个给出保留理由 |
| 本轮有无已公布数字变化 | — | **没有**。全部数字与本轮前一致，新增的只有诊断行 |

---

## 1. 第一优先：`verify_callfacts` D 段独立化（R74）

### 1.1 改造前的问题

D 段（栈槽纪律）原先这样造期望值：

```python
ctx = CG._Ctx(path, res, ".text")
defs = _defs_of(ctx, addr)      # 内部逐条调用 CG._effects(rec)
```

这就是 R74 明令禁止的形态：**校验器直接 import 被测模块的私有判定函数**。只要 `_effects` 漏判某条指令的写，校验器会用同一个漏判去"证明"事实层没违规——两条路径共用一个错误。

### 1.2 新判据路径

`_objdump_writes(path, text_va)`：跑外部 `objdump -d -M intel --no-show-raw-insn`，把 `.text` 的反汇编文本解析成 `{addr: (mnemonic, [operands])}`，再按 `_writes(mn, ops)` 独立判定该指令写哪些 64 位通用寄存器。整条链路只依赖：

- 外部工具输出（binutils 2.47 的 objdump）；
- 本文件内的 `_GPR64` / `_ALIAS` 别名表与 `_NO_DEST` / `_IMPLICIT` / `_NO_WRITE_XFER` 规则表。

不经过 `rekit` 的任何私有函数（`expr` 只用于 `verify_sitejoin`，`verify_callfacts` 里已无 `expr._` 引用）。

地址对齐：不依赖 `<.text>:` 符号头（stripped 的 `bin_ls`/`dyn_static` 没有），改为跟踪 `Disassembly of section .text:`，用该节第一条指令地址减 `recdesc` 的 `.text` 起始 VA 求 `delta`，之后一律 `addr - delta`。PE 的 ImageBase、ELF 是否为 PIE 都不写死。

### 1.3 独立路径与实现路径本来就可能不同的点，以及处理方式

这是用户点名要说明的部分。逐条：

| # | 差异点 | 实现侧（`callgraph._effects`） | 独立侧（objdump 文本） | 处理方式 |
|---|---|---|---|---|
| 1 | **数据来源** | `expr.decode` 的 `rec` 结构、按 `family` 分类 | 外部反汇编文本、按助记符 | 这是独立性的来源本身；不试图对齐内部结构 |
| 2 | **`call` 的 rsp 写是暂态** | 对 `call` 只取间接操作数，**不记 rsp 写** | `call` 压返回地址→返回即复原，对"窗口内栈槽基址是否仍有效"无持久影响 | **本轮实测踩到**：首版把 `call` 记成写 `rsp`，三样本报出 23/28/380 条"违规"，逐条打印后**全部**是同一种误报（见 1.4）。已把 `call`/`jmp`/`lcall`/`ljmp` 归入 `_NO_WRITE_XFER`（不写 GPR）；`ret` 保留 rsp 写（它持久抬高 rsp） |
| 3 | **目的操作数约定** | 按 `family` 精确分类，`cmp`/`test` 无目的 | 只建模"首操作数=目的"，`_NO_DEST` 白名单兜住无目的的助记符 | 独立侧保守：宁可多判"写了"（更易 FAIL），不漏判 |
| 4 | **寄存器别名** | 走 `expr._REG64` 的规范名 | objdump 可能打 `ebp`/`esp`/`r8d`/`al` | `_ALIAS` 归一到 64 位名（含 r8–r15 的 d/w/b 后缀循环生成），否则"写了 ebp"会被漏判成"没写 rbp" |
| 5 | **未建模助记符** | 有 `intrinsic` → 截断窗口 | 首操作数既非寄存器也非内存、且不在隐式表 → 返回 `None`（**不结论**） | 单列 `unmodeled` 计数；若 `unmodeled*2 > lookups`（>50%）直接 FAIL，判据失效必须暴露而不是静默通过 |
| 6 | **指令集合来源** | 逐条 `expr.decode` | objdump 线性反汇编（会把数据也反汇编） | 取**交集**：只对 `recdesc` 已解出的地址查表；objdump 多出来的行不参与判定 |
| 7 | **证明方向** | 正面判"有没有写" | **只证伪**：报出写 → FAIL；说"没写"不作为通过依据 | 文档与代码注释都写死这条；这也是 `unmodeled` 必须单列的原因 |

第 5 条与第 7 条是这套判据的诚实边界：它能抓"实现漏判"，不能替实现背书"没漏"。

### 1.4 能失败的自证

三样本实测覆盖后**违规 0**，而真实数据里实现已经把可疑情况转成 abstain，所以不能靠真实数据证明校验器不是空转。`--selftest` 直接伪造事实走同一条 D 段代码：

**首版误报的归因证据（说明判据确实在判东西）**：把 `call` 当写 rsp 时，三样本报 23 / 28 / 380 条，全部形如

```
cli-64.exe: 槽事实 [rsp+100] @0x12f6 的基址 rsp 在 0x1313 被改写
  → 0x1313 是 `call QWORD PTR [rip+0x1d0f]`（中间调用，返回即复原 rsp）
```

这才是真正的"能失败"：判据在真实样本上抓到过 431 条，只是这 431 条经人工归因后确认是独立侧口径错，改的是**独立侧**（第 2 条差异），不是实现。

**自证输出**（`python tests/verify_callfacts.py --selftest`）：

```
[selftest] 正例 tests/fixtures/cli-64.exe 伪造槽事实 [rsp-0x8] @0x1040（0x104f 已改写基址）
[selftest] 已检出（独立化后仍能失败）→ 通过
[selftest] 负例 0x1024 干净窗口未误报 → 通过
```

- 正例：在"块首定义、中途被改写"的窗口里塞一条槽事实 → 必须报违规；
- 负例：在"中间没有任何 rbp/rsp 写"的干净窗口里塞同样的槽事实 → 必须不报（防止判据恒 FAIL）。

### 1.5 独立判据的覆盖实测

| 样本 | 窗口内查写次数 | objdump 缺地址 | 未建模 | 违规 |
|---|---|---|---|---|
| cli-64.exe | 501 | 0 | 0 (0.0%) | 0 |
| bin_ls.elf | 602 | 0 | 0 (0.0%) | 0 |
| dyn_static | 6537 | 0 | 0 (0.0%) | 0 |

窗口内助记符分布（dyn_static 前 6）：`mov 4260 / call 1167 / lea 556 / xor 136 / add 89 / sub 58`。都是已建模助记符，因此 0 未建模是真实的，不是判据失效。

---

## 2. 第二：M8-U0 两处口径扩展（R71）与带前缀实测

### 2.1 `thunk_of`（`rekit/callgraph.py`）

口径从「函数体恰好一条指令」放宽为「**无副作用填充\* + 一条 `jmp [槽]`**」，且槽必须能回指导入。判定按 R71 跳前缀取 opcode：

- 新增 `_is_padding(raw_hex)`：跳过 legacy 前缀与 REX 后，opcode ∈ `{0x90 (nop), 0xCC (int3)}`，或 `0F 1E` / `0F 1F`（endbr64 / nop dword）；
- `lea rcx,[rip+x]; jmp [rip+y]` 是**带参数的跳板**（有可观察效果），明确不在本口径内。

### 2.2 序言识别（`rekit/recdesc.py`）

`PROLOGUE_PATTERNS` 字面字节模式改为 `_prologue_len(blob, i)` 按 opcode 判：

- 首字节必须是 `0x55`（`push rbp`）；
- 之后跳 legacy 前缀；**REX 只允许 0x48**；
- 再判 `89 E5`（`mov rbp,rsp`）或 `8B EC`（MSVC 的 `mov rbp,rsp` 变体）。

`PROLOGUE_PATTERNS` 保留但标注「仅作文档参考」，不再参与判定。

### 2.3 带前缀情况的实测数量

**序言**

| 样本 | 字面模式命中 | opcode 判据命中 | 差 | 55 与 mov 之间夹 legacy 前缀 | `41 55` 假匹配 | REX≠0x48 的假阳性 |
|---|---|---|---|---|---|---|
| cli-64.exe | 1 | 1 | 0 | 0 | 0 | 0 |
| bin_ls.elf | 1 | 1 | 0 | 0 | 0 | 0 |
| dyn_static | 25 | 25 | 0 | 0 | 0 | **2** |

dyn_static 那 2 处是 `55 4c 89 e5`（`push rbp; mov r12, rbp`，REX=0x4C 而非 0x48）：

- `0x44f886`、`0x46155f`

两处都在指令中间（非函数入口）。**若允许"任意 REX"就会被误判成序言种子**，从半条指令处开始递归下降——这正是"种子落在指令中间"的已知危险。所以 REX 必须恰为 0x48，实测有 2 个反例支撑。

**thunk**

| 样本 | 旧口径（单条 jmp） | 新口径（填充\*+jmp） | 差 | 参数桩（lea+jmp，不命名） |
|---|---|---|---|---|
| cli-64.exe | 28 | 28 | 0 | 3 |
| bin_ls.elf | 0 | 0 | 0 | 0 |
| dyn_static | 0 | 0 | 0 | 0 |

**jmp 尾指令带前缀的情况**（R71 真正起作用的地方）：

| 样本 | jmp 尾带 legacy 前缀 | jmp 尾带 REX 前缀 | 前导填充带前缀 |
|---|---|---|---|
| cli-64.exe | 0 | **3** | 0 |
| bin_ls.elf | 0 | 0 | 0 |
| dyn_static | 0 | 0 | 0 |

cli-64 那 3 处是 `48 ff 25`（REX.W + `FF /4`，仍是 RIP 相对），槽都能回指导入：

```
fn=0x1d54 尾指令 0x1d81  bytes=48 ff 25 e0 12 00 00 → KERNEL32.dll!TerminateProcess
fn=0x21e0 尾指令 0x21e7  bytes=48 ff 25 92 0e 00 00 → KERNEL32.dll!InitializeSListHead
fn=0x23e8 尾指令 0x23ef  bytes=48 ff 25 62 0c 00 00 → KERNEL32.dll!SetUnhandledExceptionFilter
```

若按首字节 `ff 25` 判，这 3 个跳板会漏掉，命名数 28 → 25。`_rip_mem` 本身已跳前缀，所以实测数字没变；这 3 处是"前缀确实存在且必须跳"的实证。

### 2.4 这节的诚实结论

两处扩展都是**判据正确性对齐**，不是修实测缺陷：三样本上序言命中数（1/1/25）与 thunk 命名数（28/0/0）**一个都没变**。变的是"为什么对"——从"恰好这批字节长这样"变成"按指令编码规则判"。dyn_static 的 2 个 REX 反例与 cli-64 的 3 个 REX 前缀跳板，是这两条判据在真实样本上唯一的可观察差异点。

---

## 3. 第三：私有符号引用逐个结论

清点方式：`tests/**/*.py` 中所有 `模块._符号` 形式的**代码行**引用（注释与 docstring 不计）。
结果：**14 个不同私有符号，25 处代码行，分布在 6 个文件**。

上一轮汇总口径记作 13 处；本轮以代码逐行为准重新清点，差异来自 `sitejoin._slots` 上轮未计入、`sitejoin._opcode_of` 只出现在 docstring 里（不计）、以及 `verify_callfacts` 的两处（`CG._effects`、`CG._Ctx`）本轮已消除。

### 3.1 必须独立化（本轮已改）

| # | 符号 | 位置 | 为什么是判据 | 处理 |
|---|---|---|---|---|
| 1 | `sitejoin._text_lines` | verify_sitejoin.py:134 | 用它重算出的 `lines` 去比 `line_text`；它错则两边同错 | 改为本文件内 `_JOIN_LINES(node)`（body+term 拼接），契约在此独立复述 |
| 2 | `sitejoin._slice` | verify_sitejoin.py:142 | 用它重算切片标注，再比模块输出，恒真 | 改为 `_JOIN_SLICE(idx, nbody)` |
| 3 | `sitejoin._KIND_ATTR` | verify_sitejoin.py:157,160 | 直接当"期望归因"用，模块改了表校验器跟着改 | 改为 `_KIND_ATTR_EXPECT`（17 条契约硬编码）；模块若新增种类，C 段报"未知冲突种类" |

### 3.2 本轮消除（不再引用）

| 符号 | 位置 | 说明 |
|---|---|---|
| `CG._effects` | verify_callfacts.py（D 段） | 见 §1，改 objdump 独立判据 |
| `CG._Ctx` | verify_callfacts.py（D 段） | 同上；`_Ctx` 实例不再创建 |

### 3.3 可以保留（逐个理由）

| # | 符号 | 位置 | 性质 | 保留理由 |
|---|---|---|---|---|
| 4 | `expr._next_flags` | test_expr.py:144 | 被测单元本身 | 白盒单测的对象就是它；跨层正确性由 verify_expr 的表达式文本 sha256 基线兜住 |
| 5 | `expr._cond_text` | test_expr.py:145,175 | 同上 | 同上 |
| 6 | `recdesc._parse_eh_frame` | test_recdesc.py:71 | 被测单元 | 单测 FDE 解析；函数入口总数由 verify_recdesc 的基线交叉 |
| 7 | `disasm._decode_any` | test_recdesc.py:96 | 造测试输入 | 该用例断言的是 recdesc 的边界，`_decode_any` 只是构造手段；其自身正确性由 verify_disasm 与 objdump 逐行对齐覆盖（1694/26353/22523 条全对齐） |
| 8 | `recdesc._EDGE_CLASSES` | test_recdesc.py:340 | 枚举闭包自洽 | 检验"发出的边类别都在声明集合里"，本身就是模块内部一致性属性 |
| 9 | `recdesc._CALL_CLASSES` | test_recdesc.py:342 | 同上 | 同上 |
| 10 | `sitejoin._text_lines` | test_sitejoin.py:76,148 | 白盒单测 | 同一符号在 verify_sitejoin 已独立复述；单测保留私有引用是合理白盒 |
| 11 | `sitejoin._slice` | test_sitejoin.py:79 | 同上 | 同上 |
| 12 | `sitejoin._KIND_ATTR` | test_sitejoin.py:101 | 同上 | 同上 |
| 13 | `sitejoin._is_call_line` | test_sitejoin.py:150 | 同上 | 同上 |
| 14 | `switchcand._scan_entries` | test_switchcand.py:175,185,195 | 被测单元 | 单测跳转表项扫描；候选层整体由 verify_switchcand 的拒绝理由账目覆盖 |
| 15 | `expr._import_names` | verify_expr.py:50 | **取输入不是判据** | 它只给 `lift_function` 提供导入名映射；被比的判据是表达式文本。该映射的正确性由 verify_iat 用外部真值 + `objdump -p` 交叉核对（E6/E7） |
| 16 | `sitejoin._decoded_calls` | verify_sitejoin.py:85 | **被测对象** | 它不是期望值来源；期望值来自同文件 `_calls_alternate`（走 `expr.decode` 另一条路径）。此处引用是"拿被测输出"，独立性由对照物保证 |
| 17 | `sitejoin._is_call_line` | verify_sitejoin.py:204 | 仅定位注入点 | 判据是注入后 `check()` 是否报 `struct_*` 冲突，不由 `_is_call_line` 决定 |
| 18 | `sitejoin._slots` | verify_sitejoin.py:275-281 | monkeypatch 自证 | 只用于"把模块某步打坏，看校验器是否 FAIL"的自证，不参与正常判定 |

归纳原则：**白盒单测可以直接摸被测私有函数**（#4–#10、#14）；**验收脚本里的私有引用分三类**——取输入（#15，正确性另有独立覆盖）、取被测输出（#16，对照物独立）、仅作定位/自证（#17、#18）——这三类可以保留；**只有"私有函数产出被当成期望值"这一类必须独立化**（#1–#3）。

---

## 4. 数字总账：本轮有没有已公布数字变化

**没有。** 逐项核对：

| 数字 | 本轮前 | 本轮后 | 变化 |
|---|---|---|---|
| pytest | 383 passed | 383 passed | 无 |
| 验证命令 | 12 条全 EXIT=0 | **13 条**全 EXIT=0（新增 `verify_callfacts --selftest`） | 命令数 +1，均为新增自证 |
| cli-64 调用点 / 节点 / 环 | 153（98/55）/ 85 / 0 | 同 | 无 |
| bin_ls 调用点 / 节点 / 环 | 1154（1116/38）/ 331 / 2 | 同 | 无 |
| dyn_static 调用点 / 节点 / 环 | 3609（3457/152）/ 1089 / 17 | 同 | 无 |
| callfacts 站点 / 事实 / 弃权 | 153·450/309·225 ；1154·3803/2293·1257 ；3609·11043/6466·4012 | 同 | 无 |
| 栈槽事实 / 槽弃权 / 窗口截断 | 96/14/3 ；378/14/51 ；2951/82/164 | 同 | 无 |
| 序言种子命中 | 1 / 1 / 25 | 同 | 无（判据换、数字不变） |
| thunk 命名 | 28 / 0 / 0 | 同 | 无（判据换、数字不变） |
| sitejoin 键/冲突 | 153·0 ；1154·0 ；3609·0 | 同 | 无 |

新增的只有**诊断输出**，不是结论变化：

- `verify_callfacts` 新增一行 `独立判据（objdump）: 窗口内查写 N 次 ｜ 未建模 M ｜ 违规 K`；
- `verify_sitejoin` 的期望归因表从 import 改为本地契约（值完全相同，17 条逐项一致）。

读者仍以 M7 收口那份数字总账为准（`outputs/TASK_m7_closeout.md` §4），本轮不推翻其中任何一项。

---

## 5. 回归证据

| 项 | 命令 | 结果 |
|---|---|---|
| 单测 | `python -m pytest tests -q` | 383 passed（29–30s），日志 `work/evidence_m8u0_pytest.log` |
| 验证脚本 | 13 条（见下） | 全部 EXIT=0，日志 `work/evidence_m8u0_scripts.log` |

13 条命令：`verify_disasm --all`、`verify_recdesc`、`verify_expr`、`verify_map`、`verify_iat`、`verify_fingerprint --all --matrix`、`verify_switchcand`、`verify_struct`、`verify_callgraph`、`verify_callfacts`、**`verify_callfacts --selftest`**、`verify_sitejoin`、`verify_sitejoin --selftest`。

环境：`PYTHONIOENCODING=utf-8`、`LC_ALL=C`、binutils 2.47 的 `bin` 前置到 PATH（R74 独立判据需要 objdump）。

---

## 6. 规则与返工

新增/沿用规则：

- **R71**（沿用，本轮首次落到 `thunk_of` 与序言识别）：判指令类别必须跳 legacy 前缀 + REX 取 opcode；`ff` 还须核 ModRM.reg ∈ {2,3}。
- **R74**（沿用，本轮首次落到 `verify_callfacts` D 段）：每条硬不变量至少一条独立来源路径；只写"与被测实现一致"不算验收。
- **R76（新）**：独立判据遇到"暂态写"（如 `call` 压栈/返回复原）不得计入"持久改写"，否则判据会产生系统性误报；同类情况必须逐条归因而非调宽判据。
- **R77（新）**：验收脚本引用被测私有符号时，按"取输入 / 取被测输出 / 仅定位或自证 / 当期望值"四类定性；只有最后一类必须独立化，其余须在文件头写明理由。

本轮返工：

1. `_objdump_writes` 首版依赖 `<.text>:` 符号头 → stripped ELF 抛错 → 改为跟踪 `Disassembly of section .text:` + 首指令推 delta。
2. 独立判据把 `call` 记成写 rsp → 三样本 23/28/380 条误报 → 归因后改判据（R76）。
3. `--selftest` 首版只做正例 → 补负例（干净窗口不得误报）。
4. 批量验证脚本用 `$args`（PowerShell 自动变量）与 `1..0` 反向切片 → 11 条命令假 EXIT=2 → 改 `$argv` 并处理单元素。

时点教训：批量跑验证时，**退出码不等于结论**——`$args` 被覆盖时 argparse 仍以 2 退出，看起来像"验证失败"，实际是调用脚本错。批量脚本本身也要自检参数拼装。

---

## 7. 边界

- 独立判据只**证伪**：它说"没写"不作为通过依据；`unmodeled > 50%` 会主动 FAIL。
- `_writes` 只建模"首操作数=目的"+少量隐式写；`xchg/xadd/cmpxchg`、`push/pop`、`mul/div`、`cmov/setcc` 已覆盖，浮点/向量寄存器不在判定范围（也不影响 rbp/rsp 基址结论）。
- `thunk_of` 仍不命名 `lea rcx,[rip+x]; jmp [rip+y]` 参数桩（cli-64 实测 3 处）。
- 序言扫描仍可能落在数据里（`0x55` 在数据中很常见），成功率单独统计，不并入权威种子。
- 本轮未改动任何判据阈值、未放宽任何 `KNOWN_HARD`。
