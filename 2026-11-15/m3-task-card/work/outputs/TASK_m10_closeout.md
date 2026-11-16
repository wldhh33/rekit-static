# TASK M10 收口：Go ELF/PE 覆盖率十倍差归因 + switchcand 超时定因

日期：2026-11-16　｜　纪律：外部参照、可失败自证、数字分列（R91–R98）

## 0. 结论先行

1. **ELF 8.24% 不是解码缺陷，也不是调度缺陷。** 只用外部 objdump 的边界与助记符，从 `e_entry` 重新做一遍递归下降，得到 **76,168 条指令，与我方逐条相同（对称差 0）**；被解出的指令与 objdump **同址同长（`len_conflict=0`、`ours_only=0`）**。十倍差的根因是**种子源不对称**：该 ELF 没有 `.symtab/.dynsym/.eh_frame`，唯一种子是 `e_entry`；而 Go 引导链把 `runtime.main` 的地址以**数据**形式交给 `runtime.newproc`，`.text` 内不存在任何指向它的直接 `call/jmp`，于是 **8,059 个函数 / 833,323 条指令结构性不可达**。PE 有 `.pdata` 的 7,152 个函数起点，同一解码器覆盖 79.81%。
2. **switchcand 超时是 O(函数数 × 指令数) 的全量重扫，外加每函数重读整个文件。** 用 `cProfile` 定位并修复后：cc1（4.05M 指令）从 **>30 分钟中止降到 8.11 秒**；同时新增**确定性指令步数预算**与 `skipped` 三分法，跳过项单列、绝不混进任何比率的分母。

---

## 1. 第一优先：同一 Go 源码 ELF 8.24% vs PE 79.81%

### 1.1 外部参照（都不是被测实现自己的结果）

| 参照 | 用途 | 结果 |
|---|---|---|
| objdump 2.47 `-d -M intel` | 指令边界 / 助记符 / 分母 | ELF 923,970 条；PE 925,712 条 |
| Go 1.27.3 `debug/gosym` + `.gopclntab` | 独立函数清单 | ELF 8,908 个函数（含 start/end/name） |
| Go 1.27.3 `debug/gosym` + PE `.rdata` 内 pcHeader | PE 具名函数清单 | 8,895 个函数 |
| PE `.pdata` RUNTIME_FUNCTION | 链接器写死的函数区间 | 7,152 个区间 |
| 仅 objdump 驱动的外部下降 | 复现"从 entry 能走到什么" | 76,168 条 / 849 个函数 |

函数清单没有使用 `rekit` 的任何解析结果：`go tool objdump/nm` 对 stripped 二进制直接报"no symbol section"，因此改用 Go 标准库 `debug/gosym` 解析 `.gopclntab`（ELF 是有名节；PE 是在 `.rdata` 里按 pcHeader magic `f1ffffff 00000108` 定位）。

### 1.2 种子源不对称（十倍差在入口就已成立）

| 侧 | 种子数 | 来源 | 结构事实 |
|---|---|---|---|
| ELF | **1** | `e_entry=0x491bc0` | 无 `.symtab`、无 `.dynsym`、无 `.eh_frame`；`.gopclntab` 不参与 recdesc 种子（R45 边界不变） |
| PE | **7,153** | `.pdata` 7,152 + `AddressOfEntryPoint` | `.pdata` 是链接器写死的函数区间，不是启发式 |

### 1.3 逐函数分层计数（分母=外部函数清单；指令数=objdump 边界）

**ELF（8,908 个函数）**

| 分层 | 函数数 | 我方指令 | objdump 指令 | 含义 |
|---|---:|---:|---:|---|
| matched（全函数逐条命中） | 3 | 67 | 67 | 同址同长 |
| partial（入口到达、函数内未走全） | 846 | 76,101 | 90,564 | 见 §1.5：间接跳转 + 尾部填充 |
| seed_missing（一条也没解出） | **8,059** | 0 | **833,323** | 入口从未被调度 |
| len_conflict（同址不同长） | **0** | 0 | 0 | 解码边界无分歧 |
| 函数区间之外的指令 | — | — | 16 | 节内填充/缝隙 |
| 合计 | 8,908 | **76,168** | 923,954 | 与 §1.4 外部复现一致 |

**PE（7,152 个 `.pdata` 区间）**

| 分层 | 函数数 | 我方指令 | objdump 指令 |
|---|---:|---:|---:|
| matched | 6,388 | 550,443 | 550,443 |
| partial | 764 | 175,846 | 201,124 |
| seed_missing | **0** | 0 | 0 |
| len_conflict | **0** | 0 | 0 |
| 合计（区间内） | 7,152 | 726,289 | 751,567 |

PE 另有 12,564 条我方指令落在 `.pdata` 区间之外（thunk/运行时胶水），已如实分列，未并入任何比率。

**关键否证项**：8,059 个 `seed_missing` 函数中，**被已解出代码直接 `call/jmp` 命中的数量 = 0**。即不存在"该调度却没调度"的情况——缺失全部来自不可达，不是漏排。

### 1.4 可失败自证：外部独立下降复现我方结果

脚本只用 objdump 的指令边界与助记符（`call/jmp/jcc` 文本目标），从 `e_entry` 做递归下降，完全不调用 `rekit.recdesc` 的解码/分类：

| 指标 | 外部下降 | 我方 recdesc | 差 |
|---|---:|---:|---:|
| 可达指令 | **76,168** | **76,168** | 0 |
| 可达函数 | **849** | 849（3 matched + 846 partial） | 0 |
| 可达率 | **0.0824356** | 0.0824 | 0 |
| 对称差 | **0** | **0** | — |

若我方解码或调度有缺陷，这一列必然出现差值；实测逐条相等。这是"可失败"的自证：任何一侧多解/少解一条，都会在这里现形。

### 1.5 至少三个具体函数的定位结果

**① `runtime.main`（seed_missing：ELF 0 条 / objdump 278 条；PE 252 条）**

断链点在引导链的函数值参数，不在解码：

```
0x48ecfd: lea rax,[rip+0x2eebec]   # 0x77d8f0   ← runtime.mainPC（数据）
0x48ed04: call 0x492e00                        ← runtime.newproc
0x77d8f0: .quad 0x453520                       ← 该 qword 就是 runtime.main 入口
```

`.text` 内**没有任何直接 `call/jmp` 指向 0x453520**（对全量 objdump 指令统计直接调用者为 0）。`runtime.newproc` 从函数值里取入口，静态直接边在这里断开——**不是种子识别写错，而是 ELF 没有第二个权威种子源可补**。

**② `main.main`（seed_missing：ELF 0 条 / objdump 571 条；PE 559 条）**

直接调用者 0 个；Go 用 `fn := main_main; fn()` 的函数值调用，地址只在数据里。它位于 `runtime.main` 的下游：`runtime.main` 不可达 ⇒ `main.main` 整棵调用树不可达。

**③ `crypto/internal/fips140/sha3.keccakF1600`（seed_missing：ELF 0 条 / objdump 5,121 条；PE 5,119 条）**

3 个直接调用者——`sha3.(*Digest).padAndPermute`、`.writeGeneric`、`.readGeneric`——**自身全部不可达**（不在 849 个已达函数内）。这是"上游整棵子树不可达"的典型，不是本函数解码失败。

**④ `runtime.typesEqual`（partial：ELF 171 / 721；PE 171 / 721）**

首个缺口紧跟一个间接跳转：

```
0x47e905: cmp rdx,0x8
0x47e909: ja  0x47e949                 ← guard
0x47e90b: lea rcx,[rip+0x3070ce]       # 0x7859e0（跳转表）
0x47e912: jmp QWORD PTR [rcx+rdx*8]    ← jmp_ind，recdesc 不跟随（R45）
0x47e915: ……                           ← 8 个 case 块，静态不可达
```

两侧同样是 171/721，说明这是同一解码器在两个格式上的一致行为；缺口来自**函数内间接跳转**，不是格式差异。

**⑤ 反面样本 `runtime.asminit`（"伪 partial"）**：函数体只有 1 条 `ret`，其余 31 字节是 `int3` 填充。objdump 把填充也当指令计数，于是显示 1/32。这类 partial 不是代码漏解，是**分母含填充**——逐函数表必须配合边界说明读。

### 1.6 结论与影响范围

| 问题 | 判定 | 证据 |
|---|---|---|
| ELF 侧解码有缺陷？ | **否** | 对称差 0；`len_conflict=0`；`ours_only=0` |
| ELF 侧种子识别有缺陷？ | **否，但种子源缺失** | 结构上只有 1 个权威种子；外部下降同样只到 8.24% |
| 有该调度却没调度的函数？ | **否** | 8,059 个缺失函数中直接引用命中 = 0 |
| 十倍差归因 | **种子源 + 可达性** | PE `.pdata` 7,152 vs ELF 1 |

**对既有的 ELF 结论的影响（必须加注）**：

- 分子/分母定义（R91：分母=外部 objdump 节内指令数；分子=同址同长）**不变**，历史数字仍可复算。
- 凡把该数值表述为"覆盖率"的地方，必须加注：**"stripped Go ELF，覆盖率 = entry 可达域，不是全二进制可执行域"**；不得据此推断"解码器对 Go ELF 只能解 8%"。
- 凡关于**解码正确性**的结论（同址同长、VEX 四分类、边界一致性）**不受影响**。
- 后续若要让 Go ELF 的覆盖率可与非 Go 样本并列，只能：①显式声明为"可达域口径"；或②新增权威种子源（如解析 `.gopclntab` 的 functab 作为独立种子层），且这会改变统计口径，必须新建指标名，不能与既有"覆盖率"混算。

---

## 2. 第二优先：switchcand 百万级样本超时

### 2.1 瓶颈定位（cProfile，python3.10 样本 627,658 条 / 417 个含间接 jmp 的函数）

| 位置 | 累计耗时 | 原因 |
|---|---:|---|
| `analyze_function` | 105.1 s | 每个函数都重做全局扫描 |
| └ `_func_sets` | 47.3 s | 每函数 `[i for i in res["instructions"] if origin==fn]`，417 × 627,658 ≈ **2.6 亿次** `dict.get` |
| └ `_decoded_index` | 30.5 s | 每函数重建 62 万条指令的 start/end 索引 |
| `analyze_binary` 自身 | 6.3 s | 全量扫描（线性，合理） |
| 每函数 `open(path).read()` | 47.3 s 中的一部分 + 修复后暴露的 19.0 s | cc1 34MB × 1,974 次 ≈ **67GB** 重复读取 |

复杂度是 **O(F × N)**（F=含间接 jmp 的函数数，N=全部指令数）。gdb（F 更大、N=1.54M）与 cc1（N=4.05M）因此分别 709 CPU 秒未完成、>30 分钟中止。

### 2.2 修复（不改任何判定规则）

- 新增 `build_context(res)`：`by_origin`、`blocks_by_func`、`seeds_by_addr`、`decoded`、`idx`、`reader`、`decoder` **各建一次**，全部函数共享只读切片。
- `analyze_function(..., ctx=...)`：默认仍可单独调用（自建 ctx，兼容旧接口）；批量路径必须传 ctx。
- 文件字节只读一次，`TableReader(path, data=...)` 共享同一份数据。

### 2.3 修复前后（同一批样本、同一判定规则）

| 样本 | 指令数 | 含间接 jmp 函数 | 修复前 | 修复后 analyze | 候选数 |
|---|---:|---:|---:|---:|---:|
| python3.10 | 627,658 | 417 | 77 s | **0.89 s** | 104（不变） |
| gdb (PE) | 1,542,816 | 2,081 | 709 CPU 秒中止 | **2.67 s** | 317 |
| cc1 | 4,049,517 | 1,974 | >1,800 s 中止 | **8.11 s** | 64 |

候选数在 python3.10 上与修复前一致（104），说明只改了复杂度、没有任何判定变化。

### 2.4 预算与降级（确定性、可复现、不粉饰）

- **成本模型**：单函数成本 = `len(insns) + len(blocks)`。只依赖输入，不依赖机器速度；同一预算在任何机器上跳过同一批函数。
- **入口**：`analyze_binary(..., step_budget=N)` 总量预算；`max_functions=K` 分批上限。默认 `None` = 全量（行为不变）。
- **三分法**：`functions_analyzed` / `functions_skipped_budget` / `analysis_coverage = analyzed/(analyzed+skipped)`；每个跳过项写入 `budget.skipped_detail`（函数、成本、原因 `step_budget_exhausted` / `function_batch_limit`）。
- **防粉饰**：`skipped` 既不算作已分析，也不算作"无候选"；`stats` 中所有候选/升格计数只来自已分析函数，`render_candidates` 强制打印"分母只含已分析函数"。

实测（`evidence_m10_switchcand_budget.json`）：

| 预算 | analyzed | skipped | coverage | candidates | 备注 |
|---|---:|---:|---:|---:|---|
| 全量 | 417 | 0 | 1.0000 | 104 | 基线 |
| step=50,000 | 384 | 33 | 0.9209 | 57 | 两次运行 JSON 逐字节相同 |
| step=0 | 0 | 417 | 0.0000 | 0 | 不产出任何候选，显式报 417 跳过 |

### 2.5 自证清单（全部可失败）

1. `step_budget=0`：analyzed=0、skipped=417、coverage=0、candidates=0、`functions=[]`（不是"0 候选"冒充"跑完了"）。
2. `step_budget=50000` 两次运行：`json.dumps(sort_keys=True)` 逐字节相等 ⇒ 降级可复现。
3. 跳过的函数不进入 `candidates`/`promoted`；候选数 57 是全量 104 的子集。
4. 空边界负控：`verify_switchcand.py` 仍 0 升格，`promotion_checks.external_boundary=False` 时 `blocked`；`res` 深比较不变。
5. pytest 新增 3 条预算断言（`test_budget_skip_is_separate_from_candidates`、`test_budget_zero_analyzes_nothing_and_reports_it`、`test_budget_is_deterministic`）。

---

## 3. 回归

| 项 | 结果 |
|---|---|
| pytest 全量 | **447 passed**（M9 基线 444 + 新增 3），40.92 s |
| verify 命令 | **19/19 exit 0**：15 个 `tests/verify_*.py`（`verify_fingerprint.py` 按自身要求带 `--all --matrix`）+ 4 个 `--selftest`（coverage/vexaudit/recdesc/disasm） |
| 日志 | `work/evidence_m10_verify.log` |

证据文件：

- `work/evidence_m10_perfunc.json`（逐函数分层）
- `work/evidence_m10_external_reach.json`（外部独立下降复现）
- `work/evidence_m10_gofunc_attribution.json`（汇总 + 函数档案）
- `work/evidence_m10_switchcand_perf.json` / `..._perf_cc1.json`（性能）
- `work/evidence_m10_switchcand_budget.json`（预算自证）
- `work/evidence_m10_verify.log`（回归）

## 4. 新规则

- **R97**：stripped Go ELF 的覆盖率必须同时标注**种子源**（只有一个 `e_entry`）与**可达函数数/总函数数**，并写明"可达域"；禁止表述为全二进制覆盖率。函数清单必须来自外部工具（objdump / `.pdata` / `debug/gosym`），不得用被测实现自证。
- **R98**：超时类分析层必须提供**确定性预算**（按指令步数/函数批次，不按墙钟），并把 `skipped` 作为第三类单列；任何候选/升格比率的分母只含 `analyzed`，且必须并列 `analysis_coverage`，不得让跳过悄无声息地改变比率。

## 5. 已知限制（不掩饰）

1. "外部独立下降"复用了同样的直接边规则（`call/jmp/jcc` 立即目标），它不是第三方反编译器；它证明的是"外部边界 + 相同控制流规则也只得 8.24%"，不是"任何工具都只能 8.24%"。真正的独立证据是 `.eh_frame/.symtab` 缺失与 `mainPC` 数据指针。
2. PE 有 12,564 条我方指令落在 `.pdata` 区间之外，未逐条追；不影响 ELF 归因。
3. `partial` 中混有"尾部填充"（如 `runtime.asminit`），逐函数表不能单独当"漏解"读；报告已给边界例证。
4. 预算成本模型是"指令条数 + 块数"的近似，不含实际解码耗时差异；它保证**可复现**，不保证"预算=墙钟上限"。
5. 本次没有新增样本，也没有改动覆盖率分子/分母定义；所有新旧数字可比性沿用 R91–R96。
