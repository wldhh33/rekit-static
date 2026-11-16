# TASK — M7-U2：带前缀 call 漏检修正 + 重定标（2026-11-16）

> 授权：2026-11-16 用户裁决「批准按 §14 执行 M7-U2：修带前缀 call 的漏检并重定标」。
> 前置约束来自 `outputs/TASK_m7u1_join.md` §14（修法、重跑范围、对比字段、不是放宽的四条判据、零失败）。

## 1. 范围

| 项 | 内容 |
| --- | --- |
| 改了什么 | `callgraph._call_insns`（漏检根因）、`callgraph._Ctx.rip_mem_target` / `thunk_of`（同类判据，审计 #3/#4）、`tests/verify_callgraph.py` 与 `tests/test_callgraph.py`（校验器自身同错，见 §6）、`tests/test_sitejoin.py` / `tests/verify_sitejoin.py`（重定标 + 覆盖注入） |
| 没改什么 | `recdesc`、`disasm`、`expr`、`struct`、`switchcand`、`callfacts` 一行未动；`tests/baselines/definite_baseline.json` 一字未改 |
| 判据 | 跳过 legacy 前缀（0x26/2E/36/3E/64/65/66/67/F0/F2/F3）与 REX（0x40..0x4F）后取 opcode；`e8` = 直接 call，`ff` 须 ModRM.reg ∈ {2,3}；仍交 `expr.decode` 复核 `family == "call"` |
| 未采用的简化 | 「跳前缀后见 `ff` 就算 call」会误收 28 / 5 / 112 条带前缀的 ff 非 call/jmp（inc/dec/push）；「按 raw 首字节」就是原缺陷本身 |

## 2. 修法与代码位置

1. `rekit/callgraph.py` 新增 `_LEGACY_PREFIX` 与 `_opcode_of(raw)`（返回 opcode 与下标）。
2. `_call_insns`：先 `_opcode_of`，`e8` 放行；`ff` 读紧随的 ModRM（组扩展位不受 REX.R 影响）并只放行 reg ∈ {2,3}；最后 `expr.decode` 复核 family。
3. `_Ctx._rip_mem(va)`：跳过前缀后再读 opcode/ModRM/disp，长度按实际前缀数算（**不写死 6 字节、disp 不写死 +2**）；`rip_mem_target` 保留「FF /2 或 /4 + [rip+disp32]」语义，`thunk_of` 只接受 reg=4（jmp）。
4. `tests/verify_callgraph.py`：E8 集合与逐边判定改用独立的 `_opcode()`（不复用被测实现，但同样跳前缀）。
5. `tests/test_callgraph.py`：同上，并把「直接调用点 == E8 集合」扩到 dyn_static（原只测 bin_ls）。

## 3. 修正前后对比表（三样本全字段）

### 3.1 cli-64.exe（无带前缀 call，预期不变）

| 字段 | 修正前 | 修正后 | 说明 |
| --- | --- | --- | --- |
| 调用点 | 153 | 153 | 不变 |
| 直接 / 间接 | 98 / 55 | 98 / 55 | 不变 |
| decoded | 63（64.29%） | 63（64.29%） | 不变 |
| plt_or_import | 35（35.71%） | 35（35.71%） | 不变 |
| unresolved | 0（0.00%） | 0（0.00%） | 不变 |
| 函数节点 / 环 | 85 / 0 | 85 / 0 | 不变 |
| 键 / 已解出 call / 两层都漏 | 153 / 153 / 0 | 153 / 153 / 0 | 不变 |
| aligned / 冲突 | 153 / 0 | 153 / 0 | 不变 |
| expr 文本 sha256 | `60029159…79c0` | `60029159…79c0` | 逐字相同 |

### 3.2 bin_ls.elf（+13，全为间接）

| 字段 | 修正前 | 修正后 | 说明 |
| --- | --- | --- | --- |
| 调用点 | 1141 | **1154** | +13 |
| 直接 / 间接 | 1116 / 25 | 1116 / **38** | 13 条全为 `41 ff d6`、`41 ff 54 24 30` 类（FF /2、/3 + REX） |
| decoded | 428（38.35%） | 428（38.35%） | 分子分母均不变 |
| plt_or_import | 688（61.65%） | 688（61.65%） | 不变 |
| unresolved | 0（0.00%） | 0（0.00%） | 不变 |
| 候选层 high/medium/low | 1 / 2 / 22 | 1 / 2 / **35** | 新增 13 条都是寄存器/基址+索引，只能到 low |
| 函数节点 / 环 | 331 / 2（self 2） | 331 / 2（self 2） | 不变（间接目标不可静态确定） |
| 键 / 已解出 call / 两层都漏 | 1141 / 1154 / **13** | 1154 / 1154 / **0** | 覆盖由「有缺口」变「完整」 |
| aligned | 1141 | 1154 | 新增站点全部在三层对齐 |
| 冲突 | 13（硬 13） | **0（硬 0）** | 13 条 `call_site_missing` 全部转为正常站点 |
| callfacts abstain / 槽弃权 / 窗口截断 | 1230 / 14 / 50 | 1257 / 14 / **51** | 弃权与截断**只增不减** |
| expr abstains / sha256 | 608 / `ca75e956…3eb8e` | 608 / `ca75e956…3eb8e` | 文本层逐字不变 |

### 3.3 dyn_static（+53：52 间接 + 1 直接）

| 字段 | 修正前 | 修正后 | 说明 |
| --- | --- | --- | --- |
| 调用点 | 3556 | **3609** | +53 |
| 直接 / 间接 | 3456 / 100 | **3457** / **152** | 1 条 `67 e8`（地址长度前缀直接 call）+ 52 条 `43 ff 14 fe` 类 |
| decoded | 3049（88.22%） | **3050（88.23%）** | 分母 +1、分子 +1（新直接调用的目标本就已解出） |
| plt_or_import | 402（11.63%） | 402（11.63%） | 不变（402/3456 与 402/3457 都进位到 11.63%） |
| unresolved | 5（0.14%） | 5（0.14%） | 不变 |
| 候选层 high/medium/low | 0 / 1 / 99 | 0 / 1 / **151** | 新增 52 条间接都是 low |
| 函数节点 / 环 | 1089 / 17（self 15 / mutual 2） | 1089 / 17（self 15 / mutual 2） | 不变 |
| 键 / 已解出 call / 两层都漏 | 3556 / 3609 / **53** | 3609 / 3609 / **0** | 覆盖完整 |
| aligned | 3553 | **3606** | +53；口径差异 3（`struct_function_absent`）保留 |
| 冲突 | 56（硬 53 ｜ 口径 3） | **3（硬 0 ｜ 口径 3）** | 只剩口径差异 |
| callfacts abstain / 栈槽事实 / 槽弃权 / 窗口截断 | 3905 / 2898 / 81 / 163 | 4012 / 2951 / **82** / **164** | 只增不减 |
| expr abstains / sha256 | 9258 / `59959b86…c3516` | 9258 / `59959b86…c3516` | 文本层逐字不变 |

## 4. 受影响基线逐项「旧 → 新 + 字节证据」

| 基线 | 旧 | 新 | 字节证据 |
| --- | --- | --- | --- |
| `tests/baselines/definite_baseline.json`（recdesc 17 项 + 两处文本 sha256） | — | **不变**（文件 sha256 `e6d62a5f…1a6c`，本轮从未写入） | `verify_callgraph` 三次打印「负向基线 17 项」且 PASS；`verify_recdesc` / `verify_disasm --all` 输出与修正前逐行相同 |
| expr 文本哈希（cli / bin_ls / dyn） | `600291…` / `ca75e9…` / `59959b…` | 逐字相同 | 修正前后快照 JSON 的 `expr.text_sha256` 相等；`verify_expr` 输出零差异 |
| `test_sitejoin.py` 数字常量 | keys 1141、间接 25、缺口 >0 | keys **1154**、间接 **38**、缺口 **0** | `sitejoin` counts：`keys=1154`、`graph_edges=1116`、`graph_indirect_no_edge=38`、`call_site_missing=0` |
| `verify_sitejoin.py` `KNOWN_HARD` | `{"call_site_missing"}`（放行） | `set()`（出现任何硬冲突即 FAIL） | 文件 diff；三样本 `hard_conflicts=0` 下 PASS |
| `verify_callgraph.py` / `test_callgraph.py` 的 E8 判定 | raw 首字节 `startswith("e8")` | 跳前缀后的 opcode == 0xE8 | 见 §6：修正前正是这条「同错」让 `67 e8` 在两边同时隐形 |
| `test_callgraph.py` 直接调用点一致性 | 只测 bin_ls | bin_ls + dyn_static | dyn 直接 3457 条与 E8 集合逐点相等 |
| `verify_sitejoin.py` 注入项 | 3 类（state / edge / struct） | 4 类（+ coverage） | 日志：`注入自证: state=检出, edge=检出, struct=检出, coverage=检出` |
| 其余 9 个脚本的判定行 | — | **不变** | 前后日志逐行 diff 仅有第 3 节列出的数字变化与耗时 |

## 5. 四条「不是放宽」判据，逐条证据

1. **冲突数不得减少 —— 但真实缺陷消失导致 13/53 → 0，这不是放宽，证据链**：
   - 校验强度**被收紧**：`KNOWN_HARD` 从放行 `call_site_missing` 改为空集（任何硬冲突即 FAIL）。
   - 检出能力**用注入证明**：新增「两层同时删掉同一直接调用点」注入，报出 `call_site_missing` 且归因 `layer_bug`；原有三类注入与 `--selftest`（打断 `_slots` 报 98 条 `struct_line_count_mismatch`）全部照旧检出。
   - 减少的冲突**逐条有归因**：13/53 条的 key 全部成为正常键，且 `aligned` 同步 +13 / +53（1141→1154、3553→3606），不是删掉不报。
   - 其他冲突种类**不变**：dyn_static 的 3 条 `struct_function_absent`（口径差异）原样保留。
2. **abstain 数不得减少 —— 实测只增**：callfacts abstain 1230→1257、3905→4012；expr abstain 30 / 608 / 9258 完全不变（文本层 sha256 相同）；槽弃权 14→14、81→82。
3. **截断数不得减少 —— 实测只增**：窗口截断 50→51、163→164（新站点落在块边界附近，照实报）。
4. **基线更新逐项旧→新 + 字节证据**：见 §4；`definite_baseline.json` 未改，测试内常量改动都能被 `sitejoin` counts 反查。

## 6. 审计补漏：校验器自身犯了同一个错（新增第 12 项）

修正后首次跑 `verify_callgraph.py` **FAIL**：

```
! dyn_static: 直接边 0x4015db 不是 E8 指令
! dyn_static: 直接调用点集合与 E8 指令集合不一致（3457 vs 3456）
```

原因：该脚本第 73 行 `_call_insns` 式过滤也是 `bytes.startswith("e8")`——**校验器与被测模块共享同一个错误假设**，所以修正前这条不变量「看起来一直成立」。处置：脚本与 `test_callgraph.py` 改用独立的 `_opcode()`（跳前缀），并把一致性检查扩到 dyn_static。

这条要单列，因为它说明 §13 的审计范围漏了 `tests/`：**按「判据」审计必须覆盖校验器**，否则「校验器与被测方同错」会形成自洽假象（R73）。

## 7. 回归（零失败）

| 项 | 结果 |
| --- | --- |
| pytest | **383 passed**，exit 0（`work/evidence_m7u2_pytest.log`） |
| 11 个验证脚本 + `verify_sitejoin --selftest` | **12 条全部 exit 0**（`work/evidence_m7u2_scripts.log`） |
| 前后日志 diff | 仅第 3 节的数字与耗时变化；其余逐行相同 |

## 8. 「数字变好看」需要额外解释的三处

1. **硬冲突 13→0、53→0（最显眼）**：根因修复的必然结果，但单看数字像「问题凭空消失」。解释与证据见 §5.1；尤其注意**校验器变得更严**（`KNOWN_HARD` 空集）且新增覆盖注入仍在报警。
2. **dyn_static decoded 占比 88.22% → 88.23%**：分子分母同时 +1，新发现的是 `67 e8` 直接调用，其目标原本就已在函数集合里——这是「站点可见性」补齐，不代表目标解析能力提升，**不得**据此宣称能力增强。
3. **候选层 low 22→35、99→151**：新增间接调用全部只能到 low（寄存器/基址+索引），high/medium 一条未增——说明修正只补事实、没有顺带把不可知目标「猜」成已知。
4. 反向也要说清：**函数节点数与环数完全不变**（85/331/1089；0/2/17），所以 M6 公布的环数基线不受本次修正影响，不需要重定标。

## 9. 能力边界与遗留

- 本次只解决「枚举层漏 call」；间接调用目标仍不可静态确定（候选层 low 归 low，不进确定集）。
- `thunk_of` 的「函数体仅 1 条指令」口径未变：cli-64 三处 `48 ff 25`（函数体 13/2/2 条指令）仍不按导入跳板命名——这是口径限制，不是前缀缺陷；要扩口径须单独立项。
- `67 e8` 的目标按 `expr.decode` 的既有 rel32 语义计算，未新增地址长度前缀的语义分支（本轮实测目标已解出、三态自洽）。
