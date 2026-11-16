# 青铜任务：rekit M4 第三单元 —— 基本块规则显式化 + CFG 边分级

日期：2026-11-15 ｜ 前置：M4 第二单元（递归下降 + 基本块）已收口
用户口径：先明确上一单元基本块是否做了；若没做才补。CFG 必须区分确定边与疑似/
无法判定，间接跳转标明未解析、不猜目标；用 `.pdata`/`.eh_frame` 边界约束 CFG，
跨函数边单列；完成后全量 pytest + 既有三个验证脚本零回归。

## 0. 上一单元的基本块：做了

- `_build_blocks` 上一单元已实现并在 `descend` 中调用；CLI 输出块数，
  cli-64.exe **338** 块、dyn_static **18705** 块、avx_dense **4** 块。
- 已有断言 `test_blocks_partition_every_instruction_exactly_once`：每条指令恰好
  属于一个块、块内连续、后继都在已解出集合内。

缺的是规则陈述、函数归属和 CFG 边，本单元补齐，原有切块语义不变。

## 1. 块切分规则（写死）

- **leader**：函数入口种子 / 直接分支目标 / jmp·jcc 后的顺序地址 / 函数
  （origin）变化处。
- **终结符**：`ret` `hlt` `trap` `ud2` `jmp_rel` `jmp_ind`。
- **call 不终结块**：`call_rel`/`call_ind` 后顺序流继续；函数内 CFG 只有
  fallthrough 边，调用目标单列到 `cfg.calls`。
- **块与函数**：每块带 `function/range/boundary/authority`；块内每条指令的
  origin 必须等于块 function；块绝不跨函数合并；顺序流进入另一个已声明函数
  立即截断，交给该函数自己的种子。
- **块与 CFG**：CFG 节点是块，边只连块首；跳进指令内部的目标本身已因
  “分支目标”成为 leader。

## 2. CFG 五类边（互斥，不合并）

| 类别 | 判定 |
|---|---|
| definite 确定 | 源函数有权威声明 end、根非启发式；目标已解出且同函数 |
| speculative 疑似 | 目标已解出且同函数，但函数边界未声明，或根来自启发式 |
| cross_function 跨函数 | 目标已解出但属于另一个函数，单列，附 `to_boundary` |
| undecoded 无法判定 | 直接目标未解出（数据/填充/VEX abstain） |
| unresolved 无法判定 | 间接 jmp/call，`target=None`，不猜目标 |

调用边（`calls`）单独一组：definite / undecoded / unresolved。

每样本（`verify_recdesc.py --all`，`cfg_check` 独立重算）：

| 样本 | 确定 | 疑似 | 跨函数 | 未解出 | 未解析 | 调用 定/未解/未解析 | 函数 声明/未知 |
|---|---|---|---|---|---|---|---|
| cli-64.exe | 394 | 0 | 9 | 0 | 33 | 8/0/5 | 41/44 |
| minidll.dll | 0 | 0 | 0 | 0 | 0 | 0/0/0 | 0/5 |
| bin_ls.elf | 5340 | 0 | 82 | 80 | 9 | 49/112/4 | 331/0 |
| dyn_pie | 0 | 13 | 1 | 0 | 2 | 0/1/0 | 2/4 |
| dyn_nopie | 0 | 10 | 1 | 0 | 2 | 0/0/0 | 3/4 |
| dyn_static | 26882 | 15 | 313 | 42 | 123 | 702/16/11 | 1061/5 |
| avx_dense.exe | 0 | 3 | 0 | 0 | 0 | 0/0/0 | 0/2 |

要点：dyn_pie/nopie 只有少数 FDE 带 range，其余种子无结束界，所以没有一个
“确定”边，全部记疑似；avx_dense 无任何声明边界，3 条边全疑似；cli-64 每个
`.pdata` 函数都有 end，确定边全部同函数。这是分类正确，不是边数多少。

## 3. 函数边界作为 CFG 约束

- 范围只取权威声明：`.pdata EndAddress`、FDE `address_range`、`st_size`；
  合并同址多来源时取较大 end，冲突写进 seeds details。
- 分支/调用目标：在当前范围内 → 沿用 origin/end；落在另一声明范围 → 改属目标
  函数并记跨函数；不在任何声明范围 → **不得算进当前已声明函数**，另起
  `boundary=unknown` 的根，仍记跨函数并标 `to_boundary=unknown`。
- 跨函数边只出现在 `cfg.edges.cross_function`，带 `to_function/to_boundary`，
  永不进入 definite/speculative；CLI 文本先列 5 条，JSON 全量。
- 函数末尾不是顺序边：块结束地址等于声明 end 时，后面即使被别的函数解出，
  也不连 fallthrough（那是函数边界，不是控制流）。

## 4. 验收与回归

| 命令 | 结果 |
|---|---|
| `pytest tests -q` | **242 passed**（235 + 本单元 7 项） |
| `verify_disasm.py --all` | 分歧 0 / 环境错误 0，PASS |
| `verify_map.py --all --matrix` | 2402/2402 命中，失配 0，PASS |
| `verify_iat.py --all --selftest` | 失配 0，selftest 检出，PASS |
| `verify_recdesc.py --all` | PASS（新增 `cfg_check` 五类边互斥/归属检查） |
| `verify_recdesc.py --all --selftest` | 注入 1 条长度错误被检出，PASS |

行为变化：为守住“界外代码不算进有声明边界的函数”，目标既不在当前范围、也不在
任何声明范围时改起 `boundary=unknown` 新根；dyn_static 因此少解 12 条越界指令
（83007→82995），其余样本条数不变。新增检查只加严，未删旧断言、未放宽阈值。

## 5. 已知限制

- 无声明边界的函数（大量派生调用目标）内部边只能记疑似，无法证明没跨函数。
- 间接 jmp/call 目标不解析，其后代码不可达；跳转表未恢复。
- 不做数据/代码判别；VEX/EVEX abstain 按上一单元口径量化，不冒充解出。
- CFG 只覆盖 `.text` 单节、x86-64。

## 6. 交付物

- `work/rekit/recdesc.py`（块规则、`_build_cfg`、CLI CFG 摘要）
- `work/tests/test_recdesc.py`（+7 项：块函数域、确定边、疑似互斥、间接不猜、
  跨函数单列、AVX 无确定边、计数一致）
- `work/tests/verify_recdesc.py`（`cfg_check` + 每样本 CFG 行）
- `work/evidence_cfg_2026-11-15.log`
