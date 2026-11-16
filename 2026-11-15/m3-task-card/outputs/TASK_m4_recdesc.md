# 青铜任务：rekit M4 第二单元 —— 递归下降 + 基本块划分

日期：2026-11-15 ｜ 依据：CHARTER.md M4 ｜ 前置：M4 首日线性扫描已收口
用户口径：入口种子必须来自权威结构声明并与启发式分列；正面回答“边界是否落在
真指令上”并给可复现验证；引入 AVX/VEX 密度高的样本并量化 abstain 代价；
线性扫描与递归下降差异单列；完成后全量 pytest + 既有矩阵零回归。

## 0. 一句话定义

从**工具链写进文件的入口**出发做递归下降，回答“哪些解出的边界真的会被执行到”；
每条边界可被 objdump/capstone 同址同长复核，函数范围可由 `.pdata`/FDE/symtab
声明裁剪，解不出的（VEX/EVEX）明确 abstain 并量化其代价。

## 1. 范围

### 1.1 做
1. `rekit/recdesc.py`
   - 种子采集：PE 入口/导出 EAT/.pdata；ELF e_entry/symtab·dynsym STT_FUNC/
     `.eh_frame` FDE（CIE/FDE + DW_EH_PE 手解，含 pcrel/indirect）；
   - 种子分级 `authoritative` / `heuristic` / `derived`，成功率**分列**统计；
   - 递归下降（jmp/jcc/call/ret/间接跳转规则）+ 函数结束界（end limit）；
   - 基本块划分（种子/分支目标/转移后顺序地址为 leader）；
   - 重叠解码（分支跳进前一指令内部，x86 合法）单独记录；
   - CLI `rekit recdesc <file> [--section] [--heuristic] [--json]`。
2. `tests/verify_recdesc.py`：7 样本三方对拍 + 种子分级 + 范围覆盖 + 线性差集
   + VEX 代价；`--selftest` 注入错误必须被检出。
3. `tests/test_recdesc.py`：31 项不依赖 objdump 的单元断言。
4. 新增样本 `tests/samples/avx/avx_dense.exe`（自建，VEX 密度 47.2%）。

### 1.2 明确不做
- 不做 VEX/EVEX 解码（命中即 abstain，不猜长度）。
- 不做数据/代码判别、不做跳转表恢复、不做 CFG 可视化、不做跨节下降。
- 不解析 `.eh_frame` 的 CFI 指令，只取 FDE 起点与 range。
- 不处理其它架构（本轮只 x86-64）。

## 2. 验收条目

| 编号 | 判据 | 证据 |
|---|---|---|
| R1 | 权威种子与启发式种子分类统计，成功率不合并 | verify_recdesc 每样本两行；test：加 --heuristic 前后 AUTH total/hit 不变 |
| R2 | 边界落在真指令上：同址同长三方对拍 + 不同起点逐条归属 + 可失败的 selftest | 7 样本长度不一致 0 条；非 objdump 起点 12 条全部归属（overlap/seed_declared/seed_path）；UNEXPLAINED 0；--selftest 检出 1 条 |
| R3 | AVX/VEX 样本引入，abstain 代价量化到条数与比例 | avx_dense：唯一弃权点 3，漏 38/53 条 (71.7%)；dyn_static：107 点，漏 12385 条 (10.9%) |
| R4 | 线性 vs 递归差异单列，两方向都解释 | §5 表：dyn_static 线性 10022 / 递归独有 73534 / 线性独有 549；小样本 minidll 线性 128 中 127 条是填充 |
| R5 | 全量 pytest + 既有矩阵零回归 | pytest 235 passed；verify_map 2402/2402；verify_iat 失配 0；verify_recdesc PASS |

## 3. 关键结果

### 3.1 种子分级（每样本，成功率分列）
| 样本 | 权威 | 启发式 | 派生 | 指令 |
|---|---|---|---|---|
| cli-64.exe | 41/41 | 1/1 | 213/282 | 1525 |
| minidll.dll | 5/5 | 0/0 | 0/0 | 5 |
| bin_ls.elf | 331/331 | 0/0 | 2402/3947 | 17475 |
| dyn_pie | 6/6 | 0/0 | 7/9 | 56 |
| dyn_nopie | 7/7 | 1/1 | 6/7 | 53 |
| dyn_static | 1067/1090 | 6/6 | 12503/17302 | 83007 |
| avx_dense.exe | 2/5 | 0/0 | 3/6 | 15 |

权威种子来源构成：cli-64 全为 `.pdata`（41 条 RUNTIME_FUNCTION，均带 EndAddress）；
bin_ls 全为 `.eh_frame` FDE（stripped，无符号表）；minidll 为导出表（含纯序号）；
ELF 小样本为 e_entry + STT_FUNC + FDE。启发式仅 `55 48 89 e5 / 55 48 8b ec`，
默认不启用，启用后权威分母/分子逐项不变。

### 3.2 边界真指令性（要求 2）
- 判据：自研边界 vs objdump 2.47（`-z`）vs capstone 5，比 `addr+length`；
  非 objdump 线性起点的必须归入 `overlap` / `seed_declared` / `seed_path`。
- 结果：长度不一致 **0** 条；非线性起点 **12** 条全部有归属
  （dyn_static: overlap 5 / seed_declared 1 / seed_path 2；minidll: seed_declared 4）。
- 覆盖：解出的每条边界、每个权威种子起点（解出或 abstain，无第三种状态）、
  每个声明范围内的逐条覆盖与漏检归因；`--selftest` 注入长度 +1 被检出。
- 漏掉：不可达代码（间接 jmp/call 目标、跳转表、vtables）、VEX 之后的函数尾部、
  不做数据/代码判别、种子本身指向数据时无法自证（三方可能同错）。
  这些同时写进 `CAVEATS`，CLI 文本与 JSON 都会打印。

### 3.3 AVX/VEX 与 abstain 代价（要求 3）
- 样本 `tests/samples/avx/avx_dense.exe`：`_start → avx_add(VEX) → plain_loop
  → avx_mul(VEX) → avx_mix(VEX)`。
- mingw `as` 目标为 x86_64-w64-mingw32（COFF），**无法直接产 ELF**，故用 PE32+；
  ELF 侧 VEX 代价用真实 `dyn_static` 量化。构建命令：
  `as --64 -o avx_dense.o avx_dense.s`；
  `ld -e _start --export-all-symbols -o avx_dense.exe avx_dense.o`。
- avx_dense：v 开头指令 25/53（47.2%）；唯一弃权点 3（3 个 VEX 函数起点）；
  伪范围预期 53 条，覆盖 15（28.3%），abstain 归因漏 38（71.7%），其它漏 0。
- dyn_static：v 开头指令 4367/113924（3.8%）；唯一弃权点 107；逐种子伪范围
  漏 12385（10.9%）；声明范围口径（含弃权点范围）漏 12234（上界，含数据/填充）。
- abstain 语义：路径停止，不猜长度；已解出的 83007 条边界仍全部通过三方硬检查。

### 3.4 线性 vs 递归（要求 4，单列）
| 样本 | 线性 | 交集 | 递归独有 | 线性独有 |
|---|---|---|---|---|
| cli-64 | 1694 | 1525 | 0 | 169 |
| minidll | 128（停在 0x10ff 越节尾） | 1 | 4 | 127 |
| bin_ls | 22523 | 17475 | 0 | 5048 |
| dyn_pie | 64 | 56 | 0 | 8 |
| dyn_nopie | 65 | 53 | 0 | 12 |
| dyn_static | 10022（停在 0x40b89d: VEX 0xc5） | 9473 | 73534 | 549 |
| avx_dense | 8（停在 0x1022: VEX 0xc5） | 8 | 7 | 0 |

线性独有 = 数据/填充/不可达（不是“多找到的指令”，是盲区）；
递归独有 = 线性在 VEX 死点后到不了的函数（dyn_static 73529 条在停止点之后）
以及分支跳进指令内部产生的非线性起点。两个方向都报，不合并成一个总数。

## 4. 已知声明的工具链差异（不当作解码错误）

`dyn_static` 中 `__restore_rt`：
- symtab 值为 `0x44bd20`，`st_size=0`；
- `.eh_frame` FDE@0x498a44 的 initial_location 为 `0x44bd1f`，range `0xa`。
两者都是权威声明，但相差 1 字节；当前实现保留两个种子（`sources` 并列），
由 FDE 提供 end（0x44bd29），报告里不掩盖该差异。这是链接器声明与符号表
声明的不一致，不是边界解码错误（该地址字节流与 capstone 一致）。

## 5. 回归

| 命令 | 结果 |
|---|---|
| `python -m pytest tests -q` | **235 passed**（基线 204 + 新增 31） |
| `python tests/verify_map.py --all --matrix` | 2402/2402 命中，失配 0，误报 0，abstain 格 2 单列，PASS |
| `python tests/verify_iat.py --all --selftest` | 失配 0 项，加壳组按纪律 0 写字节，selftest 检出，PASS |
| `python tests/verify_recdesc.py --all` | 缺失/不可解释边界 0 项，PASS |
| `python tests/verify_recdesc.py --all --selftest` | 注入错误被检出，PASS |

注：pytest 需把 binutils-2.47\mingw64\bin 前置到 PATH；否则既有的
`test_pe.py::test_minidll_crosscheck_objdump` 会因找不到 objdump 失败（环境问题）。

## 6. 交付物

- `work/rekit/recdesc.py`（实现）
- `work/rekit/cli.py`（`recdesc` 通道）
- `work/tests/verify_recdesc.py`（验收 + selftest）
- `work/tests/test_recdesc.py`（31 项断言）
- `work/tests/samples/avx/avx_dense.s` + `avx_dense.exe`（自建 AVX 样本）
- `work/evidence_recdesc_2026-11-15.log`（本轮证据）
