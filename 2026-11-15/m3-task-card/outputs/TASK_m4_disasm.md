# 青铜任务：rekit M4 disasm —— x86-64 线性扫描（首日）

日期：2026-11-15 ｜ 依据：CHARTER.md M4 ｜ 本轮性质：**首日 + 返工降档（从轻）**
用户口径：本轮只做 `rekit/disasm.py` 的 x86-64 线性扫描——指令边界与 objdump 逐行对齐，
复用 `addr_to_off` 标注每条指令的文件落点；**不碰递归下降与 CFG**。

## 0. 一句话定义

给 rekit 增加第 6 类能力：**把一段字节切成一串指令边界**（起始地址 + 长度），
每条边界都能被外部工具独立复核，并带 M3 的文件落点换算。不做助记符、不做控制流。

## 1. 范围

### 1.1 做
1. `rekit/disasm.py`：legacy 前缀 → REX → opcode（1/2/3 字节映射）→ ModRM/SIB/disp → imm 的长度解码。
2. 线性扫描 `sweep_bytes/sweep_file`：逐条产出 `{addr, off, length, bytes, status, map}`。
3. 每条指令复用 `mapview.addr_to_off` 算文件落点，并与本节算术 offset 逐条对账（不一致即报）。
4. `tests/verify_disasm.py`：与 GNU objdump 2.47 逐行对齐；分歧处定位到地址/两方长度/上下文/仲裁。
5. `rekit/cli.py` 增加 `disasm` 通道；`tests/test_disasm.py` 70 项断言。

### 1.2 明确不做（本轮写死）
- 不做递归下降、不做 CFG、不做基本块 / 函数边界 / 交叉引用。
- 不解助记符与操作数（边界是硬事实，语义是另一层）。
- 不支持 VEX / EVEX（AVX / AVX-512）→ 一律 abstain 停止。
- 不做反汇编结果的数据/代码判别（见 §3 盲区）。

## 2. 验收条目

| 编号 | 判据 | 证据 |
|---|---|---|
| D1 | 4 个样本（2 PE + 2 ELF）逐条边界与 objdump 2.47 全对齐，0 条分歧 | verify_disasm --all：1694 / 26353 / 22523 / 64 = 50634 条，VERDICT PASS |
| D2 | 每条指令的文件落点由 `mapview.addr_to_off` 独立算出，且与本节算术一致 | map_stats hit=50634 / 不一致 0 条 |
| D3 | 分歧必须定位到具体指令（地址、两方长度、上下文），并用独立解码器仲裁 | 本轮实测 1 处分歧 → 见 §4 |
| D4 | VEX/EVEX/非法 opcode/越界 → abstain 停止，不猜长度 | test_disasm 参数化 6 例 + 越界/超长前缀 |
| D5 | 盲区必须出现在输出里 | JSON `caveats` 5 条 + 文本 caveats 段 |
| D6 | 检查器可失败 | --selftest 注入 +1 → 检出并 FAIL |

## 3. 线性扫描的已知盲区（写入输出 caveats）

1. 无法区分代码与数据：跳转表、对齐填充（0xCC/0x90）、内联字面量都会被当指令。
2. 不跟踪跳转、不做递归下降：函数之间的交错数据区照扫不误。
3. 不支持 VEX/EVEX：遇到即停止，**不是长度解错**——含 AVX 的函数扫不到底。
4. x87/3DNow 仅按长度表计长，不校验语义。
5. 超过 15 字节的非法前缀序列不单独报错（按表继续）。

> 结论口径：`sweep_file` 的输出是「从节首字节起，按字节规则切出的边界」，
> **不等于**「这些地址上就是指令」。要判断"是否真指令"必须等递归下降 + CFG（M4 后续）。

## 4. 本轮唯一失配与仲裁

- 位置：`tests/fixtures/bin_ls.elf` 第 11419 条，addr=0x101ec，本节 off=0x101ec。
- 字节：`41 0f cb 41 83 fb 06 ...`
- 我方：len=5（把 `41` 当 ModRM、`83` 当 disp8）；objdump：len=3 `bswap r11d`。
- 独立仲裁：capstone（CS_ARCH_X86 / CS_MODE_64）解出 len=3 `bswap r11d` → verdict=`ours_wrong`。
- 字节规则依据：`0F C8+rd` = BSWAP，**无 ModRM**；REX.B 只扩寄存器号。
  该规则与"capstone 与 objdump 一致"两个独立证据同向，故判我方错（未默认 objdump 全对）。
- 根因：`_NO_MODRM_2` 漏了 `0xC8..0xCF`。修复后重跑：4 样本全对齐。

## 5. 验收结果

| 检查 | 命令 | 结果 |
|---|---|---|
| 边界对拍 | `python tests/verify_disasm.py --all` | 50634/50634 对齐，0 分歧，exit 0 |
| 检查器可失败 | `... --all --selftest` | 注入 +1 被检出，exit 0 |
| 单元断言 | `python -m pytest tests/test_disasm.py -q` | 70 passed |
| 全量回归 | `python -m pytest tests -q` | 204 passed（含 M1/M2/M3 既有 134），exit 0 |
| 既有矩阵 | `python tests/verify_map.py --all --matrix` | 2402/2402 命中，exit 0 |
| 既有矩阵 | `python tests/verify_iat.py --all --selftest` | 失配 0，exit 0 |

## 6. 诚实边界（这一轮没证明的事）

- **反方向仲裁未被真实数据触发**：本轮没有出现"objdump 错而我们对"的样本；
  `ours_and_capstone_agree` 分支只由代码路径保证，未由真实样本证明。
- 样本面窄：4 个 x86-64 样本、只扫 `.text`；不含 AVX 密集样本，故 abstain 停止
  的代价（函数扫不到底）尚未量化。
- objdump 在 Windows 上会用本地代码页回显文件名（UTF-8 解码失败）——这是环境怪癖，
  已改为按字节收 + `errors="replace"`，不影响指令行解析。
