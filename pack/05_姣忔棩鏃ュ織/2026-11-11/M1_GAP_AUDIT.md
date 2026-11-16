# rekit M1 收口评估报告（2026-11-11）

> 对应任务：TASK_m1_gap_audit.md（标准先行，A1–A5）。执行者：AI 助手。耗时：约 12 min（分析型，
> 含样本探测/工具验证，超出基线 A 纯执行 1–2 min 属预期——评估型任务含盘点探索，非返工）。

## A1 对账表：CHARTER M1 清单 vs 当前实现（逐项证据）

| CHARTER M1 条目 | 状态 | 证据 |
|---|---|---|
| elf.py 头 | ✅ | `elf.py:53` Ehdr 解包；test_elf.py 58 处 assert |
| elf.py 段 | ✅ | `elf.py:16-20` PT_TYPES 常量表 + `:59-66` Phdr 循环 |
| elf.py 节 | ✅ | `elf.py:68` Shdr 循环 |
| elf.py 动态段 | ✅ DT_NEEDED | `elf.py:84-88` vaddr→file_off 经 PT_LOAD 映射；`:109` DT_NEEDED |
| elf.py 符号表 | ✅ dynsym+symtab | `elf.py:123-147` parse_symtab 双表 |
| pe.py 头 | ✅ | `pe.py:28-36` e_lfanew+COFF+OptHdr |
| pe.py 节 | ✅ | `pe.py:58-64` 节表循环 |
| pe.py 导入 | ✅ | `pe.py:70-95` INT/IAT/Name 三链 |
| **pe.py 导出** | ❌ **缺** | 无解析代码 |
| **pe.py Rich** | ❌ **缺** | 无解析代码 |
| CLI | ⚠️ 双模块 main，无统一 cli.py | `elf.py:224` / `pe.py:102`；CHARTER 目录结构约定 `rekit/cli.py` |
| fixtures 5 类覆盖 | ✅ **7 样本** | PIE/非PIE/静态/norelro/execstack/系统二进制(bin_ls)/PE(minipe) |
| 回归套件常绿 | ✅ 34 passed / 0.20s | evidence_pytest.log（今日重跑） |

**M1 完成度：CHARTER pe 侧 5 项中 3 项 ✅，2 项 ❌ → 清单达成 10/12 项，阻塞收口的硬缺口只有 2 个（导出、Rich）+ 1 个形态差口（统一 CLI）。**

## A2 缺口量化（两项缺口的成本与依赖）

### 缺口 ①：导出表（.edata / DataDirs[0]）
- **正样本 fixture**：❌ 系统全缺——aspose 的 .NET DLL 导出表全为 [0x0 size 0]（.NET 经 CLR 元数据暴露类型，无 Win32 导出）；cli-64.exe 是 EXE 无导出表。
  → **路线：自构造 minidll**（扩展 `tests/make_minipe.py`：DataDirs[0] 已预留 0 填充位（`:29`），新增 .edata 节复用 `sect()`（`:35`），构造 Export Directory 40B + 函数名表 + 序号表 + 名称 RVA 表）。
- **权威对照工具**：✅ `objdump -p`（环境已有，基线 B 验证过其导出表输出能力，三方验证金标准 R3 可复用）。
- **成本预估**：从零型 ≈ 基线 B（7.2 min/8 返工）。风险点已知：R1 字段计数先行（Export Directory 10 字段）、R2 先画 RVA→RAW 地址表防区间重叠（基线 B 返工 #7/#8 同源坑）。

### 缺口 ②：Rich 头（DOS stub 编译器指纹）
- **正样本 fixture**：✅ **无需构造**——`setuptools/cli-64.exe`（MSVC native PE32+，Rich@0xe8，key=0x31a563a3，10 对 comp.id）；
  负样本 ✅ minipe.exe（自构造无 Rich）与 3 个 .NET DLL（Rich=None，测优雅降级）。
- **权威对照工具**：✅ pefile（今日已装 venv：`pip3 install pefile`，PEP 668 需走 venv 通道），`parse_rich_header()` 输出 key/checksum/values 22 dwords。
- **成本预估**：扩展型 ≈ 基线 A（1–2 min 纯执行；DOS stub 线性解码，无 RVA 换算）。两个预研坑（今日探测发现，明日 TASK 必须含）：
  1. Rich 标记搜索必须限定 `[0x40, e_lfanew)` 区间——Aspose.Words.dll 曾在文件深处（0x147ba89）出现 "Rich" 误匹配；
  2. **pefile `values` 列表尾部语义待确认**：22 dwords = DanS+pad+10 对，而非直觉的"去掉首尾"；明日须以 pefile 源码对齐语义后再做全等比对（教训同 R16：权威工具输出格式本身也要验证）。

## A3 基线健康实证

- pytest：**34 passed in 0.20s**（evidence_pytest.log）
- CLI 7/7 fixtures exit 0（evidence_cli_fixtures.log），含 minipe.exe 走 pe 通道、六个 ELF 走 elf 通道，checksec 行输出正常。

## A4 收口路径决策（记录，明日 11-12 起执行）

**决策：补 2 个白银后收口 M1，再进 M1.5，不直接跳 M1.5。** 理由：导出表与 Rich 均是 CHARTER M1 明确清单项（跳过 = 标准降级，违反变更红线）；且 Rich 是 M2 编译器指纹的基石，导出表是 DLL 分诊刚需，两课都在 M1 补最干净。

| 日期 | 任务 | 类型/预估 | 验收标准草案 |
|---|---|---|---|
| 11-12 白银#1 | pe.py Rich 头解析 | 扩展型 2–4 min | cli-64.exe 解析结果（key+10 对 comp.id）与 pefile 逐项全等；minipe.exe/.NET DLL 优雅输出"无 Rich"；断言入库 ≥6 |
| 11-13 白银#2 | 自构造 minidll + pe.py 导出表解析 | 从零型 ≈ 基线 B | 构造/解析/objdump 三方全等（函数名、序号、DLL 名）；fixtures+1；断言入库 ≥8 |
| 11-14 收口日 | 统一 cli.py（argparse 分发 ELF/PE）+ 终对账 | 小型 | `python3 -m rekit.cli <file>` 自动识别格式；7+1 fixtures 全跑通；CHARTER M1 逐项 ✅ 后宣告收口 |

## A5 超额项（CHARTER 未要求但已实现——清单已滞后于现实）

1. **重定位解析**（五类 RELA + sh_link 联动符号名，11-09 白银，13/13 vs readelf 全对）
2. **checksec 四态**（NX/RELRO/PIE/W+X，11-10 白银，18/18 vs readelf 权威表全等）
3. fixtures 7 > 要求 5；断言 34 条常绿
4. → 建议（今日不动 CHARTER）：M1 收口日一并把超额项回写 CHARTER（走 CHANGELOG），避免章程与资产脱节。
