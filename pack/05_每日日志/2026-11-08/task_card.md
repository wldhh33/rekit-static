# rekit 白银任务卡 · 2026-11-08

## 任务布置（执行前写定，2026-11-08 10:27）

- **来源**：PROGRESS.md 下一子任务（M1 loader）—— elf.py 符号表解析
- **类型**：🥈 白银·扩展型（rekit 既有模块加功能）
- **基线期望**（PROGRESS.md 基线 A）：1–2 min / 5–8 工具轮次，预留 1–2 次返工
- **内容**：
  1. 按节表解析 SHT_SYMTAB(2) 与 SHT_DYNSYM(11) 两类符号表（Elf64_Sym 24B：st_name/st_info/st_other/st_shndx/st_value/st_size）
  2. 符号名经 sh_link 指向的字符串表节解析（注意 sh_link 是节索引，不是偏移）
  3. 输出符号名 + st_value + bind/type，理解 st_value 的 vaddr 语义（区别于 PE 的 RVA→文件偏移换算）
  4. 验收断言固化进 tests/test_elf.py，收工前 `python3 -m pytest tests/` 全绿（CHANGELOG 2026-11-07 纪律）

## 验收标准（可量化、可证伪，执行前定稿，不得事后放宽）

- **A1 数量一致**：对 tests/fixtures/bin_ls.elf，rekit 解析的 .dynsym 符号数 == `readelf -sW` 报告的 `.dynsym contains N entries` 的 N；有 .symtab 的样本（如 dyn_pie）同理比对 .symtab 数量。
- **A2 全量交叉一致（金标准）**：对 bin_ls.elf 的 .dynsym，rekit 输出的 (name, st_value) 序列与 `readelf -sW` 的 .dynsym 段逐行一致（含第 0 号 null 符号），一致率必须 100%（129/129 这种数字留证据）。
- **A3 关键符号抽查**：在 bin_ls.elf .dynsym 中定位到导入符号（如 strlen/puts 等 SHN_UNDEF 符号）且 st_value==0；在 dyn_pie 的 .symtab 中找到 main 或 _start 的 st_value，与 readelf 对应行一致（数字写进证据）。
- **A4 vaddr 语义 + 鲁棒性**：a) st_value 不做文件偏移换算、直接透传（与 readelf 显示一致即证明）；b) bin_ls.elf（无 .symtab，stripped）symtab=None 不崩溃；c) dyn_static（无动态段）若存在 .symtab 仍能从节表路径解析。
- **A5 pytest 固化**：新增 ≥4 条断言进 tests/test_elf.py（快照 + readelf 交叉验证），全套件全绿，0 失败。

## 风险预判（R1 先数后写）

- Elf64_Sym 字段表（写代码前先列）：st_name u32, st_info u8, st_other u8, st_shndx u16, st_value u64, st_size u64 → "IBBHQQ" = 4+1+1+2+8+8 = 24B ✓ 与 sh_entsize 对照
- readelf 的 .dynsym 第 0 行是 null 符号，序列对比必须包含（预期坑）
- st_shndx=0（SHN_UNDEF）表示导入符号，type/bind 从 st_info 拆（低 4 位 type、高 4 位 bind）
