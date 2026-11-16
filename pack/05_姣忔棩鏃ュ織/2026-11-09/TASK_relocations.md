# 2026-11-09 白银任务卡：elf.py 重定位解析（SHT_RELA）

## 任务（rekit M1 下一子任务，PROGRESS.md 既定）
elf.py 新增 .rela.dyn/.rela.plt 解析：Elf64_Rela(24B) → (r_offset, r_info, r_addend)，
r_info 拆解：sym_idx = r_info>>32，type = r_info&0xffffffff。
类型名表覆盖本机实测至少：5 COPY / 6 GLOB_DAT / 7 JUMP_SLOT / 8 RELATIVE / 37 IRELATIVE。
符号名经 .dynsym 联动解析（RELA 节的 sh_link 指向 .dynsym）。
CLI 按 readelf -r 风格输出。

## 验收标准（执行前写定，交叉验证优先 readelf）
- **A1 数量一致（4 样本 × 各 RELA 节）**：bin_ls.elf .rela.dyn=215/.rela.plt=110；
  dyn_pie .rela.dyn=8（无 .rela.plt）；dyn_nopie .rela.dyn=2（无 .rela.plt）；
  dyn_static .rela.plt=22（全 R_X86_64_IRELATIVE=0x25，静态 ifunc 修正，sym_idx=0）。
  8 组数字与 readelf -rW 逐一相等。
- **A2 逐条字段一致（bin_ls.elf 全量 325 条）**：每条 (r_offset, 类型名, 符号名[剥 @GLIBC_* 后缀], addend)
  与 readelf -rW 行级输出完全一致，diff = 0。注意 readelf 显示怪癖：
  RELATIVE/IRELATIVE 无符号时 addend 列是裸十六进制；带符号时是 "+ 十进制"。
- **A3 联动语义（内部一致性金标准，用自家节表交叉验证）**：
  1) 全部 JUMP_SLOT/GLOB_DAT/COPY 条目 sym_idx 落在 [0, len(.dynsym)) 且查表名与 readelf 一致；
  2) bin_ls.elf 110 条 JUMP_SLOT + 12 条 GLOB_DAT 的 r_offset 全部落在 .got 节区间
     [0x26c08, 0x26c08+0x3e8)（该二进制 .got.plt 已并入 .got，full RELRO 布局）；
  3) 6 条 COPY 的 r_offset 全部落在 .bss [0x27280, 0x27280+0x1318) 且符号 st_value 与 r_offset 一致
     （COPY 语义：把 libc 数据复制进本模块 .bss）；
  4) 抽样 5 条（getenv/puts/printf/cap_to_text/__ctype_toupper_loc 等价物）人工比对。
- **A4 回归常绿**：pytest 套件 18 → ≥23 断言全绿（新增 ≥5 个重定位断言）。

## 基线与纪律
- 类型：同模块扩展（基线 A：1.2 min / ~8 轮 / 1 返工预留）。断言固化成本预估 +3~5 轮（11-07 CHANGELOG 纪律）。
- R1 字段计数先行：Elf64_Rela 恰 3 字段 QQq = 24B，数过再写。
- R3 三方交叉验证：readelf -rW 为权威，objdump -R 复核 A2。

## 基线勘察记录（写标准前实测，防拍脑袋）
- dyn_static 竟有 22 条 .rela.plt（全 IRELATIVE）——"静态二进制无重定位"是错误直觉，
  ifunc（memcpy/strlen 等）在静态链接下仍需 IRELATIVE 运行时修正。
- bin_ls.elf 无 .got.plt 节：.got[0x26c08,0x26ff0) 同时承载 GLOB_DAT(尾部)与 JUMP_SLOT(0x26c20 起)，
  前 3 项为保留项（.dynamic 指针/link_map/dl_resolve）。
- COPY 的 .dynsym 条目不是 UND：st_value = .bss 地址（执行视图中被复制目标）。
