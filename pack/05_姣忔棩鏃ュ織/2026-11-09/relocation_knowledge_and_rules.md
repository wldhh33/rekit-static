# 重定位机制知识卡 + 可复用规则（2026-11-09）

## 一、重定位机制：动态链接的"填地址"环节（今日知识点）

**为什么需要重定位**：链接器无法在链接期确定所有地址（PIE 基址运行时才定、
跨模块符号地址归动态链接器管），于是把"待填地址的位置 + 填法 + 参与运算的符号"
做成表格交给 ld.so——这就是 .rela.dyn / .rela.plt。

**Elf64_Rela(24B) = r_offset | r_info | r_addend**：
- r_offset：要修的位置（vaddr，链接视图）
- r_info：高 32 位 = .dynsym 序号，低 32 位 = 类型
- r_addend：参与运算的常数（S+A、B+A 里的 A）

**五类核心类型语义**（今日实测全覆盖）：

| 类型 | 值 | 语义 | 落点 |
|---|---|---|---|
| RELATIVE | 8 | base + addend（纯基址重算，无符号参与） | 全数据段 |
| GLOB_DAT | 6 | GOT 表项 ← 符号地址 S（BIND_NOW 也在 .rela.dyn 处理） | .got |
| JUMP_SLOT | 7 | GOT.PLT 表项 ← 符号地址 S（惰性绑定入口） | .got.plt |
| COPY | 5 | 符号数据整块复制进本模块 .bss（executable 引用 libc 数据） | .bss |
| IRELATIVE | 37 | GOT 项 ← ifunc 选择器函数的返回值（选中实现地址） | .got |

**联动链（逆向时最常追的链）**：
PLT 桩 → jmp [GOT.PLT slot] → 该 slot 的 JUMP_SLOT r_offset ↔ r_info>>32 →
.dynsym[sym_idx] → 符号名。逆向脱壳/反混淆时"认出外部调用"靠的就是这条链。

**今日实测三大反直觉**（拍脑袋会全错，readelf 勘察救了标准）：
1. 静态链接 ≠ 无重定位：dyn_static 有 22 条 IRELATIVE（ifunc 如 memcpy/strlen
   的实现选择必须运行时做）。
2. 现代 full-RELRO 布局可能没有 .got.plt 节：bin_ls 的 110 条 JUMP_SLOT 与
   12 条 GLOB_DAT 全落 .got [0x26c08,0x26ff0)，且 .got 前 3 项是保留项
   （.dynamic ptr / link_map / _dl_resolve），JUMP_SLOT 从 0x26c20 起。
3. COPY 的 .dynsym 条目不是 UND：st_value = 本模块 .bss 地址（= r_offset），
   它是"将要装数据的本地占位"，不是导入。

**练习建议**（下次巩固）：
- 用 `readelf -rW /bin/ls | head` 数一遍五类分布，再关掉终端手画
  .got 布局图（含前 3 保留项）。
- gdb 断在一条 PLT 调用前后，观察 GOT slot 从"PLT+6"变成 libc 真地址
  （惰性绑定现场）。M2 fingerprint 可顺带固化。

## 二、新增可复用规则（R13–R15）

- **R13 正则分组三连坑（R12 升级版）**：多分组正则必须先写分组清单注释
  （`1=offset 2=info 3=type 4=tail`）；改正则必全文搜索 `m.group(` 同步引用。
  今日实测：漏一对括号 → 组号整体后移 → 下游引用全错（同一返工内连锁两处）。
- **R14 验收脚本防空转**：filter 驱动的检查必须带计数下限
  （`n_js == 110`），否则 filter 条件写错（如 `e[3] in (6,7)` 对字符串恒
  False）时检查空转假 PASS。今日 A3-2 首版即空转，被 A3-3 的计数断言救出。
- **R15 权威工具显示怪癖清单（readelf/objdump 重定位）**：
  readelf -rW 无符号行 addend 裸十六进制、带符号行 "+ 十进制"；
  objdump -R 无符号行显示 `*ABS*+0x%016x` 伪符号、JUMP_SLOT 无 addend 列。
  交叉验证脚本必须逐怪癖适配，且每个适配处写注释。
