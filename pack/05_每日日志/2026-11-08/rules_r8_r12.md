# 2026-11-08 逆向学习沉淀（规则与检查清单）

## rekit ELF 符号表解析 · 新增规则（R8–R12）

- **R8 st_value 是 vaddr**：链接视图的虚拟地址，直接透传即可（与 readelf -sW 显示值一致即自证）；读符号原始数据用节表 sh_offset——别把 st_value 当文件偏移去 read()。（对照 PE：PE 导入表给的是 RVA+IAT 双跳转，ELF 导入给的就是 SHN_UNDEF 符号，简单得多）
- **R9 sh_link 是节索引**：符号表的配套字符串表（.strtab/.dynstr）由 sh_link 指出，它是节表下标，不是偏移也不是 vaddr；sh_entsize = 表项大小（Elf64_Sym = 24B："IBBHQQ"）。
- **R10 readelf 符号名的 @VERSION 陷阱**：`readelf -sW` 显示 `getenv@GLIBC_2.2.5 (3)`，但原始 st_name 只有 `getenv`——版本后缀来自 .gnu.version/VERSYM 节的合成显示。与 readelf 做序列比对前必须剥 `@...`，否则"假性不一致"。
- **R11 SHN_UNDEF 语义**：st_shndx==0 = 导入符号（本文件未定义，运行时由动态链接器解析），其 st_value 恒为 0。bin_ls.elf 实测：138 个 .dynsym 符号中 122 个 UND。stripped = 无 .symtab（.dynsym 仍保留，动态链接必需）；纯静态链接二进制无 .dynsym 但 .symtab 巨大（dyn_static 2084 项）。
- **R12 验收脚本正则错位是历史返工 Top1**（第 3 次出现：基线 A 1 次 + 今日 1 次 + PE 期 1 次）：解析第三方工具文本输出前，先拿一行真实输出在 REPL 里验证分组索引，再写进测试/脚本。

## 栈帧识别检查清单（x86-64 System V）

1. **prologue 三件套**：`push rbp; mov rbp,rsp; sub rsp,N`（N=局部变量+对齐所需）
2. **参数位置**：前 6 个整数参数 rdi/rsi/rdx/rcx/r8/r9；第 7+ 个从右向左压栈 → 被调方 `[rbp+0x10]` 起步（[rbp] = 旧 rbp，[rbp+8] = 返回地址）
3. **局部变量**：一律 `[rbp-X]`（如本次 frame_demo 的 s = [rbp-0x4]）；跨栈参数 = `[rbp+Y]`——一正一负是逆推函数签名的罗盘
4. **epilogue**：`leave; ret` ≡ `mov rsp,rbp; pop rbp; ret`；add8 用 `pop rbp; ret`（无 sub rsp 时两者等价）
5. **栈参数调用方清理**：main 里 call 后紧跟 `add rsp,0x10`（ cdecl 遗风）
6. **endbr64 指纹**：现代 Ubuntu 发行版函数入口常有（CET/IBT），本环境 gcc 默认未开——**环境差异必须实测，不能凭"常识"断言**
