# ELF64 速查卡（逆向学习 · 2026-11-06 沉淀）

## 文件头布局（手解速记）

```
偏移   大小   字段              说明
0x00    4    e_ident.magic     7F 45 4C 46
0x04    1    e_ident.class     1=32位 2=64位
0x05    1    e_ident.data      1=LE 2=BE
0x06    1    e_ident.version   1
0x10    2    e_type            2=EXEC 3=DYN(PIE或SO)
0x12    2    e_machine         0x3E=x64 0xB7=ARM64
0x14    4    e_version
0x18    8    e_entry           入口虚拟地址
0x20    8    e_phoff           段表文件偏移（常为64）
0x28    8    e_shoff           节区表文件偏移
0x30    4    e_flags
0x34    2    e_ehsize          64
0x36    2    e_phentsize       56（64位）
0x38    2    e_phnum
0x3a    2    e_shentsize       64
0x3c    2    e_shnum
0x3e    2    e_shstrndx        节区名字符串表索引
```
struct 格式串：`<HHIQQQIHHHHHH`（16 字节 e_ident 之后）

## Program Header（每项 56B）

```
p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8) p_memsz(8) p_align(8)
```
- 常见 type：1=LOAD 2=DYNAMIC 3=INTERP 4=NOTE 6=PHDR 7=TLS
- flags 位：PF_R=4，PF_W=2，PF_X=1（注意：与 Unix 文件权限 4/2/1 数值巧合但语义独立）
- GNU 扩展：0x6474E551=GNU_STACK，0x6474E552=GNU_RELRO

## 判读规则（经验）

1. DYN + PT_INTERP 存在 → PIE 可执行；DYN + 无 INTERP → 共享库
2. offset ≠ vaddr（对齐填充差）→ 文件偏移换算虚拟地址按段各自算
3. GNU_STACK 无 E（NX 生效）；GNU_RELRO 存在 → 至少部分 RELRO
4. .bss 对应 p_memsz > p_filesz 的零填充区
5. 加壳特征：节区名如 UPX0/UPX1 或段数异常少 + 入口落在最后一个 LOAD
