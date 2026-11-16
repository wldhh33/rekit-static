#!/usr/bin/env python3
# mini_elf.py — 纯 struct 手解 ELF64（逆向学习日报 2026-11-06 白银任务）
# 布局依据：e_ident(16B) + ELF64头(e_type H, e_machine H, e_version I,
# e_entry Q, e_phoff Q, e_shoff Q, e_flags I, e_ehsize H, e_phentsize H,
# e_phnum H, e_shentsize H, e_shnum H, e_shstrndx H) + Phdr(64B each)
import struct
import sys

PATH = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
data = open(PATH, "rb").read()

# ---- e_ident ----
assert data[:4] == b"\x7fELF", "not an ELF file"
ei_class, ei_data, ei_version = data[4], data[5], data[6]
endian = "<" if ei_data == 1 else ">"
print("Magic:            7f 45 4c 46 (0x7f 'ELF')")
print("Class:            %s" % ("ELF64" if ei_class == 2 else "ELF32"))
print("Data:             2's complement, %s endian" % ("little" if ei_data == 1 else "big"))

# ---- ELF64 header ----
(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
 e_flags, e_ehsize, e_phentsize, e_phnum,
 e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)

TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
MACH = {0x03: "Intel 80386", 0x28: "ARM", 0x3E: "Advanced Micro Devices X86-64",
        0xB7: "AArch64", 0xF3: "RISC-V"}
print("Type:             %s" % TYPES.get(e_type, hex(e_type)))
print("Machine:          %s" % MACH.get(e_machine, hex(e_machine)))
print("Entry point:      0x%x" % e_entry)
print("Start of program headers: %d (bytes into file)" % e_phoff)
print("Number of program headers: %d" % e_phnum)
print("Number of section headers: %d" % e_shnum)

# ---- Program headers ----
PT = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 6: "PHDR", 7: "TLS",
      0x6474E550: "GNU_EH_FRAME", 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO",
      0x6474E553: "GNU_PROPERTY"}

def perm(fl):
    s = ""
    for bit, ch in ((4, "R"), (2, "W"), (1, "E")):
        s += ch if fl & bit else " "
    return s

print("\nProgram headers:")
print("  %-14s %10s %18s %12s %5s" % ("Type", "Offset", "VirtAddr", "FileSiz", "Flg"))
loads = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    (p_type, p_flags, p_offset, p_vaddr, p_paddr,
     p_filesz, p_memsz, p_align) = struct.unpack_from(endian + "IIQQQQQQ", data, off)
    print("  %-14s 0x%08x 0x%016x 0x%010x %5s" %
          (PT.get(p_type, hex(p_type)), p_offset, p_vaddr, p_filesz, perm(p_flags)))
    if p_type == 1:
        loads.append((p_offset, p_vaddr, p_filesz, perm(p_flags)))

print("\nPT_LOAD count: %d" % len(loads))
for n, (o, v, f, p) in enumerate(loads, 1):
    print("  LOAD#%d off=0x%x vaddr=0x%x filesz=0x%x flags=[%s]" % (n, o, v, f, p))
