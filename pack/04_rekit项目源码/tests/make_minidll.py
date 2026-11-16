#!/usr/bin/env python3
# make_minidll.py — 独立构造带导出表的最小 PE32+ DLL（与 rekit/pe.py 互不引用，三方验证之一）
# 2026-11-13 白银#2。布局遵循 R2：RVA→RAW 区间表见下，先画后写。
#
#   DOS头64B(e_lfanew=0x40) + PE sig + COFF(20B) + OptHdrPE32+(0xF0) + 节表(2×40B)
#   .text @RVA0x1000 / RAW0x400  — DllMain@0x1000 + Add@0x1010 Sub@0x1020 Mul@0x1030 Ord@0x1040
#   .edata @RVA0x2000 / RAW0x600 — delta = 0x2000-0x600 = 0x1A00
#
#   .edata RVA→RAW 区间表（R2，无重叠）：
#     ExportDir 40B   RVA 0x2000 → RAW 0x600  [0x600,0x628)
#     DLL 名 12B      RVA 0x2028 → RAW 0x628  [0x628,0x634)  "minidll.dll\0"
#     EAT 4×DWORD     RVA 0x2040 → RAW 0x640  [0x640,0x650)
#     NamePtr 3×DWORD RVA 0x2050 → RAW 0x650  [0x650,0x65C)
#     Ordinal 3×WORD  RVA 0x205C → RAW 0x65C  [0x65C,0x662)
#     "Add\0"         RVA 0x2070 → RAW 0x670
#     "Mul\0"         RVA 0x2074 → RAW 0x674
#     "Sub\0"         RVA 0x2078 → RAW 0x678
#   导出语义（Base=1，名字表字母序 ≠ EAT 序，专门检验 AddressOfNameOrdinals 换算）：
#     EAT[0]=Add@0x1010 ordinal1  EAT[1]=Sub@0x1020 ordinal2
#     EAT[2]=Mul@0x1030 ordinal3  EAT[3]=(纯序号)@0x1040 ordinal4
#     NamePtrs=[Add→0x2070, Mul→0x2074, Sub→0x2078]  Ordinals=[0, 2, 1]
import struct

SIZE = 0x800
buf = bytearray(SIZE)

# ---- DOS header ----
buf[0:2] = b"MZ"
struct.pack_into("<I", buf, 0x3C, 0x40)          # e_lfanew

# ---- PE signature + COFF header @0x40 ----
buf[0x40:0x44] = b"PE\x00\x00"
# Characteristics 0x2022 = EXECUTABLE_IMAGE|LINE_NUMS_STRIPPED|32BIT_MACHINE + 0x2000(IMAGE_FILE_DLL)
MACHINE, NSECT, OPTSZ, CHARS = 0x8664, 2, 0xF0, 0x2022
struct.pack_into("<HHIIIHH", buf, 0x44, MACHINE, NSECT, 0x672A0000, 0, 0, OPTSZ, CHARS)

# ---- Optional header PE32+ @0x58 (240B) ----
# R1 字段计数：Magic H, LinkVer BB, SizeOfCode I, SizeOfInitData I, SizeOfUninitData I,
#   Entry I, BaseOfCode I, ImageBase Q, SectAlign I, FileAlign I, OSVer HH, ImgVer HH,
#   SubsysVer HH, Win32Ver I, SizeOfImage I, SizeOfHeaders I, CheckSum I, Subsys H, DllChars H,
#   StackRes Q, StackCom Q, HeapRes Q, HeapCom Q, LoaderFlags I, NumRva I  → 与 minipe 相同串
ENTRY, IMAGE_BASE, SECT_ALIGN, FILE_ALIGN = 0x1000, 0x140000000, 0x1000, 0x200
SIZEOF_IMAGE, SIZEOF_HEADERS, SUBSYS = 0x3000, 0x200, 3
EXPORT_RVA, EXPORT_SZ = 0x2000, 0x7C            # 0x207C(最后名字串尾)-0x2000
opt = struct.pack("<HBBIIIII Q II HHHHHH IIII HH QQQQ II",
                  0x20B, 14, 0, 0x200, 0x400, 0, ENTRY, 0x1000,
                  IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
                  6, 0, 0, 0, 6, 0, 0,
                  SIZEOF_IMAGE, SIZEOF_HEADERS, 0, SUBSYS, 0x8160,
                  0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
dirs = (struct.pack("<II", EXPORT_RVA, EXPORT_SZ)        # [0] Export — 导出表（本任务主角）
        + struct.pack("<II", 0, 0)                        # [1] Import — 空（覆盖无导入路径）
        + b"\x00" * (14 * 8))                             # [2..15] 空
buf[0x58:0x58 + len(opt) + len(dirs)] = opt + dirs

# ---- 节表 @0x148 (2×40B) ----
def sect(name, vsize, vaddr, rawsize, rawptr, chars):
    return struct.pack("<8sIIIIIIHHI", name.encode(), vsize, vaddr,
                       rawsize, rawptr, 0, 0, 0, 0, chars)

buf[0x148:0x148 + 40] = sect(".text", 0x100, 0x1000, 0x200, 0x400, 0x60000020)
buf[0x148 + 40:0x148 + 80] = sect(".edata", 0x140, 0x2000, 0x200, 0x600, 0x40000040)

# ---- .text @0x400：DllMain + 4 个导出函数体（各 0xC3 ret，仅验证结构）----
for rva in (0x1000, 0x1010, 0x1020, 0x1030, 0x1040):
    buf[rva - 0x1000 + 0x400] = 0xC3

# ---- .edata @0x600 ----
# IMAGE_EXPORT_DIRECTORY 40B（R1 字段计数：Char I, Time I, MajVer H, MinVer H,
#   Name I, Base I, NumFuncs I, NumNames I, AddrFuncs I, AddrNames I, AddrOrds I = 10 字段）
EXPORT_NAME_RVA, BASE = 0x2028, 1
N_FUNCS, N_NAMES = 4, 3
ADDR_FUNCS, ADDR_NAMES, ADDR_ORDS = 0x2040, 0x2050, 0x205C
buf[0x600:0x600 + 40] = struct.pack(
    "<IIHHIIIIIII", 0, 0x672A0000, 0, 0,
    EXPORT_NAME_RVA, BASE, N_FUNCS, N_NAMES,
    ADDR_FUNCS, ADDR_NAMES, ADDR_ORDS)
# DLL 名
buf[0x628:0x628 + 12] = b"minidll.dll\x00"
# EAT：Add@0x1010, Sub@0x1020, Mul@0x1030, OrdinalOnly@0x1040
struct.pack_into("<IIII", buf, 0x640, 0x1010, 0x1020, 0x1030, 0x1040)
# 名字表（字母序）→ Ordinal 表（EAT idx）：Add→0, Mul→2, Sub→1
struct.pack_into("<III", buf, 0x650, 0x2070, 0x2074, 0x2078)
struct.pack_into("<HHH", buf, 0x65C, 0, 2, 1)
# 名字字符串
buf[0x670:0x674] = b"Add\x00"
buf[0x674:0x678] = b"Mul\x00"
buf[0x678:0x67C] = b"Sub\x00"

open("<旧仓库根>/tests/minidll.dll", "wb").write(bytes(buf))
print("minidll.dll written, %d bytes" % len(buf))
