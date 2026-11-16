#!/usr/bin/env python3
# make_minipe.py — 独立构造最小 PE32+（与 rekit/pe.py 解析代码互不引用，双向验证）
# 布局：DOS头64B(含e_lfanew=0x40) + PE sig + COFF(20B) + OptHdrPE32+(0xF0) +
#       节表(2×40B) + .text@0x400 + .idata@0x600
import struct

SIZE = 0x800
buf = bytearray(SIZE)

# ---- DOS header ----
buf[0:2] = b"MZ"
struct.pack_into("<I", buf, 0x3C, 0x40)          # e_lfanew

# ---- PE signature + COFF header @0x40 ----
buf[0x40:0x44] = b"PE\x00\x00"
MACHINE, NSECT, OPTSZ, CHARS = 0x8664, 2, 0xF0, 0x0022
struct.pack_into("<HHIIIHH", buf, 0x44, MACHINE, NSECT, 0x672A0000, 0, 0, OPTSZ, CHARS)

# ---- Optional header PE32+ @0x58 (240B) ----
ENTRY, IMAGE_BASE, SECT_ALIGN, FILE_ALIGN = 0x1000, 0x140000000, 0x1000, 0x200
SIZEOF_IMAGE, SIZEOF_HEADERS, SUBSYS = 0x3000, 0x200, 3
IMPORT_RVA, IMPORT_SZ = 0x2000, 0x50
opt = struct.pack("<HBBIIIII Q II HHHHHH IIII HH QQQQ II",
                  0x20B, 14, 0, 0x200, 0x400, 0, ENTRY, 0x1000,
                  IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
                  6, 0, 0, 0, 6, 0, 0,
                  SIZEOF_IMAGE, SIZEOF_HEADERS, 0, SUBSYS, 0x8160,
                  0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
dirs = (struct.pack("<II", 0, 0)                      # [0] Export — 空
        + struct.pack("<II", IMPORT_RVA, IMPORT_SZ)   # [1] Import — 导入表
        + b"\x00" * (14 * 8))                         # [2..15] 空
buf[0x58:0x58 + len(opt) + len(dirs)] = opt + dirs

# ---- 节表 @0x148 (2×40B) ----
def sect(name, vsize, vaddr, rawsize, rawptr, chars):
    return struct.pack("<8sIIIIIIHHI", name.encode(), vsize, vaddr,
                       rawsize, rawptr, 0, 0, 0, 0, chars)

buf[0x148:0x148 + 40] = sect(".text", 0x100, 0x1000, 0x200, 0x400, 0x60000020)
buf[0x148 + 40:0x148 + 80] = sect(".idata", 0x140, 0x2000, 0x200, 0x600, 0xC0000040)

# ---- .text @0x400: 入口代码（ret）---- （基线仅验证结构，不需真实指令）
buf[0x400] = 0xC3

# ---- .idata @0x600: 导入表（RVA→RAW: delta = 0x2000-0x600 = 0x1A00）----
#   Descriptor  @RVA0x2000 → RAW0x600 : INT_RVA=0x2060, Name_RVA=0x2028, IAT_RVA=0x2040
#   终止符      @RVA0x2014 → RAW0x614 : 20B 全零（descriptor 表共 2×20B=0x28）
#   DLL 名      @RVA0x2028 → RAW0x628 : "KERNEL32.dll\0"（避开 0x614-0x628 终止区）
#   IAT         @RVA0x2040 → RAW0x640 : [0x2100, 0]
#   INT         @RVA0x2060 → RAW0x660 : [0x2100, 0]
#   Hint/Name   @RVA0x2100 → RAW0x700 : hint=0 + "ExitProcess\0"
buf[0x600:0x600 + 20] = struct.pack("<IIIII", 0x2060, 0, 0, 0x2028, 0x2040)
buf[0x600 + 20:0x600 + 40] = b"\x00" * 20          # 终止 descriptor
buf[0x628:0x628 + 13] = b"KERNEL32.dll\x00"
struct.pack_into("<Q", buf, 0x640, 0x2100)
struct.pack_into("<Q", buf, 0x640 + 8, 0)
struct.pack_into("<Q", buf, 0x660, 0x2100)
struct.pack_into("<Q", buf, 0x660 + 8, 0)
buf[0x700:0x700 + 2] = b"\x00\x00"                  # hint
buf[0x702:0x702 + 12] = b"ExitProcess\x00"

open("<旧仓库根>/tests/minipe.exe", "wb").write(bytes(buf))
print("minipe.exe written, %d bytes" % len(buf))
