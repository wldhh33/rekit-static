#!/usr/bin/env python3
# make_fakerich.py — 构造 Rich 误匹配负样本（2026-11-12 白银#1 C2/C3）
# 场景复刻：Aspose.Words.dll 在文件深处 0x147ba89 出现 "Rich" 字节串的真坑。
# 本样本埋两处陷阱：
#   1) DOS stub 区 0x80：明文 "Rich" + 合理 key(0x11223344) + 伪加密数据
#      —— 无 DanS^key 锚。仅单向找 "Rich" 的解析器会误匹配；双向锚定实现须返回 None。
#   2) .text 数据深处 0x500：又一处 "Rich" —— 限界 [0x40, e_lfanew) 之外的匹配必须被排除。
# 与 make_minipe.py 同构（e_lfanew 0x40→0x200，headers 0x200→0x400），独立构造不引用 rekit。
import os
import struct

SIZE = 0x800
buf = bytearray(SIZE)

# ---- DOS header：e_lfanew=0x200（长 DOS stub，给陷阱留空间）----
buf[0:2] = b"MZ"
struct.pack_into("<I", buf, 0x3C, 0x200)

# ---- 陷阱 1：DOS stub 区 0x80 埋 "Rich"+key+伪加密垃圾（无 DanS 锚）----
FAKE_KEY = 0x11223344
buf[0x80:0x84] = b"Rich"
struct.pack_into("<I", buf, 0x84, FAKE_KEY)
# 0x88..0xFC：伪加密数据（看着像 comp.id 对，但无 DanS 开头）
for i, v in enumerate([0xDEADBEEF ^ FAKE_KEY, 0x10, 0xCAFEBABE ^ FAKE_KEY, 0x2]):
    struct.pack_into("<I", buf, 0x88 + 4 * i, v)

# ---- PE signature + COFF header @0x200 ----
buf[0x200:0x204] = b"PE\x00\x00"
MACHINE, NSECT, OPTSZ, CHARS = 0x8664, 2, 0xF0, 0x0022
struct.pack_into("<HHIIIHH", buf, 0x204, MACHINE, NSECT, 0x672A0000, 0, 0, OPTSZ, CHARS)

# ---- Optional header PE32+ @0x218（240B + 16 目录）----
ENTRY, IMAGE_BASE, SECT_ALIGN, FILE_ALIGN = 0x1000, 0x140000000, 0x1000, 0x200
SIZEOF_IMAGE, SIZEOF_HEADERS, SUBSYS = 0x3000, 0x400, 3
IMPORT_RVA, IMPORT_SZ = 0x2000, 0x50
opt = struct.pack("<HBBIIIII Q II HHHHHH IIII HH QQQQ II",
                  0x20B, 14, 0, 0x200, 0x400, 0, ENTRY, 0x1000,
                  IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
                  6, 0, 0, 0, 6, 0, 0,
                  SIZEOF_IMAGE, SIZEOF_HEADERS, 0, SUBSYS, 0x8160,
                  0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
dirs = (struct.pack("<II", 0, 0)
        + struct.pack("<II", IMPORT_RVA, IMPORT_SZ)
        + b"\x00" * (14 * 8))
buf[0x218:0x218 + len(opt) + len(dirs)] = opt + dirs

# ---- 节表 @0x388（2×40B，止于 0x3D8 < 0x400）----
def sect(name, vsize, vaddr, rawsize, rawptr, chars):
    return struct.pack("<8sIIIIIIHHI", name.encode(), vsize, vaddr,
                       rawsize, rawptr, 0, 0, 0, 0, chars)

buf[0x388:0x388 + 40] = sect(".text", 0x100, 0x1000, 0x200, 0x400, 0x60000020)
buf[0x388 + 40:0x388 + 80] = sect(".idata", 0x140, 0x2000, 0x200, 0x600, 0xC0000040)

# ---- .text @0x400 ----
buf[0x400] = 0xC3
# 陷阱 2：.text 深处 0x500 埋 "Rich"（限界外，[0x40,0x200) 之外）
buf[0x500:0x504] = b"Rich"
struct.pack_into("<I", buf, 0x504, 0xAABBCCDD)

# ---- .idata @0x600（与 minipe 同构）----
buf[0x600:0x600 + 20] = struct.pack("<IIIII", 0x2060, 0, 0, 0x2028, 0x2040)
buf[0x600 + 20:0x600 + 40] = b"\x00" * 20
buf[0x628:0x628 + 13] = b"KERNEL32.dll\x00"
struct.pack_into("<Q", buf, 0x640, 0x2100)
struct.pack_into("<Q", buf, 0x640 + 8, 0)
struct.pack_into("<Q", buf, 0x660, 0x2100)
struct.pack_into("<Q", buf, 0x660 + 8, 0)
buf[0x700:0x700 + 2] = b"\x00\x00"
buf[0x702:0x702 + 12] = b"ExitProcess\x00"

out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "fixtures", "minipe_fakerich.exe")
open(out, "wb").write(bytes(buf))
print("minipe_fakerich.exe written, %d bytes" % len(buf))
