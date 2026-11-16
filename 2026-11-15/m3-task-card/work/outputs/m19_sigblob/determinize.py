#!/usr/bin/env python3
# determinize.py — 把 ilasm 输出里随机的两处（COFF 时间戳 / #GUID 里的 MVID）固定下来
#
# 背景：ilasm 每次汇编都会重新生成 MVID，导致同一份 .il 两次输出 sha256 不同，
#       样本登记（m19_sample_manifest.json）随之漂移。实测两次汇编只差 16 字节，
#       且都在 #GUID 堆首（MVID）；COFF TimeDateStamp 本机同为常量，仍一并清零。
#
# 用法：python determinize.py <file.dll> [...]
# 产出：原位改写（只在同一偏移改固定值，不加减字节）；成功 exit 0，解析失败 exit 1。
#
# 固定值来源：sha256("rekit/m19/" + 文件名)[:16]，逐文件不同、跨机器相同。
# 注意：只保证「同版本 ilasm + 本脚本」逐字节可复现；换 ilasm 版本仍可能变，
#       重跑 gen.ps1 会重写 manifest，preflight 会对不上就 exit 2。
import hashlib
import os
import struct
import sys


def _u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def _u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def _rva_to_off(b, pe, sections, rva):
    for va, vsize, raw_size, raw_ptr in sections:
        if va <= rva < va + max(vsize, raw_size):
            return raw_ptr + (rva - va)
    raise ValueError("RVA 0x%x 不落任何节" % rva)


def _sections(b, pe):
    nsec = _u16(b, pe + 6)
    opt_size = _u16(b, pe + 20)
    base = pe + 24 + opt_size
    out = []
    for i in range(nsec):
        off = base + i * 40
        vsize = _u32(b, off + 8)
        va = _u32(b, off + 12)
        raw_size = _u32(b, off + 16)
        raw_ptr = _u32(b, off + 20)
        out.append((va, vsize, raw_size, raw_ptr))
    return out


def _streams(b, meta):
    if b[meta:meta + 4] != b"BSJB":
        raise ValueError("元数据根不是 BSJB")
    ver_len = _u32(b, meta + 12)
    p = meta + 16 + ((ver_len + 3) & ~3)
    nstreams = _u16(b, p + 2)
    p += 4
    out = []
    for _ in range(nstreams):
        off = _u32(b, p)
        size = _u32(b, p + 4)
        p += 8
        end = b.index(b"\x00", p)
        name = b[p:end].decode("ascii")
        p += ((end - p) + 4) & ~3
        out.append((name, meta + off, size))
    return out


def patch(path):
    with open(path, "rb") as f:
        b = bytearray(f.read())
    if b[:2] != b"MZ":
        raise ValueError("不是 PE（缺 MZ）")
    pe = _u32(b, 0x3C)
    if b[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("不是 PE（缺 PE 签名）")
    struct.pack_into("<I", b, pe + 8, 0)              # COFF TimeDateStamp
    opt = pe + 24
    magic = _u16(b, opt)
    dd = opt + (96 if magic == 0x10B else 112)        # DataDirectory 起点
    cli_rva = _u32(b, dd + 14 * 8)                    # 第 14 项 = CLI Header
    secs = _sections(b, pe)
    cli = _rva_to_off(b, pe, secs, cli_rva)
    meta_rva = _u32(b, cli + 8)
    meta = _rva_to_off(b, pe, secs, meta_rva)
    streams = _streams(b, meta)
    guids = [s for s in streams if s[0] == "#GUID"]
    if not guids:
        raise ValueError("缺 #GUID 堆")
    _, goff, gsize = guids[0]
    if gsize < 16:
        raise ValueError("#GUID 堆不足 16 字节")
    fixed = hashlib.sha256(
        b"rekit/m19/" + os.path.basename(path).lower().encode("utf-8")).digest()[:16]
    b[goff:goff + 16] = fixed
    with open(path, "wb") as f:
        f.write(b)
    return goff


def main(argv):
    if len(argv) < 2:
        print("usage: determinize.py <file.dll> [...]")
        return 2
    rc = 0
    for p in argv[1:]:
        try:
            off = patch(p)
            print("determinize: OK %s (MVID@0x%x)" % (os.path.basename(p), off))
        except Exception as e:
            print("determinize: FAIL %s: %s: %s"
                  % (os.path.basename(p), type(e).__name__, e))
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
