#!/usr/bin/env python3
# rekit.pe — PE32/PE32+ 手解解析器（纯 struct）
# 2026-11-07 基线B：头/节表/数据目录/导入表（DLL+函数名）
# 2026-11-12 白银#1：Rich 头解析（双向锚定，防数据深处 "Rich" 误匹配）
import struct
import sys

from .errors import FormatMismatch, MalformedBinary, RekitError

MACHINES = {0x014C: "i386", 0x8664: "AMD64", 0x01C0: "ARM", 0xAA64: "ARM64"}
SUBSYS = {1: "Native", 2: "GUI", 3: "Console", 5: "OS/2", 9: "CE GUI"}

# Rich 头常量（2026-11-12 定标：pefile 源码 + 手动 dump 双重验证）
_DANS = 0x536E6144     # 'DanS' as dword
_RICH = 0x68636952     # 'Rich' as dword


def parse_rich_header(data, e_lfanew):
    """解析 DOS stub 里的 Rich 头（MSVC 编译器指纹）。

    结构（加密域 = 每 dword ^ key）：
        [DanS][pad x3 = 0][(comp.id, count) x N]['Rich' 明文][key 明文]
    双向锚定：先限界找明文 'Rich'+key，再向前找加密态 DanS——
    单向找 'Rich' 会被 .NET 元数据/数据段深处的巧合字节串骗到（Aspose 0x147ba89 实坑）。
    返回 dict(key/pairs/dans_off/rich_off) 或 None（无 Rich / 无 DanS 锚 / 结构非法）。
    """
    # 1) 限界 [0x40, e_lfanew)：Rich 标记只可能出现在 DOS stub 区
    rich_off = data.find(b"Rich", 0x40, e_lfanew)
    if rich_off == -1 or rich_off + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, rich_off + 4)[0]
    if key == 0:
        return None
    # 2) 向前 4 字节对齐扫描加密态 DanS（双向锚定的第二锚）
    enc_dans = _DANS ^ key
    dans_off = -1
    off = 0x40
    while off + 4 <= rich_off:
        if struct.unpack_from("<I", data, off)[0] == enc_dans:
            dans_off = off
            break
        off += 4
    if dans_off == -1:
        return None
    # 3) 解密 [dans_off, rich_off)：DanS + 3 pad + 偶数个 comp.id
    n = (rich_off - dans_off) // 4
    if n < 6 or (n - 4) % 2 != 0:
        return None
    dws = [struct.unpack_from("<I", data, dans_off + 4 * i)[0] ^ key
           for i in range(n)]
    # dws[0] 已验证 = DanS；老格式(DanS^ck,ck,ck,ck)与新格式(DanS,0,0,0)
    # 在解密域统一为 [DanS, 0, 0, 0]——严格校验 3 个 padding
    if dws[1] != 0 or dws[2] != 0 or dws[3] != 0:
        return None
    pairs = [(dws[i], dws[i + 1]) for i in range(4, n, 2)]
    if not pairs:
        return None
    return {"key": key, "pairs": pairs, "dans_off": dans_off, "rich_off": rich_off}


def rva_to_raw(rva, sections):
    for (va, vsize, rawptr, rawsize, _name) in sections:
        if va <= rva < va + max(vsize, rawsize):
            if rawsize == 0:            # NOBITS/未初始化
                return None
            return rawptr + (rva - va)
    return None


def cstr(data, off):
    end = data.index(b"\x00", off)
    return data[off:end].decode("ascii", "replace")


def parse_exports(data, dirs, sections):
    """解析导出目录（目录[0]，IMAGE_EXPORT_DIRECTORY 40B）→ 三数组联动。

    结构（10 字段，R1 计数）：<IIHHIIIIIII
      Char, Time, MajVer, MinVer, Name, Base, NumFuncs, NumNames,
      AddrFuncs(EAT), AddrNames(名字RVA表), AddrOrds(EAT索引表,WORD)
    语义：
      名字导出   ordinal = Base + AddrOrds[i]，RVA = EAT[AddrOrds[i]]
      纯序号导出 只在 EAT、不在名字表（遍历全 EAT 反查发现）
      名字表顺序 ≠ EAT 顺序（本函数不假设任何顺序，全凭 AddrOrds 换算）。
    返回 dict(dll/base/nfuncs/exports=[(name|None, ordinal, rva)]) 或 None（无导出表）。
    """
    exp_rva, _sz = dirs[0]
    if not exp_rva:
        return None
    off = rva_to_raw(exp_rva, sections)
    if off is None:
        return None
    (_char, _ts, _maj, _min, name_rva, base, nfuncs, nnames,
     eat_rva, names_rva, ords_rva) = struct.unpack_from("<IIHHIIIIIII", data, off)
    dll = cstr(data, rva_to_raw(name_rva, sections))

    # EAT 全表（含纯序号项）
    eat = [struct.unpack_from("<I", data, rva_to_raw(eat_rva, sections) + i * 4)[0]
           for i in range(nfuncs)]
    # 名字表 + 序号表 → EAT 索引
    named = {}
    for i in range(nnames):
        s_rva = struct.unpack_from("<I", data, rva_to_raw(names_rva, sections) + i * 4)[0]
        eat_idx = struct.unpack_from("<H", data, rva_to_raw(ords_rva, sections) + i * 2)[0]
        named[eat_idx] = cstr(data, rva_to_raw(s_rva, sections))

    exports = [(named.get(i), base + i, eat[i]) for i in range(nfuncs)]
    return {"dll": dll, "base": base, "nfuncs": nfuncs, "exports": exports}


def parse(path):
    """解析 PE 文件。

    失败语义（库调用方按类型分支，不看消息文本）：
      读不了 -> OSError；不是 PE -> FormatMismatch；
      签名对但结构截断/损坏 -> MalformedBinary。均为显式 raise，`python -O` 下不变。
    """
    with open(path, "rb") as f:
        data = f.read()
    try:
        return _parse(data)
    except RekitError:
        raise
    except (struct.error, IndexError, ValueError) as e:
        raise MalformedBinary("PE 解析失败: %s: %s" % (type(e).__name__, e)) from e


def _parse(data):
    if data[:2] != b"MZ":
        raise FormatMismatch("no MZ header")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise FormatMismatch("no PE signature")

    # ---- COFF header ----
    machine, nsect, _ts, _psym, _nsym, optsize, chars = \
        struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)

    # ---- Optional header ----
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    if pe32plus:
        (entry, _basecode, image_base, sect_align, file_align, _mos, _mios,
         _mim, _mimn, _msub, _msubn, _w32v, size_image, size_headers, _csum,
         subsystem, _dllch, *_rest) = struct.unpack_from("<IIQIIHHHHHHIIIIHH", data, opt + 16)
    else:
        (entry, _basecode, _basedata, image_base, sect_align, file_align, _mos,
         _mios, _mim, _mimn, _msub, _msubn, _w32v, size_image, size_headers,
         _csum, subsystem, _dllch, *_rest) = struct.unpack_from("<IIIIIIHHHHHHIIIIHH", data, opt + 16)
    ndirs_off = opt + (108 if pe32plus else 92)
    num_dirs = struct.unpack_from("<I", data, ndirs_off)[0]

    # ---- 数据目录：导入表 = 目录[1] ----
    dirs = []
    for i in range(min(num_dirs, 16)):
        rva, sz = struct.unpack_from("<II", data, ndirs_off + 4 + i * 8)
        dirs.append((rva, sz))

    # ---- 节表 ----
    # M8-U2：另存一份含 schars/rawptr 的节头（既有 5 元组 sections 保持不变）。
    # PE 节名只有 8 字节；Go 等工具链把长名（.zdebug_info）写成 "/<十进制偏移>"，
    # 偏移指向 COFF 符号表末尾的字符串表。这里一并解析，供声明来源审计使用。
    sect_off = opt + optsize
    sections = []
    section_headers = []
    strtab_off = None
    if _psym and _nsym:
        cand = _psym + 18 * _nsym
        if cand + 4 <= len(data):
            strtab_off = cand

    def _long_name(raw):
        if not (raw.startswith("/") and raw[1:].isdigit() and strtab_off):
            return raw
        o = strtab_off + int(raw[1:])
        if o + 1 >= len(data):
            return raw
        e = data.find(b"\x00", o)
        if e < 0:
            return raw
        return data[o:e].decode("ascii", "replace")

    for i in range(nsect):
        o = sect_off + i * 40
        name = data[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
        (vsize, vaddr, rawsize, rawptr, _rel, _ln, _nrel, _nln,
         schars) = struct.unpack_from("<IIIIIIHHI", data, o + 8)
        sections.append((vaddr, vsize, rawptr, rawsize, name))
        section_headers.append({
            "index": i, "name": _long_name(name), "raw_name": name,
            "vaddr": vaddr, "vsize": vsize, "rawptr": rawptr,
            "rawsize": rawsize, "chars": schars,
            "header_off": o, "name_field_off": o,
        })

    # ---- 导入表（目录[1]）----
    imports = []
    imp_rva, imp_sz = dirs[1]
    if imp_rva:
        off = rva_to_raw(imp_rva, sections)
        while off is not None and data[off:off + 20] != b"\x00" * 20:
            int_rva, _ts2, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", data, off)
            dll = cstr(data, rva_to_raw(name_rva, sections))
            funcs = []
            thunk_rva = int_rva or iat_rva
            toff = rva_to_raw(thunk_rva, sections)
            while toff is not None:
                if pe32plus:
                    val = struct.unpack_from("<Q", data, toff)[0]
                    step = 8
                else:
                    val = struct.unpack_from("<I", data, toff)[0]
                    step = 4
                if val == 0:
                    break
                if val & (1 << 63 if pe32plus else 1 << 31):
                    funcs.append("#%d" % (val & 0xFFFF))
                else:
                    ho = rva_to_raw(val, sections)
                    funcs.append(cstr(data, ho + 2))   # 跳过 2 字节 hint
                toff += step
            imports.append((dll, funcs))
            off += 20
    return {"machine": MACHINES.get(machine, hex(machine)), "magic": magic,
            "entry": entry, "image_base": image_base, "subsystem": SUBSYS.get(subsystem, subsystem),
            "size_image": size_image, "size_headers": size_headers,
            "nsect": nsect, "chars": hex(chars), "sections": sections,
            "section_headers": section_headers,
            "import_dir": (imp_rva, imp_sz), "imports": imports,
            "export_dir": dirs[0], "exports": parse_exports(data, dirs, sections),
            "dirs": dirs, "symptr": _psym, "nsym": _nsym,
            "opt_off": opt, "dirs_off": ndirs_off,
            "rich": parse_rich_header(data, e_lfanew)}


def main(argv=None):
    # 2026-11-14 参数化：argv=None 时取 sys.argv（直调行为不变）；
    # cli.py 统一入口以 main([path]) 复用本渲染通道，保证输出逐字节一致。
    argv = sys.argv[1:] if argv is None else list(argv)
    path = argv[0] if argv else "tests/minipe.exe"
    r = parse(path)
    print("Machine:    %s" % r["machine"])
    print("Magic:      0x%X (%s)" % (r["magic"], "PE32+" if r["magic"] == 0x20B else "PE32"))
    print("EntryPoint: 0x%X (RVA)" % r["entry"])
    print("ImageBase:  0x%X" % r["image_base"])
    print("Subsystem:  %s" % r["subsystem"])
    print("SizeOfImage: 0x%X  SizeOfHeaders: 0x%X" % (r["size_image"], r["size_headers"]))
    print("ImportDir:  RVA 0x%X size 0x%X" % r["import_dir"])
    ex = r["exports"]
    if ex is None:
        print("Exports:    (none)")
    else:
        print("Exports:    %s (base=%d, %d funcs)" % (ex["dll"], ex["base"], ex["nfuncs"]))
        for (nm, ordinal, rva) in ex["exports"]:
            print("  ord %-4d  RVA 0x%04X  %s" % (ordinal, rva, nm if nm else "(ordinal-only)"))
    print("Sections (%d):" % r["nsect"])
    for (va, vs, rp, rs, nm) in r["sections"]:
        print("  %-8s VA=0x%08x VSize=0x%x RawPtr=0x%x RawSize=0x%x" % (nm, va, vs, rp, rs))
    print("Imports:")
    for (dll, funcs) in r["imports"]:
        print("  %s: %s" % (dll, ", ".join(funcs)))
    rh = r["rich"]
    if rh is None:
        print("Rich:       (none)")
    else:
        print("Rich:       key=0x%08X DanS@0x%x Rich@0x%x pairs=%d" %
              (rh["key"], rh["dans_off"], rh["rich_off"], len(rh["pairs"])))
        for (cid, cnt) in rh["pairs"]:
            print("    comp.id=0x%08X (prodid=%d build=%d) count=%d" %
                  (cid, cid >> 16, cid & 0xFFFF, cnt))


if __name__ == "__main__":
    main()
