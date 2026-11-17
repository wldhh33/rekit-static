#!/usr/bin/env python3
# rekit.elf — ELF64 手解解析器（纯 struct）
# 谱系：2026-11-06 mini_elf.py（白银任务）→ 2026-11-07 基线A：新增节区表+节名解析
#        → 2026-11-07 白银：新增动态段解析（PT_DYNAMIC → DT_NEEDED）
#        → 2026-11-08 白银：新增符号表解析（SHT_SYMTAB/SHT_DYNSYM → 符号名+地址）
#        → 2026-11-09 白银：新增重定位解析（SHT_RELA → offset/type/sym_idx/sym_name/addend）
import struct
import sys

from .errors import FormatMismatch, MalformedBinary, RekitError

SH_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
            5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
            10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
            17: "GROUP", 18: "SYMTAB SHndx", 0x6ffffff6: "GNU_HASH",
            0x6ffffffd: "VERDEF", 0x6ffffffe: "VERNEED", 0x6fffffff: "VERSYM"}

PT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
            6: "PHDR", 7: "TLS", 0x6474e550: "EH_FRAME", 0x6474e551: "STACK",
            0x6474e552: "RELRO", 0x6474e553: "PROPERTY"}
PT_LOAD, PT_DYNAMIC = 1, 2
PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 3, 0x6474e551, 0x6474e552

DT_TAGS = {0: "NULL", 1: "NEEDED", 2: "PLTRELSZ", 3: "PLTGOT", 4: "HASH",
           5: "STRTAB", 6: "SYMTAB", 7: "RELA", 8: "RELASZ", 9: "RELAENT",
           10: "STRSZ", 11: "SYMENT", 15: "RPATH", 20: "PLTREL", 21: "DEBUG",
           22: "TEXTREL", 23: "JMPREL", 24: "BIND_NOW", 30: "FLAGS",
           0x19: "INIT_ARRAY", 0x1a: "FINI_ARRAY",
           0x1b: "INIT_ARRAYSZ", 0x1c: "FINI_ARRAYSZ", 0x6ffffffb: "FLAGS_1",
           0x6ffffffe: "VERNEED", 0x6fffffff: "VERNEEDNUM", 0x6ffffff0: "VERSYM"}
# 2026-11-10 修正：原表 15:"DEBUG"/21:"JMPREL"/23:"BIND_NOW" 三处错位
# （真值 15=RPATH 21=DEBUG 22=TEXTREL 23=JMPREL 24=BIND_NOW 30=FLAGS），
# 今日 RELRO 语义依赖 tag 24 精确值，错误暴露并修复。
DT_BIND_NOW_TAG, DT_FLAGS_TAG, DT_FLAGS_1_TAG = 24, 30, 0x6ffffffb
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1  # DT_FLAGS / DT_FLAGS_1 的立即绑定位
ET_EXEC, ET_DYN = 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB = 0, 1, 5
SHT_SYMTAB, SHT_DYNSYM, SHT_RELA = 2, 11, 4
ST_BIND = {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}
ST_TYPE = {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}
# x86-64 重定位类型（本机实测覆盖：5/6/7/8/37；其余为常见静态链接类型，防御性收录）
R_TYPES = {0: "R_X86_64_NONE", 1: "R_X86_64_64", 2: "R_X86_64_PC32", 3: "R_X86_64_GOT32",
           4: "R_X86_64_PLT32", 5: "R_X86_64_COPY", 6: "R_X86_64_GLOB_DAT",
           7: "R_X86_64_JUMP_SLOT", 8: "R_X86_64_RELATIVE", 9: "R_X86_64_GOTPCREL",
           11: "R_X86_64_32", 12: "R_X86_64_32S", 16: "R_X86_64_16", 17: "R_X86_64_PC16",
           18: "R_X86_64_8", 32: "R_X86_64_PC64", 37: "R_X86_64_IRELATIVE",
           41: "R_X86_64_GOTPCRELX", 42: "R_X86_64_REX_GOTPCRELX"}


def parse(path):
    """解析 ELF 文件。

    失败语义（库调用方按类型分支，不看消息文本）：
      读不了 -> OSError；不是 ELF -> FormatMismatch；
      签名对但结构截断/损坏 -> MalformedBinary。均为显式 raise，`python -O` 下不变。
    """
    with open(path, "rb") as f:
        data = f.read()
    try:
        return _parse(data)
    except RekitError:
        raise
    except (struct.error, IndexError, ValueError) as e:
        raise MalformedBinary("ELF 解析失败: %s: %s" % (type(e).__name__, e)) from e


def _parse(data):
    if data[:4] != b"\x7fELF":
        raise FormatMismatch("not ELF")
    ei_class, ei_data = data[4], data[5]
    end = "<" if ei_data == 1 else ">"
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flg, _ehsz,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
        struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)

    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, _msz, _al) = \
            struct.unpack_from(end + "IIQQQQQQ", data, off)
        phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz))

    # ---- 节表 + shstrtab 节名（基线A新增） ----
    # 元组增补 sh_link/sh_entsize（2026-11-08：符号表解析需要 sh_link 定位字符串表节）
    shdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size,
         sh_link, _info, _align, sh_entsz) = struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        shdrs.append((sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsz))

    # shstrtab: 节表第 e_shstrndx 项给出字符串表的文件偏移与大小
    sn_off, sn_size = shdrs[e_shstrndx][3], shdrs[e_shstrndx][4]
    blob = data[sn_off:sn_off + sn_size]

    def cstr(o):
        e = blob.index(b"\x00", o)
        return blob[o:e].decode("ascii", "replace")

    sections = [(cstr(n), SH_TYPES.get(t, hex(t)), a, o, s)
                for (n, t, a, o, s, _lk, _es) in shdrs]
    # ---- 动态段解析（2026-11-07 白银新增）----
    # 技术核心：DT_STRTAB 的值是 vaddr，PIE/非 PIE 中都可能与文件偏移不同，
    # 必须经 PT_LOAD 映射换算：file_off = vaddr - p_vaddr + p_offset
    def vaddr_to_off(v):
        for (_t, _fl, off, va, fsz) in phdrs:
            if _t == PT_LOAD and va <= v < va + fsz:
                return v - va + off
        return None

    dynamic = None
    dyn_ph = next((p for p in phdrs if p[0] == PT_DYNAMIC), None)
    if dyn_ph is not None:
        _t, _fl, d_off, d_va, d_fsz = dyn_ph
        # Elf64_Dyn = { Elf64_Sxword d_tag; union d_val; } 共 16 字节
        entries = []
        for i in range(d_fsz // 16):
            tag, val = struct.unpack_from(end + "QQ", data, d_off + i * 16)
            if tag == DT_NULL:
                entries.append((tag, val))
                break
            entries.append((tag, val))
        strtab_va = next((v for (t, v) in entries if t == DT_STRTAB), None)
        strtab_off = vaddr_to_off(strtab_va) if strtab_va is not None else None
        needed = []
        if strtab_off is not None:
            for (t, v) in entries:
                if t == DT_NEEDED:
                    s = strtab_off + v
                    e = data.index(b"\x00", s)
                    needed.append(data[s:e].decode("ascii", "replace"))
        dynamic = {"offset": d_off, "vaddr": d_va, "filesz": d_fsz,
                   "strtab_vaddr": strtab_va, "strtab_off": strtab_off,
                   "needed": needed, "n_entries": len(entries), "raw": entries}

    # ---- 符号表解析（2026-11-08 白银新增）----
    # 路线：节表直查（SHT_SYMTAB=2 完整静态表 / SHT_DYNSYM=11 动态表），
    # 符号名在 sh_link 指向的字符串表节（.strtab/.dynstr）里——sh_link 是【节索引】
    # Elf64_Sym(24B): st_name u32 | st_info u8 | st_other u8 | st_shndx u16 | st_value u64 | st_size u64
    # 注意：st_value 是链接视图的 vaddr（readelf 原样显示，无需换算文件偏移）；
    #       st_shndx==0(SHN_UNDEF) 表示导入符号，value 恒为 0
    def parse_symtab(sh_type):
        sym_sh = next((s for s in shdrs if s[1] == sh_type), None)
        if sym_sh is None:
            return None
        str_sh = shdrs[sym_sh[5]]  # sh_link → 配套字符串表节
        strtab = data[str_sh[3]:str_sh[3] + str_sh[4]]
        entsz = sym_sh[6] or 24
        n = sym_sh[4] // entsz
        syms = []
        for i in range(n):
            off = sym_sh[3] + i * entsz
            (st_name, st_info, _st_other, st_shndx, st_value, st_size) = \
                struct.unpack_from(end + "IBBHQQ", data, off)
            nm = ""
            if st_name:
                e2 = strtab.index(b"\x00", st_name)
                nm = strtab[st_name:e2].decode("ascii", "replace")
            syms.append((nm, st_value, st_size,
                         ST_BIND.get(st_info >> 4, hex(st_info >> 4)),
                         ST_TYPE.get(st_info & 0xF, hex(st_info & 0xF)),
                         st_shndx))
        return syms

    symbols = {"dynsym": parse_symtab(SHT_DYNSYM),
               "symtab": parse_symtab(SHT_SYMTAB)}

    # ---- 重定位解析（2026-11-09 白银新增）----
    # 路线：节表直查 SHT_RELA(4) 节（.rela.dyn / .rela.plt）
    # Elf64_Rela(24B) = r_offset u64 | r_info u64 | r_addend i64（3 字段，R1 数过）
    # r_info 拆解：高 32 位 = 符号表序号（0=无符号，RELATIVE/IRELATIVE 皆如此），
    #              低 32 位 = 重定位类型（x86_64: 8=RELATIVE 6=GLOB_DAT 7=JUMP_SLOT 5=COPY 37=IRELATIVE）
    # 联动：RELA 节的 sh_link 指向配套符号表节（.dynsym）→ 序号查名字；
    #       sh_info 指向重定位作用的节（.got/.got.plt/.bss）——A3 验收用它做落点交叉验证
    def parse_rela_sections():
        relocs = []
        for i, (_n, t, _a, o, s, lk, es) in enumerate(shdrs):
            if t != SHT_RELA:
                continue
            syms = None
            if lk < len(shdrs) and shdrs[lk][1] in (SHT_DYNSYM, SHT_SYMTAB):
                syms = parse_symtab(shdrs[lk][1])
            entsz = es or 24
            entries = []
            for j in range(s // entsz):
                off = o + j * entsz
                r_offset, r_info, r_addend = struct.unpack_from(end + "QQq", data, off)
                sym_idx = r_info >> 32
                rtype = r_info & 0xFFFFFFFF
                sym_nm, sym_val = "", 0
                if sym_idx and syms is not None and sym_idx < len(syms):
                    sym_nm, sym_val = syms[sym_idx][0], syms[sym_idx][1]
                entries.append((r_offset, r_info, rtype,
                                R_TYPES.get(rtype, "R_X86_64_?%d" % rtype),
                                sym_idx, sym_nm, sym_val, r_addend))
            relocs.append((sections[i][0], o, entries))
        return relocs

    relocations = parse_rela_sections()

    # ---- 安全态检测（2026-11-10 白银新增，checksec 语义对齐）----
    # NX：PT_GNU_STACK flags 含 X(1) → 栈可执行 → disabled；RW → enabled；
    #     段缺失 → 老内核回退栈可执行语义，保守报 disabled 并注明原因
    # RELRO 三态：无 PT_GNU_RELRO → none；有 + 立即绑定 → full；有 + 延迟绑定 → partial
    #     立即绑定三路：DT_BIND_NOW(24) 存在 ∨ DT_FLAGS(30)&DF_BIND_NOW(0x8)
    #                   ∨ DT_FLAGS_1(0x6ffffffb)&DF_1_NOW(0x1)
    #     （证据等级：FLAGS/FLAGS_1 路径有真实样本；tag-24 为防御性收录，无样本覆盖）
    # PIE：ET_EXEC → no；ET_DYN+PT_INTERP → yes；ET_DYN 无 INTERP → dso（共享库）
    # W+X 扫描：任一 PT_LOAD 同含 W(2)+X(1) → 报警（壳/自修改代码的常见指纹）
    dyn_raw = dynamic["raw"] if dynamic else []
    stack_ph = next((p for p in phdrs if p[0] == PT_GNU_STACK), None)
    relro_ph = next((p for p in phdrs if p[0] == PT_GNU_RELRO), None)
    if stack_ph is None:
        nx, nx_reason = "disabled", "no PT_GNU_STACK (kernel default: exec)"
    else:
        nx = "disabled" if stack_ph[1] & 0x1 else "enabled"
        nx_reason = "GNU_STACK %s" % ("RWE" if stack_ph[1] & 0x1 else "RW")
    bind_now = (any(t == DT_BIND_NOW_TAG for t, _v in dyn_raw)
                or any(t == DT_FLAGS_TAG and _v & DF_BIND_NOW for t, _v in dyn_raw)
                or any(t == DT_FLAGS_1_TAG and _v & DF_1_NOW for t, _v in dyn_raw))
    relro = "none" if relro_ph is None else ("full" if bind_now else "partial")
    if e_type == ET_EXEC:
        pie = "no"
    elif any(p[0] == PT_INTERP for p in phdrs):
        pie = "yes"
    else:
        pie = "dso"
    wx_loads = ["0x%x" % p[3] for p in phdrs
                if p[0] == PT_LOAD and p[1] & 0x3 == 0x3]
    security = {"nx": nx, "nx_reason": nx_reason, "relro": relro,
                "bind_now": bind_now, "pie": pie,
                "gnu_stack_flags": None if stack_ph is None else stack_ph[1],
                "relro_filesz": 0 if relro_ph is None else relro_ph[4],
                "wx_segments": wx_loads}

    return {"type": e_type, "machine": e_machine, "entry": e_entry,
            "phdrs": phdrs, "sections": sections, "dynamic": dynamic,
            "symbols": symbols, "relocations": relocations,
            "security": security}


# ── M3（2026-11-15）：映射层所需的原始表 ────────────────────────────────
# parse() 的 phdrs 元组为兼容 M1 断言只含 5 个字段（无 p_memsz），sections 元组
# 也不含 sh_flags。映射层要区分「文件背书 / 零填充」必须拿到 memsz 与 alloc 标志，
# 故另立两个只读函数——纯增量，不改 parse() 的返回结构（92 条断言不受影响）。

def program_headers(data):
    """全部 program header（dict 列表，含 p_memsz/p_align）。不是 ELF 抛 FormatMismatch。"""
    if data[:4] != b"\x7fELF":
        raise FormatMismatch("not ELF")
    end = "<" if data[5] == 1 else ">"
    (_t, _m, _v, _e, e_phoff, _so, _fl, _eh, e_phentsize, e_phnum,
     _shentsize, _shnum, _shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, p_memsz, p_align) = \
            struct.unpack_from(end + "IIQQQQQQ", data, off)
        out.append({"type_id": p_type, "type": PT_TYPES.get(p_type, hex(p_type)),
                    "flags": p_flags, "offset": p_offset, "vaddr": p_vaddr,
                    "filesz": p_filesz, "memsz": p_memsz, "align": p_align})
    return out


def section_headers(data):
    """全部节头（dict 列表，含 sh_flags/sh_type_id）。

    e_shnum == 0（如 UPX 加壳后节表被移除）时返回 []，不抛异常——
    映射层据此把节级换算判为「不可判定」而不是崩或猜 0 节。不是 ELF 抛 FormatMismatch。
    """
    if data[:4] != b"\x7fELF":
        raise FormatMismatch("not ELF")
    end = "<" if data[5] == 1 else ">"
    (_t, _m, _v, _e, _po, e_shoff, _fl, _eh, _pe, _pn,
     e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    if e_shoff == 0 or e_shnum == 0:
        return []
    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, _info, _align, sh_entsize) = \
            struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                    sh_link, sh_entsize))
    # 节名：第 e_shstrndx 项的 offset/size 指向节名串表
    blob = b""
    if 0 <= e_shstrndx < len(raw):
        _n, _t2, _f, _a, sn_off, sn_size = raw[e_shstrndx][:6]
        blob = data[sn_off:sn_off + sn_size]

    def cstr(o):
        if not blob:
            return ""
        e = blob.index(b"\x00", o) if b"\x00" in blob[o:] else len(blob)
        return blob[o:e].decode("ascii", "replace")

    out = []
    for (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_entsize) in raw:
        out.append({"index": len(out), "name": cstr(sh_name),
                    "type_id": sh_type, "type": SH_TYPES.get(sh_type, hex(sh_type)),
                    "flags": sh_flags, "addr": sh_addr, "offset": sh_offset,
                    "size": sh_size, "link": sh_link, "entsize": sh_entsize,
                    "alloc": bool(sh_flags & 0x2), "write": bool(sh_flags & 0x1),
                    "exec": bool(sh_flags & 0x4)})
    return out


def main(argv=None):
    # 2026-11-14 参数化：argv=None 时取 sys.argv（直调行为不变）；
    # cli.py 统一入口以 main([path]) 复用本渲染通道，保证输出逐字节一致。
    argv = sys.argv[1:] if argv is None else list(argv)
    path = argv[0] if argv else "/bin/ls"
    r = parse(path)
    s = r["security"]
    print("Checksec: NX %s (%s) | RELRO %s | PIE %s | W+X segs %s" %
          (s["nx"], s["nx_reason"], s["relro"], s["pie"],
           ",".join(s["wx_segments"]) or "none"))
    print("Entry: 0x%x  Sections: %d  Phdrs: %d" %
          (r["entry"], len(r["sections"]), len(r["phdrs"])))
    print("%-3s %-24s %-14s %-18s %10s %10s" %
          ("Nr", "Name", "Type", "Address", "Off", "Size"))
    for i, (nm, t, a, o, s) in enumerate(r["sections"]):
        print("[%2d] %-24s %-14s 0x%016x 0x%08x 0x%08x" % (i, nm, t, a, o, s))
    d = r["dynamic"]
    if d:
        print("\nDYNAMIC: offset 0x%x vaddr 0x%x filesz 0x%x (%d entries)" %
              (d["offset"], d["vaddr"], d["filesz"], d["n_entries"]))
        print("  STRTAB vaddr 0x%x -> file offset 0x%x" %
              (d["strtab_vaddr"] or 0, d["strtab_off"] or 0))
        for lib in d["needed"]:
            print("  NEEDED: %s" % lib)
    for key in ("dynsym", "symtab"):
        syms = r["symbols"][key]
        if syms:
            print("\n%s: %d symbols" % (key, len(syms)))
            print("%-30s %-18s %-6s %-8s %-8s %s" %
                  ("Name", "Value", "Size", "Bind", "Type", "Ndx"))
            shown = 0
            for (nm, val, sz, bd, ty, ndx) in syms:
                if not nm and key == "symtab":
                    continue  # symtab 噪音多，跳过匿名 SECTION 符号
                print("%-30s 0x%016x %-6d %-8s %-8s %s" % (nm or "<null>", val, sz, bd, ty, ndx))
                shown += 1
                if shown >= 12 and key == "symtab":
                    print("  ... (%d total)" % len(syms))
                    break
        else:
            print("\n%s: (absent)" % key)

    # 重定位（readelf -r 风格；无符号行 addend 为裸十六进制，带符号行为 "+ 十进制"）
    for (nm, off, ents) in r["relocations"]:
        print("\nRelocation section '%s' at offset 0x%x contains %d entries:" %
              (nm, off, len(ents)))
        print("%-18s %-18s %-21s %s" %
              ("Offset", "Info", "Type", "Sym.Value Sym. Name + Addend"))
        for (o, info, _tn, tname, si, sn, sv, ad) in ents:
            if sn:
                print("%016x  %016x %-21s %016x %s + %d" % (o, info, tname, sv, sn, ad))
            else:
                print("%016x  %016x %-21s %x" % (o, info, tname, ad))


if __name__ == "__main__":
    main()
