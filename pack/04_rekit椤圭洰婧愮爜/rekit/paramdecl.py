#!/usr/bin/env python3
# rekit.paramdecl — 声明来源读取与参数绑定（M8-U2）
#
# 本模块只回答一件事：**文件里真的写着的形参声明**能否把调用点的操作数绑到形参上。
#
# 硬约束（对应 M8-U2 四条）：
#   1) 只认 declared：DWARF 的 DW_TAG_subprogram / DW_TAG_formal_parameter、
#      PE 导出表、PDB 引用（RSDS）、ELF/PE 符号表、.eh_frame、.pdata。
#      每一条来源必须给出「文件哪一处 + 怎么读到的」：
#      节头索引/sh_offset/sh_size/压缩头、PE 数据目录索引/RVA→文件偏移、
#      DIE 偏移/CU 偏移/位置列表偏移/表达式字节。
#      读不到（压缩失败、外部 debug 文件缺失、PDB 类型流未解码）一律 abstain，
#      不用「看起来像标准 ABI」补齐。
#   2) 禁止 ABI 推断：不按寄存器顺序猜参数序号，不按平台惯例补参数个数。
#      导出表/符号表只声明函数身份（名字/序号/地址），**不含参数**——这是结构性的，
#      不是「本样本碰巧为 0」。PDB 的 TPI 只声明类型；位置需要 CodeView 位置记录，
#      本轮未解码，故 PDB 一律 abstain（缺：可复核的 PDB 位置记录读取）。
#   3) 分母先行：audit() 返回每个样本每类来源的 present/readable/声明计数；
#      某类来源在现有样本中一条都没有时，调用方必须报「本轮无法验证」，
#      不得把 0 当作「该类来源没有参数声明」的结论。
#   4) 数字分列：bind_site() 返回 bound / partial / abstained 三类，
#      每条弃权都写 missing；调用方分别计数，不合成净增量。
#
# DWARF 支持范围（每个 form 都有读取路径）：
#   DWARF 2–5，32/64 位；ELF SHF_COMPRESSED / .zdebug 与 PE .zdebug 解压；
#   .debug_abbrev / .debug_info / .debug_str / .debug_line_str /
#   .debug_str_offsets / .debug_addr / .debug_loclists。
#   位置表达式只解释「入口处的寄存器段列表」（DW_OP_reg*/DW_OP_piece）与
#   栈位置（DW_OP_fbreg/DW_OP_call_frame_cfa）；其它表达式一律 abstain。
import os
import struct
import zlib

from . import elf, pe

# ── DWARF 常量 ──────────────────────────────────────────────────────
DW_TAG_compile_unit = 0x11
DW_TAG_subprogram = 0x2E
DW_TAG_formal_parameter = 0x05
# M16：数据对象层（datarefs）需要变量声明与类型链尺寸；见模块 docstring 的边界说明。
DW_TAG_variable = 0x34
DW_TAG_array_type = 0x01
DW_TAG_enumeration_type = 0x04
DW_TAG_pointer_type = 0x0F
DW_TAG_reference_type = 0x10
DW_TAG_structure_type = 0x13
DW_TAG_typedef = 0x16
DW_TAG_union_type = 0x17
DW_TAG_subrange_type = 0x21
DW_TAG_base_type = 0x24
DW_TAG_const_type = 0x26
DW_TAG_volatile_type = 0x35
DW_TAG_restrict_type = 0x37
DW_TAG_unspecified_type = 0x3B
DW_TAG_rvalue_reference_type = 0x42
DW_TAG_atomic_type = 0x47

DW_AT_name = 0x03
DW_AT_location = 0x02
DW_AT_low_pc = 0x11
DW_AT_high_pc = 0x12
DW_AT_ranges = 0x55
DW_AT_type = 0x49
DW_AT_byte_size = 0x0B
DW_AT_upper_bound = 0x2F
DW_AT_lower_bound = 0x22
DW_AT_count = 0x37
DW_AT_abstract_origin = 0x31
DW_AT_specification = 0x47
DW_AT_variable_parameter = 0x4B
DW_AT_str_offsets_base = 0x72
DW_AT_addr_base = 0x73
DW_AT_loclists_base = 0x74

DW_FORM_addr = 0x01
DW_FORM_block2 = 0x03
DW_FORM_block4 = 0x04
DW_FORM_data2 = 0x05
DW_FORM_data4 = 0x06
DW_FORM_data8 = 0x07
DW_FORM_string = 0x08
DW_FORM_block = 0x09
DW_FORM_block1 = 0x0A
DW_FORM_data1 = 0x0B
DW_FORM_flag = 0x0C
DW_FORM_sdata = 0x0D
DW_FORM_strp = 0x0E
DW_FORM_udata = 0x0F
DW_FORM_ref_addr = 0x10
DW_FORM_ref1 = 0x11
DW_FORM_ref2 = 0x12
DW_FORM_ref4 = 0x13
DW_FORM_ref8 = 0x14
DW_FORM_ref_udata = 0x15
DW_FORM_indirect = 0x16
DW_FORM_sec_offset = 0x17
DW_FORM_exprloc = 0x18
DW_FORM_flag_present = 0x19
DW_FORM_strx = 0x1A
DW_FORM_addrx = 0x1B
DW_FORM_ref_sup4 = 0x1C
DW_FORM_strp_sup = 0x1D
DW_FORM_data16 = 0x1E
DW_FORM_line_strp = 0x1F
DW_FORM_ref_sig8 = 0x20
DW_FORM_implicit_const = 0x21
DW_FORM_loclistx = 0x22
DW_FORM_rnglistx = 0x23
DW_FORM_ref_sup8 = 0x24
DW_FORM_strx1 = 0x25
DW_FORM_strx2 = 0x26
DW_FORM_strx3 = 0x27
DW_FORM_strx4 = 0x28
DW_FORM_addrx1 = 0x29
DW_FORM_addrx2 = 0x2A
DW_FORM_addrx3 = 0x2B
DW_FORM_addrx4 = 0x2C

DW_LLE_end_of_list = 0x00
DW_LLE_base_addressx = 0x01
DW_LLE_startx_endx = 0x02
DW_LLE_startx_length = 0x03
DW_LLE_offset_pair = 0x04
DW_LLE_default_location = 0x05
DW_LLE_base_address = 0x06
DW_LLE_start_end = 0x07
DW_LLE_start_length = 0x08

# x86-64 DWARF 寄存器编号（psABI，0..16）
REG_NAMES = ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"]

# 声明来源分类：只有 dwarf 这一类携带形参「位置」；其余只声明函数身份/范围。
CLASS_DECLARES = {
    "dwarf": "formal_parameters",
    "pdb": "types_only_undecoded",
    "export_table": "function_identity_only",
    "coff_symbols": "function_identity_only",
    "elf_symtab": "function_identity_only",
    "elf_dynsym": "function_identity_only",
    "gnu_debuglink": "external_reference_only",
    "eh_frame": "function_range_only",
    "pdata": "function_range_only",
}


# ── 字节读取 ────────────────────────────────────────────────────────
def _u(data, off, size, end="<"):
    if off < 0 or off + size > len(data):
        raise ValueError("read out of bounds: off=0x%x size=%d len=%d"
                         % (off, size, len(data)))
    if size == 1:
        return data[off]
    if size == 2:
        return struct.unpack_from(end + "H", data, off)[0]
    if size == 4:
        return struct.unpack_from(end + "I", data, off)[0]
    if size == 8:
        return struct.unpack_from(end + "Q", data, off)[0]
    raise ValueError("bad int size %d" % size)


def _uleb(data, off):
    val, shift = 0, 0
    while True:
        if off >= len(data):
            raise ValueError("uleb out of bounds")
        b = data[off]
        off += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, off
        shift += 7
        if shift > 70:
            raise ValueError("uleb too long")


def _sleb(data, off):
    val, shift = 0, 0
    while True:
        if off >= len(data):
            raise ValueError("sleb out of bounds")
        b = data[off]
        off += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if shift < 70 and (b & 0x40):
                val |= -(1 << shift)
            return val, off


def _cstr(data, off):
    if off < 0 or off >= len(data):
        raise ValueError("cstring out of bounds")
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", "replace"), end + 1


def _uint3(data, off):
    if off + 3 > len(data):
        raise ValueError("read out of bounds: off=0x%x size=3" % off)
    return int.from_bytes(data[off:off + 3], "little")


# ── 节解压 ──────────────────────────────────────────────────────────
def _zlib_old(raw, loc):
    if len(raw) < 12:
        return b"", loc + "；'ZLIB' 头不足 12 字节", False
    usize = struct.unpack_from(">Q", raw, 4)[0]
    try:
        out = zlib.decompress(raw[12:])
    except zlib.error as e:
        return b"", loc + "；ZLIB 解压失败：%s" % e, False
    return out, loc + "；首 4 字节 'ZLIB'+u64(BE)=0x%x；zlib 解压得 0x%x 字节" \
        % (usize, len(out)), True


def _elf_section_bytes(data, hdr):
    raw = data[hdr["offset"]:hdr["offset"] + hdr["size"]]
    loc = ("ELF 节头[%d] %s sh_offset=0x%x sh_size=0x%x sh_flags=0x%x" %
           (hdr["index"], hdr["name"], hdr["offset"], hdr["size"], hdr["flags"]))
    if hdr["flags"] & 0x800:                        # SHF_COMPRESSED
        if len(raw) < 24:
            return b"", loc + "(SHF_COMPRESSED)；压缩头不足 24 字节", False
        ctype, _res, csize, _align = struct.unpack_from("<IIQQ", raw, 0)
        if ctype != 1:
            return b"", loc + "(SHF_COMPRESSED)；Chdr.ch_type=%d（非 zlib）" % ctype, False
        try:
            out = zlib.decompress(raw[24:])
        except zlib.error as e:
            return b"", loc + "(SHF_COMPRESSED)；Chdr ch_size=0x%x；zlib 失败：%s" \
                % (csize, e), False
        return out, loc + "(SHF_COMPRESSED)；Chdr{ch_type=%d,ch_size=0x%x}；" \
            "zlib 解压得 0x%x 字节" % (ctype, csize, len(out)), True
    if raw[:4] == b"ZLIB":
        return _zlib_old(raw, loc)
    return raw, loc + "；未压缩", True


def _pe_section_bytes(data, hdr):
    raw = data[hdr["rawptr"]:hdr["rawptr"] + hdr["rawsize"]]
    loc = ("PE 节头[%d] raw_name=%r→%r rawptr=0x%x rawsize=0x%x chars=0x%x" %
           (hdr["index"], hdr["raw_name"], hdr["name"], hdr["rawptr"],
            hdr["rawsize"], hdr["chars"]))
    if raw[:4] == b"ZLIB":
        return _zlib_old(raw, loc)
    return raw, loc + "；未压缩", True


def _canon(name):
    # ".zdebug_" 是 8 个字符（含下划线），故取 name[8:]；
    # 原先写成 name[7:] 会得到 ".debug__info"（多一个下划线），PE 的
    # .zdebug_info 因此查不到 .debug_info。ELF 压缩节保留 .debug_* 原名，
    # 不经过此处，所以这个 bug 只在 PE .zdebug_* 上暴露。
    if name.startswith(".zdebug_"):
        return ".debug_" + name[8:]
    return name


# ── DWARF abbrev / CU / DIE ────────────────────────────────────────
def _abbrev_table(data, offset, _cache={}):
    """解析从 offset 开始的一张 abbrev 表（以 code=0 终止）。

    缓存键用内容（bytes 可哈希）而不是 id(data)：id 是进程内内存地址，
    上一份节字节被回收后地址会被复用，仅按 (id, offset, len) 命中会把
    别的字节的 abbrev 表当成这一份的 → 同一文件偶发解析失败。键里带上
    data 本身同时保证字节对象不被回收，id 复用的问题一并消失。
    """
    key = (data, offset)
    if key in _cache:
        return _cache[key]
    tables = {}
    off = offset
    while off < len(data):
        code, off = _uleb(data, off)
        if code == 0:
            break
        tag, off = _uleb(data, off)
        if off >= len(data):
            raise ValueError("abbrev truncated")
        children = data[off]
        off += 1
        specs = []
        while True:
            at, off = _uleb(data, off)
            form, off = _uleb(data, off)
            ic = None
            if form == DW_FORM_implicit_const:
                ic, off = _sleb(data, off)
            if at == 0 and form == 0:
                break
            specs.append((at, form, ic))
        tables[code] = (tag, children, specs)
    _cache[key] = tables
    return tables


def _cu_header(info, off):
    start = off
    length = _u(info, off, 4)
    off += 4
    dwarf64 = length == 0xFFFFFFFF
    if dwarf64:
        length = _u(info, off, 8)
        off += 8
    end = off + length
    version = _u(info, off, 2)
    off += 2
    osz = 8 if dwarf64 else 4
    if version >= 5:
        unit_type = _u(info, off, 1)
        off += 1
        addr_size = _u(info, off, 1)
        off += 1
        abbrev_off = _u(info, off, osz)
        off += osz
        if unit_type in (0x02, 0x04, 0x05, 0x06):
            off += 8
    else:
        # DWARF 2–4 的 CU 头顺序固定为：version、debug_abbrev_offset、address_size。
        # 原先 v2/v3 分支把 addr_size 读在 abbrev_off 之前，与规范相反；语料里
        # 没有 v2/v3 样本，只有合成单测能暴露它，故按规范改正并留单测钉住。
        abbrev_off = _u(info, off, osz)
        off += osz
        addr_size = _u(info, off, 1)
        off += 1
        unit_type = 0x01
    return {"start": start, "body": off, "end": end, "version": version,
            "unit_type": unit_type, "addr_size": addr_size,
            "offset_size": osz, "abbrev_off": abbrev_off, "attrs": {}}


def _resolve_strx(idx, cu, ctx):
    so = ctx.get("str_offsets")
    s = ctx.get("str")
    if not so or not s:
        return None
    base = cu["attrs"].get("str_offsets_base")
    if base is None:
        base = 8
    try:
        off = _u(so, base + idx * cu["offset_size"], cu["offset_size"])
        return _cstr(s, off)[0]
    except ValueError:
        return None


def _resolve_addrx(idx, cu, ctx):
    ad = ctx.get("addr")
    if not ad:
        return None
    base = cu["attrs"].get("addr_base")
    if base is None:
        base = 8
    try:
        return _u(ad, base + idx * cu["addr_size"], cu["addr_size"])
    except ValueError:
        return None


def _read_form(data, off, form, cu, ctx, ic=None):
    if form == DW_FORM_indirect:
        form, off = _uleb(data, off)
        return _read_form(data, off, form, cu, ctx)
    if form == DW_FORM_addr:
        return "addr", _u(data, off, cu["addr_size"]), off + cu["addr_size"]
    if form == DW_FORM_data1:
        return "const", _u(data, off, 1), off + 1
    if form == DW_FORM_data2:
        return "const", _u(data, off, 2), off + 2
    if form == DW_FORM_data4:
        return "const", _u(data, off, 4), off + 4
    if form == DW_FORM_data8:
        return "const", _u(data, off, 8), off + 8
    if form == DW_FORM_data16:
        return "block", data[off:off + 16], off + 16
    if form == DW_FORM_sdata:
        v, off = _sleb(data, off)
        return "const", v, off
    if form == DW_FORM_udata:
        v, off = _uleb(data, off)
        return "const", v, off
    if form == DW_FORM_string:
        s, off = _cstr(data, off)
        return "str", s, off
    if form == DW_FORM_strp:
        o = _u(data, off, cu["offset_size"])
        off += cu["offset_size"]
        s = ctx.get("str")
        return "str", (_cstr(s, o)[0] if s else None), off
    if form == DW_FORM_line_strp:
        o = _u(data, off, cu["offset_size"])
        off += cu["offset_size"]
        s = ctx.get("line_str")
        return "str", (_cstr(s, o)[0] if s else None), off
    if form == DW_FORM_strx:
        v, off = _uleb(data, off)
        return "str", _resolve_strx(v, cu, ctx), off
    if form in (DW_FORM_strx1, DW_FORM_strx2, DW_FORM_strx3, DW_FORM_strx4):
        n = {DW_FORM_strx1: 1, DW_FORM_strx2: 2, DW_FORM_strx3: 3,
             DW_FORM_strx4: 4}[form]
        v = _uint3(data, off) if n == 3 else _u(data, off, n)
        return "str", _resolve_strx(v, cu, ctx), off + n
    if form == DW_FORM_addrx:
        v, off = _uleb(data, off)
        return "addrx", v, off
    if form in (DW_FORM_addrx1, DW_FORM_addrx2, DW_FORM_addrx3, DW_FORM_addrx4):
        n = {DW_FORM_addrx1: 1, DW_FORM_addrx2: 2, DW_FORM_addrx3: 3,
             DW_FORM_addrx4: 4}[form]
        v = _uint3(data, off) if n == 3 else _u(data, off, n)
        return "addrx", v, off + n
    if form == DW_FORM_block1:
        n = _u(data, off, 1)
        return "block", data[off + 1:off + 1 + n], off + 1 + n
    if form == DW_FORM_block2:
        n = _u(data, off, 2)
        return "block", data[off + 2:off + 2 + n], off + 2 + n
    if form == DW_FORM_block4:
        n = _u(data, off, 4)
        return "block", data[off + 4:off + 4 + n], off + 4 + n
    if form == DW_FORM_block:
        n, off = _uleb(data, off)
        return "block", data[off:off + n], off + n
    if form == DW_FORM_exprloc:
        n, off = _uleb(data, off)
        return "block", data[off:off + n], off + n
    if form == DW_FORM_flag:
        return "flag", bool(_u(data, off, 1)), off + 1
    if form == DW_FORM_flag_present:
        return "flag", True, off
    if form in (DW_FORM_ref1, DW_FORM_ref2, DW_FORM_ref4, DW_FORM_ref8):
        n = {DW_FORM_ref1: 1, DW_FORM_ref2: 2, DW_FORM_ref4: 4,
             DW_FORM_ref8: 8}[form]
        return "ref", cu["start"] + _u(data, off, n), off + n
    if form == DW_FORM_ref_udata:
        v, off = _uleb(data, off)
        return "ref", cu["start"] + v, off
    if form == DW_FORM_ref_addr:
        n = cu["addr_size"] if cu["version"] == 2 else cu["offset_size"]
        return "ref", _u(data, off, n), off + n
    if form in (DW_FORM_ref_sup4, DW_FORM_ref_sup8):
        n = 4 if form == DW_FORM_ref_sup4 else 8
        return "refsup", _u(data, off, n), off + n
    if form == DW_FORM_ref_sig8:
        return "sig", _u(data, off, 8), off + 8
    if form == DW_FORM_sec_offset:
        return "sec", _u(data, off, cu["offset_size"]), off + cu["offset_size"]
    if form == DW_FORM_loclistx:
        v, off = _uleb(data, off)
        return "loclistx", v, off
    if form == DW_FORM_rnglistx:
        v, off = _uleb(data, off)
        return "rnglistx", v, off
    if form == DW_FORM_implicit_const:
        return "const", ic, off
    raise ValueError("unsupported DWARF form 0x%x" % form)


def _entry_location(kind, val, cu, ctx):
    if kind == "block":
        return {"kind": "expr", "expr": bytes(val)}
    if kind == "sec":
        return {"kind": "loclist", "off": val}
    if kind == "loclistx":
        lo = ctx.get("loclists")
        base = cu["attrs"].get("loclists_base", 0)
        try:
            off = _u(lo, base + val * cu["offset_size"], cu["offset_size"])
            return {"kind": "loclist", "off": off}
        except (ValueError, TypeError):
            return {"kind": "none", "why": "loclistx 需 .debug_loclists/loclists_base"}
    return {"kind": "none", "why": "位置属性形式未支持"}


def _decl_from(attrs, die_off, cu, ctx):
    def val(name):
        v = attrs.get(name)
        return None if v is None else v[1]

    low = None
    v = attrs.get(DW_AT_low_pc)
    if v is not None:
        if v[0] == "addr":
            low = v[1]
        elif v[0] == "addrx":
            low = _resolve_addrx(v[1], cu, ctx)
    high = None
    v = attrs.get(DW_AT_high_pc)
    if v is not None:
        if v[0] == "addr":
            high = v[1]
        elif v[0] == "const":
            high = (low + v[1]) if low is not None else None
    loc = None
    v = attrs.get(DW_AT_location)
    if v is not None:
        loc = _entry_location(v[0], v[1], cu, ctx)
    origin = None
    for at in (DW_AT_abstract_origin, DW_AT_specification):
        v = attrs.get(at)
        if v is not None and v[0] == "ref":
            origin = v[1]
            break
    return {
        "die_off": die_off,
        "cu_off": cu["start"],
        "name": val(DW_AT_name),
        "low_pc": low,
        "high_pc": high,
        "ranges": val(DW_AT_ranges),
        "origin": origin,
        "params": [],
        "cu_attrs": dict(cu["attrs"]),
        "offset_size": cu["offset_size"],
        "addr_size": cu["addr_size"],
        "source": cu["source"],
    }


def _param_from(attrs, die_off, decl, cu, ctx):
    loc = None
    v = attrs.get(DW_AT_location)
    if v is not None:
        loc = _entry_location(v[0], v[1], cu, ctx)
    typ = attrs.get(DW_AT_type)
    name = attrs.get(DW_AT_name)
    var = attrs.get(DW_AT_variable_parameter)
    return {
        "die_off": die_off,
        "decl_off": decl["die_off"],
        "name": name[1] if name else None,
        "type_off": typ[1] if typ and typ[0] == "ref" else None,
        "variable_parameter": bool(var[1]) if var else False,
        "location": loc or {"kind": "none", "why": "无 DW_AT_location"},
        "inherited": False,
    }


_TYPE_TAGS = {
    DW_TAG_array_type: "array_type",
    DW_TAG_enumeration_type: "enumeration_type",
    DW_TAG_pointer_type: "pointer_type",
    DW_TAG_reference_type: "reference_type",
    DW_TAG_structure_type: "structure_type",
    DW_TAG_typedef: "typedef",
    DW_TAG_union_type: "union_type",
    DW_TAG_subrange_type: "subrange_type",
    DW_TAG_base_type: "base_type",
    DW_TAG_const_type: "const_type",
    DW_TAG_volatile_type: "volatile_type",
    DW_TAG_restrict_type: "restrict_type",
    DW_TAG_unspecified_type: "unspecified_type",
    DW_TAG_rvalue_reference_type: "rvalue_reference_type",
    DW_TAG_atomic_type: "atomic_type",
}


def _die_record(attrs, die_off, tag, parent_off):
    """M16：只保留类型链解析要用到的字段（非类型 DIE 返回 None，不占内存）。"""
    kind = _TYPE_TAGS.get(tag)
    if kind is None:
        return None

    def const(at):
        v = attrs.get(at)
        return v[1] if v is not None and v[0] == "const" else None

    def ref(at):
        v = attrs.get(at)
        return v[1] if v is not None and v[0] == "ref" else None

    name = attrs.get(DW_AT_name)
    return {
        "off": die_off, "tag": tag, "kind": kind, "parent": parent_off,
        "name": name[1] if name is not None and name[0] == "str" else None,
        "byte_size": const(DW_AT_byte_size),
        "type_off": ref(DW_AT_type),
        "upper": const(DW_AT_upper_bound),
        "lower": const(DW_AT_lower_bound),
        "count": const(DW_AT_count),
    }


def _variable_from(attrs, die_off, cu, ctx, parent, parent_off):
    """M16：DW_TAG_variable 声明。位置原样保留，静态地址判定留给 datarefs。"""
    v = attrs.get(DW_AT_location)
    loc = _entry_location(v[0], v[1], cu, ctx) if v is not None else \
        {"kind": "none", "why": "无 DW_AT_location"}
    name = attrs.get(DW_AT_name)
    typ = attrs.get(DW_AT_type)
    bs = attrs.get(DW_AT_byte_size)
    return {
        "die_off": die_off, "cu_off": cu["start"],
        "name": name[1] if name is not None and name[0] == "str" else None,
        "type_off": typ[1] if typ is not None and typ[0] == "ref" else None,
        "byte_size": bs[1] if bs is not None and bs[0] == "const" else None,
        "location": loc,
        "parent_off": parent_off,
        "parent_tag": parent["tag"] if parent else None,
        "offset_size": cu["offset_size"], "addr_size": cu["addr_size"],
        "source": dict(cu["source"]),
    }


def _parse_dwarf(secs, meta):
    """secs: 规范名→字节。返回 (decls, meta, ctx)。"""
    info = secs.get(".debug_info")
    abbrev = secs.get(".debug_abbrev")
    if info is None or abbrev is None:
        raise ValueError("缺 .debug_info / .debug_abbrev")
    ctx = {
        "str": secs.get(".debug_str"),
        "line_str": secs.get(".debug_line_str"),
        "str_offsets": secs.get(".debug_str_offsets"),
        "addr": secs.get(".debug_addr"),
        "loclists": secs.get(".debug_loclists"),
    }
    decls = []
    variables = []
    dies = []
    cus = 0
    versions = {}
    off = 0
    while off < len(info):
        cu = _cu_header(info, off)
        if cu["end"] <= cu["body"]:
            break
        cu["source"] = dict(meta.get("locator") or {})
        cu["source"]["cu_off"] = cu["start"]
        cus += 1
        versions[cu["version"]] = versions.get(cu["version"], 0) + 1
        pos = cu["body"]
        parents = []
        while pos < cu["end"]:
            die_off = pos
            code, pos = _uleb(info, pos)
            if code == 0:
                if parents:
                    parents.pop()
                continue
            ent = _abbrev_table(abbrev, cu["abbrev_off"]).get(code)
            if ent is None:
                raise ValueError("CU@0x%x DIE@0x%x 未找到 abbrev code %d"
                                 % (cu["start"], die_off, code))
            tag, has_children, specs = ent
            attrs = {}
            for at, form, ic in specs:
                k, v, pos = _read_form(info, pos, form, cu, ctx, ic)
                attrs[at] = (k, v)
            if tag == DW_TAG_compile_unit:
                for name, key in ((DW_AT_addr_base, "addr_base"),
                                  (DW_AT_str_offsets_base, "str_offsets_base"),
                                  (DW_AT_loclists_base, "loclists_base")):
                    if name in attrs and attrs[name][0] in ("const", "sec"):
                        cu["attrs"][key] = attrs[name][1]
            parent = parents[-1] if parents else None
            parent_off = parent["off"] if parent else None
            rec = _die_record(attrs, die_off, tag, parent_off)
            if rec is not None:
                dies.append(rec)
            if tag == DW_TAG_variable:
                variables.append(_variable_from(attrs, die_off, cu, ctx,
                                                parent, parent_off))
            if tag == DW_TAG_subprogram:
                d = _decl_from(attrs, die_off, cu, ctx)
                decls.append(d)
                if has_children:
                    parents.append({"tag": tag, "decl": d, "off": die_off})
            elif tag == DW_TAG_formal_parameter:
                if parent and parent["tag"] == DW_TAG_subprogram and parent["decl"]:
                    parent["decl"]["params"].append(
                        _param_from(attrs, die_off, parent["decl"], cu, ctx))
                if has_children:
                    parents.append({"tag": tag, "decl": None, "off": die_off})
            else:
                if has_children:
                    parents.append({"tag": tag, "decl": None, "off": die_off})
        off = cu["end"]
    by_off = {d["die_off"]: d for d in decls}
    for d in decls:
        if d["origin"] in by_off:
            src = by_off[d["origin"]]
            if not d["name"]:
                d["name"] = src["name"]
            if not d["params"] and src["params"] and d["low_pc"] is not None:
                d["params"] = [dict(p, inherited=True,
                                    location={"kind": "none",
                                              "why": "继承自 abstract_origin，"
                                                     "无具体位置"})
                               for p in src["params"]]
    meta = dict(meta)
    meta.update({
        "cus": cus,
        "versions": versions,
        "declarations": len(decls),
        "variables": len(variables),
        "variables_with_expr": sum(1 for v in variables
                                   if v["location"]["kind"] == "expr"),
        "type_dies": len(dies),
        "subprograms_with_low_pc": sum(1 for d in decls if d["low_pc"] is not None),
        "formal_parameters": sum(len(d["params"]) for d in decls),
        "params_with_expr": sum(1 for d in decls for p in d["params"]
                                if p["location"]["kind"] == "expr"),
        "params_with_loclist": sum(1 for d in decls for p in d["params"]
                                   if p["location"]["kind"] == "loclist"),
        "params_without_location": sum(1 for d in decls for p in d["params"]
                                       if p["location"]["kind"] == "none"),
    })
    # M16：变量声明与类型 DIE 只从 ctx 取出，不改 _parse_dwarf 的返回形状
    # （既有调用方按 (decls, meta, ctx) 解包）。
    ctx["variables"] = variables
    ctx["types"] = {d["off"]: d for d in dies}
    return decls, meta, ctx


# ── 位置表达式 ──────────────────────────────────────────────────────
def _loclist_expr(lo, off, low_pc, cu, ctx):
    """返回 (entry_off, expr, why)。"""
    if lo is None:
        return None, None, "缺 .debug_loclists"
    base = 0
    default = None
    pos = off
    while pos < len(lo):
        entry_off = pos
        kind = lo[pos]
        pos += 1
        try:
            if kind == DW_LLE_end_of_list:
                break
            if kind == DW_LLE_base_addressx:
                idx, pos = _uleb(lo, pos)
                a = _resolve_addrx(idx, cu, ctx)
                if a is None:
                    return None, None, "base_addressx 的 .debug_addr 条目不可读"
                base = a
            elif kind == DW_LLE_startx_endx:
                s, pos = _uleb(lo, pos)
                e, pos = _uleb(lo, pos)
                n, pos = _uleb(lo, pos)
                expr = lo[pos:pos + n]
                pos += n
                a = _resolve_addrx(s, cu, ctx)
                b = _resolve_addrx(e, cu, ctx)
                if a is not None and b is not None and a <= low_pc < b:
                    return entry_off, expr, None
            elif kind == DW_LLE_startx_length:
                s, pos = _uleb(lo, pos)
                ln, pos = _uleb(lo, pos)
                n, pos = _uleb(lo, pos)
                expr = lo[pos:pos + n]
                pos += n
                a = _resolve_addrx(s, cu, ctx)
                if a is not None and a <= low_pc < a + ln:
                    return entry_off, expr, None
            elif kind == DW_LLE_start_end:
                a = _u(lo, pos, cu["addr_size"])
                b = _u(lo, pos + cu["addr_size"], cu["addr_size"])
                pos += 2 * cu["addr_size"]
                n, pos = _uleb(lo, pos)
                expr = lo[pos:pos + n]
                pos += n
                if a <= low_pc < b:
                    return entry_off, expr, None
            elif kind == DW_LLE_start_length:
                a = _u(lo, pos, cu["addr_size"])
                pos += cu["addr_size"]
                ln, pos = _uleb(lo, pos)
                n, pos = _uleb(lo, pos)
                expr = lo[pos:pos + n]
                pos += n
                if a <= low_pc < a + ln:
                    return entry_off, expr, None
            elif kind == DW_LLE_offset_pair:
                s, pos = _uleb(lo, pos)
                e, pos = _uleb(lo, pos)
                n, pos = _uleb(lo, pos)
                expr = lo[pos:pos + n]
                pos += n
                if base + s <= low_pc < base + e:
                    return entry_off, expr, None
            elif kind == DW_LLE_default_location:
                n, pos = _uleb(lo, pos)
                default = (entry_off, lo[pos:pos + n])
                pos += n
            elif kind == DW_LLE_base_address:
                base = _u(lo, pos, cu["addr_size"])
                pos += cu["addr_size"]
            else:
                return None, None, "未支持的 loclist 条目类型 0x%x" % kind
        except ValueError as e:
            return None, None, "loclist 读取越界：%s" % e
    if default:
        return default[0], default[1], None
    return None, None, "位置列表没有覆盖函数入口的条目"


def _entry_regs(expr):
    pieces = []
    pending = None
    i = 0
    while i < len(expr):
        op = expr[i]
        i += 1
        if 0x50 <= op <= 0x6F:
            pending = ("reg", op - 0x50)
        elif op == 0x90:
            r, i = _uleb(expr, i)
            pending = ("reg", r)
        elif op == 0x93:
            sz, i = _uleb(expr, i)
            if pending is None:
                return {"kind": "unknown", "why": "DW_OP_piece 前无位置操作"}
            pieces.append((pending[0], pending[1], sz))
            pending = None
        elif op == 0x91:
            v, i = _sleb(expr, i)
            pending = ("stack", v)
        elif op == 0x9C:
            pending = ("stack", "cfa")
        elif op == 0x92:
            return {"kind": "unknown", "why": "DW_OP_bregx 未解释"}
        else:
            return {"kind": "unknown", "op": "0x%x" % op}
    if pending is not None:
        pieces.append((pending[0], pending[1], None))
    named = [{"reg": (REG_NAMES[r] if r < len(REG_NAMES) else "reg%d" % r),
              "size": sz} for (kind, r, sz) in pieces if kind == "reg"]
    stack = [p for p in pieces if p[0] == "stack"]
    if named and not stack:
        return {"kind": "regs", "regs": [n["reg"] for n in named],
                "pieces": named}
    if named and stack:
        return {"kind": "mixed", "regs": [n["reg"] for n in named],
                "pieces": named, "stack_pieces": len(stack)}
    return {"kind": "stack", "stack_pieces": len(stack) or 1}


def _param_entry_expr(param, decl, ctx):
    loc = param.get("location") or {"kind": "none"}
    if loc.get("kind") == "expr":
        return loc.get("expr"), None, None
    if loc.get("kind") == "loclist":
        if decl.get("low_pc") is None:
            return None, None, "形参有位置列表，但函数入口地址不可读"
        cu = {"attrs": dict(decl.get("cu_attrs") or {}),
              "offset_size": decl.get("offset_size", 4),
              "addr_size": decl.get("addr_size", 8)}
        entry_off, expr, why = _loclist_expr(ctx.get("loclists"), loc["off"],
                                             decl["low_pc"], cu, ctx)
        return expr, entry_off, why
    return None, None, loc.get("why") or "无位置声明"


# ── 审计 ────────────────────────────────────────────────────────────
def _class_entry(present, locator, declares, readable=None, note=None,
                 count=None):
    # 不存在的来源不得报 readable=True：分母矩阵里 present=False + readable=True
    # 会让人误读成「这类来源可读，只是没找到声明」。
    if readable is None:
        readable = present
    return {"present": present, "readable": readable, "declares": declares,
            "locator": locator, "param_decl_count": count, "note": note}


def _dwarf_class(dbg, reader, data, format_name):
    if not dbg:
        return _class_entry(
            False, "%s 节表无 .debug_info/.zdebug_info" % format_name,
            CLASS_DECLARES["dwarf"], readable=False,
            note="没有声明字节可读；不得据其它来源推断形参"), None
    secs, locs, readable = {}, [], True
    for n, h in sorted(dbg.items(), key=lambda kv: kv[1]["index"]):
        b, loc, ok = reader(data, h)
        secs[_canon(n)] = b
        locs.append(loc + ("；可读" if ok else "；不可读"))
        readable = readable and ok
    dwarf = None
    note = None
    if readable:
        try:
            decls, meta, ctx = _parse_dwarf(secs, {"locator": {
                "format": format_name, "sections": locs}})
            dwarf = {"decls": decls, "meta": meta, "ctx": ctx}
            # M16：变量/类型索引从 ctx 提到顶层，供 datarefs 直接读。
            dwarf["variables"] = ctx.pop("variables", [])
            dwarf["types"] = ctx.pop("types", {})
        except Exception as e:                  # 不把解析失败说成"没有声明"
            readable = False
            note = "DWARF 解析失败：%s" % e
    cls = {
        "present": True, "readable": readable,
        "declares": CLASS_DECLARES["dwarf"],
        "locator": "；".join(locs),
        "param_decl_count": (dwarf["meta"]["formal_parameters"]
                             if dwarf else None),
        "note": note or "声明字节可读；参数计数见 param_decl_count",
        "detail": (dwarf["meta"] if dwarf else None),
    }
    return cls, dwarf


def _audit_elf(path):
    data = open(path, "rb").read()
    hdrs = elf.section_headers(data)
    by_name = {h["name"]: h for h in hdrs}
    classes = {}

    dbg = {n: h for n, h in by_name.items()
           if _canon(n).startswith(".debug_")}
    classes["dwarf"], dwarf = _dwarf_class(dbg, _elf_section_bytes, data, "ELF")

    if ".gnu_debuglink" in by_name:
        h = by_name[".gnu_debuglink"]
        raw = data[h["offset"]:h["offset"] + h["size"]]
        fn = raw.split(b"\x00")[0].decode("ascii", "replace")
        cands = [os.path.join(os.path.dirname(path), fn),
                 os.path.join(os.path.dirname(path), ".debug", fn)]
        found = next((c for c in cands if os.path.isfile(c)), None)
        classes["gnu_debuglink"] = _class_entry(
            True, "ELF 节头[%d] .gnu_debuglink sh_offset=0x%x sh_size=0x%x；"
                  "文件名=%r；候选=%s" %
                  (h["index"], h["offset"], h["size"], fn, ";".join(cands)),
            CLASS_DECLARES["gnu_debuglink"], readable=bool(found),
            note=("外部 debug 文件存在：%s（本轮未解析外部文件）" % found) if found
                 else "外部 debug 文件不存在：声明指向的文件读不到 → 不作判据")
    else:
        classes["gnu_debuglink"] = _class_entry(
            False, "无 .gnu_debuglink 节", CLASS_DECLARES["gnu_debuglink"])

    try:
        sym = elf.parse(path)["symbols"]
    except Exception as e:
        sym = {"symtab": [], "dynsym": [], "_error": str(e)}
    for key, cls in (("symtab", "elf_symtab"), ("dynsym", "elf_dynsym")):
        rows = sym.get(key) or []
        funcs = [r for r in rows if len(r) > 4 and r[4] == "FUNC"]
        classes[cls] = _class_entry(
            bool(rows),
            "ELF %s：%d 条符号，其中 FUNC %d 条（名字/地址/size）" %
            (key, len(rows), len(funcs)),
            CLASS_DECLARES[cls], readable=bool(rows),
            note=None if rows else "无该类符号表（或节表不可读：%s）"
                 % sym.get("_error", "N/A"))

    if ".eh_frame" in by_name:
        h = by_name[".eh_frame"]
        classes["eh_frame"] = _class_entry(
            True, "ELF 节头[%d] .eh_frame sh_offset=0x%x sh_size=0x%x" %
                  (h["index"], h["offset"], h["size"]),
            CLASS_DECLARES["eh_frame"],
            note="FDE 只声明函数地址范围，不含形参")
    else:
        classes["eh_frame"] = _class_entry(
            False, "无 .eh_frame 节", CLASS_DECLARES["eh_frame"])

    for cls in ("pdb", "export_table", "coff_symbols", "pdata"):
        classes[cls] = _class_entry(False, "ELF 文件不存在此类来源",
                                    CLASS_DECLARES[cls])
    # ELF 的 DW_AT_low_pc 与调用点目标同为虚拟地址（vaddr），无需换算。
    return {"format": "ELF", "classes": classes, "addr_base": 0}, dwarf


def _audit_pe(path):
    data = open(path, "rb").read()
    r = pe.parse(path)
    by_name = {}
    for h in r["section_headers"]:
        by_name.setdefault(h["name"], h)
    classes = {}

    dbg = {n: h for n, h in by_name.items()
           if _canon(n).startswith(".debug_")}
    classes["dwarf"], dwarf = _dwarf_class(dbg, _pe_section_bytes, data, "PE")

    # PDB：PE 里的 CodeView RSDS 只声明"PDB 文件名/GUID/age"
    drva, dsz = (r.get("dirs") or [(0, 0)] * 7)[6]
    pdb_entry = None
    if drva and dsz:
        off = None
        for va, vsize, rawptr, rawsize, _n in r["sections"]:
            if va <= drva < va + max(vsize, rawsize) and rawsize:
                off = rawptr + (drva - va)
                break
        if off is not None:
            for i in range(dsz // 28):
                eo = off + i * 28
                (_ch, _ts, _maj, _min, typ, _dsz, _arva, ptr) = \
                    struct.unpack_from("<IIHHIIII", data, eo)
                if typ == 2 and data[ptr:ptr + 4] == b"RSDS":
                    guid = data[ptr + 4:ptr + 20].hex()
                    age = struct.unpack_from("<I", data, ptr + 20)[0]
                    nm, _ = _cstr(data, ptr + 24)
                    pdb_entry = {"dir_rva": drva, "dir_size": dsz,
                                 "entry_file_off": eo, "rsds_file_off": ptr,
                                 "pdb_name": nm, "guid": guid, "age": age}
                    break
    if pdb_entry:
        cand = os.path.join(os.path.dirname(path),
                            os.path.basename(pdb_entry["pdb_name"]))
        exists = os.path.isfile(cand)
        msf = None
        if exists:
            try:
                pd = open(cand, "rb").read()
                if pd[:32].startswith(b"Microsoft C/C++ MSF 7.00"):
                    bs, _fb, _nb, ndb, _unk, bma = struct.unpack_from("<IIIIII", pd, 32)
                    nb_dir = (ndb + bs - 1) // bs
                    blocks = struct.unpack_from("<%dI" % nb_dir, pd, bma * bs)
                    dirb = b"".join(pd[b * bs:(b + 1) * bs] for b in blocks)[:ndb]
                    ns = struct.unpack_from("<I", dirb, 0)[0]
                    sizes = list(struct.unpack_from("<%dI" % ns, dirb, 4))
                    pos = 4 + 4 * ns
                    streams = []
                    for s in sizes:
                        if s == 0xFFFFFFFF:
                            streams.append(None)
                        else:
                            n = (s + bs - 1) // bs
                            bl = struct.unpack_from("<%dI" % n, dirb, pos)
                            pos += 4 * n
                            streams.append(bl)
                    if len(streams) > 2 and streams[2]:
                        tpi = b"".join(pd[b * bs:(b + 1) * bs] for b in streams[2])
                        ver, hsz, tbeg, tend, recbytes = \
                            struct.unpack_from("<IIIII", tpi, 0)
                        msf = {"file": cand, "block_size": bs,
                               "streams": ns, "tpi_stream": 2,
                               "tpi_version": ver, "tpi_header_size": hsz,
                               "tpi_type_begin": tbeg, "tpi_type_end": tend,
                               "tpi_record_bytes": recbytes}
            except Exception as e:
                msf = {"file": cand, "error": str(e)}
        loc = ("PE 数据目录[6] Debug RVA=0x%x size=0x%x；条目 28 字节@文件偏移 "
               "0x%x；CodeView RSDS@0x%x：GUID=%s age=%d PdbFileName=%r" %
               (pdb_entry["dir_rva"], pdb_entry["dir_size"],
                pdb_entry["entry_file_off"], pdb_entry["rsds_file_off"],
                pdb_entry["guid"], pdb_entry["age"], pdb_entry["pdb_name"]))
        if msf:
            loc += ("；同名 PDB %s：MSF 块大小=%d，流数=%d，TPI=流2"
                    "（version=%s, header=%s, type 0x%x..0x%x, 记录 %s 字节）" %
                    (cand, msf.get("block_size", 0), msf.get("streams", 0),
                     msf.get("tpi_version"), msf.get("tpi_header_size"),
                     msf.get("tpi_type_begin", 0), msf.get("tpi_type_end", 0),
                     msf.get("tpi_record_bytes")))
        classes["pdb"] = {
            "present": True, "readable": False,
            "declares": CLASS_DECLARES["pdb"], "locator": loc,
            "param_decl_count": None,
            "note": ("PDB 引用与文件已定位；本轮未解码 TPI 类型记录与 CodeView "
                     "位置记录，故参数声明不可复核 → 一律 abstain"),
            "detail": dict(pdb_entry, msf=msf),
        }
    else:
        classes["pdb"] = _class_entry(
            False, "无 IMAGE_DIRECTORY_ENTRY_DEBUG/CodeView RSDS",
            CLASS_DECLARES["pdb"], readable=False)

    exp = r.get("exports") or {}
    if exp:
        classes["export_table"] = _class_entry(
            True, "PE 数据目录[0] Export RVA=0x%x size=0x%x；"
                  "IMAGE_EXPORT_DIRECTORY 40B；EAT/名字表/序号表；nfuncs=%d" %
                  (r["export_dir"][0], r["export_dir"][1], exp.get("nfuncs", 0)),
            CLASS_DECLARES["export_table"],
            note="导出表只有 名字/序号/RVA，不含参数个数/类型/位置（结构性）")
    else:
        classes["export_table"] = _class_entry(
            False, "PE 数据目录[0] 为 0", CLASS_DECLARES["export_table"])

    if r.get("nsym"):
        classes["coff_symbols"] = _class_entry(
            True, "COFF header PointerToSymbolTable=0x%x NumberOfSymbols=%d；"
                  "每条 18 字节；字符串表在符号记录之后" %
                  (r["symptr"], r["nsym"]),
            CLASS_DECLARES["coff_symbols"],
            note="COFF 符号只声明名字/地址；不声明参数（结构性）")
    else:
        classes["coff_symbols"] = _class_entry(
            False, "COFF NumberOfSymbols=0", CLASS_DECLARES["coff_symbols"])

    erva, esz = (r.get("dirs") or [(0, 0)] * 4)[3]
    pdata_h = by_name.get(".pdata")
    if erva or pdata_h:
        loc = ("PE 数据目录[3] Exception RVA=0x%x size=0x%x" % (erva, esz)
               if erva else
               "PE 节头[%d] .pdata rawptr=0x%x rawsize=0x%x" %
               (pdata_h["index"], pdata_h["rawptr"], pdata_h["rawsize"]))
        classes["pdata"] = _class_entry(
            True, loc, CLASS_DECLARES["pdata"],
            note="RUNTIME_FUNCTION 只声明函数地址范围，不含形参")
    else:
        classes["pdata"] = _class_entry(
            False, "无异常目录/.pdata", CLASS_DECLARES["pdata"])

    for cls in ("gnu_debuglink", "elf_symtab", "elf_dynsym", "eh_frame"):
        classes[cls] = _class_entry(False, "PE 文件不存在此类来源",
                                    CLASS_DECLARES[cls])
    # PE 的 DW_AT_low_pc 是 ImageBase+RVA，而调用点目标按 RVA 记录；
    # 匹配时必须换算到同一地址空间（换算依据写进 locator，便于复核）。
    return {"format": "PE", "classes": classes,
            "addr_base": r["image_base"]}, dwarf


_CACHE = {}


def read(path):
    """审计 + 解析（按 path/size/mtime 缓存）。返回 {audit, dwarf}。"""
    ap = os.path.abspath(path)
    st = os.stat(ap)
    key = (ap, st.st_size, st.st_mtime_ns)
    if key in _CACHE:
        return _CACHE[key]
    with open(ap, "rb") as f:
        head = f.read(4)
    if head[:4] == b"\x7fELF":
        audit, dwarf = _audit_elf(ap)
    elif head[:2] == b"MZ":
        audit, dwarf = _audit_pe(ap)
    else:
        audit, dwarf = {"format": "unknown", "classes": {}}, None
    if dwarf is not None:
        dwarf["addr_base"] = audit.get("addr_base") or 0
        by_low = {}
        for d in dwarf["decls"]:
            if d["low_pc"] is None:
                continue
            prev = by_low.get(d["low_pc"])
            if prev is None or (not prev["params"] and d["params"]):
                by_low[d["low_pc"]] = d
        dwarf["by_low_pc"] = by_low
    out = {"audit": audit, "dwarf": dwarf}
    _CACHE[key] = out
    return out


# ── 绑定 ────────────────────────────────────────────────────────────
def _find_fact(site, reg):
    for f in site.get("facts") or []:
        if (f.get("direction") == "before" and f.get("kind") == "reg"
                and f.get("operand") == reg):
            return f, "same_block"
    for f in site.get("cross_facts") or []:
        if f.get("kind") == "reg" and f.get("operand") == reg:
            return f, "cross_block"
    return None, None


def _decl_locator(decl):
    src = decl.get("source") or {}
    sections = src.get("sections") if isinstance(src, dict) else None
    keep = [s for s in (sections or []) if ".debug_info" in s or ".debug_loclists" in s]
    text = "；".join(keep) if keep else "(来源未记录)"
    return ("DWARF [%s]：CU@0x%x；DIE@0x%x" %
            (text, decl.get("cu_off", 0), decl.get("die_off", 0)))


def bind_site(site, dwarf):
    """对单个调用点做声明绑定。返回 dict（不抛异常）。"""
    target = site.get("target")
    out = {"status": "no_target", "bound": [], "partial": [], "abstains": [],
           "zero_params": False, "target": target, "params_concluded": 0}
    if site.get("call_kind") != "direct" or target is None:
        out["abstains"].append({
            "scope": "param", "missing":
            "间接调用目标不可静态确定；缺：目标地址的解析证据，无法取形参声明"})
        return out
    if not dwarf:
        # 本样本整体没有可读形参声明来源。仍然计入分母（sites），
        # 但每个直接调用点都 abstain——不是「0 个参数」。
        out["status"] = "no_declaration"
        out["abstains"].append({
            "scope": "param", "missing":
            "本样本没有可读的形参声明来源（DWARF 不存在/不可读；导出表、符号表、"
            "PDB 均不声明形参）；缺：任何形参声明，禁止按 ABI 补"})
        return out
    # 调用点目标与 DWARF 的 DW_AT_low_pc 可能不在同一地址空间：
    # PE 的 low_pc = ImageBase+RVA，而站点目标按 RVA 记录；此处显式换算，
    # 并把换算依据随证据写清（不靠"看起来像"对齐）。
    base = (dwarf or {}).get("addr_base") or 0
    lookup = target + base if base and target < base else target
    out["lookup_addr"] = lookup
    out["addr_base"] = base
    decl = ((dwarf or {}).get("by_low_pc") or {}).get(lookup)
    if decl is None:
        out["status"] = "no_declaration"
        shift = ("（调用目标 RVA 0x%x + ImageBase 0x%x = 0x%x）"
                 % (target, base, lookup) if base and lookup != target else "")
        out["abstains"].append({
            "scope": "param", "missing":
            "目标 0x%x%s 没有可读的形参声明（DWARF DW_TAG_formal_parameter）；"
            "若某声明缺 DW_AT_low_pc，则无法与站点地址对齐，同样计入此类；"
            "导出表/符号表只声明函数身份，PDB 本轮未解码；缺：该目标的形参"
            "声明与位置，禁止按 ABI 补" % (target, shift)})
        return out
    if not decl.get("params"):
        out["status"] = "zero_params"
        out["zero_params"] = True
        out["bound"].append({
            "param": None, "name": "(无)", "type_off": None, "regs": [],
            "evidence": [{
                "level": "declared", "source": "dwarf",
                "text": _decl_locator(decl) + "：该子程序声明 0 个 "
                        "DW_TAG_formal_parameter（该调用点没有可绑定的形参）"}]})
        return out
    ctx = (dwarf or {}).get("ctx") or {}
    for idx, p in enumerate(decl["params"], 1):
        base = {"param": idx, "name": p.get("name"), "type_off": p.get("type_off"),
                "die_off": p.get("die_off")}
        expr, entry_off, why = _param_entry_expr(p, decl, ctx)
        if expr is None:
            out["abstains"].append(dict(base, scope="param", missing=(
                "形参位置不可判：%s；缺：该形参在函数入口的位置声明"
                % (why or "未知"))))
            continue
        if len(expr) == 0:
            out["abstains"].append(dict(base, scope="param", missing=(
                "形参的入口位置表达式为空（DWARF 未给出位置）；"
                "缺：该形参的位置声明，不按 ABI 补")))
            continue
        ev = _entry_regs(expr)
        if ev["kind"] == "unknown":
            out["abstains"].append(dict(base, scope="param", missing=(
                "位置表达式未解释（%s）；缺：该 DWARF 表达式的语义，"
                "不按 ABI 猜寄存器" % (ev.get("why") or ev.get("op")))))
            continue
        if ev["kind"] == "stack":
            out["abstains"].append(dict(base, scope="param", missing=(
                "形参入口位置在栈/帧基址（DW_OP_fbreg/CFA）；缺：调用点栈帧"
                "基址的值与栈布局")))
            continue
        if ev["kind"] == "mixed":
            out["abstains"].append(dict(base, scope="param", missing=(
                "形参同时占寄存器与栈（寄存器 %s + 栈段 %d）；缺：栈段布局"
                % (",".join(ev["regs"]), ev["stack_pieces"]))))
            continue
        binds, missing = [], []
        for piece in ev["pieces"]:
            reg = piece["reg"]
            f, where = _find_fact(site, reg)
            if f is None:
                missing.append(reg)
            else:
                binds.append({
                    "reg": reg, "size": piece["size"],
                    "def_at": f.get("at"), "def_bytes": f.get("bytes"),
                    "from": where,
                    "fact_evidence": f.get("evidence") or []})
        evidence = [{
            "level": "declared", "source": "dwarf",
            "text": (_decl_locator(decl) +
                     "：形参 #%d %r 的入口位置 = 寄存器段 %s"
                     "（位置表达式 %s，条目@0x%x）" %
                     (idx, p.get("name"),
                      ",".join("%s(%s)" % (q["reg"], q["size"])
                               for q in ev["pieces"]),
                      " ".join("%02x" % b for b in expr),
                      entry_off or 0))}, {
            "level": "derived", "source": "param_binding",
            "text": "形参序号↔寄存器来自文件声明（非 ABI 推断）；寄存器的最后"
                    "定义由本工具同块/跨块判据给出"}]
        if missing:
            out["partial" if binds else "abstains"].append(dict(
                base, scope="param", regs=ev["regs"], evidence=evidence,
                binds=binds,
                missing=("调用点前没有寄存器 %s 的可判定定义；缺：这些寄存器的"
                         "定义（同块窗口/跨块确定边未给出）" % ",".join(missing))))
        else:
            out["bound"].append(dict(base, regs=ev["regs"], evidence=evidence,
                                     binds=binds))
    # 站点状态必须与「形参结论」一致：只要有一个形参绑定成功、同时还有形参
    # 未绑定（缺定义会进 abstains，多段只绑到一部分会进 partial），站点就是
    # partial——不能因为「至少绑上了一个」就报 bound，那会把弃权说成结论。
    if out["partial"] or (out["bound"] and out["abstains"]):
        out["status"] = "partial"
    elif out["bound"]:
        out["status"] = "bound"
    else:
        out["status"] = "abstained"
    out["params_concluded"] = len(out["bound"])
    return out


def summarize(bindings):
    """把 bind_site 结果汇总为可核对的计数（分列，不合并）。"""
    c = {"sites": 0, "site_status": {}, "params_bound": 0, "params_partial": 0,
         "params_abstained": 0, "bound_pieces": 0, "zero_params_sites": 0,
         "no_declaration_sites": 0, "no_target_sites": 0,
         "abstain_reasons": {}}
    for b in bindings:
        c["sites"] += 1
        st = b["status"]
        c["site_status"][st] = c["site_status"].get(st, 0) + 1
        if st == "zero_params":
            c["zero_params_sites"] += 1
            continue
        if st == "no_declaration":
            c["no_declaration_sites"] += 1
        if st == "no_target":
            c["no_target_sites"] += 1
        c["params_bound"] += len(b.get("bound") or [])
        c["params_partial"] += len(b.get("partial") or [])
        c["params_abstained"] += len(b.get("abstains") or [])
        for item in (b.get("bound") or []):
            c["bound_pieces"] += len(item.get("binds") or [])
        for item in (b.get("partial") or []):
            c["bound_pieces"] += len(item.get("binds") or [])
        for item in (b.get("abstains") or []):
            # 站点级弃权按状态归固定桶：否则「目标 0x... 没有声明」会按地址
            # 裂成上千个键，既不可读，也会掩盖总量。
            if st == "no_declaration":
                reason = "目标没有可读的形参声明"
            elif st == "no_target":
                reason = "间接调用目标不可静态确定"
            else:
                reason = (item.get("missing") or "").split("；")[0].split("：")[0][:40]
            c["abstain_reasons"][reason] = c["abstain_reasons"].get(reason, 0) + 1
    return c
