#!/usr/bin/env python3
# rekit.datarefs — M16 非字符串数据引用层（全局/静态对象 ↔ 指令引用点）
#
# 为什么单独一层：
#   strxref 只覆盖字符串白名单节里的“字符串引用”；全局/静态数据对象（表、计数
#   器、常量块、.bss 缓冲）没有来源，funcreport 的 data_refs 只能记 missing_source。
#   本层补的就是这条缺线，并且只做“可数的呈现”，不做语义猜测。
#
# 四条口径（与 outputs/m16_datarefs/spec.md 一一对应）：
#   1) 对象只能由**声明**产生：ELF OBJECT 符号（有 st_size）、DWARF
#      DW_TAG_variable（静态地址 + 可解析尺寸）。PE 的 COFF 符号/导出表没有任何
#      尺寸字段，因此一律拒收并逐类计数（size_absent_in_format）——不按“像指针”
#      的字节形态反推对象。
#   2) 引用点只来自 recdesc 已解出指令 + expr 结构化操作数，形态分开计数：
#      rip_mem / lea_rip / abs_mem / abs_imm / base_disp / base_index / unlifted。
#      数据节自身的指针槽单列为 pointer_edges，不与指令引用点合并。
#   3) 归因三档不合并：object_start（精确首地址）/ inside_object（对象内部，
#      记 offset）/ after_object（对象末尾后 0<Δ<=64，记 delta）。目标在数据节
#      但对不上任何已接受对象 → data_unattributed；不在数据节 → not_data。
#   4) 分母先行：声明候选 → 接受 / 拒收（逐类）/ 去重 → 有代码引用 / 有指针槽 /
#      无引用；比例放在计数之后，accepted=0 时比例为 None（不写 0）。
#
# 本层不产生新的语义结论：不推断类型名、不推断数组长度、不推断 ABI；对象的
# “内容”只给原始字节预览（无文件字节时显式写 no_file_bytes）。
import argparse
import bisect
import json
import sys

from . import elf
from . import expr
from . import paramdecl as PD
from . import pe
from . import recdesc

SCHEMA = 1
MIN_SIZE = 4          # 小于 4 字节：与立即数/填充无法区分（口径，不是推断）
AFTER_WINDOW = 64     # 对象末尾后 0<Δ<=64 记 after_object；超窗不归因
PREVIEW = 16

REJECT_CLASSES = (
    "type_not_object", "size_zero", "size_absent_in_format", "too_small",
    "misaligned_start", "outside_data_section", "overruns_section",
    "in_exec_section", "not_allocated", "tls_section",
    "undefined_or_absolute", "location_not_static", "location_unresolved",
    "size_unresolved", "overlaps_object",
)
FORMS = ("rip_mem", "lea_rip", "abs_mem", "abs_imm", "seg_disp", "base_disp",
         "base_index")
TIERS = ("object_start", "inside_object", "after_object", "data_unattributed",
         "not_data")
CONTROL_FAMILIES = {"call", "jmp", "jcc", "ret", "loop", "int", "syscall"}

CALIBER = {
    "object_definition": (
        "对象 = 声明给出的 [start, start+size)；只接受 ELF OBJECT 符号"
        "（st_size>0）与 DWARF DW_TAG_variable（DW_OP_addr + 可解析尺寸）；"
        "PE COFF 符号/导出表无尺寸字段，拒收并计数"),
    "min_size": "size >= %d（更小的对象与立即数/填充不可区分）" % MIN_SIZE,
    "alignment": "size>=8 → start%8==0；4<=size<8 → start%4==0",
    "sections": "ELF: SHF_ALLOC 且非 SHF_EXECINSTR；PE: MEM_READ 且非 "
                "MEM_EXECUTE；含 SHT_NOBITS/.bss（file_backed=false）",
    "after_window": "对象末尾后 0<Δ<=%d 记 after_object；超窗不归因"
                    % AFTER_WINDOW,
    "forms": "引用形态见 FORMS；base_disp/base_index 不定目标，单列计数",
    "pointer_slots": "数据节按指针宽度对齐读取，值恰等于对象首地址才算"
                     " pointer_edges；落在对象内部的单列 pointer_values_inside",
}

CAVEATS = [
    "对象只从声明来：无符号表/无 DWARF 的文件，本层给 0 个对象并写明原因；"
    "这不会推成“没有数据引用”",
    "PE 的 COFF 符号与导出表没有尺寸字段（与 ELF 的差异），本层不从它们造对象，"
    "只按类计数",
    "对齐判据是保守口径：合法但未按尺寸对齐的小对象会被拒收（misaligned_start），"
    "本层不放宽也不偷偷修正",
    "after_object 只覆盖对象末尾后 64 字节：这个窗口是口径，不是“紧邻对象”的推断",
    "abs_imm 的立即数可能只是恰好等于数据地址的常量；该形态单独计数，不与 rip "
    "相对引用合并",
    "数据节里的指针槽只认与对象首地址精确相等的值；未对齐槽、其它值不解释",
    "对象内容只给原始字节预览，不做类型/字符串解释；字符串覆盖见 strxref",
]


def _u(b, off, n):
    if off < 0 or off + n > len(b):
        raise ValueError("越界读 %d@%d" % (n, off))
    return int.from_bytes(b[off:off + n], "little")


def _uleb(b, off):
    v = shift = 0
    while True:
        x = b[off]
        off += 1
        v |= (x & 0x7F) << shift
        shift += 7
        if not x & 0x80:
            return v, off


def _src(field, text):
    return {"layer": "datarefs", "field": field, "text": text}


# ── 镜像与节 ────────────────────────────────────────────────────────
def _image(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x7fELF":
        hdrs = elf.section_headers(data)
        secs = [{
            "index": h["index"], "name": h["name"], "va": h["addr"],
            "size": h["size"], "offset": h["offset"],
            "file_size": 0 if h["type_id"] == 8 else h["size"],
            "alloc": h["alloc"], "exec": h["exec"], "tls": bool(h["flags"] & 0x400),
            "nobits": h["type_id"] == 8, "raw": h,
        } for h in hdrs]
        try:
            syms = elf.parse(path)["symbols"]
        except Exception as e:
            syms = {"symtab": [], "dynsym": [], "_error": str(e)}
        return {"format": "ELF", "image_base": 0,
                "ptr": 8 if data[4] == 2 else 4, "sections": secs,
                "symbols": syms, "exports": None, "coff": None, "data": data}
    if data[:2] == b"MZ":
        r = pe.parse(path)
        secs = [{
            "index": h["index"], "name": h["name"], "va": h["vaddr"],
            "size": h["vsize"], "offset": h["rawptr"],
            "file_size": h["rawsize"],
            "alloc": bool(h["chars"] & 0x40000000),
            "exec": bool(h["chars"] & 0x20000000),
            "discardable": bool(h["chars"] & 0x02000000),
            "tls": False, "nobits": h["rawsize"] == 0, "raw": h,
        } for h in r["section_headers"]]
        exp = (r.get("exports") or {}).get("exports") or []
        return {"format": "PE", "image_base": r["image_base"],
                "ptr": 8 if r["magic"] == 0x20B else 4, "sections": secs,
                "symbols": None, "exports": exp, "coff": r, "data": data}
    raise ValueError("既不是 ELF 也不是 PE：%s" % path)


def _data_sections(img):
    return [s for s in img["sections"]
            if s["alloc"] and not s["exec"] and not s["tls"]
            and not s.get("discardable") and not s["name"].startswith(".debug")
            and s["size"] > 0]


def _sec_of(addr, secs):
    """地址 → 节。跳过 TLS 节：.tbss/.tdata 的地址与普通节重叠（TLS 地址
    不是文件地址），不跳会把 .data.rel.ro 起点的对象误判为越界。"""
    for s in secs:
        if s["tls"]:
            continue
        if s["va"] <= addr < s["va"] + s["size"]:
            return s
    return None


def _tls_of(addr, secs):
    for s in secs:
        if s["tls"] and s["va"] <= addr < s["va"] + s["size"]:
            return s
    return None


def _norm(addr, img):
    """DWARF/指针值 → recdesc 地址空间（PE 减 ImageBase）。"""
    if img["format"] == "PE" and addr >= img["image_base"]:
        return addr - img["image_base"]
    return addr


# ── 候选声明 ────────────────────────────────────────────────────────
def _cand(start, size, name, section, tier, decl_text):
    return {"start": start, "size": size, "name": name, "section": section,
            "tier": tier, "decl": decl_text}


def _from_elf(img, rejected):
    out = []
    by_idx = {s["index"]: s for s in img["sections"]}
    ds_idx = {s["index"] for s in _data_sections(img)}
    for kind in ("symtab", "dynsym"):
        rows = (img["symbols"] or {}).get(kind) or []
        for row in rows:
            if len(row) < 6:
                continue
            name, value, size, _bind, typ, shndx = row[:6]
            sec = by_idx.get(shndx) if isinstance(shndx, int) else None
            is_data = bool(sec and sec["index"] in ds_idx)
            if typ != "OBJECT" and not is_data:
                continue                      # 非 OBJECT 且不在数据节：不在候选池
            where = "ELF %s 符号 %r：st_value=0x%x st_size=%d shndx=%r" % (
                kind, name, value, size, shndx)
            if sec is None:
                rejected["undefined_or_absolute"] += 1
                continue
            if typ == "TLS" or sec["tls"]:
                rejected["tls_section"] += 1
                continue
            if sec["exec"]:
                rejected["in_exec_section"] += 1
                continue
            if not sec["alloc"]:
                rejected["not_allocated"] += 1
                continue
            if typ != "OBJECT":
                rejected["type_not_object"] += 1
                continue
            if size == 0:
                rejected["size_zero"] += 1
                continue
            out.append(_cand(value, size, name, sec["name"], "declared_symbol",
                             where))
    return out


def _type_size(off, types, kids, addr_size, depth=0):
    """类型 DIE → 字节尺寸。返回 (size, why)；解析不了返回 (None, why)。"""
    if off is None:
        return None, "无 DW_AT_type"
    d = types.get(off)
    if d is None:
        return None, "类型 DIE 0x%x 不在索引里" % off
    if depth > 12:
        return None, "类型链过深（>12）"
    k = d["kind"]
    if k in ("const_type", "volatile_type", "restrict_type", "typedef",
             "atomic_type"):
        if d["byte_size"] is not None:
            return d["byte_size"], k
        return _type_size(d["type_off"], types, kids, addr_size, depth + 1)
    if k in ("pointer_type", "reference_type", "rvalue_reference_type"):
        return addr_size, k
    if k in ("base_type", "structure_type", "union_type",
             "enumeration_type", "unspecified_type"):
        if d["byte_size"] is not None:
            return d["byte_size"], k
        return None, "%s 无 DW_AT_byte_size" % k
    if k == "array_type":
        elem, why = _type_size(d["type_off"], types, kids, addr_size, depth + 1)
        if elem is None:
            return None, "数组元素尺寸不可解析：%s" % why
        total = 0
        subs = [kids[off][i] for i in range(len(kids.get(off, [])))
                if kids[off][i]["kind"] == "subrange_type"]
        if not subs:
            return None, "数组无 subrange 子 DIE"
        for s in subs:
            if s["count"] is not None:
                total += s["count"]
            elif s["upper"] is not None:
                total += s["upper"] - (s["lower"] or 0) + 1
            else:
                return None, "数组上界不是常量"
        return elem * total, "array_type(%d×%d)" % (elem, total)
    return None, "类型 %s 不支持" % k


def _dwarf_vars(path):
    """读 DWARF（失败不抛，返回 (None, error_text)）。

    两种 None 必须分开：文件里**没有** DWARF 节 → error_text=None；
    有节但**不可解析** → error_text 带出 paramdecl 审计里的原因。否则
    “DWARF 存在但解析失败”会被报成“没有任何能给出尺寸的声明来源”。
    """
    try:
        r = PD.read(path)
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)
    if r.get("dwarf") is not None:
        return r["dwarf"], None
    cls = ((r.get("audit") or {}).get("classes") or {}).get("dwarf") or {}
    if cls.get("present") and not cls.get("readable"):
        return None, "DWARF 节存在但不可解析：%s" % (
            cls.get("note") or "原因未记录")
    return None, None


def _static_addr(v):
    loc = v.get("location") or {}
    if loc.get("kind") != "expr":
        return None, "location_not_static", "位置形式 %s（不是静态地址表达式）" % loc.get("kind")
    e = loc.get("expr") or b""
    if not e:
        return None, "location_unresolved", "位置表达式为空"
    if e[0] == 0x03 and len(e) == 1 + v["addr_size"]:
        return _u(e, 1, v["addr_size"]), "DW_OP_addr", None
    return None, "location_unresolved", "位置表达式首字节 0x%02x（非 DW_OP_addr）" % e[0]


def _from_dwarf(img, rejected, dwarf):
    if dwarf is None:
        return []
    types = dwarf.get("types") or {}
    kids = {}
    for off, d in types.items():
        kids.setdefault(d.get("parent"), []).append(d)
    out = []
    for v in dwarf.get("variables") or []:
        where = ("DWARF 变量 %r：DIE@0x%x CU@0x%x location=%s"
                 % (v.get("name"), v.get("die_off"), v.get("cu_off"),
                    v["location"].get("kind")))
        addr, how, why = _static_addr(v)
        if addr is None:
            key = "location_not_static" if how == "location_not_static" \
                else "location_unresolved"
            rejected[key] += 1
            continue
        addr = _norm(addr, img)
        where += "；%s→0x%x" % (how, addr)
        size = v.get("byte_size")
        why_size = "DW_AT_byte_size"
        if size is None:
            size, why_size = _type_size(v.get("type_off"), types, kids,
                                        v.get("addr_size") or 8)
        if size is None:
            rejected["size_unresolved"] += 1
            continue
        if size == 0:
            rejected["size_zero"] += 1
            continue
        sec = _sec_of(addr, img["sections"])
        if sec is None:
            if _tls_of(addr, img["sections"]) is not None:
                rejected["tls_section"] += 1
                continue
            rejected["outside_data_section"] += 1
            continue
        if sec["exec"]:
            rejected["in_exec_section"] += 1
            continue
        if not sec["alloc"]:
            rejected["not_allocated"] += 1
            continue
        out.append(_cand(addr, size, v.get("name"), sec["name"],
                         "declared_dwarf",
                         where + "；尺寸=%d（%s）" % (size, why_size)))
    return out


def _coff_symbols(img):
    """PE COFF 符号：只有 节号+Value，无尺寸。返回候选计数（全部拒收）。"""
    r = img["coff"] or {}
    data = img["data"]
    nsym, symptr = r.get("nsym") or 0, r.get("symptr") or 0
    if not nsym or not symptr:
        return None
    strtab = symptr + nsym * 18
    out = []
    i = 0
    while i < nsym:
        off = symptr + i * 18
        rec = data[off:off + 18]
        if len(rec) < 18:
            break
        raw = rec[:8]
        if raw[:4] == b"\x00\x00\x00\x00":
            so = _u(rec, 4, 4)
            end = data.find(b"\x00", strtab + so)
            name = data[strtab + so:end if end >= 0 else strtab + so + 64]
            name = name.decode("latin-1", "replace")
        else:
            name = raw.split(b"\x00")[0].decode("latin-1", "replace")
        value = _u(rec, 8, 4)
        snum = int.from_bytes(rec[12:14], "little", signed=True)
        typ = _u(rec, 14, 2)
        cls = rec[16]
        naux = rec[17]
        if cls in (2, 3) and snum > 0:
            sec = img["sections"][snum - 1] if snum <= len(img["sections"]) else None
            if sec is not None:
                addr = sec["va"] + value
                out.append({"name": name, "addr": addr, "sec": sec,
                            "type": typ, "class": cls})
        i += 1 + naux
    return out


# ── 接受判据 ────────────────────────────────────────────────────────
def _overlap(a, b):
    return a["start"] < b["start"] + b["size"] and b["start"] < a["start"] + a["size"]


def _accept(cands, img, rejected):
    accepted, dups = [], []
    for c in sorted(cands, key=lambda x: (x["start"], -x["size"],
                                          x["tier"], x["name"] or "")):
        if c["size"] < MIN_SIZE:
            rejected["too_small"] += 1
            continue
        if c["size"] >= 8 and c["start"] % 8:
            rejected["misaligned_start"] += 1
            continue
        if 4 <= c["size"] < 8 and c["start"] % 4:
            rejected["misaligned_start"] += 1
            continue
        sec = _sec_of(c["start"], img["sections"])
        if sec is None:
            rejected["outside_data_section"] += 1
            continue
        if c["start"] + c["size"] > sec["va"] + sec["size"]:
            rejected["overruns_section"] += 1
            continue
        hit = next((a for a in accepted if _overlap(a, c)), None)
        if hit is not None:
            if hit["start"] == c["start"] and hit["size"] == c["size"]:
                dups.append({"start": c["start"], "name": c["name"],
                             "kept": hit["name"], "decl": c["decl"]})
            else:
                rejected["overlaps_object"] += 1
            continue
        end = c["start"] + c["size"]
        file_backed = (c["start"] + c["size"] <= sec["va"] + sec["file_size"])
        content = None
        if file_backed and sec["file_size"]:
            off = sec["offset"] + (c["start"] - sec["va"])
            content = img["data"][off:off + min(c["size"], PREVIEW)]
        accepted.append({
            "start": c["start"], "end": end, "size": c["size"],
            "name": c["name"], "section": sec["name"],
            "tier": c["tier"], "file_backed": bool(file_backed),
            "content_hex": (content.hex() if content is not None else None),
            "content_note": ("无文件字节（.bss/未初始化尾部）：这不是内容为空"
                             if not file_backed else
                             "原始字节预览（最多 %d 字节），不是类型解释" % PREVIEW),
            "declaration": c["decl"],
            "sources": [_src("objects", c["decl"])],
        })
    accepted.sort(key=lambda o: o["start"])
    return accepted, dups


# ── 引用点 ──────────────────────────────────────────────────────────
def _operands(rec):
    out, seen = [], set()
    for v in rec.values():
        if isinstance(v, dict) and v.get("t") in ("mem", "imm"):
            if id(v) not in seen:
                seen.add(id(v))
                out.append(v)
    return out


def _families_control(fam):
    return fam in CONTROL_FAMILIES


def _classify(op, rec, insn_len, data_secs, img):
    """返回 (form, target, arith) 或 (form, None, why)。"""
    fam = rec.get("family")
    if op["t"] == "mem":
        if op.get("seg"):
            # fs:/gs: 前缀的“绝对”disp 实际是段基址相对（如 fs:0x28），
            # 不能当文件地址——单列，不给目标。
            return "seg_disp", None, (
                "段前缀 %s + disp=%+d：段基址不可静态确定，无文件目标"
                % (op.get("seg"), op.get("disp") or 0))
        if op.get("rip"):
            target = op.get("rip_target")
            form = "lea_rip" if fam == "lea" else "rip_mem"
            arith = ("0x%x + 0x%x + %d = 0x%x"
                     % (rec["addr"], insn_len, op.get("disp") or 0,
                        target if target is not None else 0))
            return form, target, arith
        if op.get("base") is None and op.get("index") is None:
            target = (op.get("disp") or 0) & 0xFFFFFFFF
            return "abs_mem", target, "disp32=0x%x（无基址/索引）" % target
        if op.get("index") is not None:
            return "base_index", None, (
                "base=%r index=%r scale=%d disp=%+d：寄存器相关，无静态目标"
                % (op.get("base"), op.get("index"), op.get("scale") or 1,
                   op.get("disp") or 0))
        return "base_disp", None, (
            "base=%r disp=%+d：寄存器相关，无静态目标"
            % (op.get("base"), op.get("disp") or 0))
    # imm
    if _families_control(fam) or fam == "shift":
        return None, None, None
    v = op.get("value")
    if v is None:
        return None, None, None
    v &= (1 << 64) - 1
    if not any(s["va"] <= v < s["va"] + s["size"] for s in data_secs):
        return None, None, None           # 不落在数据节：连候选都不是
    return "abs_imm", v, "立即数=0x%x" % v


def _attribute(target, objects, starts, by_start):
    if target is None:
        return None, None, None
    o = by_start.get(target)
    if o is not None:
        return "object_start", o, 0
    i = bisect.bisect_right(starts, target) - 1
    if i >= 0:
        o = objects[i]
        if o["start"] < target < o["end"]:
            return "inside_object", o, target - o["start"]
        if o["end"] <= target < o["end"] + AFTER_WINDOW:
            return "after_object", o, target - o["end"]
    return None, None, None


def _scan_sites(img, res, objects, data_secs):
    block_of = {}
    for b in res.get("blocks") or []:
        for a in b.get("insns") or []:
            block_of[a] = b
    starts = [o["start"] for o in objects]
    by_start = {o["start"]: o for o in objects}
    sites, forms, tiers = [], {f: 0 for f in FORMS}, {t: 0 for t in TIERS}
    unlifted, unresolved = [], []
    for ins in res.get("instructions") or []:
        if ins.get("status", "ok") != "ok":
            continue
        try:
            rec = expr.decode(ins)
        except expr.LiftError as e:
            unlifted.append({"addr": ins["addr"], "reason": e.reason,
                             "missing": e.missing})
            continue
        except Exception as e:                # 不把解析异常当“没有引用”
            unlifted.append({"addr": ins["addr"],
                             "reason": "%s: %s" % (type(e).__name__, e),
                             "missing": None})
            continue
        for k, op in enumerate(_operands(rec)):
            form, target, arith = _classify(op, rec, ins.get("length"),
                                             data_secs, img)
            if form is None:
                continue
            forms[form] += 1
            blk = block_of.get(ins["addr"])
            site = {
                "addr": ins["addr"], "bytes": ins.get("bytes"),
                "mnem": rec.get("mnem"),
                "function": (blk or {}).get("function"),
                "block": (blk or {}).get("start"),
                "form": form, "operand_index": k, "arith": arith,
                "target": target,
            }
            if target is None:
                unresolved.append({"addr": ins["addr"], "form": form,
                                   "why": arith})
                sites.append(dict(site, tier=None,
                                  reason="寄存器相关，无静态目标"))
                continue
            sec = _sec_of(target, data_secs)
            if sec is None:
                tiers["not_data"] += 1
                hit_sec = _sec_of(target, img["sections"])
                sites.append(dict(site, tier="not_data",
                                  target_section=hit_sec and hit_sec["name"]))
                continue
            tier, obj, delta = _attribute(target, objects, starts, by_start)
            if tier is None:
                tiers["data_unattributed"] += 1
                sites.append(dict(site, tier="data_unattributed",
                                  target_section=sec["name"],
                                  reason="目标落在数据节 %s，但对不上任何已接受对象"
                                         "（该地址没有通过 §1.3 的声明）" % sec["name"]))
                continue
            tiers[tier] += 1
            site.update({
                "tier": tier, "target_section": sec["name"],
                "object_start": obj["start"], "object_name": obj["name"],
                "object_size": obj["size"],
                "offset": delta if tier in ("inside_object", "after_object") else None,
                "evidence": [
                    _src("sites", "指令 0x%x：%s" % (ins["addr"], arith)),
                    _src("objects",
                         "对象 %r [0x%x,0x%x)（%s）"
                         % (obj["name"], obj["start"], obj["end"], obj["declaration"])),
                ],
            })
            sites.append(site)
    sites.sort(key=lambda s: (s["addr"], s["operand_index"]))
    unlifted.sort(key=lambda x: x["addr"])
    return {
        "sites": sites, "forms": forms, "tiers": tiers,
        "unlifted": unlifted, "unresolved": unresolved,
    }


def _scan_pointers(img, data_secs, objects):
    by_start = {o["start"]: o for o in objects}
    starts = [o["start"] for o in objects]
    edges, inside_vals = [], []
    w = img["ptr"]
    for sec in data_secs:
        if not sec["file_size"]:
            continue
        raw = img["data"][sec["offset"]:sec["offset"] + sec["file_size"]]
        for off in range(0, len(raw) - w + 1, w):
            v = int.from_bytes(raw[off:off + w], "little")
            cands = [v]
            if img["format"] == "PE" and v >= img["image_base"]:
                cands.append(v - img["image_base"])
            target = next((c for c in cands if c in by_start or
                           _inside(c, objects, starts)), None)
            if target is None:
                continue
            from_addr = sec["va"] + off
            o = by_start.get(target)
            if o is not None:
                edges.append({
                    "from": from_addr, "to": target, "width": w,
                    "section": sec["name"], "object_name": o["name"],
                    "evidence": [_src("pointer_edges",
                                      "0x%x 处 %d 字节值 0x%x == 对象 %r 首地址"
                                      % (from_addr, w, target, o["name"]))],
                })
            else:
                tier, o2, delta = _attribute(target, objects, starts, by_start)
                inside_vals.append({
                    "from": from_addr, "to": target, "width": w,
                    "section": sec["name"], "object_name": o2["name"],
                    "offset": delta,
                    "note": "指针槽值落在对象内部（可能是元素/成员），"
                            "不计入 pointer_edges",
                })
    edges.sort(key=lambda e: e["from"])
    inside_vals.sort(key=lambda e: e["from"])
    return edges, inside_vals


def _inside(addr, objects, starts):
    i = bisect.bisect_right(starts, addr) - 1
    return i >= 0 and objects[i]["start"] < addr < objects[i]["end"]


# ── 构建 ────────────────────────────────────────────────────────────
def build(path, section=".text", res=None, dwarf=None, limit=40):
    img = _image(path)
    res = recdesc.descend(path, section) if res is None else res
    data_secs = _data_sections(img)
    rejected = {k: 0 for k in REJECT_CLASSES}

    dwarf_err = None
    if dwarf is None:
        dwarf, dwarf_err = _dwarf_vars(path)

    sources = {}
    coff = _coff_symbols(img) if img["format"] == "PE" else None
    if img["format"] == "ELF":
        for kind in ("symtab", "dynsym"):
            rows = (img["symbols"] or {}).get(kind) or []
            sources["elf_" + kind] = {
                "present": bool(rows), "readable": True,
                "can_declare_size": True, "declarations": len(rows),
                "note": ("%d 条符号（含 st_size）" % len(rows)) if rows
                        else "无该类符号表/0 条（可能已剥离）",
            }
        sources["dwarf_variables"] = {
            "present": dwarf is not None, "readable": dwarf is not None,
            "can_declare_size": True,
            "declarations": len((dwarf or {}).get("variables") or []),
            "note": ("DW_TAG_variable %d 条（静态地址 + 类型尺寸）"
                     % len((dwarf or {}).get("variables") or []))
                    if dwarf is not None else
                    ("DWARF 不可用：%s" % dwarf_err if dwarf_err
                     else "无 .debug_info/.zdebug_info（或不可读）"),
        }
        sources["coff_symbols"] = {
            "present": False, "readable": False, "can_declare_size": False,
            "declarations": 0, "note": "ELF 文件不存在此类来源",
        }
        sources["export_table"] = dict(sources["coff_symbols"],
                                       note="ELF 文件不存在此类来源")
    else:
        r = img["coff"] or {}
        sources["coff_symbols"] = {
            "present": bool(r.get("nsym")), "readable": True,
            "can_declare_size": False,
            "declarations": (len(coff) if coff is not None else 0),
            "note": ("COFF NumberOfSymbols=%d，每条只有 节号+Value，"
                     "没有尺寸字段（PE/ELF 结构性差异）" % (r.get("nsym") or 0))
                    if r.get("nsym") else "COFF NumberOfSymbols=0",
        }
        sources["export_table"] = {
            "present": bool(img["exports"]), "readable": True,
            "can_declare_size": False,
            "declarations": len(img["exports"] or []),
            "note": ("导出表 %d 条：只有 RVA+名字，没有尺寸字段"
                     % len(img["exports"] or [])) if img["exports"]
                    else "无导出表",
        }
        sources["dwarf_variables"] = {
            "present": dwarf is not None, "readable": dwarf is not None,
            "can_declare_size": True,
            "declarations": len((dwarf or {}).get("variables") or []),
            "note": ("DW_TAG_variable %d 条（静态地址 + 类型尺寸）"
                     % len((dwarf or {}).get("variables") or []))
                    if dwarf is not None else
                    ("DWARF 不可用：%s" % dwarf_err if dwarf_err
                     else "无 .debug_info/.zdebug_info（或不可读）"),
        }
        for kind in ("symtab", "dynsym"):
            sources["elf_" + kind] = {
                "present": False, "readable": False, "can_declare_size": False,
                "declarations": 0, "note": "PE 文件不存在此类来源",
            }

    cands = []
    format_rej = {"coff_symbols": 0, "export_table": 0}
    if img["format"] == "ELF":
        cands += _from_elf(img, rejected)
    else:
        # COFF 符号/导出表：结构上无法给出尺寸。它们不是“可能成为对象的声明”，
        # 因此单独记在 format_rejections，不进对象分母（否则 PE 分母会被
        # .idata/.pdata 标签淹没，比例失去意义）。
        for s in coff or []:
            if s["sec"] in data_secs and s["type"] == 0:
                format_rej["coff_symbols"] += 1
        for (_name, _ord, rva) in img["exports"] or []:
            if _sec_of(rva, data_secs) is not None:
                format_rej["export_table"] += 1
    cands += _from_dwarf(img, rejected, dwarf)

    objects, dups = _accept(cands, img, rejected)

    scan = _scan_sites(img, res, objects, data_secs)
    edges, inside_vals = _scan_pointers(img, data_secs, objects)

    hit_objects = {s["object_start"] for s in scan["sites"]
                   if s.get("object_start") is not None}
    edge_objects = {e["to"] for e in edges}
    accepted_n = len(objects)
    with_ref = sum(1 for o in objects if o["start"] in hit_objects)
    with_edge = sum(1 for o in objects if o["start"] in edge_objects)
    rejected_total = sum(rejected.values())
    declared_n = accepted_n + rejected_total + len(dups)

    denom = {
        "declared_candidates": declared_n,
        "accepted": accepted_n,
        "rejected_total": rejected_total,
        "by_rejection": {k: v for k, v in rejected.items() if v},
        "duplicates": len(dups),
        "identity_ok": accepted_n + rejected_total + len(dups) == declared_n,
        "format_rejections": format_rej,
        "format_rejections_note": (
            "PE 的 COFF 符号/导出表没有尺寸字段，结构上无法成为对象；"
            "它们不进对象分母，只在此处计数（PE/ELF 差异）"),
        "with_code_ref": with_ref,
        "with_pointer_edge": with_edge,
        "without_ref": sum(1 for o in objects
                           if o["start"] not in hit_objects and
                           o["start"] not in edge_objects),
        "object_code_ref_ratio": (with_ref / accepted_n) if accepted_n else None,
    }
    size_capable = any(s["present"] and s["readable"] and s["can_declare_size"]
                       for s in sources.values())
    if not data_secs:
        status, reason = ("no_data_sections",
                          "本文件没有可扫描的数据节（alloc 且非 exec）；"
                          "对象分母为 0，这是“确实没有数据节”，不是“没测量的 0”")
    elif not size_capable:
        status = "no_declaration_source"
        # “没有声明来源”与“声明来源存在但读不出/解析不了”分开写：后者是
        # 缺证据（可修），不是结构性没有。
        reason = (("声明来源存在但不可用：%s；这不是“没有数据引用”，"
                   "是声明不可解析" % dwarf_err) if dwarf_err else
                  ("没有任何能给出尺寸的声明来源（ELF 符号表 / DWARF 变量）；"
                   "PE COFF 符号与导出表没有尺寸字段。这不是“没有数据引用”，"
                   "是没有可交叉对象"))
    else:
        status, reason = "ok", None

    rep = {
        "schema": SCHEMA,
        "path": str(path), "format": img["format"], "section": section,
        "status": status, "reason": reason,
        "caliber": CALIBER,
        "sections": [{"name": s["name"], "va": s["va"], "size": s["size"],
                      "file_size": s["file_size"], "nobits": s["nobits"]}
                     for s in data_secs],
        "sources": sources,
        "objects": objects,
        "rejected": {k: v for k, v in rejected.items() if v},
        "duplicates": dups,
        "denominator": denom,
        "sites": scan["sites"],
        "forms": scan["forms"],
        "tiers": scan["tiers"],
        "unlifted": scan["unlifted"],
        "unresolved_forms": scan["unresolved"],
        "pointer_edges": edges,
        "pointer_values_inside": inside_vals,
        "caveats": list(CAVEATS),
        "limit": limit,
    }
    return rep


# ── 渲染 / CLI ──────────────────────────────────────────────────────
def render(rep, limit=None):
    if rep.get("status") == "error":
        return ("== datarefs ==\n路径：%s\n错误：%s"
                % (rep.get("path"), rep.get("reason")))
    limit = rep.get("limit", 40) if limit is None else limit
    d = rep["denominator"]
    out = ["== datarefs 分母（先报分母）=="]
    out.append("声明候选 %d；接受 %d；拒收 %d；去重 %d（恒等式 %s）"
               % (d["declared_candidates"], d["accepted"], d["rejected_total"],
                  d["duplicates"], "成立" if d["identity_ok"] else "不成立"))
    if d["by_rejection"]:
        out.append("拒收分类：" + "；".join("%s=%d" % kv
                                           for kv in sorted(d["by_rejection"].items())))
    fr = d["format_rejections"]
    out.append("格式层拒收（无尺寸字段，不进对象分母）：COFF 符号 %d；导出表 %d"
               % (fr["coff_symbols"], fr["export_table"]))
    ratio = d["object_code_ref_ratio"]
    out.append("接受对象中：有代码引用 %d；有指针槽 %d；无引用 %d；"
               "对象命中率 %s"
               % (d["with_code_ref"], d["with_pointer_edge"],
                  d["without_ref"],
                  ("%d/%d" % (d["with_code_ref"], d["accepted"]))
                  if ratio is not None else "无（accepted=0，不写 0）"))
    out.append("可扫描数据节：%s" % ("; ".join(
        "%s [0x%x,0x%x) file=%d" % (s["name"], s["va"], s["va"] + s["size"],
                                    s["file_size"]) for s in rep["sections"])
        or "无"))
    out.append("")
    out.append("== 声明来源 ==")
    for k, s in rep["sources"].items():
        out.append("%s：present=%s readable=%s 可声明尺寸=%s 条数=%d；%s"
                   % (k, s["present"], s["readable"], s["can_declare_size"],
                      s["declarations"], s["note"]))
    if rep["status"] != "ok":
        out.append("状态：%s；原因：%s" % (rep["status"], rep["reason"]))
    out.append("")
    out.append("== 对象（%d 个，显示前 %d）==" % (len(rep["objects"]),
                                                min(limit, len(rep["objects"]))))
    for o in rep["objects"][:limit]:
        out.append("0x%x..0x%x %-24s size=%d %s %s file_backed=%s"
                   % (o["start"], o["end"], o["name"], o["size"],
                      o["section"], o["tier"], o["file_backed"]))
    out.append("")
    out.append("== 指令引用点（%d 条，显示前 %d）==" % (len(rep["sites"]),
                                                     min(limit, len(rep["sites"]))))
    for s in rep["sites"][:limit]:
        tgt = ("0x%x" % s["target"]) if s["target"] is not None else "无静态目标"
        extra = ""
        if s.get("tier") in ("inside_object", "after_object"):
            extra = " %s+0x%x" % (s["object_name"], s["offset"])
        out.append("0x%x %-9s → %s %s%s（%s）"
                   % (s["addr"], s["form"], tgt, s.get("tier") or "unresolved",
                      extra, s.get("arith") or ""))
    out.append("")
    out.append("形态计数：" + "；".join("%s=%d" % kv
                                       for kv in sorted(rep["forms"].items())))
    out.append("归因分档：" + "；".join("%s=%d" % kv
                                       for kv in sorted(rep["tiers"].items())))
    out.append("未解出指令 %d 条（其操作数不可检查）；寄存器相关形态 %d 条"
               % (len(rep["unlifted"]), len(rep["unresolved_forms"])))
    out.append("")
    out.append("== 数据节指针槽 ==")
    out.append("精确命中对象首地址 %d 条；落在对象内部 %d 条（单列，不合并）"
               % (len(rep["pointer_edges"]), len(rep["pointer_values_inside"])))
    for e in rep["pointer_edges"][:limit]:
        out.append("0x%x → 0x%x（%s.%s，%d 字节）"
                   % (e["from"], e["to"], e["section"], e["object_name"],
                      e["width"]))
    out.append("")
    out.append("== caveat ==")
    for c in rep["caveats"]:
        out.append("- " + c)
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rekit datarefs",
        description="非字符串数据引用层：声明对象 ↔ 指令引用点（只呈现，不判断）")
    ap.add_argument("path")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40)
    a = ap.parse_args(argv)
    try:
        rep = build(a.path, a.section, limit=a.limit)
    except Exception as e:
        rep = {"schema": SCHEMA, "path": str(a.path), "status": "error",
               "reason": "%s: %s" % (type(e).__name__, e)}
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2, sort_keys=False))
    else:
        print(render(rep))
    return 0 if rep.get("status") in ("ok", "no_data_sections",
                                      "no_declaration_source") else 2


if __name__ == "__main__":
    sys.exit(main())
