#!/usr/bin/env python3
# rekit.mapview — M3 内存映射视图与地址换算（净室观察法）
# 2026-11-15 U1：映射模型 + ELF PT_LOAD / PE 节 + header 区 + 双向换算
#
# 三值语义（差一个字节都不许"容错"）：
#   hit          地址/偏移落在某个映射单元，且该单元有文件字节背书 → 给出对应值
#   not_in_file  内存里存在（已分配/零填充），但文件里没有对应字节（.bss / 节虚拟尾部）
#   unmapped     不在任何映射单元内（段间空洞、超出镜像范围）
#   multi        反向换算命中多个单元（UPX-ELF 两个 PT_LOAD 共用文件偏移 0，实测存在）
#
# 节类型优先级（2026-11-15 裁决）：
#   SHT_NOBITS 节（.bss/.tbss）自身无文件表示，其 sh_offset 常常就是下一个节的起点。
#   纯 LOAD 算术会把 .tbss 的地址算成 hit（实测 dyn_static: .tbss addr=0x49ee40
#   落在 LOAD#3 的 filesz 内，delta=0x30 → 文件 0x9de40 有真实机器码）。但那些字节
#   属于宿主节、不是 TLS 模板，报 hit 等于向 map & patch 宣称"这个地址可改"，
#   是最危险的假阳性。故：节类型优先于算术 → 一律 not_in_file；算术落点与
#   宿主节用独立字段 host_section 记录，语义与 not_in_file 并存，不合并。
#
# 纪律：
#   1. 区间一律左闭右开 [start, start+size)。
#   2. 不逼近：落不进任何单元就报 unmapped，不取"最近的段"。
#   3. 强结论须可指名证据：每次换算都回带命中的单元名与 delta。
#   4. 已知限制：NOBITS 节与后续节共用文件偏移（工具怪癖），该偏移不可反推本节。
import argparse
import json
import os
import struct
import sys

from . import elf, pe

HIT, NOT_IN_FILE, UNMAPPED, MULTI = "hit", "not_in_file", "unmapped", "multi"
TOP_LEVEL_KEYS = ("format", "units", "entry", "gaps", "evidence", "stats")
SHT_NOBITS = 8   # ELF 节类型：无文件表示（.bss/.tbss）


def _section_covering(model, addr, section=None):
    """返回覆盖该地址的节（仅 ELF 且节表存在）。

    section 给定时按【节身份】解析（节级一致性用）：同地址被多节覆盖时可指名，
    否则默认 NOBITS 优先（保守判 not_in_file），再取最小者。
    非 alloc 节 sh_addr 恒为 0，不参与判定。
    """
    if model["format"] != "ELF":
        # PE：映射单元就是节（name 即节名），节身份用于消除同名/重叠歧义
        if section is None:
            return None
        for u in model["units"]:
            if (u["name"] == section and u["mem"][1] > 0
                    and u["mem"][0] <= addr < u["mem"][0] + u["mem"][1]):
                return {"name": u["name"], "type_id": None, "alloc": True,
                        "addr": u["mem"][0], "size": u["mem"][1],
                        "offset": u["file"][0],
                        "file_size": u["file"][1], "kind": u["kind"]}
        return None
    if not model.get("sections"):
        return None
    cands = [x for x in model["sections"]
             if x["alloc"] and x["size"] > 0 and x["addr"] > 0
             and x["addr"] <= addr < x["addr"] + x["size"]]
    if section is not None:
        named = [x for x in cands if x["name"] == section]
        if named:
            return named[0]
    if not cands:
        return None
    nobits = [x for x in cands if x["type_id"] == SHT_NOBITS]
    return min(nobits or cands, key=lambda x: x["size"])


def _host_section(model, off):
    """文件偏移 off 实际落在哪个【非 NOBITS】节的字节里（宿主节）。

    这是 NOBITS 反例的取证字段：算术声称可落盘，但那些字节不属于 NOBITS 节。
    """
    if not model.get("sections"):
        return None
    cands = [x for x in model["sections"]
             if x["type_id"] != SHT_NOBITS and x["size"] > 0
             and x["offset"] <= off < x["offset"] + x["size"]]
    if not cands:
        return None
    h = min(cands, key=lambda x: x["size"])
    return {"name": h["name"], "offset": h["offset"], "size": h["size"]}


def _detect(data):
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            return "pe"
    return None


def _unit(name, kind, file_off, file_size, mem_addr, mem_size, flags=""):
    return {"name": name, "kind": kind,
            "file": [file_off, file_size], "mem": [mem_addr, mem_size],
            "mapped": "file" if file_size > 0 else "zero",
            "flags": flags}


# ── ELF ───────────────────────────────────────────────────────────

def _build_elf(data, path):
    end = "<" if data[5] == 1 else ">"
    (_t, _m, _v, entry, _po, _so, _fl, _eh, _pe, _pn,
     _shent, e_shnum, _shstr) = struct.unpack_from(end + "HHIQQQIHHHHHH", data, 16)
    phdrs = elf.program_headers(data)
    loads = [p for p in phdrs if p["type_id"] == elf.PT_LOAD]
    units, caveats = [], []
    for i, p in enumerate(loads):
        flags = "".join(c for c, bit in (("R", 4), ("W", 2), ("X", 1)) if p["flags"] & bit)
        # filesz > memsz 属畸形；换算按 min 取，单独记 caveat
        if p["filesz"] > p["memsz"]:
            caveats.append("LOAD#%d p_filesz(0x%x) > p_memsz(0x%x)，换算按 min 截断"
                           % (i, p["filesz"], p["memsz"]))
        units.append(_unit("LOAD#%d" % i, "pt_load", p["offset"], p["filesz"],
                           p["vaddr"], p["memsz"], flags))
    # 反向换算多解检测：同一文件区间被多个单元覆盖（UPX-ELF 实测存在）
    shared = _shared_file_ranges(units)
    if shared:
        caveats.append("文件区间被多个映射单元共享（反向换算多解）：%s" % shared)
    if e_shnum == 0:
        caveats.append("e_shnum=0（节表被移除，疑似加壳）：节级换算不可判定")
    # 节表存在时附上节级信息（供 E3 对拍；节表缺失则 sections=[] 且已记 caveat）
    secs = elf.section_headers(data)
    sections = [{"name": s["name"], "type": s["type"], "type_id": s["type_id"],
                 "addr": s["addr"], "offset": s["offset"],
                 "size": s["size"], "alloc": s["alloc"]} for s in secs]
    for s in sections:
        if s["type_id"] == SHT_NOBITS and s["size"] > 0 and s["alloc"]:
            host = _host_section({"sections": sections}, s["offset"])
            caveats.append("%s: NOBITS（无文件表示），sh_offset=0x%x %s"
                           % (s["name"], s["offset"],
                              "与宿主节 %s 共用文件偏移——该偏移的字节不属于本节"
                              % host["name"] if host else "不落在任何节的文件区间"))
    # TLS 覆盖：.tbss 的 sh_addr 不预留地址空间，会与后续节地址区间重叠
    for s in sections:
        if s["type_id"] == SHT_NOBITS or not s["alloc"] or not s["size"]:
            continue
        over = [x["name"] for x in sections
                if x["type_id"] == SHT_NOBITS and x["alloc"] and x["size"] > 0
                and x["addr"] < s["addr"] + s["size"] and s["addr"] < x["addr"] + x["size"]]
        if over:
            caveats.append("%s 的地址区间被 NOBITS 节 %s 覆盖（TLS 布局）："
                           "裸地址查询按 NOBITS 保守判 not_in_file，"
                           "节级查询按节身份仍命中自己的 sh_offset"
                           % (s["name"], "/".join(over)))
    model = {
        "format": "ELF",
        "bits": 64 if data[4] == 2 else 32,
        "entry": entry,
        "image": {"base": 0, "limit": max((u["mem"][0] + u["mem"][1] for u in units), default=0)},
        "units": units,
        "caveats": caveats,
        "sections": sections,
        "evidence": [
            "映射单元 = PT_LOAD 段：文件区间 [p_offset, p_offset+p_filesz)，"
            "内存区间 [p_vaddr, p_vaddr+p_memsz)",
            "ELF 文件头/节名表不单独成单元：首个 LOAD 的 p_offset=0 已覆盖",
            "p_memsz > p_filesz 的尾部（.bss 等）→ not_in_file（零填充，无文件字节）",
            "换算不依赖节表（节表可能是空的/被壳移除）",
            "节类型优先于算术：SHT_NOBITS 地址一律 not_in_file，"
            "算术落点与实际覆盖它的宿主节用 host_section 独立字段记录",
        ],
    }
    model["stats"] = _stats(units)
    model["gaps"] = _gaps(units, len(data), model["image"]["limit"])
    return model


# ── PE ────────────────────────────────────────────────────────────

def _build_pe(data, path):
    r = pe.parse(path)
    base = r["image_base"]
    soh = r["size_headers"]
    units, caveats = [], []
    first_raw = min((s[2] for s in r["sections"] if s[3] > 0), default=None)
    if first_raw is not None and soh > first_raw:
        # 前提不成立：header 区与首个节的文件区间重叠，无法断言 offset == RVA，
        # 按 E4 的口径整段判 unmapped（不硬算），并留下 caveat。
        caveats.append("SizeOfHeaders(0x%x) > 首个节 RawPtr(0x%x)：header 区与节文件区间重叠，"
                       "header 区 RVA 判 unmapped" % (soh, first_raw))
    else:
        units.append(_unit("<headers>", "headers", 0, soh, 0, soh, "-"))
    degenerate = []
    for (va, vsize, rawptr, rawsize, name) in r["sections"]:
        # loader 语义：映射长度取 max(VSize, RawSize)——若 RawSize > VSize，
        # 文件里的字节仍必须能被映射到（否则原始数据无处可去）。
        mem_size = max(vsize, rawsize)
        if mem_size == 0:
            # 节表项全零（伪造 Rich 样例实测 2 条）：无任何可映射区间，
            # 不建单元，避免与头区重叠的零长度单元污染查询与空洞统计。
            degenerate.append(name or "<unnamed>")
            continue
        if vsize == 0:
            caveats.append("%s: VirtualSize=0，按 RawSize(0x%x) 兜底" % (name, rawsize))
        if vsize > rawsize:
            caveats.append("%s: 虚拟尾部 0x%x..0x%x 无文件字节（not_in_file）"
                           % (name, va + rawsize, va + vsize))
        units.append(_unit(name, "section", rawptr, rawsize, va, mem_size))
    if degenerate:
        caveats.append("%d 个零长度节被跳过（VSize=RawSize=0，无可映射区间）：%s"
                       % (len(degenerate), ", ".join(degenerate)))
    model = {
        "format": "PE",
        "bits": 32 if r["magic"] == 0x10B else 64,
        "entry": r["entry"],
        "image": {"base": base, "limit": r["size_image"]},
        "units": units,
        "caveats": caveats,
        "evidence": [
            "映射单元 = 头区 [0, SizeOfHeaders) + 各节：文件 [RawPtr, RawPtr+RawSize)，"
            "内存 [VirtualAddress, VirtualAddress+max(VirtualSize, RawSize))",
            "header 区：RVA < SizeOfHeaders 时 offset == RVA（本样本前提 SizeOfHeaders <= 首个节 RawPtr）",
            "节虚拟尾部（RawSize < VirtualSize）→ not_in_file（零填充）",
            "超出 SizeOfImage 的 RVA → unmapped（不以节表兜底）",
        ],
    }
    model["stats"] = _stats(units)
    model["gaps"] = _gaps(units, len(data), r["size_image"])
    return model


# ── 公共：空洞与统计 ──────────────────────────────────────────────

def _shared_file_ranges(units):
    spans = sorted((u["file"][0], u["file"][0] + u["file"][1], u["name"])
                   for u in units if u["file"][1] > 0)
    out = []
    for a, b in zip(spans, spans[1:]):
        if b[0] < a[1]:
            out.append("%s[0x%x..0x%x] 与 %s[0x%x..] 重叠" % (a[2], a[0], a[1], b[2], b[0]))
    return "; ".join(out)


def _stats(units):
    file_bytes = sum(u["file"][1] for u in units)
    mem_bytes = sum(u["mem"][1] for u in units)
    return {"units": len(units),
            "file_bytes": file_bytes, "mem_bytes": mem_bytes,
            "file_backed_units": sum(1 for u in units if u["mapped"] == "file"),
            "zero_units": sum(1 for u in units if u["mapped"] == "zero")}


def _gaps(units, file_size, mem_limit):
    """区间左闭右开；分别算内存空洞与文件空洞。"""
    def holes(spans, limit):
        spans = sorted(s for s in spans if s[1] > s[0])
        out, cur = [], 0
        for a, b in spans:
            if a > cur:
                out.append([cur, a])
            cur = max(cur, b)
        if cur < limit:
            out.append([cur, limit])
        return out
    mem = holes([(u["mem"][0], u["mem"][0] + u["mem"][1]) for u in units], mem_limit)
    f = holes([(u["file"][0], u["file"][0] + u["file"][1]) for u in units], file_size)
    return {"mem": mem, "file": f,
            "mem_bytes": sum(b - a for a, b in mem),
            "file_bytes": sum(b - a for a, b in f)}


# ── 换算 ─────────────────────────────────────────────────────────

def addr_to_off(model, addr, section=None):
    """地址（ELF=vaddr / PE=RVA）→ 文件偏移。

    返回 {"status", "offset", "unit", "delta", "reason"}；
    status ∈ hit / not_in_file / unmapped / multi。
    ELF 且地址落在 SHT_NOBITS 节时，额外带 section / arithmetic_offset /
    host_section：status 恒为 not_in_file（节类型优先于算术），
    offset 恒为 None（不宣称可改），算术落点与宿主节只作取证。

    section：节身份（可选）。TLS 节 .tbss 的 sh_addr 会与 .init_array 等节
    地址重叠（实测 dyn_static 同为 0x49ee40）。裸地址查询保守按 NOBITS 判
    not_in_file；节级查询带入 section 后按该节自身类型判定——
    非 NOBITS 节仍必须精确命中自己的 sh_offset，NOBITS 仍必须 not_in_file。

    输出契约（CLI 与 MCP 共用，两种查询必须可区分）：
      query_mode="addr"：裸地址，按保守口径（重叠时 NOBITS 优先）
      query_mode="section"：节级，追加 section 与 section_matched
    """
    mode = ({"query_mode": "section", "section": section} if section is not None
            else {"query_mode": "addr"})
    sec = _section_covering(model, addr, section)
    if section is not None:
        mode["section_matched"] = sec is not None
    limit = model["image"]["limit"]
    if addr < 0:
        return dict({"status": UNMAPPED, "offset": None, "unit": None, "delta": None,
                     "reason": "负地址"}, **mode)
    if limit and addr >= limit:
        return dict({"status": UNMAPPED, "offset": None, "unit": None, "delta": None,
                     "reason": "超出镜像范围 0x%x" % limit}, **mode)
    hits = [u for u in model["units"]
            if u["mem"][0] <= addr < u["mem"][0] + u["mem"][1]]
    if not hits:
        return dict({"status": UNMAPPED, "offset": None, "unit": None, "delta": None,
                     "reason": "不在任何映射单元（段间空洞）"}, **mode)
    if len(hits) > 1 and section is not None and sec is not None \
            and sec.get("type_id") != SHT_NOBITS:
        # 节身份能消除多解：只保留文件区间确实覆盖本节算术落点的单元
        cand = sec["offset"] + (addr - sec["addr"])
        narrowed = [u for u in hits if u["mapped"] == "file"
                    and u["file"][0] <= cand < u["file"][0] + u["file"][1]]
        if len(narrowed) == 1:
            hits = narrowed
    if len(hits) > 1:
        return dict({"status": MULTI, "offset": None,
                     "unit": ",".join(u["name"] for u in hits), "delta": None,
                     "reason": "内存区间重叠"}, **mode)
    u = hits[0]
    delta = addr - u["mem"][0]
    if section is not None and sec is None:
        return dict({"status": UNMAPPED, "offset": None, "unit": u["name"],
                     "delta": delta,
                     "reason": "地址 0x%x 不落在节 %s 内（或节不存在）"
                               % (addr, section)}, **mode)
    # 2026-11-15 裁决：节类型优先于算术。NOBITS 节自身无文件表示，算术落到的
    # 是宿主节的字节，报 hit 会让 map & patch 去改错地方 → 一律 not_in_file。
    if sec is not None and sec.get("type_id") == SHT_NOBITS:
        out = dict({"status": NOT_IN_FILE, "offset": None, "unit": u["name"],
                    "delta": delta, "section": sec["name"],
                    "reason": "SHT_NOBITS 节无文件表示（节类型优先于算术）"}, **mode)
        if u["mapped"] == "file" and delta < u["file"][1]:
            cand = u["file"][0] + delta
            out["arithmetic_offset"] = cand
            out["host_section"] = _host_section(model, cand)
            out["reason"] += "；算术落点 0x%x 的字节属于宿主节 %s" % (
                cand, (out["host_section"] or {}).get("name", "<none>"))
        return out
    if u["mapped"] == "file" and delta < u["file"][1]:
        return dict({"status": HIT, "offset": u["file"][0] + delta,
                     "unit": u["name"], "delta": delta, "reason": "文件背书"}, **mode)
    return dict({"status": NOT_IN_FILE, "offset": None, "unit": u["name"],
                 "delta": delta, "reason": "内存有、文件无（零填充/纯内存节）"}, **mode)


def off_to_addr(model, off):
    """文件偏移 → 地址（ELF=vaddr / PE=RVA）。

    返回 {"status", "addrs", "units", "reason"}；status ∈ hit / unmapped / multi。
    multi = 同一文件偏移被多个映射单元共享（UPX-ELF 实测存在），不给单值。
    """
    if off < 0:
        return {"query_mode": "offset", "status": UNMAPPED, "addrs": [], "units": [],
                "reason": "负偏移"}
    hits = [u for u in model["units"]
            if u["file"][1] > 0 and u["mapped"] == "file"
            and u["file"][0] <= off < u["file"][0] + u["file"][1]]
    if not hits:
        return {"query_mode": "offset", "status": UNMAPPED, "addrs": [], "units": [],
                "reason": "不在任何映射单元的文件区间（文件空洞）"}
    addrs = [u["mem"][0] + (off - u["file"][0]) for u in hits]
    if len(hits) > 1:
        return {"query_mode": "offset", "status": MULTI, "addrs": addrs,
                "units": [u["name"] for u in hits],
                "reason": "同一文件偏移被 %d 个单元映射" % len(hits)}
    return {"query_mode": "offset", "status": HIT, "addrs": addrs,
            "units": [hits[0]["name"]], "reason": "文件背书"}


def build(path):
    data = open(path, "rb").read()
    fmt = _detect(data)
    if fmt == "elf":
        return _build_elf(data, path)
    if fmt == "pe":
        return _build_pe(data, path)
    raise ValueError("无法识别的格式（非 ELF / 非 PE）: %s" % path)


# ── CLI ──────────────────────────────────────────────────────────

def render_text(path, m):
    lines = ["Map:      %s" % path,
             "Format:   %s (%d-bit, %d 单元)" % (m["format"], m["bits"], len(m["units"])),
             "Entry:    0x%x" % m["entry"],
             "Image:    base 0x%x  limit 0x%x"
             % (m["image"]["base"], m["image"]["limit"]),
             "Units:"]
    for u in m["units"]:
        lines.append("  %-10s mem 0x%08x..0x%08x  file 0x%08x..0x%08x  %s%s"
                     % (u["name"], u["mem"][0], u["mem"][0] + u["mem"][1],
                        u["file"][0], u["file"][0] + u["file"][1],
                        u["flags"] or "-",
                        "" if u["mapped"] == "file" else "  [zero]"))
    g = m["gaps"]
    if g["mem"]:
        lines.append("Gaps(mem):  " + ", ".join("0x%x..0x%x" % (a, b) for a, b in g["mem"][:8])
                     + ("" if len(g["mem"]) <= 8 else " ..."))
    if g["file"]:
        lines.append("Gaps(file): " + ", ".join("0x%x..0x%x" % (a, b) for a, b in g["file"][:8])
                     + ("" if len(g["file"]) <= 8 else " ..."))
    if m["caveats"]:
        lines.append("Caveats:")
        for c in m["caveats"]:
            lines.append("  ! %s" % c)
    lines.append("Evidence:")
    for e in m["evidence"]:
        lines.append("  - %s" % e)
    return "\n".join(lines)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(
        prog="rekit.cli map",
        description="内存映射视图与地址换算（ELF vaddr / PE RVA ⇄ 文件偏移）")
    ap.add_argument("file", help="待分析文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--addr", default=None,
                    help="查询地址（ELF=vaddr / PE=RVA，0x 前缀十六进制）")
    ap.add_argument("--off", default=None, help="查询文件偏移（0x 前缀十六进制）")
    ap.add_argument("--section", default=None,
                    help="节身份（仅配合 --addr）：按该节回答，与裸地址查询区分；"
                         "地址不落在该节内则 section_matched=false")
    args = ap.parse_args(argv)
    if args.section is not None and args.addr is None:
        print("rekit: --section 只能与 --addr 一起使用（文件偏移没有节身份）",
              file=sys.stderr)
        return 2

    if not os.path.exists(args.file):
        print("rekit: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        m = build(args.file)
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    except ValueError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except Exception as e:
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3

    out = dict(m)
    if args.addr is not None or args.off is not None:
        out["queries"] = {}
        if args.addr is not None:
            out["queries"]["addr"] = dict(
                addr_to_off(m, int(args.addr, 0), section=args.section),
                query=int(args.addr, 0))
        if args.off is not None:
            out["queries"]["off"] = dict(off_to_addr(m, int(args.off, 0)),
                                         query=int(args.off, 0))
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    else:
        print(render_text(args.file, m))
        if "queries" in out:
            for k, q in out["queries"].items():
                if k == "addr":
                    # 两种查询必须一眼可区分：裸地址 vs 节身份
                    label = ("bare" if q.get("query_mode") == "addr"
                             else "section %s" % q.get("section"))
                    print("Query addr 0x%x [%s] -> %s%s"
                          % (q["query"], label, q["status"],
                             "  file 0x%x (%s)" % (q["offset"], q["unit"])
                             if q["status"] == HIT else "  (%s)" % q["reason"]))
                    if q.get("host_section"):
                        h = q["host_section"]
                        print("  host_section %s [0x%x..0x%x)：算术落点的字节属该节"
                              % (h["name"], h["offset"], h["offset"] + h["size"]))
                else:
                    print("Query off 0x%x [offset] -> %s%s" % (q["query"], q["status"],
                          "  " + ", ".join("0x%x" % a for a in q["addrs"])
                          if q["addrs"] else "  (%s)" % q["reason"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
