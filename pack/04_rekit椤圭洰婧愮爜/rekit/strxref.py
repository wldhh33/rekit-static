#!/usr/bin/env python3
# rekit.strxref — 字符串/数据引用交叉（M8-U3）
#
# 这一层只回答三件事：
#   (1) 只读数据节里哪些字节**按明确口径**算字符串（分母）；
#   (2) 已解出的指令里哪些引用点的目标**恰好等于**某个字符串的起点（唯一回指）；
#   (3) 回指不到的字符串，缺的是哪一类证据（跨界/多引用/间接/未解出）。
#
# ── 字符串识别口径（先写后做，可被反驳）────────────────────────────
# 扫描范围：只扫**只读数据节白名单**：`.rodata`、`.rodata.str*`、PE `.rdata`。
#   明确排除 `.rodata.cst*`（浮点/常量池）、`.data*`、`.bss`、`.text` 与任何
#   可写节——数据节里大量二进制不是字符串，误报比漏报更伤。
#   节必须 alloc 且有文件字节（SHT_NOBITS / RawSize==0 不扫）。
# 编码：可打印 ASCII 0x20..0x7E（含空格）。含 0x80..0xFF 的段**一律不报**
#   （不猜 UTF-8：没有语言/区域证据时无法与二进制区分），计入 high_segments。
# 最短长度：4 字节（不含结尾 NUL）。短于 4 的段不报，计入 short_segments。
# 终止条件：必须在同一节内遇到 0x00；节尾未遇到 NUL 的尾段不报，
#   计入 no_nul_tail（并记字节数）。
# 重叠：按 0x00 切分成**互不相交**的段，只报整段，不做滑动窗口，
#   因此同一字节不会属于两条字符串，不存在「保留哪一条」的取舍。
#   引用点落在字符串内部（起点之后的字节）记 suffix，**不计入**唯一回指。
# 立即数引用（次级口径）：操作数里立即数的值等于某字符串起点时算引用点，
#   但要求该值 ≥ IMM_MIN(0x100000)。理由：PIE / 低地址镜像里小整数与地址
#   不可区分，宁可不报。该限制只作用于 imm，rip 相对引用不受影响。
# 数据节内的指针值（4/8 字节）：**不认作引用点**（数据→数据，没有函数归属），
#   只在解释「某字符串为什么没有引用点」时作为间接/跨界/未解出的证据。
#
# ── 度量的性质（C3）──────────────────────────────────────────────────
# “只在我们未解码的代码里、由外部 objdump 可见的引用点”是一个**补集度量**：
#   分子 = 未解码代码里的引用点；可达域越大，它越小。
#   因此它不是某个稳定分母的下界，不能写成“至少还有 N 个引用点”。
#   且 Go 字符串不是 NUL 终止，本指标对 Go 近乎盲（两 Go 样本关/开均为 0）。
#
# ── 数字分列（不合成净增量）─────────────────────────────────────────
#   字符串：unique（恰 1 个引用点）/ multi（≥2）/ no_site（0，按四类归因）。
#   引用点：rip_mem / lea_rip / imm 分开计数；有函数归属 / 无函数归属分开计数。
#   任何 0 都必须给结构性原因，不得把「没扫到」说成「没有」。
#
# ── 与既有层对账（同一引用点不得三层矛盾）───────────────────────────
#   本层引用点若同时是 callfacts 站点 / callgraph 边起点，则比对
#   (a) 函数归属（不一致 → layer_bug）；(b) 指令字节（不一致 → data_anomaly）；
#   (c) 直接调用目标落在字符串起点（语义矛盾 → layer_bug）。
#   冲突单列，不悄悄以某一方为准。

import bisect
import json
import struct

from . import expr, elf, pe, recdesc

MIN_LEN = 4
IMM_MIN = 0x100000
PTR_ALIGN = {"Q": 8, "I": 4}

CALIBER = {
    "scope": "只读数据节白名单：ELF .rodata / .rodata.str*；PE .rdata；"
             "排除 .rodata.cst*、.data*、.bss、.text 与可写节；"
             "节须 alloc 且有文件字节（SHT_NOBITS / RawSize==0 不扫）",
    "encoding": "可打印 ASCII 0x20..0x7E；含 0x80..0xFF 的段一律不报（不猜 UTF-8）",
    "min_len": MIN_LEN,
    "terminator": "必须在同一节内遇到 0x00；节尾无 NUL 的尾段不报",
    "overlap": "按 0x00 切成互不相交的段，只报整段，不做滑动窗口；"
               "引用点落在字符串内部记 suffix，不计入唯一回指",
    "immediate": "立即数值恰等于字符串起点算引用点，但要求 ≥ 0x%x"
                 "（低地址小整数与地址不可区分，宁可不报）" % IMM_MIN,
    "pointer_values": "数据节内的 4/8 字节指针值不认作引用点（无函数归属），"
                      "只作为 no_site 归因证据",
}

CAVEATS = [
    "只报可打印 ASCII：UTF-8/本地化文本本轮不报（宁可少报，不猜编码）",
    "字符串以 NUL 为唯一边界：不做滑动窗口，不报父串的子串",
    "Go/Rust 的字符串是 (指针,长度) 长度分界、不以 NUL 终止，本口径对这两类样本"
    "系统性少报；这是结构性口径限制，不是「该样本没有字符串」",
    "PE 导入名字符串前有 2 字节 hint，导入表指针指向 hint（串起点−2），"
    "故这类字符串通常归入「无证据」；COFF 节名由节头相对偏移引用，也无指针",
    "PE 导出名字符串可能在 .edata（不在白名单），本口径不报",
    "立即数引用有 0x100000 下限：PIE 低地址样本的立即数引用会被整体少报",
    "指针表（数据→数据）不产生引用点：没有函数归属，只作归因证据",
    "表达式层解不出的指令（VEX/EVEX 等）不产生引用点，单列 unlifted，不猜",
    "引用点只在 recdesc 已解出指令集合内找：未解码代码里的引用不计，"
    "会造成少报；该缺口由 verify 用外部 objdump 量化并单列",
    "没有引用点不等于字符串未使用：只说明本口径下找不到可归属的指令引用",
]


# ── 节与字节 ────────────────────────────────────────────────────────
def _load(path):
    data = open(path, "rb").read()
    secs = []
    if data[:4] == b"\x7fELF":
        for h in elf.section_headers(data):
            if not h["alloc"] or h["size"] == 0:
                continue
            end = min(len(data), h["offset"] + h["size"])
            secs.append({
                "name": h["name"], "index": h["index"], "va": h["addr"],
                "size": h["size"], "file_off": h["offset"],
                "file_size": max(0, end - h["offset"]),
                "write": h["write"], "exec": h["exec"],
                "nobits": h["type_id"] == 8,
            })
    elif data[:2] == b"MZ":
        r = pe.parse(path)
        for h in r["section_headers"]:
            if not h["vsize"] and not h["rawsize"]:
                continue
            end = min(len(data), h["rawptr"] + h["rawsize"])
            secs.append({
                "name": h["name"], "index": h["index"], "va": h["vaddr"],
                "size": h["vsize"] or h["rawsize"], "file_off": h["rawptr"],
                "file_size": max(0, end - h["rawptr"]),
                "write": bool(h["chars"] & 0x80000000),
                "exec": bool(h["chars"] & 0x20000000),
                "nobits": h["rawsize"] == 0,
            })
    else:
        raise ValueError("无法识别的格式（非 ELF / 非 PE）")
    return data, secs


def _allowed(name):
    """只读数据节白名单。`.rodata.cst*` 是常量池，明确排除。"""
    if name in (".rodata", ".rdata"):
        return True
    if name.startswith(".rodata.str"):
        return True
    return False


def _sec_of(secs, addr):
    for s in secs:
        if s["va"] <= addr < s["va"] + max(s["size"], s["file_size"]):
            return s
    return None


# ── 字符串扫描 ──────────────────────────────────────────────────────
def scan_blob(blob, base_va, min_len=MIN_LEN):
    """按口径切分一段只读数据。返回 (strings, stats)。"""
    out = []
    st = {"segments": 0, "accepted": 0, "accepted_bytes": 0,
          "rejected_binary": 0, "rejected_binary_bytes": 0,
          "rejected_short": 0, "rejected_short_bytes": 0, "rejected_high": 0,
          "no_nul_tail": 0, "no_nul_tail_bytes": 0, "bytes": len(blob)}
    i, n = 0, len(blob)
    while i < n:
        if blob[i] == 0:
            i += 1
            continue
        j = blob.find(b"\x00", i)
        if j < 0:
            st["no_nul_tail"] += 1
            st["no_nul_tail_bytes"] += n - i
            break
        seg = blob[i:j]
        st["segments"] += 1
        printable = all(0x20 <= c <= 0x7E for c in seg)
        if len(seg) < min_len:
            st["rejected_short"] += 1
            st["rejected_short_bytes"] += len(seg)
        elif not printable:
            st["rejected_binary"] += 1
            st["rejected_binary_bytes"] += len(seg)
            if any(c >= 0x80 for c in seg):
                st["rejected_high"] += 1
        else:
            out.append({"addr": base_va + i, "off": i,
                        "length": len(seg), "text": seg.decode("ascii")})
            st["accepted"] += 1
            st["accepted_bytes"] += len(seg)
        i = j + 1
    return out, st


# ── 引用点 ──────────────────────────────────────────────────────────
def _operands(rec):
    """表达式记录里的所有操作数（{t: mem|imm|reg}）。不认文本，只认结构化字段。"""
    for key, val in rec.items():
        if isinstance(val, dict) and val.get("t") in ("mem", "imm", "reg"):
            yield key, val


def _rip_arith(ins, op):
    disp = op.get("disp")
    tgt = op.get("rip_target")
    return "0x%x + 0x%x + (%+d) = 0x%x" % (ins["addr"], ins["length"], disp, tgt)


def _sites(res, starts):
    sites, unlifted = [], []
    for ins in res["instructions"]:
        try:
            rec = expr.decode(ins)
        except expr.LiftError as e:
            unlifted.append({"addr": ins["addr"], "bytes": ins["bytes"],
                             "reason": e.reason})
            continue
        except Exception as e:                    # 未预期异常也单列，不静默吞
            unlifted.append({"addr": ins["addr"], "bytes": ins["bytes"],
                             "reason": "解码异常：%s" % e})
            continue
        fam = rec.get("family")
        for role, op in _operands(rec):
            if op.get("t") == "mem" and op.get("rip") and \
                    op.get("rip_target") is not None:
                tgt = op["rip_target"]
                if tgt not in starts:
                    continue
                kind = "lea_rip" if fam == "lea" else "rip_mem"
                sites.append({
                    "addr": ins["addr"], "bytes": ins["bytes"],
                    "kind": kind, "role": role, "family": fam,
                    "target": tgt, "string": tgt,
                    "arith": _rip_arith(ins, op),
                    "operand": "%s: rip 相对内存操作数" % role,
                    "evidence": [
                        {"level": "observed",
                         "text": "0x%x 的指令字节 %s 与 rip 相对 disp=%+d"
                                 % (ins["addr"], ins["bytes"], op.get("disp"))},
                        {"level": "derived",
                         "text": "目标 = 下一条指令地址 + disp = %s"
                                 % _rip_arith(ins, op)},
                    ],
                })
            elif op.get("t") == "imm":
                v = op.get("value")
                if v is None or v < IMM_MIN or v not in starts:
                    continue
                sites.append({
                    "addr": ins["addr"], "bytes": ins["bytes"],
                    "kind": "imm", "role": role, "family": fam,
                    "target": v, "string": v,
                    "arith": "立即数 imm%d=0x%x 与字符串起点逐字节相等"
                             % (op.get("size") or 0, v),
                    "operand": "%s: 立即数" % role,
                    "evidence": [
                        {"level": "observed",
                         "text": "0x%x 的指令字节 %s 含立即数 0x%x"
                                 % (ins["addr"], ins["bytes"], v)},
                        {"level": "derived",
                         "text": "立即数与字符串起点相等（≥0x%x 才接受）" % IMM_MIN},
                    ],
                })
    return sites, unlifted


def _suffix_hits(res, strings):
    """引用点落在字符串内部（非起点）的条数：只作归因证据，不算回指。"""
    if not strings:
        return []
    ordered = sorted(strings, key=lambda s: s["addr"])
    starts = [s["addr"] for s in ordered]
    out = []
    for ins in res["instructions"]:
        try:
            rec = expr.decode(ins)
        except Exception:
            continue
        for role, op in _operands(rec):
            if op.get("t") != "mem" or not op.get("rip"):
                continue
            t = op.get("rip_target")
            if t is None:
                continue
            k = bisect.bisect_right(starts, t) - 1
            if k < 0:
                continue
            st = ordered[k]
            if st["addr"] < t < st["addr"] + st["length"]:
                out.append({"addr": ins["addr"], "target": t,
                            "string": st["addr"], "offset": t - st["addr"]})
    return out


# ── 数据节指针值（仅归因） ──────────────────────────────────────────
def _ptr_hits(data, secs, starts):
    """按 8/4 字节对齐读整数值，命中字符串起点则记录。

    .text 只做 8 字节对齐扫描（绝对地址在 64 位码里是 8 字节立即数/指针）；
    4 字节扫描只用于非可执行数据节，避免把指令里的 4 字节 disp 当指针。
    """
    hits = {}
    for s in secs:
        if s["nobits"] or s["file_size"] <= 0:
            continue
        blob = data[s["file_off"]: s["file_off"] + s["file_size"]]
        widths = ("Q",) if s["exec"] else ("Q", "I")
        for w in widths:
            size = PTR_ALIGN[w]
            cnt = len(blob) // size
            if cnt == 0:
                continue
            try:
                arr = memoryview(blob)[:cnt * size].cast(w)
            except (TypeError, ValueError):
                continue
            for k, v in enumerate(arr):
                if v in starts:
                    hits.setdefault(v, []).append({
                        "section": s["name"], "addr": s["va"] + k * size,
                        "width": size,
                    })
    return hits


def _classify(addr, ptr, decoded_starts, secs, suffix):
    """no_site 字符串的归因。优先级：跨界 > 未解出 > 间接 > 无证据。"""
    ev = {"cross_section": [], "undecoded": [], "indirect": []}
    for h in ptr:
        sec = next((s for s in secs if s["name"] == h["section"]), None)
        if sec is None:
            continue
        if _allowed(sec["name"]):
            ev["indirect"].append("%s@0x%x(%dB 指针)" %
                                  (h["section"], h["addr"], h["width"]))
        elif sec["exec"]:
            if h["addr"] not in decoded_starts:
                ev["undecoded"].append(".text@0x%x(%dB 未落在已解出指令起点)"
                                       % (h["addr"], h["width"]))
            else:
                ev["indirect"].append(".text@0x%x 命中的是已解出指令起点"
                                      "（字节巧合，不计入回指）" % h["addr"])
        else:
            ev["cross_section"].append("%s@0x%x(%dB 指针)" %
                                       (h["section"], h["addr"], h["width"]))
    if suffix:
        ev["indirect"].append("指令 0x%x 指向串内偏移 +%d"
                              % (suffix[0]["addr"], suffix[0]["offset"]))
    for kind in ("cross_section", "undecoded", "indirect"):
        if ev[kind]:
            return kind, ev
    return "no_evidence", ev


# ── 对账 ────────────────────────────────────────────────────────────
def crosscheck(report, facts, graph, seeds=None):
    """同一引用点在 本层 / callfacts / callgraph 三层不得矛盾。

    三层交集（引用点恰是调用点）可能为 0——那就如实报 0，不当作通过。
    另做函数域核对：本层给出的函数若在 recdesc 种子里有声明 end，
    站点地址必须落在 [start, end) 内（跨层函数域矛盾 → layer_bug）。
    """
    fs = {s["from"]: s for s in facts.get("sites") or []}
    ge = {}
    for e in graph.get("edges") or []:
        ge.setdefault(e["from"], e)
    seed_of = {s["addr"]: s for s in (seeds or [])}
    starts = {s["addr"] for s in report["strings_detail"]}
    conflicts, overlap, g_overlap, domain_checked = [], 0, 0, 0
    for s in report["sites"]:
        a = s["addr"]
        if a in fs:
            overlap += 1
            if fs[a].get("function") != s["function"]:
                conflicts.append({
                    "from": a, "field": "function", "attribution": "layer_bug",
                    "strxref": s["function"], "callfacts": fs[a].get("function")})
            if fs[a].get("bytes") != s["bytes"]:
                conflicts.append({
                    "from": a, "field": "bytes", "attribution": "data_anomaly",
                    "strxref": s["bytes"], "callfacts": fs[a].get("bytes")})
        if a in ge:
            g_overlap += 1
            gf = ge[a].get("from_fn")
            if gf is not None and gf != s["function"]:
                conflicts.append({
                    "from": a, "field": "function", "attribution": "layer_bug",
                    "strxref": s["function"], "callgraph": gf})
        sd = seed_of.get(s["function"]) if s["function"] is not None else None
        if sd and sd.get("end"):
            domain_checked += 1
            if not (sd["addr"] <= a < sd["end"]):
                conflicts.append({
                    "from": a, "field": "function_range",
                    "attribution": "layer_bug",
                    "strxref": s["function"],
                    "seed": [sd["addr"], sd["end"]]})
    for f in facts.get("sites") or []:
        if f.get("call_kind") == "direct" and f.get("target") in starts:
            conflicts.append({
                "from": f["from"], "field": "call_target_is_string",
                "attribution": "layer_bug",
                "detail": "直接调用目标 0x%x 落在字符串起点" % f["target"]})
    return {"ok": not conflicts, "checked": overlap + g_overlap,
            "facts_overlap": overlap, "graph_overlap": g_overlap,
            "domain_checked": domain_checked,
            "note": ("引用点与调用点的交集为 0：本层引用点不是调用点，"
                     "三层交集为空，本项无非空对账对象"
                     if not (overlap + g_overlap) else
                     "引用点与调用点交集 %d，逐点比对函数归属/字节"
                     % (overlap + g_overlap)),
            "conflicts": conflicts}


# ── 主构建 ──────────────────────────────────────────────────────────
def build(path, section=".text", res=None, facts=None, graph=None):
    data, secs = _load(path)
    scanned = [s for s in secs if _allowed(s["name"]) and not s["nobits"]]
    per_sec, strings, agg = {}, [], None
    for s in scanned:
        blob = data[s["file_off"]: s["file_off"] + s["file_size"]]
        got, st = scan_blob(blob, s["va"])
        if agg is None:
            agg = {k: 0 for k in st}
        for k in st:
            agg[k] += st[k]
        per_sec[s["name"]] = st
        strings.extend(got)
    if agg is None:
        agg = {k: 0 for k in ("segments", "accepted", "accepted_bytes",
                              "rejected_binary", "rejected_binary_bytes",
                              "rejected_short", "rejected_short_bytes",
                              "rejected_high", "no_nul_tail",
                              "no_nul_tail_bytes", "bytes")}
    starts = {s["addr"]: s for s in strings}

    res = res or None
    text = next((s for s in secs if s["name"] == section and not s["nobits"]
                 and s["file_size"] > 0), None)
    no_code = text is None
    if res is None:
        if no_code:
            res = {"format": None, "instructions": [], "blocks": [],
                   "seeds": [], "cfg": {}, "counts": {}}
        else:
            res = recdesc.descend(path, section)
    ins_of = {i["addr"]: i for i in res["instructions"]}
    block_of = {}
    for b in res["blocks"]:
        for a in b["insns"]:
            block_of[a] = b
    sites, unlifted = _sites(res, starts)
    for s in sites:
        b = block_of.get(s["addr"])
        s["function"] = b["function"] if b else None
        s["block"] = b["start"] if b else None
        s["section"] = (_sec_of(secs, s["target"]) or {}).get("name")
        if s["function"] is None:
            s["attribution"] = "无块归属：该指令不在任何已解出基本块内"

    by_string = {}
    for s in sites:
        by_string.setdefault(s["string"], []).append(s)
    suffixes = _suffix_hits(res, strings)
    suffix_of = {}
    for h in suffixes:
        suffix_of.setdefault(h["string"], []).append(h)
    ptr = _ptr_hits(data, secs, starts) if any(
        s["addr"] not in by_string for s in strings) else {}
    decoded_starts = set(ins_of)

    detail, reason_cnt = [], {"cross_section": 0, "undecoded": 0,
                              "indirect": 0, "no_evidence": 0}
    for st in strings:
        mine = by_string.get(st["addr"], [])
        if len(mine) == 1:
            status, reason, ev = "unique", None, []
        elif len(mine) > 1:
            status, reason, ev = "multi", None, []
        else:
            status = "no_site"
            reason, ev = _classify(st["addr"], ptr.get(st["addr"], []),
                                   decoded_starts, secs,
                                   suffix_of.get(st["addr"]))
            reason_cnt[reason] += 1
        detail.append({
            "addr": st["addr"], "section": (_sec_of(secs, st["addr"]) or {}).get("name"),
            "length": st["length"], "text": st["text"][:120],
            "truncated": len(st["text"]) > 120, "status": status,
            "reason": reason,
            "sites": [s["addr"] for s in mine],
            "site_kinds": sorted({s["kind"] for s in mine}),
            "evidence": ev,
        })

    counts = {
        "sections_scanned": len(scanned),
        "sections_missing": [s["name"] for s in secs
                             if _allowed(s["name"]) and s["nobits"]] or [],
        "strings_total": len(strings),
        "strings_zero_reason": (
            None if strings else
            ("白名单只读数据节缺失（本样本没有 .rodata/.rodata.str*/.rdata）"
             if not scanned else
             "白名单节内没有 NUL 终止的可打印 ASCII 段（长度≥%d）" % MIN_LEN)),
        "strings_unique": sum(1 for d in detail if d["status"] == "unique"),
        "strings_multi": sum(1 for d in detail if d["status"] == "multi"),
        "strings_no_site": sum(1 for d in detail if d["status"] == "no_site"),
        "no_site_reason": reason_cnt,
        "sites_total": len(sites),
        "sites_rip_mem": sum(1 for s in sites if s["kind"] == "rip_mem"),
        "sites_lea_rip": sum(1 for s in sites if s["kind"] == "lea_rip"),
        "sites_imm": sum(1 for s in sites if s["kind"] == "imm"),
        "sites_with_function": sum(1 for s in sites if s["function"] is not None),
        "sites_without_function": sum(1 for s in sites if s["function"] is None),
        "suffix_refs": len(suffixes),
        "unlifted": len(unlifted),
        "rejected": dict(agg),
        "per_section": per_sec,
        "coverage": {
            "decoded_instructions": len(res["instructions"]),
            "decoded_bytes": sum(i["length"] for i in res["instructions"]),
            "text_bytes": next((s["file_size"] for s in secs
                                if s["name"] == section and not s["nobits"]), 0),
            "no_code": no_code,
            "no_code_reason": ("本样本没有可分析的 %s 代码节（可能已加壳/改名），"
                               "引用点整体不可判定" % section) if no_code else None,
            "note": "引用点只覆盖 recdesc 已解出指令；未解码代码里的引用不计",
        },
    }
    cov = counts["coverage"]
    cov["ratio"] = (round(cov["decoded_bytes"] / cov["text_bytes"], 4)
                    if cov["text_bytes"] else 0.0)
    rep = {
        "path": str(path), "section": section, "format": res.get("format"),
        "caliber": CALIBER, "caveats": list(CAVEATS),
        "counts": counts, "strings_detail": detail, "sites": sites,
        "suffix_refs": suffixes, "unlifted": unlifted,
        "crosscheck": None,
    }
    if facts is not None and graph is not None:
        rep["crosscheck"] = crosscheck(rep, facts, graph, res.get("seeds"))
    return rep


# ── 渲染 ────────────────────────────────────────────────────────────
def render(report, limit=40):
    c = report["counts"]
    lines = [
        "STRXREF: %s" % report["path"],
        "  口径: %s" % CALIBER["scope"],
        "        编码=%s 最短=%d 终止=NUL 重叠=%s"
        % (CALIBER["encoding"], CALIBER["min_len"], CALIBER["overlap"]),
        "  分母: 字符串 %d（unique %d / multi %d / no_site %d）"
        "  引用点 %d（rip_mem %d / lea_rip %d / imm %d）"
        % (c["strings_total"], c["strings_unique"], c["strings_multi"],
           c["strings_no_site"], c["sites_total"], c["sites_rip_mem"],
           c["sites_lea_rip"], c["sites_imm"]),
        "  no_site 归因: 跨界 %d / 未解出 %d / 间接 %d / 无证据 %d"
        % (c["no_site_reason"]["cross_section"],
           c["no_site_reason"]["undecoded"],
           c["no_site_reason"]["indirect"],
           c["no_site_reason"]["no_evidence"]),
        "  归属: 有函数 %d / 无函数 %d   suffix %d  unlifted %d"
        % (c["sites_with_function"], c["sites_without_function"],
           c["suffix_refs"], c["unlifted"]),
        "  代码覆盖: 已解出 %d 条 / %d 字节 = %.2f%% of %s；"
        "引用点只是下界（未解码代码里的引用不计）"
        % (c["coverage"]["decoded_instructions"], c["coverage"]["decoded_bytes"],
           c["coverage"]["ratio"] * 100.0, report["section"]),
        "  拒绝: 二进制段 %d(%d 字节) / 短段 %d(%d 字节) / 高字节段 %d / "
        "节尾无 NUL %d(%d 字节)"
        % (c["rejected"]["rejected_binary"],
           c["rejected"]["rejected_binary_bytes"],
           c["rejected"]["rejected_short"],
           c["rejected"]["rejected_short_bytes"],
           c["rejected"]["rejected_high"], c["rejected"]["no_nul_tail"],
           c["rejected"]["no_nul_tail_bytes"]),
        "  扫描节: %d  %s" % (c["sections_scanned"],
                            ",".join(c["per_section"]) or "（无白名单节）"),
    ]
    if c.get("strings_zero_reason"):
        lines.append("  零值原因: %s" % c["strings_zero_reason"])
    for s in report["sites"][:limit]:
        lines.append("  ref 0x%x fn=%s %-7s → 0x%x  %s  「%s」"
                     % (s["addr"], ("0x%x" % s["function"]) if s["function"] else "-",
                        s["kind"], s["target"], s["arith"],
                        (report_string(report, s["target"]))))
    if len(report["sites"]) > limit:
        lines.append("  … 其余 %d 个引用点见 --json" % (len(report["sites"]) - limit))
    cc = report.get("crosscheck")
    if cc:
        lines.append("  对账: 交集 checked %d（facts %d / graph %d）"
                     "函数域核对 %d 冲突 %d%s"
                     % (cc["checked"], cc["facts_overlap"], cc["graph_overlap"],
                        cc["domain_checked"], len(cc["conflicts"]),
                        "" if cc["ok"] else " ← 单列归因"))
        if not cc["checked"]:
            lines.append("    · %s" % cc["note"])
        for x in cc["conflicts"][:10]:
            lines.append("    ! 0x%s %s → %s"
                         % (("%x" % x["from"]) if x["from"] else "-",
                            x["field"], x["attribution"]))
    return "\n".join(lines)


def report_string(report, addr):
    for d in report["strings_detail"]:
        if d["addr"] == addr:
            return d["text"]
    return "?"


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="rekit.strxref")
    ap.add_argument("path")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args(argv)
    rep = build(args.path, args.section)
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(render(rep, args.limit))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
