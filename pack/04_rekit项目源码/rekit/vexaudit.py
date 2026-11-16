#!/usr/bin/env python3
# rekit.vexaudit — 伪 VEX/EVEX 弃权逐条归因（M9 收敛线 B）
#
# 问题：disasm 遇到 C4/C5/62 开头、保留位/映射不合法的编码一律 Unsupported。
#   只写 “abstain” 无法区分三种完全不同的情况：
#     (a) 该地址根本不是指令边界（字节是数据/上一条指令的操作数）→ 弃权正确；
#     (b) 该地址是指令边界，但编码确实非法 → 弃权正确，objdump 也印 (bad)；
#     (c) 该地址是指令边界，objdump 能解出合法 VEX/EVEX → **解码器缺陷**。
#
# 本层的判据全部来自外部 objdump（地址 → 指令文本/长度），不用被测实现的
# 解码结果当判据；被测实现只提供“我在这个位置弃权了，类别是 X”。
#
# 扫描口径：逐字节找 lead ∈ {C4,C5,62}，对每个位置独立试解。这**不是**线性扫描，
# 也不产出任何指令边界；它只回答“这个 C4/C5/62 字节如果被当成指令起点，会怎样”。
# 因此分母有两层，必须同时报：
#   lead_bytes   = 节内 C4/C5/62 字节总数（逐字节口径）
#   abstain_sites= 其中我方确实弃权的点数（可归因集合）
# 两个数不可混用；报告里分开写。
import os

CAT_DECODER_DEFECT = "decoder_defect"        # objdump 有合法 VEX，我方却弃权
CAT_ILLEGAL = "illegal_encoding"             # objdump 同址 (bad)，双方一致拒绝
# 判据只有一条：外部 objdump 未在该地址列指令（不是指令起点）。
# 它既可能是数据/填充，也可能是上一条指令的操作数/立即数内部字节——**不能**写成
# 「数据」或「不在代码里」。域内比例必须另报（domain 字段）。
CAT_NOT_START = "not_objdump_insn_start"
CAT_NONVEX = "objdump_nonvex_at_addr"        # objdump 在该地址解出非 VEX（需人工复核）
CAT_NO_OBJDUMP = "objdump_unavailable_at_addr"  # objdump 没列该地址但也不是起点
CAT_DECODED = "decoded"                      # 我方解出（不属弃权）
CAT_LEN_DIFF = "decoded_len_differs"         # 我方解出但与 objdump 长度不同

VEX_CATEGORIES = {"vex_legacy_prefix", "vex_map_undefined",
                  "evex_reserved", "evex_map0"}

CRITERION = {
    "not_objdump_insn_start":
        "判据 = 外部 objdump 未在该地址列指令（不是指令起点）；通常表示该字节落在"
        "上一条指令的操作数/立即数内部，或位于填充/数据。它不等于「不在代码里」，"
        "也不等于「这些字节是数据」。",
    "domain_report":
        "必须同时报 abstain_sites 中落在声明函数域 [entry,end) 内的点数与比例；"
        "未提供 declared_ranges 时该比例为 None，此时不得写「全是数据」。",
}

CAVEATS = [
    "逐字节扫描只找 lead 字节，不产出指令边界；decoded 类不代表整段线性可解",
    "decoder_defect 的判据是 objdump 在同址解出 v* 指令；objdump 自身也可能错，"
    "故每条都附 objdump 文本与字节供复核",
    "not_objdump_insn_start 占多数是预期结果：该地址不是指令起点；"
    "其中可能包含函数体内的操作数字节，必须看 domain.in_domain_ratio 才能解释",
    "分母分 lead_bytes 与 abstain_sites 两层，不可互相替代",
]


def _objdump_maps(path, sec):
    from . import coverage
    obj = coverage.objdump_instructions(path, sec)
    if obj["status"] != "ok":
        return None, obj
    starts = {i["addr"]: i for i in obj["instructions"]}
    return starts, obj


def normalize_ranges(declared_ranges):
    """声明函数域 [(lo,hi)] → 去空、排序后的列表；None 表示未提供。"""
    if declared_ranges is None:
        return None
    rs = sorted((int(lo), int(hi)) for lo, hi in declared_ranges if hi > lo)
    return rs


def _in_domain(ranges, addr):
    import bisect
    i = bisect.bisect_right(ranges, (addr, float("inf"))) - 1
    return i >= 0 and ranges[i][0] <= addr < ranges[i][1]


def domain_accounting(addrs, declared_ranges):
    """把弃权点分成「声明函数域内 / 域外」。

    判据与分类无关：分类只问“是不是 objdump 指令起点”；域内比例回答另一个问题
    “这个非边界字节落在声明的函数体里还是外面”。两者必须同时报。
    """
    rs = normalize_ranges(declared_ranges)
    if rs is None:
        return {"provided": False, "ranges": 0,
                "abstain_in_domain": None, "abstain_out_domain": None,
                "in_domain_ratio": None}
    addrs = list(addrs)
    inside = sum(1 for a in addrs if _in_domain(rs, a))
    return {"provided": True, "ranges": len(rs),
            "abstain_in_domain": inside,
            "abstain_out_domain": len(addrs) - inside,
            "in_domain_ratio": (inside / len(addrs)) if addrs else None}


def classify_one(starts, addr, byte):
    """对一个“我方弃权”的 VEX lead 地址归因。starts 来自外部 objdump。

    只依赖 objdump 指令起点表；不看声明域、不看 recdesc 种子。
    """
    ins = starts.get(addr)
    if ins is None:
        return CAT_NOT_START, {"addr": addr, "byte": byte,
                               "why": "objdump 未在该地址列指令（不是指令起点）"}
    if ins["text"].startswith("(bad)"):
        return CAT_ILLEGAL, {"addr": addr, "byte": byte,
                             "objdump": ins["text"],
                             "why": "objdump 同址也判非法"}
    if ins["text"].startswith("v"):
        return CAT_DECODER_DEFECT, {"addr": addr, "byte": byte,
                                    "objdump": ins["text"],
                                    "why": "objdump 解出合法 VEX/EVEX"}
    return CAT_NONVEX, {"addr": addr, "byte": byte, "objdump": ins["text"],
                        "why": "objdump 在该地址解出非 VEX 指令，需复核"}


def audit(path, section=".text", max_samples=20, declared_ranges=None):
    """逐字节审计节内 C4/C5/62；返回分层计数 + 每类样例 + 域内比例。

    declared_ranges：声明函数域 [(lo,hi)]（与地址同基准）。提供时，报告
    domain.abstain_in_domain / in_domain_ratio；未提供时该比例是 None，
    不代表“全是数据”。域只用于解释，不参与分类。
    """
    from . import coverage, disasm
    sec = disasm.find_section(path, section)
    if sec is None:
        return {"path": path, "section": section, "status": "no_section",
                "lead_bytes": 0, "abstain_sites": 0, "counts": {},
                "domain": domain_accounting([], declared_ranges),
                "criterion": dict(CRITERION),
                "caveats": list(CAVEATS)}
    data = open(path, "rb").read()
    starts, obj = _objdump_maps(path, sec)
    lo, hi = sec["off"], sec["off"] + sec["size"]
    leads = 0
    counts = {}
    samples = {}

    def bump(k, item=None):
        counts[k] = counts.get(k, 0) + 1
        if item is not None and len(samples.setdefault(k, [])) < max_samples:
            samples[k].append(item)

    abstain_sites = 0
    abstain_addrs = []
    for pos in range(lo, hi):
        if data[pos] not in (0xC4, 0xC5, 0x62):
            continue
        leads += 1
        va = sec["va"] + (pos - lo)
        try:
            ln, meta = disasm._decode_any(data, pos, hi)
        except disasm.Unsupported as e:
            if e.category not in VEX_CATEGORIES:
                # 越界/截断/其它：不属于“伪 VEX 弃权”归因对象，单列
                bump("other_abstain:" + e.category,
                     {"addr": va, "byte": data[pos], "reason": e.reason})
                continue
            abstain_sites += 1
            abstain_addrs.append(va)
            if starts is None:
                bump(CAT_NO_OBJDUMP, {"addr": va, "byte": data[pos],
                                      "category": e.category})
                continue
            kind, item = classify_one(starts, va, data[pos])
            item["category"] = e.category
            item["reason"] = e.reason
            item["bytes"] = data[pos:pos + 16].hex(" ")
            bump(kind, item)
            continue
        # 我方解出：与外部 objdump 比长度（仅在 objdump 同址有指令时）
        ref = starts.get(va) if starts is not None else None
        if ref is not None:
            if ref["length"] == ln:
                bump(CAT_DECODED, {"addr": va, "byte": data[pos],
                                   "length": ln, "objdump": ref["text"]})
            else:
                bump(CAT_LEN_DIFF, {"addr": va, "byte": data[pos],
                                    "ours_len": ln, "objdump_len": ref["length"],
                                    "objdump": ref["text"]})
        else:
            bump(CAT_DECODED, {"addr": va, "byte": data[pos], "length": ln,
                               "objdump": None})

    total_classified = sum(counts.values())
    other_abstains = sum(v for k, v in counts.items()
                         if k.startswith("other_abstain:"))
    rep = {
        "path": path, "section": section, "status": "ok",
        "section_bytes": sec["size"],
        "lead_bytes": leads,
        "abstain_sites": abstain_sites,
        "other_abstains": other_abstains,
        "counts": counts,
        "samples": samples,
        "classified": total_classified,
        "domain": domain_accounting(abstain_addrs, declared_ranges),
        "criterion": dict(CRITERION),
        "denominator_scope":
            "lead_bytes = 节内 C4/C5/62 字节数（逐字节）；"
            "abstain_sites = 其中我方按 VEX/EVEX 规则弃权的点数；"
            "objdump = 外部工具同址文本，用于逐条归因",
        "objdump_version": (coverage._objdump_version(coverage.objdump_exe())
                            if obj and coverage.objdump_exe() else None),
        "caveats": list(CAVEATS),
    }
    rep["decoder_defect"] = counts.get(CAT_DECODER_DEFECT, 0)
    rep["illegal_encoding"] = counts.get(CAT_ILLEGAL, 0)
    rep["not_objdump_insn_start"] = counts.get(CAT_NOT_START, 0)
    return rep


def render(rep):
    if rep["status"] != "ok":
        return "文件 %s：%s（分母不适用）" % (rep["path"], rep["status"])
    lines = ["── 伪 VEX/EVEX 弃权归因 ──",
             "文件: %s  节: %s" % (rep["path"], rep["section"]),
             "分母: lead_bytes=%d ｜ abstain_sites=%d ｜ 节字节=%d"
             % (rep["lead_bytes"], rep["abstain_sites"], rep["section_bytes"]),
             "口径: %s" % rep["denominator_scope"],
             "判据: not_objdump_insn_start = 不是 objdump 指令起点；"
             "不等于「数据/不在代码里」"]
    for k in sorted(rep["counts"]):
        lines.append("  %-28s %d" % (k, rep["counts"][k]))
    d = rep.get("domain") or {}
    if d.get("provided"):
        lines.append("域内比例: 声明域 %d 个 ｜ 弃权点在域内 %s / 域外 %s ｜ 域内占比 %s"
                     % (d["ranges"], d["abstain_in_domain"],
                        d["abstain_out_domain"],
                        ("%.4f" % d["in_domain_ratio"])
                        if d["in_domain_ratio"] is not None else "-"))
    else:
        lines.append("域内比例: 未提供 declared_ranges（None）——不得据此写「全是数据」")
    lines.append("判定: decoder_defect=%d ｜ illegal_encoding=%d ｜ not_objdump_insn_start=%d"
                 % (rep["decoder_defect"], rep["illegal_encoding"],
                    rep["not_objdump_insn_start"]))
    return "\n".join(lines)
