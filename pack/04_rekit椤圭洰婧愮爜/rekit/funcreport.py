#!/usr/bin/env python3
# rekit.funcreport — M15 单函数面向人报告层（M16 接入 datarefs）
#
# 定位：只呈现、不判断。把七个既有层（recdesc / expr / callgraph / callfacts /
# strxref / paramdecl / datarefs）对「同一个函数」的记录合成一份报告；本模块不
# 产生任何新的目标、参数、语义或置信度结论，也不新增反汇编。
#
# 三条硬规则（对应验收要求）：
#   1) 每个可证伪条目带 source={layer,field,text}，layer 只能是七个既有层；
#   2) 每段必须给 evidence_state + scope + reason：
#        present           有证据
#        absent_measured   测量范围明确、范围内确实为 0（“确实没有”）
#        missing_source    该类来源整体不存在（“缺证据”）
#        missing_declaration 来源存在但该函数无声明（“缺证据”）
#        missing_decode    该函数无已解出指令，函数域内不可测量（“缺证据”）
#        abstained         有来源但证据不足，已写缺什么（“缺证据”）
#        not_applicable    不适用（仅占位，不滥用）
#   3) 缺失不省略：absence_summary 逐条列出全部非 present 字段。
#
# 层失败语义：任何层调用异常都进 layer_errors，对应段记 missing_source 并写
# 「层调用失败：<类型>: <消息>」；一个层失败不阻断其他层。绝不静默吞错。
#
# 输入对象只读：res/graph/facts/sxref/datarefs 在 build 前后不被写回（测试用
# 哈希校验）。
import argparse
import json
import sys

from . import callfacts as CF
from . import callgraph as CG
from . import datarefs as DR
from . import dotnet as DN
from . import expr
from . import paramdecl as PD
from . import recdesc
from . import strxref as SX

SCHEMA = 2
EVIDENCE_STATES = ("present", "absent_measured", "missing_source",
                   "missing_declaration", "missing_decode", "abstained",
                   "not_applicable")
ALLOWED_LAYERS = ("recdesc", "expr", "callgraph", "callfacts", "strxref",
                  "paramdecl", "datarefs")

SECTION_ORDER = ("identity", "boundary", "blocks_and_edges", "expressions",
                 "calls", "strings_and_data", "parameters")
_SECTION_FIELD = {
    "identity": "function",
    "boundary": "end",
    "blocks_and_edges": "blocks",
    "expressions": "lifted",
    "calls": "call_sites",
    "strings_and_data": "strings",
    "parameters": "own_declaration",
}
EDGE_CLASSES = ("definite", "speculative", "cross_function", "undecoded",
                "unresolved")

CFG_CALL_NOTE = ("recdesc.cfg.calls 只统计块末调用；与 callgraph 的全量调用点"
                 "口径不同，不合并")

CAVEATS = [
    "只呈现、不判断：本层不产生任何新的目标/参数/语义结论，全部引用既有层",
    "缺失显式列出：空白与省略号不用于表示缺失；见 absence_summary",
    "非字符串数据引用来自 datarefs：对象只认声明（ELF 符号 st_size / DWARF "
    "变量），PE COFF 符号与导出表无尺寸字段、只是格式层拒收；对象分母是全文件"
    "的，sites/forms/tiers 只统计本函数，两者不混用",
]


def _src(layer, field, text):
    """来源标注。layer 必须在 ALLOWED_LAYERS 内（测试会断言）。"""
    return {"layer": layer, "field": field, "text": text}


def _section(scope, state="present", reason=None, **extra):
    """统一段构造器：强制 evidence_state/scope/reason 三件套。"""
    if state not in EVIDENCE_STATES:
        raise ValueError("非法 evidence_state: %r" % (state,))
    d = {"evidence_state": state, "scope": scope, "reason": reason}
    d.update(extra)
    return d


def _seed_map(res):
    return {s["addr"]: s for s in res.get("seeds") or []}


def _status_of(res, func_addr, funcs, seeds):
    origins = {i.get("origin") for i in res.get("instructions") or []
               if i.get("origin") is not None}
    if func_addr in origins:
        return "ok", None
    if func_addr in seeds:
        e = seeds[func_addr]
        return ("no_decoded_instructions",
                "地址 0x%x 有种子记录（authority=%s，sources=%s），但递归下降没有"
                "解出任何指令" % (func_addr, e.get("authority"),
                                  ",".join(e.get("sources") or []) or "无"))
    by_addr = {i["addr"]: i for i in res.get("instructions") or []}
    if func_addr in by_addr:
        blk = next((b for b in res.get("blocks") or []
                    if func_addr in b.get("insns") or []), None)
        fn = blk["function"] if blk else None
        return ("not_a_function_start",
                "该地址是函数 0x%x 内部指令（块 0x%x）；本层只报告函数起点，"
                "不把内部地址当函数"
                % (fn or 0, (blk or {}).get("start") or 0))
    sec = res.get("section") or {}
    va, size = sec.get("va", 0), sec.get("size", 0)
    return ("function_not_found",
            "节 %s 范围 [0x%x,0x%x) 内没有函数 0x%x；该节共有已解出函数 %d 个"
            % (sec.get("name"), va, va + size, func_addr, len(funcs)))


# ── 各段构造 ─────────────────────────────────────────────────────────
def _identity_ok(func_addr, fmeta):
    return _section(
        "函数 0x%x 的全部已解出指令与基本块" % func_addr, "present", None,
        addr=func_addr, symbol=fmeta.get("symbol"),
        insns=fmeta.get("insns"), blocks=fmeta.get("blocks"),
        boundary=fmeta.get("boundary"), authority=fmeta.get("authority"),
        sources=[_src("expr", "list_functions",
                      "函数清单由 recdesc 的 origin 聚合：addr/end/boundary/"
                      "authority/symbol/insns/blocks")],
        note=None)


def _identity_missing(func_addr, status, reason):
    return _section(
        "函数 0x%x 的定位结果" % func_addr, "missing_source", reason,
        addr=func_addr, symbol=None, insns=0, blocks=0,
        boundary=None, authority=None, sources=[],
        note="status=%s" % status)


def _boundary(func_addr, seed):
    if seed is None:
        return _section(
            "函数 0x%x 的种子声明（recdesc.seeds）" % func_addr,
            "missing_source",
            "该函数没有种子记录（由 call/jmp 派生发现）；无权威结束声明"
            "（.pdata/FDE/st_size/gopclntab 均未给出结束地址）",
            boundary="unknown", authority="derived", end=None,
            sources=[], end_by_source={}, conflicts=[], declaration_text=[],
            source=[_src("recdesc", "seeds", "该地址不在 recdesc.seeds 中")])
    sources = list(seed.get("sources") or [])
    ebs = dict(seed.get("end_by_source") or {})
    details = list(seed.get("details") or [])
    conflicts = [d for d in details if "end 冲突" in (d or "")]
    end = seed.get("end")
    authority = seed.get("authority")
    if end:
        return _section(
            "函数 0x%x 的种子声明（recdesc.seeds）" % func_addr, "present", None,
            boundary="declared", authority=authority, end=end,
            sources=sources, end_by_source=ebs, conflicts=conflicts,
            declaration_text=details,
            source=[_src("recdesc", "seeds[0x%x]" % func_addr,
                         "authority=%s；sources=%s；end=0x%x"
                         % (authority, ",".join(sources) or "无", end))])
    return _section(
        "函数 0x%x 的种子声明（recdesc.seeds）" % func_addr, "missing_source",
        "无权威结束声明（.pdata/FDE/st_size/gopclntab 均未给出结束地址）；"
        "实际存在的声明来源：%s"
        % (", ".join(sources) if sources else "无（该函数没有种子记录）"),
        boundary="unknown", authority=authority, end=None,
        sources=sources, end_by_source=ebs, conflicts=conflicts,
        declaration_text=details,
        source=[_src("recdesc", "seeds[0x%x]" % func_addr,
                     "authority=%s；sources=%s；end=None"
                     % (authority, ",".join(sources) or "无"))])


def _blocks_and_edges(res, func_addr, note):
    blks = [b for b in res.get("blocks") or [] if b.get("function") == func_addr]
    if not blks:
        return _section(
            "函数 0x%x 的基本块与边" % func_addr, "missing_decode",
            "该函数没有已解出指令", blocks=[],
            edges={c: [] for c in EDGE_CLASSES}, cfg_calls=[], note=note)
    starts = {b["start"] for b in blks}
    ins_set = set()
    for b in blks:
        ins_set.update(b.get("insns") or [])
    blocks = [{
        "addr": b["start"], "start": b["start"], "end": b["end"],
        "insns": len(b.get("insns") or []),
        "insn_addrs": list(b.get("insns") or []),
        "terminator": b.get("terminator"),
        "boundary": b.get("boundary"), "authority": b.get("authority"),
        "range": b.get("range"),
        "source": _src("recdesc", "blocks",
                       "块 0x%x..0x%x，终结符 %s，边界 %s"
                       % (b["start"], b["end"], b.get("terminator"),
                          b.get("boundary"))),
    } for b in blks]
    edges = {}
    for cls in EDGE_CLASSES:
        items = []
        for e in (res.get("cfg") or {}).get("edges", {}).get(cls) or []:
            if e.get("from") not in starts:
                continue
            items.append({
                "addr": e["from"], "from": e["from"], "to": e.get("to"),
                "kind": e.get("kind"), "reason": e.get("reason"),
                "to_function": e.get("to_function"),
                "to_block": e.get("to_block"),
                "source": _src("recdesc", "cfg.edges.%s" % cls,
                               "0x%x -> %s (%s)"
                               % (e["from"],
                                  "0x%x" % e["to"] if e.get("to") is not None
                                  else "None", e.get("kind"))),
            })
        edges[cls] = items
    cfg_calls = []
    for cls, items in ((res.get("cfg") or {}).get("calls") or {}).items():
        for c in items or []:
            if c.get("from") not in ins_set:
                continue
            cfg_calls.append({
                "addr": c["from"], "from": c["from"], "to": c.get("to"),
                "class": cls, "reason": c.get("reason"),
                "source": _src("recdesc", "cfg.calls.%s" % cls,
                               "块末调用 0x%x -> %s"
                               % (c["from"],
                                  "0x%x" % c["to"] if c.get("to") is not None
                                  else "None")),
            })
    return _section(
        "函数 0x%x 的全部基本块与函数内 CFG 边" % func_addr, "present", None,
        blocks=blocks, edges=edges, cfg_calls=cfg_calls, note=note)


def _expressions(res, func_addr, imp):
    try:
        lift = expr.lift_function(res, func_addr, imp)
    except Exception as e:                       # 调用方记 layer_errors
        raise RuntimeError("%s: %s" % (type(e).__name__, e))
    if lift.get("skipped"):
        return _section(
            "函数 0x%x 的表达式恢复" % func_addr, "missing_decode",
            lift["skipped"], stats={}, verdict=None, abstains=[], blocks=[],
            stack_slots=0, text="")
    st = lift.get("stats") or {}
    abstains = []
    for a in lift.get("abstains") or []:
        abstains.append({
            "addr": a.get("addr"), "bytes": a.get("bytes"),
            "reason": a.get("reason"), "missing": a.get("missing"),
            "source": _src("expr", "lift_function.abstains",
                           "0x%x: %s（缺：%s）"
                           % (a.get("addr") or 0, a.get("reason"),
                              a.get("missing"))),
        })
    blocks = [{
        "addr": b.get("start"), "start": b.get("start"), "end": b.get("end"),
        "terminator": b.get("terminator"),
        "body_lines": b.get("body_lines") or [],
        "term_lines": b.get("term_lines") or [],
        "source": _src("expr", "lift_function.blocks",
                       "块 0x%x..0x%x 的伪 C 行（body/term 分片）"
                       % (b.get("start") or 0, b.get("end") or 0)),
    } for b in lift.get("blocks") or []]
    if st.get("insns", 0) == 0:
        return _section(
            "函数 0x%x 的表达式恢复" % func_addr, "missing_decode",
            "该函数没有已解出指令", stats=st, verdict=lift.get("verdict"),
            abstains=abstains, blocks=blocks,
            stack_slots=lift.get("stack_slots") or 0, text=lift.get("text") or "")
    if not abstains:
        return _section(
            "函数 0x%x 的已解出指令（%d 条）" % (func_addr, st.get("insns", 0)),
            "present", None, stats=st, verdict=lift.get("verdict"),
            abstains=[], blocks=blocks,
            stack_slots=lift.get("stack_slots") or 0, text=lift.get("text") or "")
    return _section(
        "函数 0x%x 的已解出指令（%d 条，abstain %d）"
        % (func_addr, st.get("insns", 0), st.get("abstained", 0)),
        "abstained",
        "有 %d 条指令无法恢复表达式；第一条缺：%s"
        % (st.get("abstained", 0), abstains[0].get("missing")),
        stats=st, verdict=lift.get("verdict"), abstains=abstains,
        blocks=blocks, stack_slots=lift.get("stack_slots") or 0,
        text=lift.get("text") or "")


def _calls(graph, facts, res, func_addr, fmeta):
    blks = [b for b in res.get("blocks") or [] if b.get("function") == func_addr]
    ins_set = set()
    for b in blks:
        ins_set.update(b.get("insns") or [])
    cfg_n = 0
    for items in ((res.get("cfg") or {}).get("calls") or {}).values():
        cfg_n += sum(1 for c in items or [] if c.get("from") in ins_set)
    direct, indirect = [], []
    for e in graph.get("edges") or []:
        if e.get("from_fn") != func_addr:
            continue
        direct.append({
            "addr": e["from"], "bytes": e.get("bytes"), "state": e.get("state"),
            "target": e.get("to"), "target_symbol": e.get("target_symbol"),
            "to_section": e.get("to_section"), "evidence": e.get("evidence"),
            "source": _src("callgraph", "edges",
                           "0x%x state=%s target=%s"
                           % (e["from"], e.get("state"),
                              "0x%x" % e["to"] if e.get("to") is not None
                              else "None")),
        })
    for s in facts.get("sites") or []:
        if s.get("function") != func_addr or s.get("call_kind") != "indirect":
            continue
        first = (s.get("abstains") or [{}])[0]
        indirect.append({
            "addr": s["from"], "bytes": s.get("bytes"), "state": "unresolved",
            "target": None, "reason": first.get("missing"),
            "source": _src("callfacts", "sites",
                           "0x%x 间接调用；目标不可静态确定" % s["from"]),
        })
    counts = {k: 0 for k in ("decoded", "plt_or_import", "unresolved")}
    for d in direct:
        if d["state"] in counts:
            counts[d["state"]] += 1
    counts["unresolved"] += len(indirect)
    note = ("调用图三态来自 callgraph；间接调用只在 callfacts 中以 unresolved "
            "单列，不并入确定集；间接候选层默认关闭")
    scope = "函数 0x%x 的全部已解出 call 指令（块末调用 %d 个）" % (func_addr, cfg_n)
    if fmeta and fmeta.get("insns", 0) == 0:
        return _section(scope, "missing_decode", "该函数没有已解出指令",
                        direct=[], indirect=[], counts=counts, note=note)
    if not direct and not indirect and cfg_n == 0:
        return _section(
            scope, "absent_measured",
            "该函数全部 %d 条已解出指令中没有 call 指令（确实没有）"
            % ((fmeta or {}).get("insns") or 0),
            direct=[], indirect=[], counts=counts, note=note)
    if not direct and not indirect and cfg_n > 0:
        return _section(
            scope, "abstained",
            "recdesc 记录 %d 个块末调用，但调用图/事实层没有该函数的站点"
            "（层覆盖缺口）" % cfg_n,
            direct=[], indirect=[], counts=counts, note=note)
    return _section(scope, "present", None, direct=direct, indirect=indirect,
                    counts=counts, note=note)


DR_TIERS = ("object_start", "inside_object", "after_object",
            "data_unattributed", "not_data")
STATIC_FORMS = ("rip_mem", "lea_rip", "abs_mem", "abs_imm")


def _data_refs_empty(reason):
    return {
        "evidence_state": "missing_source",
        "scope": "非字符串数据引用（全局/静态对象）",
        "reason": reason,
        "denominator": None, "objects": [], "sites": [], "tiers": {},
        "forms": {}, "pointer_edges": [], "function_scope": {},
        "sources": [],
    }


def _declaring_sources(dr):
    return [name for name, s in (dr.get("sources") or {}).items()
            if s.get("present") and s.get("readable")
            and s.get("can_declare_size")]


def _fmt_rej(by_rej):
    if not by_rej:
        return "无"
    return ", ".join("%s=%d" % (k, v) for k, v in sorted(by_rej.items()))


def _data_refs(dr, dr_failed, func_addr, fmeta, res):
    """datarefs 报告落到单函数：全局对象分母 + 函数域站点。只读。"""
    if dr_failed:
        return _data_refs_empty("数据引用层调用失败：%s；这不是“没有数据引用”"
                                % dr_failed)
    denom = dr.get("denominator") or {}
    insns = (fmeta or {}).get("insns") or 0
    fn_insn_set = set()
    for b in res.get("blocks") or []:
        if b.get("function") == func_addr:
            fn_insn_set.update(b.get("insns") or [])
    fn_sites = [s for s in dr.get("sites") or []
                if s.get("function") == func_addr]
    data_sites = [s for s in fn_sites if s.get("tier") in DR_TIERS]
    tiers = {k: 0 for k in DR_TIERS}
    forms = {f: 0 for f in DR.FORMS}
    for s in fn_sites:
        if s.get("tier") in tiers:
            tiers[s["tier"]] += 1
        if s.get("form") in forms:
            forms[s["form"]] += 1
    static_sites = [s for s in fn_sites if s.get("form") in STATIC_FORMS]
    hit = {s["object_start"] for s in data_sites
           if s.get("object_start") is not None}
    objs = [o for o in dr.get("objects") or [] if o["start"] in hit]
    edges = [e for e in dr.get("pointer_edges") or []
             if e["to"] in hit
             or any(o["start"] <= e["from"] < o["end"] for o in objs)]
    unlifted = len({u.get("addr") for u in dr.get("unlifted") or []}
                   & fn_insn_set)
    body = {
        "denominator": denom,
        "objects": objs,
        "sites": data_sites,
        "tiers": tiers,
        "forms": forms,
        "pointer_edges": edges,
        "function_scope": {
            "function": func_addr, "insns": insns,
            "classified_sites": len(fn_sites),
            "static_sites": len(static_sites),
            "data_sites": len(data_sites),
            "nonstatic_sites": len(fn_sites) - len(static_sites),
            "unlifted_insns": unlifted,
            "note": "denominator 是全文件对象口径；sites/forms/tiers/"
                    "static_sites 只含该函数已解出指令；objects/pointer_edges "
                    "只列该函数引用到的对象，全量对象见 `rekit datarefs`",
        },
        "sources": [
            _src("datarefs", "denominator",
                 "全文件声明候选 %d，接受 %d，拒收 %d（%s），格式层拒收 %s"
                 % (denom.get("declared_candidates", 0),
                    denom.get("accepted", 0),
                    denom.get("rejected_total", 0),
                    _fmt_rej(denom.get("by_rejection") or {}),
                    _fmt_rej(denom.get("format_rejections") or {}))),
            _src("datarefs", "sites",
                 "函数 0x%x：地址可静态确定的引用点 %d 个，其中指向数据节 %d 个"
                 % (func_addr, len(static_sites), len(data_sites))),
        ],
    }
    scope = "函数 0x%x 的已解出指令 × 全文件声明对象" % func_addr

    def _mk(state, scope_, reason_):
        out = {"evidence_state": state, "scope": scope_, "reason": reason_}
        out.update(body)
        return out

    if not insns:
        return _mk("missing_decode", scope,
                   "该函数没有已解出指令，函数域内不可测量数据引用")
    st = dr.get("status")
    if st == "no_data_sections":
        return _mk("absent_measured", scope,
                   "本文件没有可扫描的数据节；这是“确实没有数据节”，"
                   "不是“没有测量到数据引用”")
    if st == "no_declaration_source":
        return _mk("missing_source", scope,
                   dr.get("reason") or "没有任何能给出尺寸的声明来源")
    if not denom.get("accepted"):
        return _mk(
            "absent_measured", "全文件数据对象（可给尺寸的声明来源：%s）"
            % (",".join(_declaring_sources(dr)) or "无"),
            "声明来源可读，但按 §1.3 接受对象为 0：确实没有可交叉的数据对象；"
            "拒收分类：%s。这是“确实没有可交叉对象”，不是“没有数据引用”"
            % _fmt_rej(denom.get("by_rejection") or {}))
    if not data_sites:
        return _mk(
            "absent_measured", scope,
            "该函数 %d 条已解出指令中，地址可静态确定的 %d 个引用点没有一个"
            "落在数据节（确实没有）；另有不可静态确定形态 %d 个、未解出指令 "
            "%d 条不在该测量范围"
            % (insns, len(static_sites), len(fn_sites) - len(static_sites),
               unlifted))
    return _mk("present", scope, None)


def _strings_and_data(sxref, func_addr, fmeta, dr=None, dr_failed=None,
                      res=None):
    data_refs = _data_refs(dr, dr_failed, func_addr, fmeta, res or {})
    if sxref is None:
        return _section("函数 0x%x 的字符串与数据引用" % func_addr,
                        "missing_source", "字符串层调用失败", strings=[],
                        data_refs=data_refs,
                        scope_note="未取得 strxref 报告")
    detail = {d.get("addr"): d for d in sxref.get("strings_detail") or []}
    sites = [s for s in sxref.get("sites") or []
             if s.get("function") == func_addr]
    seen, strings = {}, []
    for s in sites:
        t = s.get("target")
        d = detail.get(t) or {}
        if t in seen:
            seen[t]["sites"].append(s.get("addr"))
            if s.get("kind") not in seen[t]["kinds"]:
                seen[t]["kinds"].append(s.get("kind"))
            continue
        ent = {
            "addr": t,
            "text": d.get("text"),
            "truncated": d.get("truncated"),
            "section": d.get("section"),
            "sites": [s.get("addr")],
            "kinds": [s.get("kind")],
            "source": [
                _src("strxref", "sites",
                     "0x%x 的 %s 引用字符串 0x%x"
                     % (s.get("addr"), s.get("kind"), t)),
                _src("strxref", "strings_detail",
                     "字符串 0x%x：%r" % (t, d.get("text"))),
            ],
        }
        seen[t] = ent
        strings.append(ent)
    scope = "函数 0x%x 内全部已解出指令覆盖的字符串白名单引用点" % func_addr
    if fmeta and fmeta.get("insns", 0) == 0:
        return _section(scope, "missing_decode", "该函数没有已解出指令",
                        strings=[], data_refs=data_refs,
                        scope_note="字符串识别口径见 strxref.caliber")
    if not strings:
        return _section(
            scope, "absent_measured",
            "该函数全部 %d 条已解出指令引用的字符串白名单条目为 0（确实没有）"
            % ((fmeta or {}).get("insns") or 0),
            strings=[], data_refs=data_refs,
            scope_note="字符串识别口径见 strxref.caliber")
    return _section(scope, "present", None, strings=strings,
                    data_refs=data_refs,
                    scope_note="字符串识别口径见 strxref.caliber")


def _parameters(facts, func_addr, dwarf, pd_failed_reason):
    if dwarf is None:
        reason = ("形参声明层调用失败：%s；这不是 0 个参数"
                  % pd_failed_reason) if pd_failed_reason else (
            "本样本没有可读的形参声明来源（DWARF 不存在/不可读）；"
            "这不是 0 个参数，也不能按 ABI 补齐")
        own = {"evidence_state": "missing_source", "reason": reason,
               "lookup_addr": None, "addr_base": None, "params": []}
    else:
        base = dwarf.get("addr_base") or 0
        lookup = func_addr + base if base and func_addr < base else func_addr
        decl = (dwarf.get("by_low_pc") or {}).get(lookup)
        if decl is None:
            own = {
                "evidence_state": "missing_declaration",
                "reason": "DWARF 中找不到 low_pc=0x%x 的 DW_TAG_subprogram"
                          "（换算：RVA 0x%x + ImageBase 0x%x；无 DW_AT_low_pc "
                          "的声明无法与站点对齐，同样计入此类）"
                          % (lookup, func_addr, base),
                "lookup_addr": lookup, "addr_base": base, "params": [],
            }
        elif not decl.get("params"):
            own = {
                "evidence_state": "absent_measured",
                "reason": "DWARF 明示该子程序 0 个 DW_TAG_formal_parameter"
                          "（确实没有形参）",
                "lookup_addr": lookup, "addr_base": base, "params": [],
            }
        else:
            params = []
            for i, p in enumerate(decl.get("params") or [], 1):
                params.append({
                    "param": i, "name": p.get("name"),
                    "type_off": p.get("type_off"), "die_off": p.get("die_off"),
                    "locator": PD._decl_locator(decl),
                    "source": _src("paramdecl", "dwarf.by_low_pc",
                                   "DIE@0x%x：形参 #%d %r"
                                   % (p.get("die_off") or 0, i, p.get("name"))),
                })
            own = {"evidence_state": "present", "reason": None,
                   "lookup_addr": lookup, "addr_base": base, "params": params}
    callers = [s for s in (facts or {}).get("sites") or []
               if s.get("call_kind") == "direct" and s.get("target") == func_addr]
    bindings, errs = [], []
    for s in callers:
        try:
            b = PD.bind_site(s, dwarf)
        except Exception as e:
            errs.append({"layer": "paramdecl", "stage":
                         "bind_site(0x%x)" % s.get("from"),
                         "reason": "%s: %s" % (type(e).__name__, e)})
            continue
        bindings.append({
            "addr": s.get("from"), "status": b.get("status"),
            "bound": len(b.get("bound") or []),
            "partial": len(b.get("partial") or []),
            "abstains": len(b.get("abstains") or []),
            "params": [{"param": x.get("param"), "name": x.get("name"),
                        "regs": x.get("regs"),
                        "binds": x.get("binds")}
                       for x in (b.get("bound") or [])
                       + (b.get("partial") or [])],
            "missing": [x.get("missing") for x in (b.get("abstains") or [])],
            "source": _src("paramdecl", "bind_site",
                           "调用点 0x%x 的形参绑定 status=%s"
                           % (s.get("from"), b.get("status"))),
        })
    counts = {}
    for b in bindings:
        counts[b["status"]] = counts.get(b["status"], 0) + 1
    note = CF.PARAM_RULE
    if not callers:
        note = note + "；全量直接调用点中没有以该函数为目标的调用，故无调用点绑定"
    return _section(
        "函数 0x%x 的 DWARF 声明（by_low_pc）与全量直接调用点" % func_addr,
        own["evidence_state"], own["reason"],
        own_declaration=own, caller_bindings=bindings,
        counts=counts, note=note), errs


def _empty_sections(reason, scope):
    """非 ok 状态的骨架：键齐全，全部 missing_source 并写同一 reason。"""
    sec = {}
    sec["identity"] = _section(scope, "missing_source", reason, addr=None,
                               symbol=None, insns=0, blocks=0, sources=[],
                               note=None)
    sec["boundary"] = _section(scope, "missing_source", reason, boundary=None,
                               authority=None, end=None, sources=[],
                               end_by_source={}, conflicts=[],
                               declaration_text=[], source=[])
    sec["blocks_and_edges"] = _section(
        scope, "missing_source", reason, blocks=[],
        edges={c: [] for c in EDGE_CLASSES}, cfg_calls=[],
        note=CFG_CALL_NOTE)
    sec["expressions"] = _section(scope, "missing_source", reason, stats={},
                                  verdict=None, abstains=[], blocks=[],
                                  stack_slots=0, text="")
    sec["calls"] = _section(scope, "missing_source", reason, direct=[],
                            indirect=[],
                            counts={k: 0 for k in
                                    ("decoded", "plt_or_import", "unresolved")},
                            note="未建立函数域，无调用证据")
    sec["strings_and_data"] = _section(
        scope, "missing_source", reason, strings=[],
        data_refs=_data_refs_empty("未建立函数域，未取数据引用层"),
        scope_note="未取得 strxref 报告")
    sec["parameters"] = _section(
        scope, "missing_source", reason,
        own_declaration={"evidence_state": "missing_source", "reason": reason,
                         "lookup_addr": None, "addr_base": None, "params": []},
        caller_bindings=[], counts={}, note="未建立函数域，未取形参声明层")
    return sec


def _caveats():
    mapping = [("recdesc", getattr(recdesc, "CAVEATS", [])),
               ("expr", getattr(expr, "CAVEATS", [])),
               ("callgraph", getattr(CG, "CAVEATS", [])),
               ("callfacts", getattr(CF, "CAVEATS", [])),
               ("strxref", getattr(SX, "CAVEATS", [])),
               ("paramdecl", getattr(PD, "CAVEATS", [])),
               ("datarefs", getattr(DR, "CAVEATS", []))]
    caveats, layer_caveats = [], {}
    for layer, items in mapping:
        seen, keep = set(), []
        for t in items or []:
            if t in seen:
                continue
            seen.add(t)
            keep.append(t)
            caveats.append({"layer": layer, "text": t})
        layer_caveats[layer] = keep
    for t in CAVEATS:
        caveats.append({"layer": "funcreport", "text": t})
    layer_caveats["funcreport"] = list(CAVEATS)
    return caveats, layer_caveats


def _absence(sections):
    rows = []
    for name in SECTION_ORDER:
        s = sections[name]
        if s["evidence_state"] != "present":
            rows.append({
                "section": name, "field": _SECTION_FIELD[name],
                "evidence_state": s["evidence_state"],
                "scope": s["scope"], "reason": s["reason"],
            })
    dr = (sections.get("strings_and_data") or {}).get("data_refs")
    if dr and dr.get("evidence_state") != "present":
        rows.append({
            "section": "strings_and_data", "field": "data_refs",
            "evidence_state": dr["evidence_state"],
            "scope": dr["scope"], "reason": dr["reason"],
        })
    order = {n: i for i, n in enumerate(SECTION_ORDER)}
    rows.sort(key=lambda r: (order.get(r["section"], 99), r["field"]))
    return rows


def _report(path, section, func_addr, status, sections, layer_errors):
    caveats, layer_caveats = _caveats()
    return {
        "schema": SCHEMA,
        "status": status,
        "path": str(path),
        "section": section,
        "function": {"addr": func_addr,
                     "symbol": (sections["identity"] or {}).get("symbol")},
        "sections": sections,
        "caveats": caveats,
        "absence_summary": _absence(sections),
        "layer_caveats": layer_caveats,
        "layer_errors": layer_errors,
        "read_only": {
            "layers": list(ALLOWED_LAYERS),
            "note": "本模块不写回任何一层；有副作用即违约",
        },
    }


# ── 构建 ────────────────────────────────────────────────────────────
def _dotnet_reason(path, probe):
    return (
        "该文件是 .NET 程序集（PE DataDirectory[14] 非空，CLI 头 RVA=0x%x）："
        "方法体是 CLI 字节码，不是 x86 指令。funcreport 的六层"
        "（recdesc/expr/callgraph/callfacts/strxref/datarefs/paramdecl）"
        "建立在 x86 指令与 DWARF 上，对该文件不适用。这不是“没有函数”，"
        "也不是“没有代码”；请用 `rekit dotnet %s` 查看类型/方法/方法体/IL 边界。"
        % ((probe or {}).get("cli_rva") or 0, path))


def build(path, func_addr, section=".text", res=None, graph=None, facts=None,
          sxref=None, dwarf=None, datarefs_rep=None):
    """合成单函数报告。res/graph/facts/sxref/dwarf/datarefs_rep 可注入，只读。"""
    layer_errors = []
    probe = None
    try:
        probe = DN.probe(path)
    except Exception:
        probe = None
    if probe and probe.get("is_cli"):
        reason = _dotnet_reason(path, probe)
        sections = _empty_sections(reason, "函数 0x%x 的定位结果" % func_addr)
        sections["identity"] = _identity_missing(func_addr, "not_applicable",
                                                 reason)
        return _report(path, section, func_addr, "not_applicable", sections, [])
    res = recdesc.descend(path, section) if res is None else res
    funcs = expr.list_functions(res)
    fmeta = next((f for f in funcs if f["addr"] == func_addr), None)
    seeds = _seed_map(res)
    status, status_reason = _status_of(res, func_addr, funcs, seeds)

    if status != "ok":
        sections = _empty_sections(status_reason, "函数 0x%x 的定位结果"
                                  % func_addr)
        sections["identity"] = _identity_missing(func_addr, status,
                                                 status_reason)
        return _report(path, section, func_addr, status, sections, layer_errors)

    if graph is None:
        try:
            graph = CG.build(path, section, res=res)
        except Exception as e:
            note = {"layer": "callgraph", "stage": "build",
                    "reason": "%s: %s" % (type(e).__name__, e)}
            layer_errors.append(note)
            graph = None
    if facts is None:
        try:
            facts = CF.build(path, section, res=res, graph=graph)
        except Exception as e:
            note = {"layer": "callfacts", "stage": "build",
                    "reason": "%s: %s" % (type(e).__name__, e)}
            layer_errors.append(note)
            facts = None
    if sxref is None:
        try:
            sxref = SX.build(path, section, res=res, facts=facts, graph=graph)
        except Exception as e:
            note = {"layer": "strxref", "stage": "build",
                    "reason": "%s: %s" % (type(e).__name__, e)}
            layer_errors.append(note)
            sxref = None

    pd_failed = None
    if dwarf is None:
        try:
            dwarf = PD.read(path).get("dwarf")
        except Exception as e:
            pd_failed = "%s: %s" % (type(e).__name__, e)
            layer_errors.append({"layer": "paramdecl", "stage": "read",
                                 "reason": pd_failed})
            dwarf = None

    dr_failed = None
    if datarefs_rep is None:
        try:
            datarefs_rep = DR.build(path, section, res=res, dwarf=dwarf)
        except Exception as e:
            dr_failed = "%s: %s" % (type(e).__name__, e)
            layer_errors.append({"layer": "datarefs", "stage": "build",
                                 "reason": dr_failed})
            datarefs_rep = None

    try:
        imp = expr._import_names(path)
    except Exception:
        imp = {}

    sections = {}
    sections["identity"] = _identity_ok(func_addr, fmeta)
    sections["boundary"] = _boundary(func_addr, seeds.get(func_addr))
    note = (graph or {}).get("cfg_call_note") or CFG_CALL_NOTE
    sections["blocks_and_edges"] = _blocks_and_edges(res, func_addr, note)
    try:
        sections["expressions"] = _expressions(res, func_addr, imp)
    except Exception as e:
        sections["expressions"] = _section(
            "函数 0x%x 的表达式恢复" % func_addr, "missing_source",
            "表达式层调用失败：%s: %s" % (type(e).__name__, e),
            stats={}, verdict=None, abstains=[], blocks=[], stack_slots=0,
            text="")
    if graph is None:
        sections["calls"] = _section(
            "函数 0x%x 的调用点" % func_addr, "missing_source",
            "调用图层调用失败（见 layer_errors）", direct=[], indirect=[],
            counts={k: 0 for k in
                    ("decoded", "plt_or_import", "unresolved")},
            note="未取得 callgraph 报告")
        if facts is not None:
            sections["calls"]["note"] += "；事实层已有报告，但无 graph 时不单独列三态"
    else:
        sections["calls"] = _calls(graph, facts or {}, res, func_addr, fmeta)
    sections["strings_and_data"] = _strings_and_data(
        sxref, func_addr, fmeta, datarefs_rep, dr_failed, res)
    params, errs = _parameters(facts, func_addr, dwarf, pd_failed)
    layer_errors.extend(errs)
    sections["parameters"] = params
    return _report(path, section, func_addr, "ok", sections, layer_errors)


def build_selection(path, section=".text", limit=20, res=None):
    """未指定 --func：列出候选，不猜默认函数。"""
    try:
        probe = DN.probe(path)
    except Exception:
        probe = None
    if probe and probe.get("is_cli"):
        reason = _dotnet_reason(path, probe)
        sections = _empty_sections(reason, "节 %s 的函数清单" % section)
        return _report(path, section, None, "not_applicable", sections, [])
    res = recdesc.descend(path, section) if res is None else res
    funcs = expr.list_functions(res)
    scope = "节 %s 的函数清单（expr.list_functions）" % section
    cands = [{
        "addr": f["addr"], "symbol": f["symbol"], "boundary": f["boundary"],
        "authority": f["authority"], "insns": f["insns"],
        "blocks": f["blocks"],
        "source": _src("expr", "list_functions",
                       "函数 0x%x %s，%d 条指令"
                       % (f["addr"], f["symbol"] or "(无符号)", f["insns"])),
    } for f in funcs[:limit]]
    sections = _empty_sections(
        "未指定 --func：本报告没有选择函数，因此没有该函数的证据",
        "未建立函数域（function_not_specified）")
    sections["identity"] = _section(
        scope, "present", None, addr=None, symbol=None,
        insns=None, blocks=None, boundary=None, authority=None,
        sources=[_src("expr", "list_functions",
                      "共 %d 个已解出函数；下面只显示前 %d 个"
                      % (len(funcs), len(cands)))],
        candidates=cands,
        note="请用 --func <HEX> 指定函数；本层不猜默认函数")
    return _report(path, section, None, "function_not_specified", sections, [])


# ── 渲染（只读 report dict）─────────────────────────────────────────
def _tag(srcs):
    if not srcs:
        return ""
    return " [%s]" % ";".join("%s:%s" % (s.get("layer"), s.get("field"))
                              for s in srcs if isinstance(s, dict))


def _shown(n, total):
    return "显示 %d / 共 %d" % (n, total)


def _render_section(name, s, limit):
    out = []
    if name == "identity":
        out.append("  addr=0x%x  symbol=%s  指令=%s  块=%s  边界=%s  权威=%s%s"
                   % (s.get("addr") or 0, s.get("symbol"),
                      s.get("insns"), s.get("blocks"), s.get("boundary"),
                      s.get("authority"), _tag(s.get("sources"))))
        if s.get("note"):
            out.append("  note: %s" % s["note"])
        for c in (s.get("candidates") or [])[:limit]:
            out.append("  候选 0x%06x  %-28s 边界=%s 权威=%s 指令=%d%s"
                       % (c["addr"], c.get("symbol") or "(无符号)",
                          c.get("boundary"), c.get("authority"),
                          c.get("insns"), _tag([c.get("source")])))
        cands = s.get("candidates") or []
        if len(cands) > limit:
            out.append("  " + _shown(limit, len(cands)) + " 个候选")
    elif name == "boundary":
        out.append("  boundary=%s  authority=%s  end=%s%s"
                   % (s.get("boundary"), s.get("authority"),
                      "0x%x" % s["end"] if s.get("end") else "None",
                      _tag(s.get("source"))))
        if s.get("sources"):
            out.append("  声明来源: %s" % ",".join(s["sources"]))
        for k, v in (s.get("end_by_source") or {}).items():
            out.append("    end_by_source[%s] = 0x%x" % (k, v))
        for c in (s.get("conflicts") or [])[:limit]:
            out.append("    end 冲突: %s" % c)
    elif name == "blocks_and_edges":
        for b in (s.get("blocks") or [])[:limit]:
            out.append("  块 0x%06x..0x%06x  指令=%d  终结=%s  边界=%s%s"
                       % (b["start"], b["end"], b["insns"], b["terminator"],
                          b["boundary"], _tag([b.get("source")])))
        if len(s.get("blocks") or []) > limit:
            out.append("  " + _shown(limit, len(s.get("blocks"))))
        for cls in EDGE_CLASSES:
            items = (s.get("edges") or {}).get(cls) or []
            out.append("  边[%s] = %d" % (cls, len(items)))
            for e in items[:limit]:
                out.append("    0x%06x -> %s (%s)%s"
                           % (e["from"],
                              "0x%x" % e["to"] if e.get("to") is not None
                              else "None", e.get("kind"),
                              _tag([e.get("source")])))
            if len(items) > limit:
                out.append("    " + _shown(limit, len(items)))
        if s.get("cfg_calls"):
            out.append("  cfg 块末调用 = %d%s"
                       % (len(s["cfg_calls"]), _tag([s["cfg_calls"][0].get("source")])))
            for c in s["cfg_calls"][:limit]:
                out.append("    0x%06x -> %s [%s]"
                           % (c["from"],
                              "0x%x" % c["to"] if c.get("to") is not None
                              else "None", c.get("class")))
        if s.get("note"):
            out.append("  note: %s" % s["note"])
    elif name == "expressions":
        st = s.get("stats") or {}
        if st:
            out.append("  指令=%s 已提升=%s abstain=%s 语句=%s 弃权率=%s verdict=%s"
                       % (st.get("insns"), st.get("lifted"),
                          st.get("abstained"), st.get("statements"),
                          st.get("abstain_ratio"), s.get("verdict")))
        for a in (s.get("abstains") or [])[:limit]:
            out.append("  abstain 0x%06x %s：%s（缺：%s）%s"
                       % (a.get("addr") or 0, a.get("bytes"), a.get("reason"),
                          a.get("missing"), _tag([a.get("source")])))
        if len(s.get("abstains") or []) > limit:
            out.append("  " + _shown(limit, len(s["abstains"])))
        for b in (s.get("blocks") or [])[:limit]:
            out.append("  L_0x%x:" % b["start"])
            for ln in b.get("body_lines") or []:
                out.append("    " + ln)
            for ln in b.get("term_lines") or []:
                out.append("    " + ln)
        if len(s.get("blocks") or []) > limit:
            out.append("  " + _shown(limit, len(s["blocks"])) + " 个块")
        out.append("  stack_slots=%s" % s.get("stack_slots"))
    elif name == "calls":
        c = s.get("counts") or {}
        out.append("  三态 decoded=%s plt_or_import=%s unresolved=%s"
                   % (c.get("decoded"), c.get("plt_or_import"),
                      c.get("unresolved")))
        for d in (s.get("direct") or [])[:limit]:
            out.append("  直接 0x%06x -> %s state=%s%s"
                       % (d["addr"],
                          "0x%x" % d["target"] if d.get("target") is not None
                          else "None", d.get("state"),
                          _tag([d.get("source")])))
        if len(s.get("direct") or []) > limit:
            out.append("  " + _shown(limit, len(s["direct"])) + " 个直接调用")
        for d in (s.get("indirect") or [])[:limit]:
            out.append("  间接 0x%06x state=unresolved 缺：%s%s"
                       % (d["addr"], d.get("reason") or "(未给原因)",
                          _tag([d.get("source")])))
        if len(s.get("indirect") or []) > limit:
            out.append("  " + _shown(limit, len(s["indirect"])) + " 个间接调用")
        out.append("  note: %s" % s.get("note"))
    elif name == "strings_and_data":
        for x in (s.get("strings") or [])[:limit]:
            out.append("  字符串 0x%06x %r  引用点=%s  类型=%s%s"
                       % (x["addr"], x.get("text"),
                          ",".join("0x%x" % a for a in x.get("sites") or []),
                          ",".join(x.get("kinds") or []),
                          _tag(x.get("source"))))
        if len(s.get("strings") or []) > limit:
            out.append("  " + _shown(limit, len(s["strings"])) + " 个字符串")
        dr = s.get("data_refs") or {}
        out.append("  非字符串数据引用: 状态=%s 范围=%s"
                   % (dr.get("evidence_state"), dr.get("scope")))
        if dr.get("evidence_state") != "present":
            label = ("确实没有" if dr.get("evidence_state") == "absent_measured"
                     else "缺")
            out.append("    %s：%s" % (label, dr.get("reason")))
        den = dr.get("denominator") or {}
        if den:
            fmt = den.get("format_rejections") or {}
            out.append("    分母：声明候选=%s 接受=%s 拒收=%s 去重=%s "
                       "有代码引用=%s 有指针槽=%s 无引用=%s 比例=%s"
                       % (den.get("declared_candidates"), den.get("accepted"),
                          den.get("rejected_total"), den.get("duplicates"),
                          den.get("with_code_ref"), den.get("with_pointer_edge"),
                          den.get("without_ref"),
                          ("-（accepted=0）"
                           if den.get("object_code_ref_ratio") is None
                           else "%.6f" % den["object_code_ref_ratio"])))
            out.append("    拒收分类：%s"
                       % (", ".join("%s=%d" % (k, v) for k, v in
                                    sorted((den.get("by_rejection") or {}).items()))
                          or "无"))
            out.append("    格式层拒收（无尺寸字段，不进对象分母）：coff_symbols=%s"
                       " export_table=%s"
                       % (fmt.get("coff_symbols", 0), fmt.get("export_table", 0)))
        for o in (dr.get("objects") or [])[:limit]:
            out.append("    对象 %r [0x%06x,0x%06x) size=%d 节=%s 声明=%s%s"
                       % (o.get("name"), o["start"], o["end"], o["size"],
                          o.get("section"), o.get("declaration"),
                          _tag(o.get("sources"))))
        if len(dr.get("objects") or []) > limit:
            out.append("    " + _shown(limit, len(dr.get("objects"))) + " 个对象")
        for x in (dr.get("sites") or [])[:limit]:
            out.append("    引用点 0x%06x %-8s 形态=%-10s 目标=0x%x 档=%s 对象=%r "
                       "offset=%s"
                       % (x.get("addr") or 0, x.get("mnem"), x.get("form"),
                          x.get("target") or 0, x.get("tier"),
                          x.get("object_name"), x.get("offset")))
            if x.get("arith"):
                out.append("      %s" % x["arith"])
        if len(dr.get("sites") or []) > limit:
            out.append("    " + _shown(limit, len(dr.get("sites"))) + " 个引用点")
        if dr.get("tiers"):
            out.append("    分档：%s" % " ".join(
                "%s=%d" % (k, v) for k, v in dr["tiers"].items()))
        for e in (dr.get("pointer_edges") or [])[:limit]:
            out.append("    指针槽 0x%06x -> 对象 %r 首地址 0x%x（宽 %d）"
                       % (e["from"], e.get("object_name"), e["to"],
                          e.get("width") or 0))
        fs = dr.get("function_scope") or {}
        if fs:
            out.append("    函数域：指令=%s 静态引用点=%s 指向数据节=%s "
                       "不可静态确定=%s 未解出=%s"
                       % (fs.get("insns"), fs.get("static_sites"),
                          fs.get("data_sites"), fs.get("nonstatic_sites"),
                          fs.get("unlifted_insns")))
            out.append("    口径：%s" % fs.get("note"))
        if s.get("scope_note"):
            out.append("  note: %s" % s["scope_note"])
    elif name == "parameters":
        own = s.get("own_declaration") or {}
        out.append("  自身声明: 状态=%s  params=%d  lookup=%s%s"
                   % (own.get("evidence_state"), len(own.get("params") or []),
                      "0x%x" % own["lookup_addr"]
                      if own.get("lookup_addr") is not None else "None",
                      _tag([p.get("source")
                            for p in own.get("params") or []])))
        if own.get("evidence_state") != "present":
            out.append("  自身声明：%s（原因见上方“缺：”行）"
                       % own.get("evidence_state"))
        for p in (own.get("params") or [])[:limit]:
            out.append("    形参 #%d %-12s type_off=%s die=0x%x"
                       % (p["param"], p.get("name"), p.get("type_off"),
                          p.get("die_off") or 0))
        bind = s.get("caller_bindings") or []
        out.append("  调用点绑定: 站点=%d  %s"
                   % (len(bind),
                      " ".join("%s=%d" % (k, v)
                               for k, v in sorted((s.get("counts") or {}).items()))
                      or "无"))
        for b in bind[:limit]:
            out.append("    0x%06x status=%s bound=%d partial=%d abstains=%d%s"
                       % (b["addr"], b.get("status"), b.get("bound"), b.get("partial"),
                          b.get("abstains"), _tag([b.get("source")])))
        if len(bind) > limit:
            out.append("    " + _shown(limit, len(bind)) + " 个站点")
        out.append("  note: %s" % s.get("note"))
    return out


def render(report, limit=8):
    """人读渲染：只读 report dict，与 JSON 同源。"""
    out = []
    fn = report.get("function") or {}
    out.append("== rekit funcreport ==")
    out.append("文件: %s  节: %s" % (report.get("path"), report.get("section")))
    out.append("函数: %s  状态=%s"
               % ("0x%x" % fn["addr"] if fn.get("addr") is not None
                  else "(未指定)", report.get("status")))
    for name in SECTION_ORDER:
        s = report["sections"][name]
        out.append("")
        out.append("== %s ==  状态=%s  范围=%s"
                   % (name, s.get("evidence_state"), s.get("scope")))
        if s.get("evidence_state") == "absent_measured":
            out.append("确实没有：%s" % (s.get("reason") or "(未给测量结论，这是缺陷)"))
        elif s.get("evidence_state") != "present":
            out.append("缺：%s" % (s.get("reason") or "(未给原因，这是缺陷)"))
        out.extend(_render_section(name, s, limit))
    out.append("")
    out.append("== absence_summary ==  共 %d 条"
               % len(report.get("absence_summary") or []))
    for r in report.get("absence_summary") or []:
        label = "确实没有" if r["evidence_state"] == "absent_measured" else "缺"
        out.append("  [%s/%s] %s 范围=%s %s：%s"
                   % (r["section"], r["field"], r["evidence_state"],
                      r["scope"], label, r["reason"]))
    if report.get("layer_errors"):
        out.append("")
        out.append("== layer_errors ==  共 %d 条"
                   % len(report["layer_errors"]))
        for e in report["layer_errors"]:
            out.append("  [%s/%s] %s" % (e["layer"], e["stage"], e["reason"]))
    out.append("")
    out.append("== caveats ==  共 %d 条（逐层原文）"
               % len(report.get("caveats") or []))
    for c in report.get("caveats") or []:
        out.append("  [%s] %s" % (c["layer"], c["text"]))
    return "\n".join(out)


# ── CLI ─────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rekit funcreport",
        description="M15 单函数报告：合成六层既有结果，只呈现、不判断")
    ap.add_argument("file")
    ap.add_argument("--func", help="函数起始地址（HEX，支持 0x 前缀）")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=8)
    args = ap.parse_args(argv)
    addr = None
    if args.func is not None:
        try:
            addr = int(args.func, 0)
        except ValueError:
            print("rekit: --func %r: 不是合法地址（例：0x401320）"
                  % args.func, file=sys.stderr)
            return 2
    try:
        if addr is None:
            rep = build_selection(args.file, args.section, max(args.limit, 1))
        else:
            rep = build(args.file, addr, args.section)
    except OSError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except Exception as e:
        print("rekit: %s: 解析失败(%s: %s)"
              % (args.file, type(e).__name__, e), file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(render(rep, args.limit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
