#!/usr/bin/env python3
# rekit.sitejoin — M7-U1 三层拼接（调用图 / 参数事实层 / 结构化文本）
#
# 目标只有一个：把「同一个调用点」在三层的记录对齐，并把三处结论不一致的地方
# **单列**。本模块不产生任何新判断，也不修正任何一层：
#   - 不推断 ABI / 参数个数 / 参数名（沿用 M6 禁令）；
#   - 不追跨块数据流；
#   - 只读：graph / facts / struct 的报告对象只被读取，绝不写回（有副作用即违约）。
#
# 对齐键（唯一且可解释）：
#   主键 = 调用指令的虚拟地址（`from`）。理由：recdesc 的指令边界按地址唯一确定，
#   三层都从同一份 recdesc 结果出发，因此地址是唯一能不依赖任何一层文本格式的键。
#   风险：若同一地址出现在两个块（recdesc 允许 overlaps），键会重复——此时不合并、
#   不取其一，直接报 `duplicate_key`（data_anomaly），要求回 recdesc 复核。
#
#   结构化文本这一层没有指令地址（`expr` 的语句行不带 addr），只有块号与行文本，
#   所以结构化侧的定位键是 **(函数, 块起始地址) + 块内第 j 个调用**：
#     j 由「本块已解出 call 按地址排序」的顺序确定（与调用图/事实层同源，而不是
#     用事实层的站点，否则下层漏 call 会连带把文本行号错位）；
#     行序 = 调用语句行 + 指向 call 指令的 abstain 注释行（调用可作为块终结指令，
#     故 body 与 term 两段都要看）；三重机械校验：
#       ① 块内行数 == 块内已解出 call 数
#       ② 直接调用的文本目标 `sub_0x…` == 事实层 target
#       ③ 行号落在 body 还是 term 有切片标注
#     校验不过就报冲突，不猜行号。
#
#   键覆盖另有一道独立账：本模块自己从已解出指令里枚举 call（按「跳空前缀后的
#   opcode」判定，不复用下层那套 e8/ff 首字节过滤），任何一条 call 在两层里都没有
#   记录即报 `call_site_missing`。实测由此发现下层漏 call（见 TASK_m7u1_join.md §6）。
#
# 冲突归因（三类，逐条写在冲突记录里）：
#   layer_bug         —— 两层对同一事实给出不同结论，至少一层有误；按 R63 不以任何
#                        一方为准，单列待查（不静默丢弃、不取其一）；
#   caliber_difference—— 各层口径本就不同（覆盖范围/粒度），不是错误，单列解释；
#   data_anomaly      —— 输入数据异常（同一地址多个块），需回 recdesc 复核。
import argparse
import json
import re
import sys

from . import expr, recdesc, callfacts as CF, callgraph as CG, struct as S

KEY_RULE = ("主键 = 调用指令虚拟地址（from）；结构化侧用 (函数, 块起始) + "
            "块内第 j 个调用定位，j 按本块已解出 call 的地址顺序确定")

ATTRIBUTION = {
    "layer_bug": "两层对同一事实结论不同，至少一层有误；不以任何一方为准，单列待查",
    "caliber_difference": "各层覆盖范围/粒度本就不同，不是错误；单列说明",
    "data_anomaly": "输入数据异常（同一地址出现在多个块），需回 recdesc 复核",
}

_KIND_ATTR = {
    "duplicate_key": "data_anomaly",
    "function_mismatch": "layer_bug",
    "state_mismatch": "layer_bug",
    "target_mismatch": "layer_bug",
    "graph_edge_missing": "layer_bug",
    "facts_site_missing": "layer_bug",
    "operand_declared": "layer_bug",
    "struct_block_missing": "layer_bug",
    "struct_line_unmatched": "layer_bug",
    "struct_line_target": "layer_bug",
    "struct_line_count_mismatch": "layer_bug",
    "struct_function_absent": "caliber_difference",
    "struct_block_unreachable": "caliber_difference",
    "struct_abstain_line": "caliber_difference",
    "call_site_missing": "layer_bug",
    "facts_site_not_call": "layer_bug",
    "graph_edge_not_call": "layer_bug",
}

CAVEATS = [
    "只拼接、不判断：不产生新的目标/参数结论，只把三层的既有记录按调用地址对齐",
    "只读：graph / facts / struct 报告对象不被写回；任何副作用都视为违约",
    "结构化文本不含指令地址：结构化侧定位到 (函数, 块) + 块内第 j 个调用，"
    "j 用本块已解出 call 的地址顺序 + 行数 + 目标文本三重校验，失败即报冲突",
    "键覆盖由本模块独立枚举 call 核对：M7-U2 起下层 `_call_insns` 已按「跳前缀后"
    "的 opcode + ModRM.reg」判定，三样本缺口为 0；若再出现 call_site_missing，"
    "归因 layer_bug 单列，不以任何一层为准",
    "结构化层默认只覆盖 declared 函数：未声明函数/不可达块的缺失记为口径差异，"
    "不是冲突（不当成 bug，也不静默丢弃）",
    "间接调用在调用图里没有确定边（候选层默认关闭）：图侧记 indirect，不算冲突",
    "不推断 ABI、不猜参数个数与名称；本模块不新增任何参数语义",
]


def _dup_map(items, key):
    seen, dup = {}, {}
    for it in items:
        k = it.get(key)
        if k in seen:
            dup.setdefault(k, [seen[k]]).append(it)
        else:
            seen[k] = it
    return seen, dup


def _walk_blocks(node, acc):
    """收集结构化树里的块节点：{块起始: 节点}（同一块只应出现一次）。"""
    if isinstance(node, dict):
        if "block" in node and "lines" in node:
            acc.setdefault(node["block"], node)
        for k in ("children", "then", "else", "body", "inner"):
            _walk_blocks(node.get(k), acc)
    elif isinstance(node, list):
        for x in node:
            _walk_blocks(x, acc)


def struct_index(res, funcs, include_inferred=False):
    """按函数建立结构化索引：{函数地址: {status, blocks, unreachable, ...}}。

    只调用既有结构层（`structure_function`），不修改其返回值；status 取值：
      ok / not_declared / no_decoded_instructions / no_function

    C2：这里原来用 "skipped"，与 switchcand 的“预算跳过”同名不同义。本分支的真实
    含义是“该函数没有已解出指令”，故改名为 no_decoded_instructions（自解释）。
    """
    decl = {f["addr"]: f for f in expr.list_functions(res)}
    out = {}
    for fn in funcs:
        if fn is None or fn not in decl:
            out[fn] = {"status": "no_function"}
            continue
        meta = decl[fn]
        if meta["boundary"] != "declared" and not include_inferred:
            out[fn] = {"status": "not_declared"}
            continue
        lifted = expr.lift_function(res, fn)
        if lifted.get("skipped"):
            out[fn] = {"status": "no_decoded_instructions",
                       "detail": lifted["skipped"]}
            continue
        rep = S.structure_function(res, fn, lifted=lifted)
        blocks = {}
        _walk_blocks(rep["tree"], blocks)
        out[fn] = {"status": "ok", "blocks": blocks,
                   "unreachable": set(rep["stats"].get("unreachable") or []),
                   "violations": rep["violations"],
                   "symbol": rep.get("symbol")}
    return out


def _text_lines(node):
    """块节点的可读语句行 = body 行 + term 行（调用可以是块终结指令）。

    返回 (拼接后的行, body 行数)，便于把行号换算回 body/term 切片。
    """
    body = node.get("lines") or []
    term = node.get("term") or []
    return list(body) + list(term), len(body)


def _slice(idx, nbody):
    """行号属于 body 切片还是 term 切片（结构化节点两个列表分别渲染）。"""
    return "body" if idx < nbody else "term"


def _is_call_line(ln):
    """判断一行是否是 call 语句（不是 pop/syscall/__halt 之类 intrinsic）。

    依据 expr 的渲染模板（见 expr._call_text 与 _statements）：
      sub_0x<hex>(); / dll!name(); / (*...)( ); / (*unknown)();
    排除 `x = pop();`、`rsp = rbp; rbp = pop();`、`__int3();`、`syscall()`。
    """
    s = ln.strip()
    if "();" not in s:
        return False
    if s.startswith("(*"):
        return True
    head = s.split("(", 1)[0].strip()
    if not head or not re.match(r"^[A-Za-z_?$@][\w@.$?!\-]*$", head):
        return False
    if head.startswith("__") or head == "syscall":
        return False
    return True


_ABST_RE = re.compile(r"/\* abstain @0x([0-9a-f]+)")
_PREFIX = {0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3}


def _opcode_of(raw):
    """跳过前缀（含 REX 0x40..0x4f）后的第一个 opcode 字节；返回 (opcode, 前缀字节数)。

    `raw` 是去空格的十六进制串（每字节两位）。
    """
    i = 0
    while 2 * i + 2 <= len(raw):
        b = int(raw[2 * i:2 * i + 2], 16)
        if b in _PREFIX or 0x40 <= b <= 0x4f:
            i += 1
            continue
        return b, i
    return None, i


def _decoded_calls(res):
    """从已解出指令里独立枚举 call，作为对齐键的「应然全集」。

    刻意保留与调用图不同的代码路径（M7-U2 前 `_call_insns` 按首字节 `e8/ff`
    过滤，带前缀的 call 被漏；现已同口径修正）：两边独立重算，任一侧退化都会被
    对账发现，避免「同一份枚举互相背书」。
    """
    blk_of = {}
    for b in res.get("blocks") or []:
        for a in b.get("insns") or []:
            blk_of[a] = b
    out = {}
    for ins in res.get("instructions") or []:
        raw = (ins.get("bytes") or "").replace(" ", "")
        op, _n = _opcode_of(raw)
        if op not in (0xe8, 0xff):
            continue
        try:
            rec = expr.decode(ins)
        except expr.LiftError:
            continue
        if rec.get("family") != "call":
            continue
        blk = blk_of.get(ins["addr"]) or {}
        out[ins["addr"]] = {"bytes": ins["bytes"],
                            "block": blk.get("start"),
                            "function": blk.get("function"),
                            "target": rec.get("target")}
    return out


def _slots(node, addr_set):
    """块内与调用一一对应的行序列：[(kind, 行号, 地址|None, 行文本)]。

    kind='stmt'    调用语句行（`sub_0x…();` / `(*… )();`）；
    kind='abstain' `/* abstain @0x… */` 注释行，只收地址属于本块已解出 call
                    集合的那些，避免把非调用指令的 abstain 注释算进来。
    """
    lines, nbody = _text_lines(node)
    out = []
    for i, ln in enumerate(lines):
        if _is_call_line(ln):
            out.append(("stmt", i, None, ln))
            continue
        m = _ABST_RE.search(ln)
        if m and int(m.group(1), 16) in addr_set:
            out.append(("abstain", i, int(m.group(1), 16), ln))
    return out, lines, nbody


def _struct_side(site, sidx, order):
    """返回该站点在结构化层的定位结果；不修改任何输入。

    `order` 是块内调用地址的期望顺序：优先取「已解出 call」（含事实层漏掉的），
    无 res 时退回事实层同块站点。行号按该顺序的位置取，不做文本猜测。
    """
    fn, blk = site["function"], site["block"]
    si = sidx.get(fn)
    if si is None or si.get("status") != "ok":
        reason = (si or {}).get("status", "no_function")
        return {"status": "function_not_structured",
                "reason": reason, "function": fn,
                "detail": ("函数 0x%x 未进入结构化层（%s）：结构化默认只覆盖"
                           " declared 函数，属口径差异" % (fn or 0, reason))}
    if blk is None:
        return {"status": "block_missing", "function": fn, "block": None,
                "detail": "调用点没有归属块（blk 为空）"}
    node = si["blocks"].get(blk)
    if node is None:
        if blk in si["unreachable"]:
            return {"status": "block_unreachable", "function": fn, "block": blk,
                    "detail": "块 0x%x 不可达，结构化层不输出该块" % blk}
        return {"status": "block_missing", "function": fn, "block": blk,
                "detail": "块存在但未出现在结构化输出里（既非可达也未列不可达）"}
    if site["from"] not in order:
        return {"status": "not_a_call", "function": fn, "block": blk,
                "detail": "事实层站点不在本块已解出 call 集合内"}
    slots, _lines, nbody = _slots(node, set(order))
    j = order.index(site["from"])
    if j >= len(slots):
        return {"status": "line_unmatched", "function": fn, "block": blk,
                "detail": "块内第 %d 个调用在文本中没有对应语句行" % j}
    kind, idx, _addr, text = slots[j]
    if kind == "abstain":
        return {"status": "abstain_line", "function": fn, "block": blk,
                "line_index": idx, "slice": _slice(idx, nbody),
                "line_text": text}
    tgt = site.get("target")
    if tgt is not None and "sub_0x" in text and ("0x%x" % tgt) not in text:
        return {"status": "line_target_mismatch", "function": fn, "block": blk,
                "line_index": idx, "slice": _slice(idx, nbody),
                "line_text": text,
                "detail": "文本目标与事实层目标不一致"}
    return {"status": "aligned", "function": fn, "block": blk,
            "node_kind": node.get("kind"), "line_index": idx,
            "slice": _slice(idx, nbody), "line_text": text}


_STRUCT_ISSUE = {
    "function_not_structured": ("struct_function_absent", "caliber_difference"),
    "block_unreachable": ("struct_block_unreachable", "caliber_difference"),
    "abstain_line": ("struct_abstain_line", "caliber_difference"),
    "block_missing": ("struct_block_missing", "layer_bug"),
    "line_unmatched": ("struct_line_unmatched", "layer_bug"),
    "line_target_mismatch": ("struct_line_target", "layer_bug"),
}


def _conflict(kind, key, detail, **extra):
    c = {"kind": kind, "key": key, "attribution": _KIND_ATTR[kind],
         "detail": detail}
    c.update(extra)
    return c


def check(graph, facts, sidx, res=None):
    """三层逐点对账（纯函数：只读入参，不写回）。返回 links/conflicts/counts。

    `res` 只用于「键覆盖」这一项独立枚举：已解出的 call 指令集合是三层共同的
    应然全集（同一份 recdesc 结果），缺谁都要报。不给 res 时跳过该项（测试注入）。
    """
    edges = graph.get("edges") or []
    sites = facts.get("sites") or []
    g_by, g_dup = _dup_map(edges, "from")
    f_by, f_dup = _dup_map(sites, "from")
    call_set = _decoded_calls(res) if res is not None else {}
    cands = {}
    if (graph.get("indirect") or {}).get("enabled"):
        cands = {c["from"]: c
                 for c in (graph["indirect"].get("candidates") or [])}

    conflicts = []
    for addr in sorted(set(g_dup) | set(f_dup)):
        conflicts.append(_conflict(
            "duplicate_key", addr,
            "同一调用地址出现多次：graph=%d 次，facts=%d 次；不合并、不取其一"
            % (len(g_dup.get(addr) or []), len(f_dup.get(addr) or [])),
            duplicate={"graph": len(g_dup.get(addr) or []),
                       "facts": len(f_dup.get(addr) or [])}))

    # 键覆盖：独立枚举「已解出 call」，与两层记录逐地址比对（只报，不修下层）
    if call_set:
        for addr in sorted(call_set):
            if addr in f_by or addr in g_by:
                continue
            info = call_set[addr]
            raw = (info["bytes"] or "").replace(" ", "")
            op, npfx = _opcode_of(raw)
            conflicts.append(_conflict(
                "call_site_missing", addr,
                "已解出的 call 指令 0x%x（%s，跳过 %d 个前缀后 opcode=0x%02x）"
                "在事实层与调用图里都没有记录；两层共用的 call 枚举自 M7-U2 起"
                "按「跳前缀后的 opcode + ModRM.reg」判定，出现缺口说明枚举再次"
                "退化或站点被误删，需人工复核"
                % (addr, info["bytes"], npfx, op or 0),
                function=info["function"], block=info["block"],
                bytes=info["bytes"]))
        for addr in sorted(set(f_by) - set(call_set)):
            conflicts.append(_conflict(
                "facts_site_not_call", addr,
                "事实层站点 0x%x 对应的指令不是已解出的 call（独立枚举未命中）"
                % addr, function=(f_by.get(addr) or {}).get("function")))
        for addr in sorted(set(g_by) - set(call_set)):
            conflicts.append(_conflict(
                "graph_edge_not_call", addr,
                "调用图边 0x%x 对应的指令不是已解出的 call（独立枚举未命中）"
                % addr, function=(g_by.get(addr) or {}).get("from_fn")))

    groups = {}
    for s in sites:
        groups.setdefault((s["function"], s["block"]), []).append(s)
    for k in groups:
        groups[k].sort(key=lambda x: x["from"])

    # 块内调用地址的期望顺序：优先「已解出 call」（含两层都漏的），否则事实层站点
    order_map = {}
    for addr, info in call_set.items():
        order_map.setdefault((info["function"], info["block"]), []).append(addr)
    for v in order_map.values():
        v.sort()
    for k, group in groups.items():
        order_map.setdefault(k, [x["from"] for x in group])

    links = []
    keys = sorted(set(g_by) | set(f_by))
    for addr in keys:
        g, f = g_by.get(addr), f_by.get(addr)
        own = []
        fn = (f or {}).get("function")
        blk = (f or {}).get("block")
        if g and not f:
            own.append(_conflict(
                "facts_site_missing", addr,
                "调用图有直接边，事实层没有对应站点（两层扫描口径不应不同）",
                function=g.get("from_fn")))
        if f and not g:
            if f.get("call_kind") == "direct":
                own.append(_conflict(
                    "graph_edge_missing", addr,
                    "事实层判为直接调用，调用图没有对应确定边",
                    function=f.get("function")))
        if g and f:
            if g.get("from_fn") != f.get("function"):
                own.append(_conflict(
                    "function_mismatch", addr,
                    "所属函数不一致：graph=%s facts=%s"
                    % (g.get("from_fn"), f.get("function")),
                    graph_function=g.get("from_fn"),
                    facts_function=f.get("function")))
            if f.get("call_kind") == "direct":
                if f.get("state") != g.get("state"):
                    own.append(_conflict(
                        "state_mismatch", addr,
                        "目标状态不一致：graph=%s facts=%s（两类证据独立重算，"
                        "至少一层有误，不以任何一方为准）"
                        % (g.get("state"), f.get("state")),
                        graph_state=g.get("state"), facts_state=f.get("state")))
                if f.get("target") != g.get("to"):
                    own.append(_conflict(
                        "target_mismatch", addr,
                        "目标地址不一致：graph=0x%x facts=0x%x"
                        % (g.get("to") or 0, f.get("target") or 0),
                        graph_target=g.get("to"), facts_target=f.get("target")))
            elif f.get("state") is not None:
                own.append(_conflict(
                    "state_mismatch", addr,
                    "事实层判为间接调用，却给出了 state=%s" % f.get("state"),
                    facts_state=f.get("state")))
        if f:
            for fact in f.get("facts") or []:
                for ev in fact.get("evidence") or []:
                    if ev.get("level") == "declared":
                        own.append(_conflict(
                            "operand_declared", addr,
                            "操作数事实出现 declared 级证据（结构性恒等式被破坏）：%s"
                            % ev.get("text")))
        sside = (_struct_side(f, sidx, order_map.get(
                    ((f or {}).get("function"), (f or {}).get("block"))) or [])
                 if f else {"status": "function_not_structured",
                            "reason": "no_site"})
        if sside["status"] in _STRUCT_ISSUE:
            kind, _attr = _STRUCT_ISSUE[sside["status"]]
            own.append(_conflict(kind, addr, sside.get("detail") or
                                 "结构化层缺失：%s" % sside["status"],
                                 function=sside.get("function"),
                                 block=sside.get("block"),
                                 struct_status=sside["status"]))
        conflicts.extend(own)
        links.append({
            "key": addr,
            "function": fn,
            "block": blk,
            "graph": ({"kind": "direct_edge", "state": g.get("state"),
                       "target": g.get("to"), "evidence": g.get("evidence"),
                       "target_symbol": g.get("target_symbol")}
                      if g else
                      {"kind": "indirect_no_edge",
                       "candidate": cands.get(addr)} if f and
                      f.get("call_kind") == "indirect" else
                      {"kind": "missing"}),
            "facts": ({"call_kind": f.get("call_kind"),
                       "state": f.get("state"), "target": f.get("target"),
                       "function_declaration": (f.get("function_declaration")
                                                or {}).get("level"),
                       "facts_before": sum(1 for x in f.get("facts") or []
                                           if x.get("direction") == "before"),
                       "facts_after": sum(1 for x in f.get("facts") or []
                                          if x.get("direction") == "after"),
                       "abstains": len(f.get("abstains") or [])}
                      if f else None),
            "struct": sside,
            "conflicts": own,
        })

    # 块级：文本调用行数 vs 块内应然调用数（多/少都说明定位规则被破坏）。
    # 「应然」优先用已解出 call（含两层都漏的），否则用事实层同块站点，
    # 因此下层漏 call 只会以 call_site_missing 报一次，不会在这里重复计一笔。
    for (fn, blk) in sorted(set(order_map) | set(groups),
                            key=lambda x: (x[0] or 0, x[1] or 0)):
        si = sidx.get(fn)
        if not si or si.get("status") != "ok" or blk is None:
            continue
        node = si["blocks"].get(blk)
        if node is None:
            continue
        want = order_map.get((fn, blk)) or []
        slots, _l, _n = _slots(node, set(want))
        if len(slots) != len(want):
            miss = ["0x%x" % a for a in want[len(slots):]] if len(want) > len(slots) else []
            conflicts.append(_conflict(
                "struct_line_count_mismatch", None,
                "块 0x%x：文本调用行 %d 条，块内应然调用 %d 个%s"
                % (blk, len(slots), len(want),
                   ("（文本缺：" + ", ".join(miss) + "）") if miss
                   else "（文本多出行）"),
                function=fn, block=blk))

    hard = [c for c in conflicts
            if c["attribution"] in ("layer_bug", "data_anomaly")]
    kinds = {}
    for c in conflicts:
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    status_counts = {}
    for ln in links:
        st = ln["struct"]["status"]
        status_counts[st] = status_counts.get(st, 0) + 1
    extra_f = set(f_by) - set(call_set) if call_set else set()
    extra_g = set(g_by) - set(call_set) if call_set else set()
    coverage_ok = (not call_set) or (
        not extra_f and not extra_g and not (set(call_set) - set(keys)))
    counts = {
        "facts_sites": len(sites), "graph_edges": len(edges),
        "keys": len(keys),
        "key_unique": sum(1 for k in keys
                          if len(g_dup.get(k) or []) <= 1
                          and len(f_dup.get(k) or []) <= 1),
        "duplicate_keys": len(set(g_dup) | set(f_dup)),
        "decoded_calls": len(call_set),
        "call_site_missing": kinds.get("call_site_missing", 0),
        "facts_site_not_call": len(extra_f),
        "graph_edge_not_call": len(extra_g),
        "key_coverage_ok": coverage_ok,
        "graph_direct_edge": sum(1 for ln in links
                                 if ln["graph"]["kind"] == "direct_edge"),
        "graph_indirect_no_edge": sum(1 for ln in links
                                      if ln["graph"]["kind"] == "indirect_no_edge"),
        "graph_missing": sum(1 for ln in links
                             if ln["graph"]["kind"] == "missing"),
        "struct": status_counts,
        "aligned": status_counts.get("aligned", 0),
        "conflicts": len(conflicts), "hard_conflicts": len(hard),
        "caliber_differences": len(conflicts) - len(hard),
        "conflict_kinds": kinds,
        "sites_with_hard_conflict": len({c["key"] for c in hard
                                         if c["key"] is not None}),
    }
    return {"links": links, "conflicts": conflicts, "counts": counts}


def build(path, section=".text", res=None, graph=None, facts=None,
          sidx=None, include_inferred=False, indirect=False):
    """三层拼接报告。graph/facts/sidx 可注入（测试用），本函数只读它们。"""
    res = res if res is not None else recdesc.descend(path, section)
    graph = graph if graph is not None else CG.build(
        path, section, res=res, indirect=indirect)
    facts = facts if facts is not None else CF.build(path, res=res, graph=graph)
    if sidx is None:
        funcs = sorted({s["function"] for s in facts["sites"]},
                       key=lambda x: (x is None, x or 0))
        sidx = struct_index(res, funcs, include_inferred)
    r = check(graph, facts, sidx, res=res)
    report = {
        "path": str(path), "section": section,
        "key": {"rule": KEY_RULE,
                "uniqueness": "unique=%d / keys=%d / duplicate_keys=%d"
                              % (r["counts"]["key_unique"],
                                 r["counts"]["keys"],
                                 r["counts"]["duplicate_keys"]),
                "coverage": "decoded_calls=%d / keys=%d / both_layers_missing=%d"
                            " / facts_extra=%d / graph_extra=%d"
                            % (r["counts"]["decoded_calls"],
                               r["counts"]["keys"],
                               r["counts"]["call_site_missing"],
                               r["counts"]["facts_site_not_call"],
                               r["counts"]["graph_edge_not_call"]),
                "coverage_ok": r["counts"]["key_coverage_ok"]},
        "counts": r["counts"],
        "conflicts": r["conflicts"],
        "sites": r["links"],
        "attribution": ATTRIBUTION,
        "read_only": {"graph": True, "facts": True, "struct": True,
                      "note": "本模块不写回任何一层；有副作用即违约"},
        "caveats": list(CAVEATS),
    }
    return report


def render(report, limit=8):
    c = report["counts"]
    out = []
    out.append("== 三层拼接（%s，节 %s）==" % (report["path"], report["section"]))
    out.append("对齐键: %s" % report["key"]["rule"])
    out.append("唯一性: %s" % report["key"]["uniqueness"])
    out.append("键覆盖: %s（%s）"
               % (report["key"]["coverage"],
                  "完整" if report["key"]["coverage_ok"] else "有缺口，见冲突"))
    out.append("站点: 事实层 %d ｜ 调用图直接边 %d ｜ 键 %d"
               % (c["facts_sites"], c["graph_edges"], c["keys"]))
    st = c["struct"]
    out.append("结构化定位: aligned %d ｜ 函数未结构化 %d ｜ 块不可达 %d ｜ "
               "abstain 行 %d ｜ 定位失败 %d"
               % (st.get("aligned", 0), st.get("function_not_structured", 0),
                  st.get("block_unreachable", 0), st.get("abstain_line", 0),
                  st.get("line_unmatched", 0) + st.get("block_missing", 0)
                  + st.get("line_target_mismatch", 0)))
    out.append("冲突: %d（硬冲突 %d / 口径差异 %d）：%s"
               % (c["conflicts"], c["hard_conflicts"],
                  c["caliber_differences"],
                  ", ".join("%s=%d" % (k, v)
                            for k, v in sorted(c["conflict_kinds"].items()))
                  or "无"))
    hard = [x for x in report["conflicts"]
            if x["attribution"] in ("layer_bug", "data_anomaly")]
    if hard:
        out.append("-- 硬冲突（不以任何一方为准，单列待查）--")
        for x in hard[:limit]:
            out.append("  ! [%s/%s] key=%s %s"
                       % (x["kind"], x["attribution"],
                          "0x%x" % x["key"] if x["key"] else "-", x["detail"]))
        if len(hard) > limit:
            out.append("  … 另有 %d 条硬冲突（--json 查看全部）" % (len(hard) - limit))
    cal = [x for x in report["conflicts"]
           if x["attribution"] == "caliber_difference"]
    if cal:
        out.append("-- 口径差异（非错误，逐类计数）--")
        seen = {}
        for x in cal:
            seen[x["kind"]] = seen.get(x["kind"], 0) + 1
        for k, v in sorted(seen.items()):
            out.append("  ~ [%s] %d 条：%s" % (k, v, _CALIBER_TEXT.get(k, "")))
    aligned = [s for s in report["sites"] if s["struct"]["status"] == "aligned"]
    if aligned:
        out.append("-- 对齐样例 --")
        for s in aligned[:limit]:
            out.append("  0x%06x  %-8s graph=%-14s facts=%-14s struct=%s:第 %d 行"
                       % (s["key"], s["facts"]["call_kind"],
                          s["graph"].get("state") or s["graph"]["kind"],
                          (s["facts"] or {}).get("state") or "None",
                          s["struct"]["node_kind"], s["struct"]["line_index"]))
    return "\n".join(out)


_CALIBER_TEXT = {
    "struct_function_absent": "结构化层只覆盖 declared 函数（默认），该函数未结构化",
    "struct_block_unreachable": "结构化层只输出可达块；该块不可达",
    "struct_abstain_line": "表达式层在该指令 abstain，文本位置是注释而非调用语句",
}


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rekit sitejoin",
        description="M7-U1 三层拼接：调用图 / 参数事实层 / 结构化文本按调用地址对齐")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--include-inferred", action="store_true",
                    help="结构化层也覆盖未声明函数（单独标注，不改变默认口径）")
    ap.add_argument("--indirect-candidates", action="store_true",
                    help="调用图间接候选层（单列、带证据等级，不并入确定集）")
    ap.add_argument("--limit", type=int, default=8)
    args = ap.parse_args(argv)
    try:
        rep = build(args.file, args.section,
                    include_inferred=args.include_inferred,
                    indirect=args.indirect_candidates)
    except OSError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=1))
    else:
        print(render(rep, args.limit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
