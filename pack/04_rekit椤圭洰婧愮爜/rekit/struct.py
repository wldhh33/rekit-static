#!/usr/bin/env python3
# rekit.struct — 控制流结构化输出（M5-U3）
#
# 只做一件事：把「块 + 边」重排成 if / loop / switch 的嵌套结构；不新增任何语义。
# 三条硬约束（对应 M5-U3 验收）：
#   1) 结构化的每一处都能退回原始块与边：每个节点都带 block / edges / join，
#      `check_traceable()` 逐节点核对这些引用确实存在于 recdesc 的 CFG 里；
#   2) switch 只在候选层证据为 high 时渲染；证据不足一律保留 goto，并在节点里
#      写明没结构化的原因（表长未证明 / 有被拒表项 / 无候选）；
#   3) 已知不可结构化（不可约循环、条件不可判、多入口区域、不可达块）单独统计，
#      绝不为了输出好看强行套 if/loop。
#
# 判定口径：
#   - 支配/后支配用迭代数据流（确定性顺序，无随机性）；
#   - 自然循环 = 回边 u→h 且 h ∈ dom(u)；循环体再与 dom(h) 求交，避免把
#     非支配路径（多入口）算进自然循环；
#   - 不可约 = SCC 大小 >1 且入口（来自 SCC 外的前驱）>1，整段标 unstructured；
#   - if 的 join 用两条后继的最近公共后支配；找不到 → 视为都走向出口。
#
# 结构化结果是一棵树（node dict），文本由 `render()` 生成：
#   block / seq / if / while / do_while / for / switch / break / continue /
#   goto / label / unstructured
# 每个 block 节点带 `lines`（expr 的 body_lines，不含块间跳转）与 `term` 原文，
# 因而文本里的任何一行都能回指到「哪一块的哪条指令」。
import re

from . import expr

CAVEATS = [
    "结构化是对已恢复块与边的重排，不新增语义；条件文本仍受“标志位只在本块内跟踪”限制",
    "switch 只在候选证据为 high 时渲染；medium/low 或无候选一律保留 goto 并写明原因",
    "不可约循环（SCC 多入口）、条件不可判、不可达块单独统计，不强行套 if/loop",
    "每个 if/loop 节点都记录消费的 CFG 边；check_traceable() 逐节点核对可回指性",
]

_EXIT = "EXIT"
_COND_TERMS = ("jcc_rel", "jcc_rel32", "loop_rel")
_IF_RE = re.compile(r"^if \((.*)\) goto L_0x([0-9a-fA-F]+);")
_GOTO_RE = re.compile(r"^goto L_0x([0-9a-fA-F]+);")


# ── CFG 视图（只读 recdesc 的结果） ─────────────────────────────────
def _cfg(res, func_addr):
    blks = {b["start"]: b for b in res["blocks"] if b["function"] == func_addr}
    succ = {s: [t for t in b["successors"] if t in blks] for s, b in blks.items()}
    pred = {s: [] for s in blks}
    kind = {}
    edges = []
    for cls in ("definite", "speculative"):
        for e in res["cfg"]["edges"][cls]:
            f, tb = e["from"], e.get("to_block")
            if f in blks and tb in blks:
                kind[(f, tb)] = e["kind"]
                edges.append({"from": f, "to": tb, "kind": e["kind"],
                              "class": cls, "to_addr": e["to"]})
    for s in blks:
        for t in succ[s]:
            pred[t].append(s)
            kind.setdefault((s, t), "fallthrough" if t == blks[s]["end"] else "taken")
    entry = func_addr if func_addr in blks else (min(blks) if blks else None)
    reach, work = set(), [entry] if entry is not None else []
    while work:
        x = work.pop()
        if x in reach or x not in blks:
            continue
        reach.add(x)
        work.extend(succ[x])
    return {"blocks": blks, "succ": succ, "pred": pred, "kind": kind,
            "edges": edges, "entry": entry, "reachable": reach}


def _dominators(g):
    nodes = sorted(g["reachable"])
    dom = {n: set(nodes) for n in nodes}
    if not nodes:
        return dom
    dom[g["entry"]] = {g["entry"]}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n == g["entry"]:
                continue
            ps = [p for p in g["pred"][n] if p in dom]
            new = {n} | (set.intersection(*[dom[p] for p in ps]) if ps else set())
            if new != dom[n]:
                dom[n] = new
                changed = True
    return dom


def _postdominators(g):
    nodes = sorted(g["reachable"])
    alln = set(nodes) | {_EXIT}
    pd = {n: set(alln) for n in nodes}
    pd[_EXIT] = {_EXIT}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            ss = g["succ"][n] or [_EXIT]
            new = {n} | set.intersection(*[pd[s] for s in ss if s in pd])
            if new != pd[n]:
                pd[n] = new
                changed = True
    return pd


def _ncp(pd, a, b):
    """最近公共后支配；返回 _EXIT 表示都走到出口。"""
    ca = pd.get(a, set()) & pd.get(b, set())
    if not ca:
        return _EXIT
    return min(ca, key=lambda x: (len(pd.get(x, {x})), str(x)))


def _sccs(g):
    """Tarjan（迭代版），返回大小 >1 的 SCC 列表。"""
    nodes = sorted(g["reachable"])
    index, low, on, stack, out = {}, {}, set(), [], []
    idx = [0]

    for root in nodes:
        if root in index:
            continue
        work = [(root, 0)]
        while work:
            v, pi = work.pop()
            if pi == 0:
                index[v] = low[v] = idx[0]
                idx[0] += 1
                stack.append(v)
                on.add(v)
            recurse = False
            ss = g["succ"][v]
            for i in range(pi, len(ss)):
                w = ss[i]
                if w not in index:
                    work.append((v, i + 1))
                    work.append((w, 0))
                    recurse = True
                    break
                if w in on:
                    low[v] = min(low[v], index[w])
            if recurse:
                continue
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == v:
                        break
                if len(comp) > 1:
                    out.append(sorted(comp))
            if work:
                u = work[-1][0]
                low[u] = min(low[u], low[v])
    return out


def _irreducible(g):
    """SCC 多入口 → 判为不可约；返回 (blocks, scc 列表)。"""
    bad, sccs = set(), []
    for comp in _sccs(g):
        cs = set(comp)
        entries = [n for n in comp if any(p not in cs for p in g["pred"][n])]
        if len(entries) > 1:
            bad |= cs
            sccs.append({"blocks": comp, "entries": sorted(entries)})
    return bad, sccs


def _loop_body(g, dom, h, sources):
    """自然循环体：从回边源反向可达、且被 h 支配的块（含 h）。"""
    body, work = {h}, list(sources)
    while work:
        x = work.pop()
        if x in body:
            continue
        body.add(x)
        work.extend(p for p in g["pred"][x] if p in g["reachable"] and h in dom.get(x, ()))
    return {b for b in body if h in dom.get(b, ()) or b == h}


# ── 结构化树 ─────────────────────────────────────────────────────────
_IDX_RE = re.compile(r"\+\s*([a-z][a-z0-9]*)\s*\*\s*(?:1|2|4|8)\b")


def _index_text(node, idx):
    """从 expr 已渲染的块文本里取索引寄存器名（宽度已由操作数宽度决定）。

    取不到就退化成编号 reg#N —— 不猜宽度（32/64 位进程的寄存器名不同）。
    """
    lines = []

    def walk(n):
        if isinstance(n, dict):
            lines.extend(n.get("lines") or [])
            for k in ("body", "then", "else", "inner", "children"):
                walk(n.get(k))
        elif isinstance(n, list):
            for x in n:
                walk(x)

    walk(node)
    for ln in lines:
        m = _IDX_RE.search(ln)
        if m:
            return m.group(1)
    return "reg#%d" % idx


class _Builder:
    def __init__(self, g, dom, pd, lifted_blocks, cands):
        self.g, self.dom, self.pd = g, dom, pd
        self.info = lifted_blocks
        self.cands = cands or {}
        self.emitted = set()
        self.stats = {"if": 0, "else": 0, "while": 0, "do_while": 0,
                      "for": 0, "switch": 0, "switch_downgraded": 0,
                      "switch_no_candidate": 0,
                      "goto": 0, "break": 0, "continue": 0,
                      "cond_unknown": 0}
        self.notes = []
        self.bad, self.irr_sccs = _irreducible(g)
        self.loops = self._find_loops()

    # -- 循环表 ----------------------------------------------------
    def _find_loops(self):
        g, dom = self.g, self.dom
        backs = {}
        for u in sorted(g["reachable"]):
            for h in g["succ"][u]:
                if h in dom.get(u, ()):
                    backs.setdefault(h, []).append(u)
        loops = {}
        for h, srcs in backs.items():
            body = _loop_body(g, dom, h, srcs)
            outs = sorted({t for b in body for t in g["succ"][b] if t not in body})
            exit_ = None
            if outs:
                cur = outs[0]
                for o in outs[1:]:
                    cur = _ncp(self.pd, cur, o)
                exit_ = None if cur == _EXIT else cur
            loops[h] = {"header": h, "body": body, "backs": sorted(srcs),
                        "exit": exit_}
        return loops

    # -- 条件文本 --------------------------------------------------
    def _term_info(self, b):
        info = self.info[b]
        lines = info.get("term_lines") or []
        cond, target = None, None
        for ln in lines:
            m = _IF_RE.match(ln)
            if m:
                cond, target = m.group(1), int(m.group(2), 16)
                break
            m = _GOTO_RE.match(ln)
            if m and target is None:
                target = int(m.group(1), 16)
        return cond, target, lines

    # -- 主流程 ----------------------------------------------------
    def build(self):
        root = self._seq(self.g["entry"], None, [])
        left = sorted(self.g["reachable"] - self.emitted)
        tail = []
        for b in left:
            if b in self.emitted:
                continue
            self.emitted.add(b)
            cond, target, lines = self._term_info(b)
            tail.append({"kind": "label", "block": b,
                         "lines": self.info[b].get("body_lines") or [],
                         "term": lines,
                         "reason": "可达但未纳入嵌套结构（循环多出口/交叉边/共享块），"
                                   "按块原样输出，可回指 recdesc.blocks"})
        unreach = sorted(set(self.g["blocks"]) - self.g["reachable"])
        return {"kind": "seq", "children": [root] + tail}, unreach

    def _seq(self, cur, stop, ctx):
        items = []
        guard = 0
        while cur is not None and cur != stop:
            guard += 1
            if guard > len(self.g["blocks"]) + 4:
                items.append({"kind": "unstructured", "blocks": [],
                              "reason": "结构递归步数超限（异常 CFG），已停止"})
                break
            if cur in self.emitted:
                if stop is not None and cur == stop:
                    break
                items.append({"kind": "goto", "block": cur, "target": cur,
                              "reason": "共享块/回边：已输出，改用 goto 回指"})
                self.stats["goto"] += 1
                break
            node, cur = self._one(cur, stop, ctx)
            items.append(node)
        return {"kind": "seq", "children": items}

    def _one(self, cur, stop, ctx):
        g, info = self.g, self.info[cur]
        self.emitted.add(cur)
        body = {"kind": "block", "block": cur,
                "lines": info.get("body_lines") or [],
                "term": info.get("term_lines") or [],
                "terminator": info.get("terminator")}
        term = info.get("terminator")
        cond, target, _ = self._term_info(cur)

        # 不可约循环：不猜结构，保留块 + goto 并记原因
        if cur in self.bad:
            node = {"kind": "unstructured", "blocks": [cur],
                    "body": body,
                    "reason": "不可约循环（SCC 多入口），不强行套 if/loop"}
            nxt = g["succ"][cur][0] if g["succ"][cur] else None
            if term in _COND_TERMS:
                for s in g["succ"][cur]:
                    node.setdefault("gotos", []).append(s)
                # 不猜 SCC 内部结构，但顺序后继继续往下写：另外的边已用 goto
                # 显式保留，线性续写不构成「强行套 if/loop」的结构断言
                nxt = next((s for s in g["succ"][cur]
                            if g["kind"].get((cur, s)) == "fallthrough"), None)
            elif term == "jmp_rel":
                nxt = target if target in g["blocks"] else None
            return node, nxt

        # 循环头
        if cur in self.loops and self.loops[cur]["exit"] != cur \
                and not any(c.get("header") == cur for c in ctx):
            return self._loop(cur, body, ctx)

        if term in _COND_TERMS:
            return self._if(cur, body, cond, target, stop, ctx)
        if term == "jmp_ind":
            return self._switch(cur, body, stop, ctx)
        if term == "jmp_rel":
            t = target if target in g["blocks"] else None
            if t is None:
                return body, None
            if t == stop:
                return body, stop
            if ctx and t == ctx[-1]["header"]:
                self.stats["continue"] += 1
                body["loop_note"] = "回边 → 循环头（continue）"
                return body, None
            if ctx and t in ctx[-1]["exits"]:
                self.stats["break"] += 1
                body["loop_note"] = "跳出循环（break）"
                return body, None
            if t in self.emitted:
                self.stats["goto"] += 1
                node = {"kind": "seq", "children": [
                    body, {"kind": "goto", "block": cur, "target": t,
                           "reason": "目标已输出（共享块），保留 goto"}]}
                return node, None
            return body, t
        ss = g["succ"].get(cur) or []
        # 非转移指令（next / call 之后等）：顺序后继就是下一个块；
        # ret/hlt 没有后继才算路径终结。之前这里一律返回 None，导致
        # 顶层顺序块之后的所有块都掉进「tail label」，结构层覆盖不到。
        return body, (ss[0] if ss else None)

    def _if(self, cur, body, cond, target, stop, ctx):
        g = self.g
        ss = g["succ"][cur]
        if len(ss) < 2:
            t = ss[0] if ss else None
            return body, (t if t != stop else stop)
        s1, s2 = ss[0], ss[1]
        taken = target if target in (s1, s2) else None
        cond_unknown = cond is None
        if cond_unknown:
            self.stats["cond_unknown"] += 1
            node = {"kind": "seq", "children": [
                body,
                {"kind": "unstructured", "blocks": [cur],
                 "reason": "条件不可判（跨块标志位），保留两条 goto"}]}
            for s in (s1, s2):
                node["children"].append({"kind": "goto", "block": cur,
                                         "target": s,
                                         "reason": "条件不可判：分支目标原样保留"})
                self.stats["goto"] += 1
            return node, None

        # 循环内：一条边直接回循环头（stop）→ 另一条边决定 「break」还是「continue」
        if ctx and stop == ctx[-1]["header"] and stop in (s1, s2):
            other = s2 if s1 == stop else s1
            back = stop
            # 条件必须对「去 other 的那条边」求：taken 指向 other 时用 cond，
            # 否则取反。之前这里拿 taken==stop 判断，把 break/continue 反过来过。
            cond_to_other = cond if taken == other else "!(%s)" % cond
            cond_to_back = cond if taken == back else "!(%s)" % cond
            edges = [{"from": cur, "to": s, "kind": g["kind"].get((cur, s))}
                     for s in (s1, s2)]
            if other in ctx[-1]["body"]:
                # 另一条边仍在循环体内 → 带条件的 continue（回循环头）
                self.stats["continue"] += 1
                return {"kind": "seq", "children": [
                    body, {"kind": "continue", "block": cur, "target": back,
                           "cond": cond_to_back, "edges": edges}]}, other
            # 另一条边离开循环体 → break；break 之后该路径终结（不回接 other 的块）
            self.stats["break"] += 1
            return {"kind": "seq", "children": [
                body, {"kind": "break", "block": cur, "target": other,
                       "cond": cond_to_other, "edges": edges}]}, None

        join = _ncp(self.pd, s1, s2)
        if join == _EXIT:
            join = None
        # 编译器最常见的形态：`if (c) goto L; <fall 区域>; L:`。
        # 此时 L 才是自然汇合点，用后支配会一路塌到 exit，导致巨型 if/else 嵌套；
        # 只要 taken 是前向目标，就用「if-then（then=fall 区域）」还原原形态。
        fall = next((s for s in ss if g["kind"].get((cur, s)) == "fallthrough"), None)
        taken_s = next((s for s in ss if s != fall), None)
        if taken_s is not None and fall is not None and taken_s > cur \
                and taken_s != fall and taken_s != stop:
            then_entry, join = fall, taken_s
            then_cond = ("!(%s)" % cond) if target == taken_s else cond
            els = None
        elif join == s1:
            then_entry, then_cond = s2, ("!(%s)" % cond if taken == s2 else cond)
            els = None
        elif join == s2:
            then_entry, then_cond = s1, (cond if taken == s1 else "!(%s)" % cond)
            els = None
        else:
            then_entry, then_cond = s1, (cond if taken == s1 else "!(%s)" % cond)
            els = s2
        edges = [{"from": cur, "to": s1, "kind": g["kind"].get((cur, s1))},
                 {"from": cur, "to": s2, "kind": g["kind"].get((cur, s2))}]
        node = {"kind": "if", "block": cur, "cond": then_cond, "body": body,
                "then": self._seq(then_entry, join, ctx), "else": None,
                "join": join, "edges": edges}
        self.stats["if"] += 1
        if els is not None:
            node["else"] = self._seq(els, join, ctx)
            node["else_cond"] = "!(%s)" % then_cond if then_cond.startswith("!(") \
                else "!(%s)" % then_cond
            self.stats["else"] += 1
        return node, join

    def _switch(self, cur, body, stop, ctx):
        c = self.cands.get(cur)
        if not c:
            self.stats["switch_no_candidate"] += 1
            node = {"kind": "seq", "children": [
                body, {"kind": "unstructured", "blocks": [cur],
                       "reason": "间接 jmp 无候选：目标不可静态确定（R45），保留 goto"}]}
            return node, None
        if c["evidence"] != "high":
            self.stats["switch_downgraded"] += 1
            node = {"kind": "seq", "children": [
                body, {"kind": "unstructured", "blocks": [cur],
                       "reason": "候选证据 %s（%s），不渲染 switch，保留 goto"
                                 % (c["evidence"], "；".join(c["basis"][:2]))}]}
            return node, None
        cases = [{"index": i, "target": t} for i, t in enumerate(c["targets"])]
        node = {"kind": "switch", "block": cur, "body": body,
                "index_reg": c["index_reg"],
                # 索引寄存器名直接取 expr 已渲染的块文本（宽度由操作数宽度决定）；
                # 取不到就退化成编号，不猜宽度
                "index_text": _index_text(body, c["index_reg"]),
                "cases": cases,
                "candidate": {"jmp": c["jmp"], "table": c["table"],
                              "evidence": c["evidence"], "count": c["count"],
                              "basis": c["basis"]},
                "edges": [{"from": cur, "to": None, "kind": "jmp_ind"}]}
        self.stats["switch"] += 1
        return node, None

    def _loop(self, h, body, ctx):
        g, lp = self.g, self.loops[h]
        exit_ = lp["exit"]
        ctx2 = ctx + [{"header": h, "exits": {exit_} if exit_ else set(),
                       "body": lp["body"]}]
        cond, target, _ = self._term_info(h)
        if h in self.bad:
            node = {"kind": "unstructured", "blocks": sorted(lp["body"]),
                    "body": body, "reason": "不可约循环（SCC 多入口）"}
            return node, exit_
        # while：头是条件块，条件可判，且循环体入口唯一
        if self.info[h].get("terminator") in _COND_TERMS:
            ss = g["succ"][h]
            inside = [s for s in ss if s in lp["body"]]
            if cond is not None and len(inside) == 1:
                entry = inside[0]
                cbody = cond if target == entry else "!(%s)" % cond
                seq = self._seq(entry, h, ctx2)
                self.stats["while"] += 1
                return {"kind": "while", "header": h, "cond": cbody,
                        "body": body, "inner": seq, "exit": exit_,
                        "back_edges": lp["backs"],
                        "edges": [{"from": h, "to": s,
                                   "kind": g["kind"].get((h, s))} for s in ss]}, exit_
            # 条件不可判或多入口：保留 goto 形态
            node = {"kind": "unstructured", "blocks": [h],
                    "body": body,
                    "reason": "循环头条件不可判/多入口，保留 goto 循环"}
            self._drain(lp["body"] - self.emitted)
            return node, exit_
        # do-while / for(;;)：头不是条件块，条件在闩尾
        latch = lp["backs"][0] if lp["backs"] else None
        if latch is None:
            return body, exit_
        lcond, ltarget, _ = self._term_info(latch)
        # 头块 h 已被 _one 标 emitted 且 body 节点已建好；这里从 h 的后继续写，
        # 再把 body 放在最前——否则 h 自己会变成一条 goto，块在树里就丢了
        nxt = (g["succ"].get(h) or [None])[0]
        rest = self._seq(nxt, latch, ctx2)
        inner = {"kind": "seq", "children": [body] + rest["children"]}
        if latch not in self.emitted:
            self.emitted.add(latch)
            li = self.info[latch]
            inner["children"].append({"kind": "block", "block": latch,
                                      "lines": li.get("body_lines") or [],
                                      "term": []})
        if lcond is not None and ltarget == h:
            self.stats["do_while"] += 1
            return {"kind": "do_while", "header": h, "latch": latch,
                    "cond": lcond, "body": inner, "exit": exit_,
                    "back_edges": lp["backs"]}, exit_
        self.stats["for"] += 1
        return {"kind": "for", "header": h, "latch": latch, "body": inner,
                "exit": exit_, "back_edges": lp["backs"]}, exit_

    def _drain(self, blocks):
        # 只登记「这段没展开」，不标 emitted：那些块必须在文本里以 label 原样出现，
        # 否则「结构里看不到、却计入已输出」就是不可回溯（build() 会补 label）
        for b in sorted(blocks):
            if b not in self.notes:
                self.notes.append(b)


# ── 可回溯校验 ───────────────────────────────────────────────────────
def _nodes(node, acc):
    acc.append(node)
    for k in ("children",):
        for c in node.get(k) or []:
            _nodes(c, acc)
    for k in ("then", "else", "body", "inner"):
        if isinstance(node.get(k), dict):
            _nodes(node[k], acc)
    return acc


def check_traceable(tree, g, cand_targets=None):
    """逐节点核对：块引用存在、边引用存在、goto 目标存在。返回违规列表。"""
    cand_targets = cand_targets or set()
    bad = []
    seen = set()

    def walk(n):
        k = n.get("kind")
        if k in ("block", "label"):
            b = n.get("block")
            if b not in g["blocks"]:
                bad.append("block 引用不存在: %s" % hex(b or 0))
            elif b in seen:
                bad.append("block 重复输出: 0x%x" % b)
            else:
                seen.add(b)
        if k in ("if", "while", "do_while", "for", "switch", "unstructured",
                 "break", "continue"):
            b = n.get("block")
            if b is not None and b not in g["blocks"]:
                bad.append("%s 的 block 不存在: 0x%x" % (k, b))
        for e in n.get("edges") or []:
            f, t = e.get("from"), e.get("to")
            if f not in g["blocks"]:
                bad.append("边源不存在: 0x%x" % (f or 0))
            elif t is not None and t not in g["blocks"]:
                bad.append("边目标不存在: 0x%x" % t)
            elif t is not None and t not in g["succ"].get(f, []):
                bad.append("边在 CFG 中不存在: 0x%x→0x%x" % (f, t))
        if k == "goto":
            t = n.get("target")
            if t not in g["blocks"]:
                bad.append("goto 目标不存在: 0x%x" % (t or 0))
        if k == "switch":
            for c in n.get("cases") or []:
                t = c.get("target")
                if t not in cand_targets:
                    bad.append("switch case 目标不在候选集: 0x%x" % t)
        for key in ("children",):
            for c in n.get(key) or []:
                walk(c)
        for key in ("then", "else", "body", "inner"):
            if isinstance(n.get(key), dict):
                walk(n[key])

    walk(tree)
    # 完备性：每个可达块必须在文本里出现且仅出现一次——否则「看着像 C，但某块
    # 在输出里根本找不到」就是不可回溯
    for b in sorted(set(g["reachable"]) - seen):
        bad.append("可达块未出现在结构化输出: 0x%x" % b)
    return bad


# ── 对外 API ─────────────────────────────────────────────────────────
def structure_function(res, func_addr, cand_report=None, imp=None, lifted=None):
    lifted = lifted or expr.lift_function(res, func_addr, imp)
    if lifted.get("skipped"):
        return {"function": func_addr, "skipped": lifted["skipped"],
                "stats": {}, "tree": {"kind": "seq", "children": []},
                "violations": [], "caveats": list(CAVEATS)}
    g = _cfg(res, func_addr)
    dom = _dominators(g)
    pd = _postdominators(g)
    info = {b["start"]: b for b in lifted.get("blocks") or []}
    cands = {}
    if cand_report:
        for c in cand_report.get("candidates") or []:
            for b in res["blocks"]:
                if b["function"] == func_addr and c["jmp"] in b["insns"]:
                    cands[b["start"]] = c
                    break
    b = _Builder(g, dom, pd, info, cands)
    tree, unreach = b.build()
    ctargets = {t for c in cands.values() if c["evidence"] == "high"
                for t in c["targets"]}
    violations = check_traceable(tree, g, ctargets)
    blocks_total = len(g["blocks"])
    stats = dict(b.stats)
    stats.update({
        "blocks_total": blocks_total,
        "blocks_reachable": len(g["reachable"]),
        "blocks_emitted": len(b.emitted),
        "blocks_unreachable": len(unreach),
        "unreachable": unreach,
        "irreducible_blocks": len(b.bad),
        "irreducible_sccs": b.irr_sccs,
        "leftover": b.notes,
        "goto_ratio": (b.stats["goto"] / blocks_total) if blocks_total else 0.0,
        "goto_dense": (b.stats["goto"] / blocks_total) > 0.30 if blocks_total else False,
        "structured": (b.stats["if"] + b.stats["while"] + b.stats["do_while"]
                       + b.stats["for"] + b.stats["switch"]),
    })
    return {"function": func_addr, "symbol": lifted.get("symbol"),
            "range": lifted.get("range"), "boundary": lifted.get("boundary"),
            "tree": tree, "stats": stats, "violations": violations,
            "unreachable": unreach, "caveats": list(CAVEATS)}


def structure_binary(res, cand_report=None, include_inferred=False):
    funcs = expr.list_functions(res)
    per, tot = [], {"functions": 0, "structured": 0, "if": 0, "else": 0,
                    "while": 0, "do_while": 0, "for": 0, "switch": 0,
                    "switch_downgraded": 0, "switch_no_candidate": 0,
                    "goto": 0, "break": 0,
                    "continue": 0, "cond_unknown": 0, "violations": 0,
                    "irreducible_functions": 0, "irreducible_blocks": 0,
                    "unreachable_blocks": 0, "goto_dense_functions": 0,
                    "blocks": 0}
    by_fn = {}
    if cand_report:
        for f in cand_report.get("functions") or []:
            by_fn[f["function"]] = f
    for f in funcs:
        if f["boundary"] != "declared" and not include_inferred:
            continue
        r = structure_function(res, f["addr"], by_fn.get(f["addr"]))
        if r.get("skipped"):
            continue
        s = r["stats"]
        per.append({"function": f["addr"], "symbol": f["symbol"],
                    "blocks": s["blocks_total"], "structured": s["structured"],
                    "if": s["if"], "while": s["while"] + s["do_while"] + s["for"],
                    "switch": s["switch"], "goto": s["goto"],
                    "violations": len(r["violations"]),
                    "goto_dense": s["goto_dense"]})
        tot["functions"] += 1
        tot["structured"] += 1 if s["structured"] else 0
        for k in ("if", "else", "while", "do_while", "for", "switch",
                  "switch_downgraded", "switch_no_candidate", "goto", "break",
                  "continue", "cond_unknown"):
            tot[k] += s[k]
        tot["violations"] += len(r["violations"])
        tot["blocks"] += s["blocks_total"]
        tot["irreducible_blocks"] += s["irreducible_blocks"]
        tot["irreducible_functions"] += 1 if s["irreducible_blocks"] else 0
        tot["unreachable_blocks"] += s["blocks_unreachable"]
        tot["goto_dense_functions"] += 1 if s["goto_dense"] else 0
    return {"functions": per, "stats": tot, "caveats": list(CAVEATS)}


# ── 渲染 ─────────────────────────────────────────────────────────────
def _ind(n):
    return "  " * n


def render(tree, depth=0):
    k = tree.get("kind")
    i = _ind(depth)
    out = []
    if k == "seq":
        for c in tree.get("children") or []:
            out.extend(render(c, depth))
        return out
    if k == "block":
        out.append("%sL_0x%x:  // blk 0x%x term=%s"
                   % (i, tree["block"], tree["block"],
                      tree.get("terminator")))
        for ln in tree.get("lines") or []:
            out.append("%s  %s" % (i, ln))
        for ln in tree.get("term") or []:
            out.append("%s  // %s" % (i, ln))
        return out
    if k == "if":
        # 条件块先输出，再输出 if —— 否则条件会被套进自己的 then 分支
        out.extend(render(tree["body"], depth))
        out.append("%sif (%s) {  // blk 0x%x  join=%s  edges=%s"
                   % (i, tree["cond"], tree["block"],
                      ("0x%x" % tree["join"]) if tree.get("join") else "exit",
                      ",".join("%s→0x%x" % (e["kind"], e["to"])
                               for e in tree.get("edges") or [])))
        out.extend(render(tree["then"], depth + 1))
        out.append("%s}%s" % (i, " else {" if tree.get("else") else ""))
        if tree.get("else"):
            out.extend(render(tree["else"], depth + 1))
            out.append("%s}" % i)
        return out
    if k == "while":
        out.append("%swhile (%s) {  // header=0x%x exit=%s back=%s"
                   % (i, tree["cond"], tree["header"],
                      ("0x%x" % tree["exit"]) if tree.get("exit")
                      else "∅（多出口：出口块在循环后按块原样输出）",
                      ",".join("0x%x" % x for x in tree.get("back_edges") or [])))
        # 头块的指令每轮都执行（cmp/test 就在头块里），所以放进循环体内，
        # 不能像 if 那样把 body 提到结构头之前（那会读成“只执行一次”）
        out.extend(render(tree["body"], depth + 1))
        out.extend(render(tree["inner"], depth + 1))
        out.append("%s}" % i)
        return out
    if k == "do_while":
        out.append("%sdo {  // header=0x%x latch=0x%x"
                   % (i, tree["header"], tree["latch"]))
        out.extend(render(tree["body"], depth + 1))
        out.append("%s} while (%s);" % (i, tree["cond"]))
        return out
    if k == "for":
        out.append("%sfor (;;) {  // header=0x%x latch=0x%x"
                   % (i, tree["header"], tree["latch"]))
        out.extend(render(tree["body"], depth + 1))
        out.append("%s}" % i)
        return out
    if k == "switch":
        c = tree["candidate"]
        out.append("%sswitch (%s) {  // jmp@0x%x table=0x%x evidence=%s"
                   % (i, tree.get("index_text") or "reg#%d" % tree["index_reg"],
                      c["jmp"], c["table"], c["evidence"]))
        out.extend(render(tree["body"], depth + 1))
        for case in tree["cases"]:
            out.append("%s  case %d: goto L_0x%x;   // 候选目标（未提升为表达式）"
                       % (i, case["index"], case["target"]))
        out.append("%s}  // 候选层口径：case 体不在确定集内" % i)
        return out
    if k == "break":
        out.append("%sif (%s) break;  // blk 0x%x → 0x%x（循环出口）"
                   % (i, tree["cond"], tree["block"], tree["target"]))
        return out
    if k == "continue":
        out.append("%sif (%s) continue;  // blk 0x%x → 0x%x（循环头，回边）"
                   % (i, tree["cond"], tree["block"], tree["target"]))
        return out
    if k == "goto":
        out.append("%sgoto L_0x%x;  // %s" % (i, tree["target"], tree.get("reason", "")))
        return out
    if k == "label":
        out.append("%sL_0x%x:  // %s" % (i, tree["block"], tree.get("reason", "")))
        for ln in tree.get("lines") or []:
            out.append("%s  %s" % (i, ln))
        for ln in tree.get("term") or []:
            out.append("%s  // %s" % (i, ln))
        return out
    if k == "unstructured":
        out.append("%s/* 未结构化: %s */" % (i, tree.get("reason", "")))
        if tree.get("body"):
            out.extend(render(tree["body"], depth))
        for t in tree.get("gotos") or []:
            out.append("%sgoto L_0x%x;  // 不可约循环：入口原样保留" % (i, t))
        return out
    return out


def render_function(r):
    if r.get("skipped"):
        return "STRUCT 0x%x: 跳过（%s）" % (r["function"], r["skipped"])
    s = r["stats"]
    head = [
        "// STRUCT 0x%x %s  blocks=%d reachable=%d emitted=%d"
        % (r["function"], r.get("symbol") or "", s["blocks_total"],
           s["blocks_reachable"], s["blocks_emitted"]),
        "// if %d / else %d / while %d / do-while %d / for %d / switch %d"
        % (s["if"], s["else"], s["while"], s["do_while"], s["for"], s["switch"]),
        "// goto %d（%.1f%% 块）%s / break %d / continue %d / 条件不可判 %d"
        % (s["goto"], 100 * s["goto_ratio"],
           "  ← goto 密集" if s["goto_dense"] else "", s["break"],
           s["continue"], s["cond_unknown"]),
        "// 不可约 %d 块 / 不可达 %d 块 / 可回溯违规 %d 项 / switch 降级 %d"
        % (s["irreducible_blocks"], s["blocks_unreachable"],
           len(r["violations"]), s["switch_downgraded"]),
        "// 约定: 每个结构头都标 block/edges/join；L_0x.. 为原始块起点，可回指 recdesc.blocks",
    ]
    return "\n".join(head + render(r["tree"]))
