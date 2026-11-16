#!/usr/bin/env python3
# tests/verify_callfacts.py — M6-U2 验收：跨函数参数传递的事实层
#
# 硬不变量（任一不成立 → FAIL/退出码 1）：
#   A) 账目对平：sites = direct + indirect；facts_before/after、abstains、
#      三级证据计数都能由 sites 独立重算得到（不信任模块自报的 counts）。
#   B) 操作数事实只允许 observed+derived 两级；declared 级证据只出现在
#      目标侧/函数域侧（绝不贴到"某个寄存器的值来自哪里"上）。
#   C) 同块窗口：s["facts"] 里 before.at < call < after.at，且都在调用点所在块内。
#      跨块结论必须单独放在 s["cross_facts"]，不得混进 s["facts"]（分开计数）。
#   D) 栈槽纪律：报出的 slot 事实，其基址寄存器在（定义点, 调用点）区间内
#      不得被**持久**写。R76：call 对 rsp 的写是持久写（复原证据在被调函数体内，
#      且 ret imm16 会多弹参数、调用约定未知），故窗口内含 call 的 rsp 槽事实
#      必须 abstain。判据独立化（R74）：写集合来自外部 objdump 的反汇编文本，
#      不经 callgraph._effects / _Ctx。独立路径只用于证伪（它说"没写"不作为通过
#      依据），未建模助记符单列计数；`--selftest` 注入错例必须被检出。
#   G) 跨块（M8-U1）：每条分支逐跳用 objdump 的**后继文本**复核（不看 recdesc
#      的边类别），定义指令必须真的写该操作数（objdump），且该块内其后无再写；
#      块的前驱完整性用 objdump 后继反推的集合复核；环/合流分歧/间接目标一律
#      abstain 且必须写清缺什么。
#   E) 与调用图一致：consistency.ok、checked = sites、矛盾 0；事实层构建前后
#      调用图的渲染逐字节一致（只读）。
#   F) 负向基线：三样本 recdesc 17 项 + cli-64.exe 表达式文本 sha256 不变。
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import callfacts as CF, callgraph as CG, disasm, expr, recdesc  # noqa: E402

SAMPLES = ["tests/fixtures/cli-64.exe", "tests/fixtures/bin_ls.elf",
           "tests/fixtures/dyn_static"]
BASELINE = os.path.join(HERE, "baselines", "definite_baseline.json")


def _base_of(slot):
    return slot[1:].split("]")[0].split("+")[0].split("-")[0]


# ── R74：栈槽纪律的独立判据（不复用被测实现的效果判定） ──────────────
# 两条路径本来就可能不同，差异与处理方式：
#   · 数据来源不同：objdump 文本 vs expr.decode 记录 → 外部工具，不经被测栈；
#   · 覆盖不同：本路径只建模「首操作数=目的」+ 少量体系结构隐式写规则，
#     未建模的助记符返回 None（不结论）。因此它**只能证伪**：报出写 → FAIL；
#     说"没写"不代表真的没写，不作为通过依据；
#   · 别名：objdump 可能打 ebp/esp，必须归一到 64 位名，否则会漏报；
#   · 指令集合以 recdesc 解出的地址为准（只取交集），避免把数据当指令。
_GPR64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
_ALIAS = {}
for _r, _subs in (("rax", ("eax", "ax", "al", "ah")),
                  ("rbx", ("ebx", "bx", "bl", "bh")),
                  ("rcx", ("ecx", "cx", "cl", "ch")),
                  ("rdx", ("edx", "dx", "dl", "dh")),
                  ("rsi", ("esi", "si", "sil")), ("rdi", ("edi", "di", "dil")),
                  ("rbp", ("ebp", "bp", "bpl")), ("rsp", ("esp", "sp", "spl")),
                  ("rip", ("eip", "ip"))):
    for _s in _subs:
        _ALIAS[_s] = _r
for _k in range(8, 16):
    for _suf in ("d", "w", "b", ""):
        _ALIAS["r%d%s" % (_k, _suf)] = "r%d" % _k

_NO_DEST = frozenset((
    "cmp", "test", "bt", "ucomiss", "ucomisd", "comiss", "comisd",
    "vucomiss", "vucomisd", "vcomiss", "vcomisd", "ptest", "vptest",
    "nop", "endbr64", "endbr32", "prefetch", "prefetcht0", "prefetcht1",
    "prefetcht2", "prefetchnta", "clflush", "pause", "cld", "std",
    "lfence", "sfence", "mfence", "ud2", "int3", "hlt",
))
_IMPLICIT = {                       # 隐式写（不含显式目的操作数）
    "push": {"rsp"}, "pushfq": {"rsp"}, "pushfd": {"rsp"},
    "pop": {"rsp"}, "popfq": {"rsp"}, "popfd": {"rsp"},
    "ret": {"rsp"}, "retf": {"rsp"},
    "leave": {"rsp", "rbp"}, "enter": {"rsp", "rbp"},
    "mul": {"rax", "rdx"}, "div": {"rax", "rdx"}, "idiv": {"rax", "rdx"},
    "cdq": {"rdx"}, "cqo": {"rdx"}, "cdqe": {"rax"}, "cwde": {"rax"},
}
# call 的 rsp 写是**持久写**（R76）：复原证据在被调函数体内，且 ret imm16 会
# 多弹参数、调用约定未知，无法判定。这里不设「call 不算写」的豁免，而是让
# call 像其它指令一样报出它写的寄存器；「是否持久」由下面的判据统一决定。
_NO_DEST_XFER = frozenset(("jmp", "ljmp"))   # 只转移控制，不写通用寄存器


def _canon(name):
    name = name.strip()
    if name in _ALIAS:
        return _ALIAS[name]
    return name if name in _GPR64 else None


def _split_ops(text):
    """按顶层逗号切操作数（不切 `[...]` 里的逗号）。"""
    text = text.split("#")[0].strip()
    if not text:
        return []
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    out.append(cur.strip())
    return out


def _objdump_writes(path, text_va):
    """objdump -d 文本 → {addr: (mnemonic, [operands])}，地址归一到 recdesc 口径。

    只收 `Disassembly of section .text:` 之后的行；地址基准用该节第一条指令与
    recdesc 的 .text 起始地址之差推出（PE 的 ImageBase、PIE 与否都不写死）。
    """
    exe = shutil.which("objdump")
    if not exe:
        raise RuntimeError("找不到 objdump：R74 独立判据需要 binutils 的 objdump 在 PATH 上")
    p = subprocess.run([exe, "-d", "-M", "intel", "--no-show-raw-insn", path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("objdump 失败：%s"
                           % p.stderr.decode("utf-8", "replace")[:200])
    out, delta, sec = {}, None, None
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        m = re.match(r"^Disassembly of section (\S+):", line.strip())
        if m:
            sec = m.group(1)
            continue
        if sec != ".text":
            continue
        m = re.match(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if delta is None:
            delta = addr - text_va
        out[addr - delta] = (m.group(2).lower(), _split_ops(m.group(3)))
    if delta is None:
        raise RuntimeError("objdump 输出里没有 .text 的反汇编，无法对齐地址")
    return out, delta


def _writes(mn, ops):
    """独立判定：该指令**持久**写哪些寄存器。返回 set；未建模 → None（不结论）。"""
    if mn in _NO_DEST or mn in _NO_DEST_XFER:
        return set()
    if mn in ("call", "lcall"):
        # R76：call 确实写 rsp（压返回地址）。按 T1 它需要「同一函数内已解出的
        # 复原证据」，而 ret 在被调函数体内、且 ret imm16 的净效果取决于调用
        # 约定 → 该写不可判定为暂态，按持久写报出。
        return {"rsp"}
    if mn.startswith("j"):
        return set()
    if mn in ("xchg", "xadd", "cmpxchg"):
        return {r for r in (_canon(o) for o in ops) if r}
    implicit = _IMPLICIT.get(mn)
    w = set(implicit or ())
    if mn == "imul" and len(ops) == 1:
        w |= {"rax", "rdx"}
    if mn in ("pop", "popfq", "popfd") and ops:
        r = _canon(ops[0])
        if r:
            w.add(r)
    if ops:
        first = ops[0]
        if "[" not in first and "PTR" not in first:
            r = _canon(first)
            if r:
                w.add(r)
            elif implicit is None:
                return None            # 首操作数既不是寄存器也不是内存：不建模
    elif implicit is None:
        return None                    # 无操作数且不在隐式表：不建模
    return w


def _written(wmap, addr):
    ent = wmap.get(addr)
    if ent is None:
        return None
    return _writes(*ent)


def _slot_scan(rel, facts, blk_of, wmap):
    """D) 栈槽纪律。返回 (fails, stats)。"""
    fails = []
    st = {"slot_facts": 0, "slot_abstains": 0, "lookups": 0,
          "unmodeled": 0, "violations": 0}
    for s in facts["sites"]:
        b = blk_of.get(s["from"])
        if b is None:
            continue
        for f in s["facts"]:
            if f["kind"] != "slot":
                continue
            st["slot_facts"] += 1
            base = _base_of(f["operand"])
            if base not in _GPR64:
                fails.append("%s: 栈槽 %s 基址不可识别" % (rel, f["operand"]))
                continue
            for a in b["insns"]:
                if not (f["at"] < a < s["from"]):
                    continue
                st["lookups"] += 1
                w = _written(wmap, a)
                if w is None:
                    st["unmodeled"] += 1
                    continue
                if base in w:
                    st["violations"] += 1
                    fails.append("%s: 槽事实 %s @0x%x 的基址 %s 在 0x%x 被改写"
                                 "（独立判据：objdump 文本）"
                                 % (rel, f["operand"], f["at"], base, a))
                    break
        for a in s["abstains"]:
            if not a["scope"].startswith("slot:"):
                continue
            st["slot_abstains"] += 1
            if "缺" not in a["missing"]:
                fails.append("%s: 槽弃权 0x%x 未写缺什么" % (rel, s["from"]))
            addr = [int(x, 16) for x in re.findall(r"0x([0-9a-f]+)", a["missing"])]
            if not addr or addr[-1] >= s["from"]:
                fails.append("%s: 槽弃权 0x%x 的改写地址不在调用点之前"
                             % (rel, s["from"]))
    return fails, st


def _branch_target(text):
    """objdump 的直接跳转目标：`48fa <sym+0x1d2>` → 0x48fa（无 0x 前缀）。"""
    m = re.match(r"^([0-9a-f]+)(?:\s|$)", text.strip())
    return int(m.group(1), 16) if m else None


def _objdump_edges(res, wmap, blk_by_start, delta):
    """用 objdump 文本独立推出每块后继，不看 recdesc 的边类别。

    返回 {块首: set(后继块首)|None}；None = 该块终结符无法判定（间接跳转、
    代码边界不可读）。只用于 G 段的逐跳复核与「前驱是否完整」的独立反推。
    跳转目标来自 objdump 文本，必须减掉同一 delta 才能和块首地址对齐。
    """
    succ = {}
    for b in res["blocks"]:
        last = b["insns"][-1]
        ent = wmap.get(last)
        if ent is None:
            succ[b["start"]] = None
            continue
        mn, ops = ent

        def tgt():
            t = _branch_target(ops[0]) if ops else None
            return None if t is None else t - delta

        if mn in ("ret", "retf", "hlt", "ud2", "int3"):
            succ[b["start"]] = set()
            continue
        if mn == "jmp":
            t = tgt()
            succ[b["start"]] = {t} if t in blk_by_start else None
            continue
        if mn.startswith("j"):
            t = tgt()
            ft = b["end"]
            if t is None or t not in blk_by_start or ft not in blk_by_start:
                succ[b["start"]] = None
            else:
                succ[b["start"]] = {t, ft}
            continue
        succ[b["start"]] = {b["end"]} if b["end"] in blk_by_start else None
    return succ


def _cross_scan(rel, facts, res, wmap, blk_by_start, blk_of, delta):
    """G) 跨块结论的独立复核（objdump 文本，外部工具）。"""
    fails = []
    st = {"facts": 0, "abstains": 0, "sites": 0, "branches": 0, "hops": 0,
          "def_writes": 0, "unmodeled": 0, "incomplete": 0}
    succ = _objdump_edges(res, wmap, blk_by_start, delta)
    preds = {}
    for p, ss in succ.items():
        for c in ss or ():
            preds.setdefault(c, set()).add(p)
    for s in facts["sites"]:
        b = blk_of.get(s["from"])
        cf = s.get("cross_facts") or []
        ca = s.get("cross_abstains") or []
        if cf or ca:
            st["sites"] += 1
        # 分开存放：跨块结论不得混进同块事实
        same = {(x["kind"], x["operand"]) for x in s["facts"]
                if x["direction"] == "before"}
        for f in cf:
            st["facts"] += 1
            if f["kind"] != "reg":
                fails.append("%s: 跨块事实 0x%x 不是寄存器操作数"
                             % (rel, s["from"]))
            if (f["kind"], f["operand"]) in same:
                fails.append("%s: 跨块事实 0x%x 与同块事实重复"
                             % (rel, s["from"]))
            db = blk_of.get(f["at"])
            if b is None or db is None:
                fails.append("%s: 跨块事实 0x%x 的块归属缺失" % (rel, f["at"]))
                continue
            if db["start"] == b["start"]:
                fails.append("%s: 跨块事实 0x%x 的定义与调用点同块"
                             % (rel, f["at"]))
            # 定义指令必须真的写该操作数（外部工具），且该块内其后无再写
            w = _written(wmap, f["at"])
            if w is None:
                st["unmodeled"] += 1
            elif f["operand"] not in w:
                fails.append("%s: 跨块事实 0x%x 声称定义了 %s，但 objdump 文本里"
                             "该指令不写它" % (rel, f["at"], f["operand"]))
            else:
                st["def_writes"] += 1
            for a in db["insns"]:
                if a <= f["at"] or a >= s["from"]:
                    continue
                w2 = _written(wmap, a)
                if w2 is None:
                    st["unmodeled"] += 1
                elif f["operand"] in w2:
                    fails.append("%s: 跨块事实 0x%x 之后 0x%x 又写了 %s（不是最后一次）"
                                 % (rel, f["at"], a, f["operand"]))
                    break
            # 每条分支逐跳复核（objdump 后继文本）
            for br in f["branches"]:
                st["branches"] += 1
                if not br or br[0] != b["start"]:
                    fails.append("%s: 跨块分支未从调用点所在块 0x%x 起"
                                 % (rel, b["start"]))
                    continue
                if len(set(br)) != len(br):
                    fails.append("%s: 跨块分支 0x%x 含重复块（成环）"
                                 % (rel, s["from"]))
                    continue
                if br[-1] != db["start"]:
                    fails.append("%s: 跨块分支 0x%x 的末端不是定义块 0x%x"
                                 % (rel, s["from"], db["start"]))
                    continue
                # 分支是**上游**序列：br[0] = 调用点所在块，br[-1] = 定义块。
                # 所以边的方向是 br[i] → br[i-1]（卫语句在前，前驱在后）。
                for i in range(1, len(br)):
                    child, parent = br[i - 1], br[i]
                    st["hops"] += 1
                    sp = succ.get(parent)
                    if sp is None:
                        fails.append("%s: objdump 无法判定块 0x%x 的后继，"
                                     "跨块边 0x%x→0x%x 不可复核"
                                     % (rel, parent, parent, child))
                        break
                    if child not in sp:
                        fails.append("%s: 跨块边 0x%x→0x%x 不在 objdump 后继里"
                                     % (rel, parent, child))
                        break
                    want = {x for x in preds.get(child, set())
                            if (blk_by_start.get(x) or {}).get("function")
                            == db["function"]}
                    got = {br2[i] for br2 in f["branches"]
                           if len(br2) > i and br2[i - 1] == child}
                    if want and got != want:
                        st["incomplete"] += 1
                        fails.append(
                            "%s: 块 0x%x 的确定前驱不完整：objdump 反推 %s ｜ "
                            "分支里只有 %s"
                            % (rel, child, sorted("0x%x" % x for x in want),
                               sorted("0x%x" % x for x in got)))
                        break
        for a in ca:
            st["abstains"] += 1
            if not a["scope"].startswith("cross:"):
                fails.append("%s: 跨块弃权 scope 非法 %r" % (rel, a["scope"]))
            if "缺" not in a["missing"]:
                fails.append("%s: 跨块弃权 0x%x 未写缺什么" % (rel, s["from"]))
    cc = facts["cross_block"]["counts"]
    if (cc["facts"], cc["abstains"], cc["sites"]) != (
            st["facts"], st["abstains"], st["sites"]):
        fails.append("%s: 跨块账目与站点重算不一致（自报 %r）"
                     % (rel, (cc["facts"], cc["abstains"], cc["sites"])))
    if not facts["cross_block"].get("traced"):
        fails.append("%s: 跨块追踪未开启（M8-U1 应已开启）" % rel)
    return fails, st


def check_sample(rel, baseline):
    path = os.path.join(WORK, rel)
    res = recdesc.descend(path)
    graph = CG.build(path, res=res)
    render_before = CG.render(graph)
    facts = CF.build(path, res=res, graph=graph)
    render_after = CG.render(graph)
    fails = []

    # A) 独立重算账目
    c = facts["counts"]
    fs = [f for s in facts["sites"] for f in s["facts"]]
    re_before = sum(1 for f in fs if f["direction"] == "before")
    re_after = sum(1 for f in fs if f["direction"] == "after")
    re_abst = sum(len(s["abstains"]) for s in facts["sites"])
    if (re_before, re_after, re_abst) != (c["facts_before"], c["facts_after"],
                                          c["abstains"]):
        fails.append("%s: 事实/弃权账目与站点重算不一致" % rel)
    if c["sites"] != c["direct"] + c["indirect"] or c["sites"] != len(facts["sites"]):
        fails.append("%s: 站点数账目不平" % rel)
    for lvl in CF.LEVELS:
        want = sum(1 for f in fs for e in f["evidence"] if e["level"] == lvl)
        if want != c["evidence"][lvl]:
            fails.append("%s: 操作数证据 %s 计数不一致" % (rel, lvl))
        want_t = sum(1 for s in facts["sites"] for e in s["target_evidence"]
                     if e["level"] == lvl)
        if want_t != c["target_evidence"][lvl]:
            fails.append("%s: 目标证据 %s 计数不一致" % (rel, lvl))

    # B) 证据分级纪律
    for f in fs:
        if [e["level"] for e in f["evidence"]] != ["observed", "derived"]:
            fails.append("%s: 操作数事实证据等级非法 @0x%x" % (rel, f["at"]))
            break
    for s in facts["sites"]:
        for e in s["target_evidence"]:
            if e["level"] not in CF.LEVELS or not e["source"] or not e["text"]:
                fails.append("%s: 目标证据条目不完整 @0x%x" % (rel, s["from"]))
                break
        if any(a["scope"] == "full_argument_set" for a in s["abstains"]) is False:
            fails.append("%s: 站点 0x%x 缺少「不判定参数」的 abstain"
                         % (rel, s["from"]))
            break
        if s["call_kind"] == "indirect" and (s["state"] is not None
                                             or s["target"] is not None):
            fails.append("%s: 间接站点 0x%x 出现在三态/目标里" % (rel, s["from"]))
            break

    # C) 同块窗口
    blk_of = {}
    for b in res["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    for s in facts["sites"]:
        b = blk_of.get(s["from"])
        if b is None:
            fails.append("%s: 站点 0x%x 不在任何块" % (rel, s["from"]))
            break
        for f in s["facts"]:
            ok = b["start"] <= f["at"] <= b["end"]
            ok = ok and (f["at"] < s["from"] if f["direction"] == "before"
                         else f["at"] > s["from"])
            if not ok:
                fails.append("%s: 事实 0x%x 越出调用点 0x%x 的同块窗口"
                             % (rel, f["at"], s["from"]))
                break
        want_cb = ("traced" if s.get("cross_facts") else
                   ("abstained" if s.get("cross_abstains") else "same_block"))
        if s["cross_block"] != want_cb:
            fails.append("%s: 站点 0x%x 的 cross_block 标记与内容不符"
                         % (rel, s["from"]))
            break

    # D) 栈槽纪律（独立判据：objdump 文本，不复用 callgraph._effects）
    wmap, delta = _objdump_writes(path, disasm.find_section(path, ".text")["va"])
    d_fails, dst = _slot_scan(rel, facts, blk_of, wmap)
    fails.extend(d_fails)
    if dst["lookups"] and dst["unmodeled"] * 2 > dst["lookups"]:
        fails.append("%s: 独立判据未建模 %d/%d（>50%%），判据失效"
                     % (rel, dst["unmodeled"], dst["lookups"]))
    # G) 跨块（独立判据：objdump 后继文本 + 写集合）
    blk_by_start = {b["start"]: b for b in res["blocks"]}
    g_fails, gst = _cross_scan(rel, facts, res, wmap, blk_by_start, blk_of, delta)
    fails.extend(g_fails)

    # E) 与调用图一致 + 只读（含 --observe 的操作数结论交叉核对）
    con = facts["consistency"]
    if not con["ok"] or con["contradictions"]:
        fails.append("%s: 与调用图存在 %d 条矛盾"
                     % (rel, len(con["contradictions"])))
    if con["checked"] != c["sites"]:
        fails.append("%s: 一致性核对数 != 站点数" % rel)
    if render_before != render_after:
        fails.append("%s: 事实层构建改写了调用图渲染" % rel)
    obs = CG.build(path, res=res, observe=True)
    o_by = {o["from"]: o for o in obs["observations"]}
    for s in facts["sites"]:
        o = o_by[s["from"]]
        for d, key in (("before", "before_defs"), ("after", "after_uses")):
            fb = {f["operand"] for f in s["facts"]
                  if f["direction"] == d and f["kind"] == "reg"}
            ob = {x["operand"] for x in o[key] if x["kind"] == "reg"}
            if fb != ob:
                fails.append("%s: 0x%x %s 寄存器结论与 --observe 不一致"
                             % (rel, s["from"], d))
                break
            fs = {f["operand"] for f in s["facts"]
                  if f["direction"] == d and f["kind"] == "slot"}
            os_ = {x["operand"] for x in o[key] if x["kind"] == "slot"}
            if not fs <= os_:
                fails.append("%s: 0x%x %s 槽结论超出 --observe（%s）"
                             % (rel, s["from"], d, sorted(fs - os_)))
                break

    # F) 负向基线
    for k, want in baseline["recdesc"].items():
        got = res["stats"].get(k)
        if want != got:
            fails.append("%s: recdesc.%s 基线 %r != 现 %r" % (rel, k, want, got))
    expr_sha = None
    if rel == "tests/fixtures/cli-64.exe":
        b = expr.lift_binary(path, res=res)
        expr_sha = hashlib.sha256("\n".join(
            expr.lift_function(res, f["function"])["text"]
            for f in b["functions"]).encode()).hexdigest()
        if expr_sha != baseline["expr"]["text_sha256"]:
            fails.append("%s: 表达式文本 sha256 变化" % rel)

    st = {
        "sites": c["sites"], "direct": c["direct"], "indirect": c["indirect"],
        "facts_before": c["facts_before"], "facts_after": c["facts_after"],
        "abstains": c["abstains"], "evidence": c["evidence"],
        "target_evidence": c["target_evidence"],
        "declared_func_sites": sum(1 for s in facts["sites"]
                                   if s["function_declaration"]["level"] == "declared"),
        "derived_func_sites": sum(1 for s in facts["sites"]
                                  if s["function_declaration"]["level"] == "derived"),
        "slot_facts": dst["slot_facts"], "slot_abstains": dst["slot_abstains"],
        "slot_lookups": dst["lookups"], "slot_unmodeled": dst["unmodeled"],
        "slot_violations": dst["violations"],
        "cross_facts": gst["facts"], "cross_abstains": gst["abstains"],
        "cross_sites": gst["sites"], "cross_branches": gst["branches"],
        "cross_hops": gst["hops"], "cross_def_writes": gst["def_writes"],
        "cross_unmodeled": gst["unmodeled"],
        "cross_incomplete": gst["incomplete"],
        "cross_reasons": facts["cross_block"]["abstain_reasons"],
        "window_barriers": sum(1 for s in facts["sites"] for a in s["abstains"]
                               if a["scope"].startswith("window_")),
        "consistency_checked": con["checked"],
        "contradictions": len(con["contradictions"]),
        "expr_sha": expr_sha,
    }

    print("\n=== %s ===" % rel)
    print("站点 %d（直接 %d ｜ 间接 %d）"
          % (st["sites"], st["direct"], st["indirect"]))
    print("事实 before %d / after %d ｜ abstain %d"
          % (st["facts_before"], st["facts_after"], st["abstains"]))
    print("操作数证据 declared %d / observed %d / derived %d ｜ "
          "目标证据 declared %d / observed %d / derived %d"
          % (st["evidence"]["declared"], st["evidence"]["observed"],
             st["evidence"]["derived"], st["target_evidence"]["declared"],
             st["target_evidence"]["observed"], st["target_evidence"]["derived"]))
    print("函数域: declared %d 站 ｜ derived %d 站 ｜ 栈槽事实 %d ｜ 槽弃权 %d ｜ "
          "窗口截断 %d"
          % (st["declared_func_sites"], st["derived_func_sites"],
             st["slot_facts"], st["slot_abstains"], st["window_barriers"]))
    print("独立判据（objdump）: 窗口内查写 %d 次 ｜ 未建模 %d ｜ 违规 %d"
          % (st["slot_lookups"], st["slot_unmodeled"], st["slot_violations"]))
    print("跨块（只走确定边）: 事实 %d ｜ 弃权 %d ｜ 站点 %d ｜ 分支 %d ｜ 逐跳 "
          "复核 %d ｜ 定义指令经 objdump 确认 %d ｜ 未建模 %d ｜ 前驱不完整 %d"
          % (st["cross_facts"], st["cross_abstains"], st["cross_sites"],
             st["cross_branches"], st["cross_hops"], st["cross_def_writes"],
             st["cross_unmodeled"], st["cross_incomplete"]))
    print("一致性: checked %d ｜ 矛盾 %d ｜ 调用图渲染只读 %s"
          % (st["consistency_checked"], st["contradictions"],
             "OK" if render_before == render_after else "FAIL"))
    return fails, st


def selftest():
    """注入自证：三类注入都必须被独立判据检出/不误报。

    1) 正例：伪造一条槽事实，基址在定义点之后被指令改写 → D 段必须检出；
    2) R76 正例：伪造一条 rsp 基址槽事实，窗口内含 call（call 写 rsp 且不可判定
       为暂态）→ D 段必须检出。这条专门证明 R76 不是空转的开关；
    3) 负例：干净窗口（无 rbp/rsp 写、无 call）的槽事实 → 不得误报。

    真实样本里实现已经把这些情况转成 abstain，所以不能靠真实数据证明检查器
    不是空转；这里直接造错的槽事实，走与 check_sample 完全相同的 D 段路径。
    """
    rel = SAMPLES[0]
    path = os.path.join(WORK, rel)
    res = recdesc.descend(path)
    graph = CG.build(path, res=res)
    facts = CF.build(path, res=res, graph=graph)
    blk_of = {}
    for b in res["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    wmap, _delta = _objdump_writes(path, disasm.find_section(path, ".text")["va"])

    def fake_slot(call, at, base):
        return {"sites": [{"from": call, "abstains": [], "facts": [
            {"kind": "slot", "direction": "before", "at": at,
             "operand": "[%s-0x8]" % base}]}]}

    # 正例：伪造一条基址在定义点之后被改写的槽事实 → 必须检出
    for s in facts["sites"]:
        b = blk_of.get(s["from"])
        if b is None:
            continue
        for a in b["insns"]:
            if not (b["start"] < a < s["from"]):
                continue
            w = _written(wmap, a) or set()
            base = next((r for r in ("rbp", "rsp") if r in w), None)
            if base is None:
                continue
            _f2, st2 = _slot_scan(rel, fake_slot(s["from"], b["start"], base),
                                  blk_of, wmap)
            if st2["violations"]:
                print("[selftest] 正例 %s 伪造槽事实 [%s-0x8] @0x%x（0x%x 已改写基址）"
                      % (rel, base, b["start"], a))
                print("[selftest] 已检出（独立化后仍能失败）→ 通过")
                break
        else:
            continue
        break
    else:
        print("[selftest] 未检出：独立判据是空转的 → 失败")
        return 1

    # R76 正例：窗口内含 call 的 rsp 槽事实 → 必须检出
    for s in facts["sites"]:
        b = blk_of.get(s["from"])
        if b is None:
            continue
        call_in = next((a for a in b["insns"] if b["start"] < a < s["from"]
                        and (wmap.get(a) or ("",))[0] in ("call", "lcall")), None)
        if call_in is None:
            continue
        _f4, st4 = _slot_scan(rel, fake_slot(s["from"], b["start"], "rsp"),
                              blk_of, wmap)
        if not st4["violations"]:
            print("[selftest] R76 未检出：窗口内含 call 的 rsp 槽事实被判合法 → 失败")
            return 1
        print("[selftest] R76 正例 0x%x 窗口内含 call 0x%x，伪造 [rsp-0x8] 槽事实"
              "→ 已检出（call 的 rsp 写按持久写）" % (s["from"], call_in))
        break
    else:
        print("[selftest] 找不到窗口内含 call 的站点做 R76 正例（跳过）")

    # 负例：把「干净窗口」（中间没有任何 rbp/rsp 写）的槽事实塞进去 → 不得误报
    for s in facts["sites"]:
        b = blk_of.get(s["from"])
        if b is None:
            continue
        dirty = any(
            (_written(wmap, a) or set()) & {"rbp", "rsp"}
            for a in b["insns"] if b["start"] < a < s["from"])
        if dirty:
            continue
        _f3, st3 = _slot_scan(rel, fake_slot(s["from"], b["start"], "rsp"),
                              blk_of, wmap)
        if st3["violations"]:
            print("[selftest] 负例误报：干净窗口被判违规 → 失败")
            return 1
        print("[selftest] 负例 0x%x 干净窗口未误报 → 通过" % s["from"])
        return 0
    print("[selftest] 找不到干净窗口做负向对照（跳过，不视为失败）")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    baseline = json.load(open(BASELINE, encoding="utf-8"))
    out, fails = {}, []
    for rel in SAMPLES:
        f, st = check_sample(rel, baseline[rel])
        out[rel] = st
        fails.extend(f)
    if args.json:
        print(json.dumps({"stats": out, "failures": fails},
                         ensure_ascii=False, indent=2))
    print("\n结果: %s" % ("PASS" if not fails else "FAIL"))
    for x in fails:
        print("  ! %s" % x)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
