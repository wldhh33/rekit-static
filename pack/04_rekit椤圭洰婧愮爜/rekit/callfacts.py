#!/usr/bin/env python3
# rekit.callfacts — 跨函数参数传递的「事实层」（M6-U2）
#
# 这一层不回答「参数是什么」，只回答「调用点前后，哪些寄存器/栈槽在什么地址
# 被写/被读，证据是什么等级、来自哪里」。三条硬约束：
#
#   1) 证据必须分三级、分开报，不得混成一个"已确定"：
#        declared  文件/链接器写死的声明：节表、导入表(IAT)、重定位(.rela.plt)、
#                  符号表、.pdata(RUNTIME_FUNCTION)、.eh_frame FDE、st_size。
#                  这一类是"别人写进文件的声明"，我们只是读出来。
#        observed  字节事实：某地址的指令原始字节、call 目标地址的算术结果。
#                  我们读到了字节，但没有解释它的语义。
#        derived   我方推导：同一基本块内线性倒扫的"最后一次定义"/顺序扫描的
#                  "首次使用"、按 FF25 形态判定导入跳板、按块归属推断函数域。
#                  这一类是本工具算出来的，换实现可能变，必须单独标注。
#       → 每一条证据是 {level, source, text}，绝不存在"混合等级"的单条证据。
#
#   2) 不做 ABI 推断：不猜参数个数、不给参数命名、不认定调用约定。
#      因此本层不产出"参数列表"，只产出「调用点状态（寄存器/栈槽的读写事实）」，
#      并对"哪些操作数是参数"统一 abstain（缺调用约定证据）。
#      证据不足一律 abstain，并写清缺什么（missing）。
#
#   3) 跨块数据流（M8-U1）：只在「确定边」上追，且只追定义侧（before）。
#      · 边只认 recdesc 的 cfg.edges.definite（函数有权威声明 end、根非启发式、
#        目标已解出且同函数）；疑似边一律不用，不为了让数字好看把疑似当确定；
#      · 目标块若有非确定入边（疑似/跨函数/目标未解出/间接目标）→ 回溯不完整，
#        该操作数 abstain 并写清缺哪一类入边的判定；
#      · 合流点要求**所有**确定前驱给出同一个定义地址，否则 abstain；
#      · 回边（循环）靠回溯栈检测，遇环即 abstain（缺不动点迭代/循环不变式）；
#      · 跨块只追寄存器操作数；栈槽要跨块栈指针值追踪，一律 abstain。
#
#   4) R76：窗口内的写只有「可判定复原」才算暂态写，否则按持久写处理。
#      判据见 _TRANSIENT_RULE；`call` 对 rsp 的写是这条判据的应用结果，
#      不是「call 不算写 rsp」的特例豁免。
#
# 与调用图（M6-U1）的关系：同一批调用点、同一份 recdesc 结果。本层**独立重算**
# 目标三态的证据项，再与调用图的 state 逐点比对；不一致的单列在 consistency，
# 绝不悄悄以某一方为准。
#
# 特别地，栈槽只在基址寄存器（rsp/rbp）在"定义点之后、调用点之前"未被改写时
# 才作为事实报出；否则该槽 abstain（缺栈指针/帧基址的值追踪）。这条是 M6-U1
# 只加提示、本单元升级为 abstain 的唯一口径变化，先写在此处再实现。
import json
import sys

from . import callgraph as CG, expr, paramdecl as PD, recdesc

LEVELS = ("declared", "observed", "derived")

LEVEL_LEGEND = {
    "declared": "文件/链接器声明：节表、导入表(IAT)、重定位、符号表、"
                ".pdata/.eh_frame FDE、st_size（读出来，不是我方推导）",
    "observed": "字节事实：某地址的指令原始字节、call 目标地址的算术结果",
    "derived": "我方推导：同块倒扫的最后定义/顺序扫描的首次使用、"
               "FF25 跳板形态判定、按基本块归属推断函数域、跨块确定边回溯",
}

CAVEATS = [
    "本层不产出参数列表：不猜参数个数、不给参数命名、不认定调用约定（禁止 ABI 推断）",
    "「哪些操作数是参数」统一 abstain：缺调用约定证据；事实只描述读写位置与来源",
    "参数绑定（M8-U2）只认文件里真有的声明：DWARF DW_TAG_formal_parameter + 位置；",
    "导出表/符号表/COFF 只声明函数身份，不含参数（结构性）；PDB 引用可定位但本轮未解码 → abstain",
    "没有可读形参声明时，param_binding.available=false：不是「0 个参数」，是整体不可判定",
    "before/after 的同块窗口不变；跨块只追定义侧（before）且只走确定边，",
    "跨块不追使用侧（after）：缺「沿确定后继路径的首次使用」判定，故不报",
    "栈槽仅在基址寄存器于「定义点之后、调用点之前」未被持久改写时作为事实，否则 abstain",
    "R76：call 对 rsp 的写按持久写处理（复原依赖被调方 ret 与调用约定，本工具不推断）",
    "窗口内的 call 不建模被调方对其它寄存器的破坏：寄存器事实只回答「窗口内最后一次显式写」，",
    "derived 级证据都是本工具算出来的，不是链接器声明",
    "间接调用目标不可静态确定：目标侧 abstain，操作数事实照常（与候选层无关）",
]

# M8-U2：参数绑定的判据（先于实现写在这里，便于被反驳）
PARAM_RULE = (
    "只有声明来源能给出「第 k 个形参在函数入口位于哪个寄存器/栈位置」时，"
    "才把调用点该寄存器的最后定义绑定到第 k 个形参。"
    "声明必须能指到文件偏移/节/DIE/位置表达式；读不到即 abstain。"
    "导出表、COFF/ELF 符号表、.eh_frame、.pdata 只声明函数身份/范围，"
    "不声明参数（结构性缺失）；PDB 本轮只定位到 RSDS 与 TPI 流，未解码位置记录，"
    "因此 PDB 来源一律 abstain。禁止按寄存器顺序/平台惯例补参数——那不是声明证据。"
)

# R76：暂态写的可判定定义。写在这里是为了让判据先于实现被读到、被反驳。
_TRANSIENT_RULE = (
    "设指令 w（地址 a）写寄存器 r，目标点 t > a。w 对 (r, t) 是**暂态写**，"
    "当且仅当存在 b（a < b ≤ t）使 (T1) b 是同一函数内**已解出**的指令，且把 r "
    "写成 a 之前 r 的值（可判定的复原证据）；(T2) (a, b) 内没有对 r 的其它写；"
    "(T3) (b, t) 内没有对 r 的写。本轮可判定的复原证据集合为**空**：没有任何"
    "「抵消配对」被承认为证据（理由见下）。因此窗口内除 t 自身外，任何写都是持久写。"
)
_TRANSIENT_CALL = (
    "call 写 rsp（压返回地址）。它的复原证据在**被调函数体内**（ret 弹返回地址），"
    "不在本函数已解出的窗口内；且 `ret imm16` 会额外弹出参数（stdcall 清栈），"
    "净效果取决于调用约定——本工具禁止 ABI 推断。故 T1 不成立，call 的 rsp 写是持久写。"
)
_TRANSIENT_FALSIFY = (
    "证伪方式：给出一个被报出的 rsp 基址槽事实，其窗口内的 call 目标在返回时 rsp "
    "与进入时不等（如 `ret 8` 的被调方、或在被调方里 pop 掉返回地址后尾跳），"
    "该槽在调用点的地址就与定义点不同，事实即错。反方向同样可证伪：若把 call 判成"
    "暂态，任何 callee-cleanup 的被调方都能立刻造出上面这个反例。"
)


_DECLARED_SOURCES = {"pdata", "eh_frame_fde", "symtab_func", "dynsym_func",
                     "export", "entry"}


def _ev(level, source, text):
    assert level in LEVELS
    return {"level": level, "source": source, "text": text}


def _slot_base(operand):
    """`[rbp-0x8]` → `rbp`（callgraph._slot_name 的逆，只取基址名）。"""
    return operand[1:].split("]")[0].split("+")[0].split("-")[0]


# ── 函数域：声明 vs 推导 ─────────────────────────────────────────────
def _func_declaration(ctx, fn):
    """函数域的来源必须分开：有声明报 declared，否则报 derived。"""
    if fn is None:
        return {"level": "derived", "sources": [], "range": [None, None],
                "text": "调用点不属于任何已解出函数（无块归属）"}
    seed = ctx.seeds.get(fn)
    srcs = [s for s in (seed or {}).get("sources") or []
            if s in _DECLARED_SOURCES]
    if seed and seed.get("end") and srcs:
        return {"level": "declared", "sources": sorted(set(srcs)),
                "authority": seed.get("authority"),
                "range": [fn, seed["end"]],
                "text": "函数域来自文件声明 %s：0x%x..0x%x"
                        % ("/".join(sorted(set(srcs))), fn, seed["end"])}
    if seed and seed.get("end"):
        return {"level": "derived", "sources": sorted(set(seed["sources"])),
                "authority": seed.get("authority"),
                "range": [fn, seed["end"]],
                "text": "函数域只有启发式来源（%s），按推导报出"
                        % "/".join(seed["sources"])}
    return {"level": "derived", "sources": [],
            "authority": (seed or {}).get("authority"),
            "range": [fn, None],
            "text": "无声明边界：函数域由我方基本块归属推断（end 未知）"}


# ── 目标侧证据：独立重算，再与调用图比对 ─────────────────────────────
def _target_provenance(ctx, target):
    """返回 (state, items, abstain)。items 内每条证据只有一个等级。"""
    sec = ctx.section_of(target) or ""
    items = []
    if sec.startswith(".plt"):
        items.append(_ev("declared", "section", "目标 0x%x 落在 %s 节（节表声明）"
                         % (target, sec)))
        slot, nm = ctx.plt_stub_info(target)
        if slot is not None:
            items.append(_ev("observed", "stub_bytes",
                             "桩首指令按 FF25 解出 jmp [0x%x]（字节事实）" % slot))
            if nm:
                items.append(_ev("declared", "reloc",
                                 "槽 0x%x 有导入重定位 → %s" % (slot, nm)))
            else:
                items.append(_ev("derived", "stub_parse",
                                 "槽 0x%x 无重定位/导入名（不按节内序号猜名字）"
                                 % slot))
        return CG.STATE_PLT, items, None
    if target in ctx.ins_by_addr:
        ins = ctx.ins_by_addr[target]
        items.append(_ev("observed", "instruction",
                         "目标 0x%x 有已解出指令（%s）" % (target, ins["bytes"])))
        sym = ctx.symbol_of(target)
        if sym and sym.endswith("@plt"):
            items.append(_ev("declared", "symbol", "符号 %s 带 @plt 后缀" % sym))
            return CG.STATE_PLT, items, None
        thunk = ctx.thunk_of(target)
        if thunk:
            items.append(_ev("observed", "thunk_bytes",
                             "目标函数体是单条 jmp [0x%x]（字节事实）" % thunk[0]))
            items.append(_ev("declared", "iat",
                             "槽 0x%x 在导入表里 = %s" % thunk))
            items.append(_ev("derived", "thunk_shape",
                             "「单条 jmp [导入槽] ⇒ 导入跳板」是我方形态判定"))
            return CG.STATE_PLT, items, None
        seed = ctx.seeds.get(target)
        if target in ctx.func_start:
            srcs = [s for s in (seed or {}).get("sources") or []
                    if s in _DECLARED_SOURCES]
            if srcs:
                items.append(_ev("declared", "function_decl",
                                 "目标是声明函数入口（%s）" % "/".join(srcs)))
            else:
                items.append(_ev("derived", "function_start",
                                 "目标是函数入口，但只有启发式种子（无声明）"))
        else:
            blk = ctx.block_by_addr.get(target)
            items.append(_ev("derived", "block_ownership",
                             "目标落在函数 0x%x 的中部（非入口），按我方块归属判断"
                             % ((blk or {}).get("function") or 0)))
        return CG.STATE_DECODED, items, None
    items.append(_ev("observed", "address",
                     "目标 0x%x 不在已解出指令集合内，也不在任何 .plt* 节"
                     % target))
    return CG.STATE_UNRESOLVED, items, {
        "scope": "target",
        "missing": "目标地址既无已解出指令、也无 PLT/导入槽证据；"
                   "缺：该地址的数据/代码判别与该目标函数的链接器声明",
    }


# ── 操作数事实（同块窗口，不做 ABI 推断） ────────────────────────────
def _operand_facts(ctx, ins, rec, blk):
    """返回 (facts, abstains, window)。before=定义，after=使用，均限同块。"""
    insns = blk["insns"] if blk else []
    facts, abstains = [], []
    try:
        i = insns.index(ins["addr"])
    except ValueError:
        return facts, [{"scope": "window", "missing": "调用点不在基本块内："
                                                    "缺该指令的块归属"}], None

    # ---- before：倒扫到块首或屏障，取每个操作数最近一次定义 ----
    defs, seen, barrier, win = {}, {}, None, []
    decoded_before = 0
    for a in reversed(insns[:i]):
        prev = ctx.ins_by_addr.get(a)
        try:
            r = expr.decode(prev)
        except expr.LiftError as e:
            barrier = {"addr": a, "reason": e.reason}
            break
        dd, _uu, unknown = CG._effects(r)
        if unknown:
            barrier = {"addr": a, "reason": "未建模隐式读写（%s）"
                                            % (r.get("text") or "intrinsic")}
            break
        decoded_before += 1
        win.append((a, r))
        for kind, name in dd:
            if (kind, name) not in seen:
                seen[(kind, name)] = {"kind": kind, "operand": name, "at": a,
                                      "bytes": prev["bytes"]}
    defs = seen
    # 基址寄存器改写 → 栈槽失效（先判后报，不事后打补丁）。
    # R76：只把「可判定复原」的写当暂态；本轮的复原证据集合为空，故窗口内的写
    # 一律持久，call 对 rsp 的写同样按持久处理（理由见 _TRANSIENT_CALL）。
    invalid = {}
    for key, d in defs.items():
        if key[0] != "slot":
            continue
        base = _slot_base(d["operand"])
        hit = None
        for (k2, name2), d2 in defs.items():
            if k2 == "reg" and name2 == base and d2["at"] > d["at"]:
                hit = {"operand": base, "at": d2["at"], "why": "write"}
                break
        if hit is None and base == "rsp":
            call_at = next((a for a, r in win
                            if a > d["at"] and r.get("family") == "call"), None)
            if call_at is not None:
                hit = {"operand": "rsp", "at": call_at, "why": "call"}
        if hit is not None:
            invalid[key] = hit
    for key, d in sorted(defs.items(), key=lambda kv: (kv[1]["at"], kv[0])):
        if key in invalid:
            hit = invalid[key]
            if hit["why"] == "call":
                missing = ("窗口内 0x%x 是 call：它写 rsp（压返回地址），复原依赖被调方"
                           "的 ret 与调用约定（ret imm16 会多弹参数），本工具不推断调用"
                           "约定 → 该槽在调用点的地址不可判；缺：被调函数的栈平衡契约"
                           % hit["at"])
            else:
                missing = ("基址 %s 在 0x%x 被改写（晚于该槽定义 0x%x），"
                           "槽的实际位置不可判；缺：栈指针/帧基址的值追踪"
                           % (hit["operand"], hit["at"], d["at"]))
            abstains.append({"scope": "slot:%s" % d["operand"],
                             "missing": missing})
            continue
        facts.append({
            "direction": "before", "kind": d["kind"], "operand": d["operand"],
            "at": d["at"], "bytes": d["bytes"],
            "evidence": [
                _ev("observed", "instruction", "0x%x: %s" % (d["at"], d["bytes"])),
                _ev("derived", "last_def_in_block",
                    "同块倒扫的第一条写（= 调用点前最后一次定义）；"
                    "无别名/值编号分析，不代表值来源链"),
            ],
        })
    if barrier:
        abstains.append({
            "scope": "window_before",
            "missing": "0x%x 处指令无法给出读写事实（%s）；缺：该指令的语义，"
                       "窗口在屏障处截断，不越过它声称「最后定义」"
                       % (barrier["addr"], barrier["reason"]),
        })

    # ---- after：顺序扫描，取每个操作数首次使用 ----
    used, barrier2 = set(), None
    decoded_after = 0
    for a in insns[i + 1:]:
        nxt = ctx.ins_by_addr.get(a)
        try:
            r = expr.decode(nxt)
        except expr.LiftError as e:
            barrier2 = {"addr": a, "reason": e.reason}
            break
        _dd, uu, unknown = CG._effects(r)
        if unknown:
            barrier2 = {"addr": a, "reason": "未建模隐式读写（%s）"
                                             % (r.get("text") or "intrinsic")}
            break
        decoded_after += 1
        for kind, name in uu:
            if (kind, name) in used:
                continue
            used.add((kind, name))
            facts.append({
                "direction": "after", "kind": kind, "operand": name,
                "at": a, "bytes": nxt["bytes"],
                "evidence": [
                    _ev("observed", "instruction", "0x%x: %s" % (a, nxt["bytes"])),
                    _ev("derived", "first_use_in_block",
                        "同块顺序扫描的第一条读（= 调用点后首次使用）"),
                ],
            })
    if barrier2:
        abstains.append({
            "scope": "window_after",
            "missing": "0x%x 处指令无法给出读写事实（%s）；后向窗口在此截断"
                       % (barrier2["addr"], barrier2["reason"]),
        })

    # 统一 abstain：本层不判定哪些操作数是参数
    abstains.append({
        "scope": "full_argument_set",
        "missing": "不判定哪些寄存器/栈槽是参数、也不给参数个数与名字；"
                   "缺调用约定证据（本单元禁止 ABI 推断）",
    })
    window = {
        "block_start": blk["start"], "block_end": blk["end"],
        "before_insns": i, "after_insns": len(insns) - i - 1,
        "before_decoded": decoded_before, "after_decoded": decoded_after,
        "barrier_before": barrier, "barrier_after": barrier2,
    }
    return facts, abstains, window


# ── 跨块定义侧回溯（M8-U1：只走确定边） ──────────────────────────────
_NONDET_CLASSES = ("speculative", "cross_function", "undecoded", "unresolved")
_CROSS_MAX_DEPTH = 64
_CROSS_MAX_BRANCHES = 32
_CROSS_STATUS_TEXT = {
    "entry": "有前驱回溯到函数入口（缺调用方赋值）",
    "nondet": "有前驱块带非确定入边（缺该入边的目标判定）",
    "loop": "有前驱在回溯中遇到回边（循环），缺不动点迭代/循环不变式",
    "barrier": "有前驱块内含无法解码/未建模的指令（缺该指令语义）",
    "disagree": "更前面的合流处各路径定义不同（缺同一定义）",
    "depth": "回溯深度超限（缺更长的路径）",
    "breadth": "分支数超限（缺路径剪枝判据）",
    "ambiguous": "更前面的回溯不完整（原因见并列项）",
}


def _cross_index(res):
    """块索引 + 确定边前驱表 + 每块的非确定入边清单。

    只从 cfg.edges.definite 取前驱；其它四类（疑似/跨函数/目标未解出/间接目标）
    一律进 nondet_in——它们不在回溯路径上，但会让「回溯已完整」这个前提不成立。
    """
    blk_of, start_of = {}, {}
    for b in res["blocks"]:
        start_of[b["start"]] = b
        for a in b["insns"]:
            blk_of[a] = b

    def sink(addr):
        b = start_of.get(addr) or blk_of.get(addr)
        return b["start"] if b else None

    preds, nondet = {}, {}
    cfg = res.get("cfg") or {}
    for e in (cfg.get("edges") or {}).get("definite") or []:
        to = sink(e["to"])
        if to is not None:
            preds.setdefault(to, set()).add(e["from"])
    for cls in _NONDET_CLASSES:
        for e in (cfg.get("edges") or {}).get(cls) or []:
            to = sink(e["to"])
            if to is not None:
                nondet.setdefault(to, []).append(
                    {"from": e["from"], "class": cls, "kind": e.get("kind")})
    return {"blk_of": blk_of, "start_of": start_of, "preds": preds,
            "nondet_in": nondet}


def _scan_block(ctx, blk, operand, upto):
    """块内 `upto` 之前（不含）的最后一次写。返回 (addr|None, status)。

    屏障（无法解码 / 未建模隐式读写）会截断扫描，此时「块内没有该操作数的写」
    这个前提不成立，必须 abstain 而不是继续回溯。
    """
    for a in reversed(blk["insns"]):
        if a >= upto:
            continue
        try:
            r = expr.decode(ctx.ins_by_addr.get(a))
        except expr.LiftError as e:
            return None, {"status": "barrier", "addr": a, "reason": e.reason}
        dd, _uu, unknown = CG._effects(r)
        if unknown:
            return None, {"status": "barrier", "addr": a,
                          "reason": "未建模隐式读写（%s）"
                                    % (r.get("text") or "intrinsic")}
        if operand in dd:
            return a, {"status": "found"}
    return None, {"status": "absent"}


def _cross_exit(ctx, ix, blk, operand, memo, stack, depth):
    """块出口处该操作数的状态：块内有写 → def；否则合并确定前驱。

    每个结果带 branches：从本块到定义块的**线性**块序列列表；合流处每支各一条。
    把分支保持为线性链（而不是拼接成一串）是为了让外部校验能逐跳核对边。
    """
    key = (operand, blk["start"])
    if key in memo:
        return memo[key]
    if key in stack:
        return {"status": "loop", "addr": blk["start"], "branches": []}
    if depth > _CROSS_MAX_DEPTH:
        return {"status": "depth", "addr": blk["start"], "branches": []}
    a, st = _scan_block(ctx, blk, operand, blk["end"])
    if st["status"] == "found":
        out = {"status": "def", "addr": a, "branches": [[blk["start"]]]}
        memo[key] = out
        return out
    if st["status"] == "barrier":
        st["branches"] = []
        memo[key] = st
        return st
    stack.add(key)
    out = _cross_merge(ctx, ix, blk, operand, memo, stack, depth)
    stack.discard(key)
    memo[key] = out
    return out


def _cross_merge(ctx, ix, blk, operand, memo, stack, depth):
    """块入口状态 = 所有确定前驱出口状态的合并。

    要求：入边完整（无非确定入边）、前驱非空、每个前驱都给出**同一个**定义地址、
    分支数不超上限。任一条不成立就 abstain，并把缺什么写清楚——不猜、不拿疑似边
    补覆盖率。
    """
    extra = ix["nondet_in"].get(blk["start"])
    if extra:
        return {"status": "nondet", "addr": blk["start"], "branches": [],
                "classes": sorted({e["class"] for e in extra}),
                "kinds": sorted({e["kind"] for e in extra})}
    preds = sorted(ix["preds"].get(blk["start"]) or ())
    if not preds:
        return {"status": "entry", "addr": blk["start"], "branches": []}
    results = []
    for p in preds:
        pb = ix["start_of"].get(p)
        if pb is None:
            return {"status": "entry", "addr": blk["start"], "branches": []}
        results.append(_cross_exit(ctx, ix, pb, operand, memo, stack, depth + 1))
    if all(r["status"] == "def" for r in results):
        addrs = {r["addr"] for r in results}
        if len(addrs) == 1:
            branches = []
            for r in results:
                for br in r["branches"]:
                    branches.append([blk["start"]] + br)
                    if len(branches) > _CROSS_MAX_BRANCHES:
                        return {"status": "breadth", "addr": blk["start"],
                                "branches": []}
            return {"status": "def", "addr": addrs.pop(), "branches": branches,
                    "merged": len(results)}
        return {"status": "disagree", "addr": blk["start"], "branches": [],
                "defs": sorted(addrs)}
    # 合并失败时必须传播**根因**：嵌套的 ambiguous 只带自身 why 会把最深处的
    # 「loop / nondet / entry」丢掉，弃权文案就说不清缺什么。
    bad = [r for r in results if r["status"] != "def"]
    why, classes, kinds = set(), set(), set()
    for r in bad:
        if r["status"] == "ambiguous":
            why.update(r.get("why") or ["ambiguous"])
        else:
            why.add(r["status"])
        classes.update(r.get("classes") or ())
        kinds.update(r.get("kinds") or ())
    out = {"status": "ambiguous", "addr": blk["start"], "branches": [],
           "why": sorted(why)}
    if classes:
        out["classes"] = sorted(classes)
    if kinds:
        out["kinds"] = sorted(kinds)
    return out


def _cross_missing(st):
    """把回溯失败的原因翻译成「缺什么」。"""
    k, a = st["status"], st.get("addr")
    if k == "entry":
        return ("回溯到 0x%x 已是函数入口/无确定前驱：缺调用方在该入口前对该"
                "寄存器的赋值（跨函数入口状态，本层不追跨函数）" % a)
    if k == "nondet":
        cls, kinds = st.get("classes") or [], st.get("kinds") or []
        tail = ""
        if "unresolved" in cls and any(x in ("jmp_ind", "call_ind") for x in kinds):
            tail = "；其中含间接跳转（跳转表/函数指针），目标不可静态确定"
        return ("块 0x%x 有非确定入边（%s%s）：缺这些入边的目标判定，"
                "回溯路径不完整" % (a, "/".join(cls), tail))
    if k == "loop":
        return ("回溯遇到回边 0x%x（循环）：缺不动点迭代/循环不变式，"
                "环上可能有多次定义" % a)
    if k == "disagree":
        return ("块 0x%x 的确定前驱在合流处给出不同定义（0x%s）："
                "缺「各路径同一定义」" % (a, "、0x".join("%x" % x
                                                       for x in st["defs"])))
    if k == "ambiguous":
        reasons = [_CROSS_STATUS_TEXT.get(x, x) for x in st["why"]]
        cls, kinds = st.get("classes") or [], st.get("kinds") or []
        extra = ""
        if cls:
            extra = "；非确定入边类别 %s" % "/".join(cls)
            if "unresolved" in cls and any(x in ("jmp_ind", "call_ind")
                                           for x in kinds):
                extra += "（含间接跳转：跳转表/函数指针，目标不可静态确定）"
        return ("块 0x%x 的回溯不完整：%s%s。缺：这些路径上的唯一定义"
                % (a, "；".join(reasons), extra))
    if k == "barrier":
        return ("0x%x 处指令无法给出读写事实（%s）：缺该指令的语义，"
                "不能越过它声称「块内无写」" % (a, st.get("reason")))
    if k == "depth":
        return ("回溯深度超过 %d 个基本块（0x%x 处截断）：缺更长的路径"
                % (_CROSS_MAX_DEPTH, a))
    if k == "breadth":
        return ("回溯分支数超过 %d（在 0x%x 截断）：缺路径剪枝判据"
                % (_CROSS_MAX_BRANCHES, a))
    return "跨块回溯失败（%s）：缺该原因对应的判据" % k


def _cross_before(ctx, ix, blk, operand, call_addr, memo):
    """调用点前、跨块回溯该操作数的唯一定义；返回 def / 失败状态。"""
    a, st = _scan_block(ctx, blk, operand, call_addr)
    if st["status"] == "found":
        return {"status": "same_block", "addr": a}
    if st["status"] == "barrier":
        return st
    return _cross_merge(ctx, ix, blk, operand, memo, set(), 0)


def _cross_record(ctx, ix, memo, ins, rec, blk, facts, window):
    """一个站点的跨块结论：跨块事实 + 跨块弃权（与同块事实分开存放）。"""
    got = {(f["kind"], f["operand"]) for f in facts
           if f["direction"] == "before"}
    try:
        uses = CG._effects(rec)[1]
    except Exception:                        # 解码已由 _call_insns 复核过
        return [], []
    cfacts, cabst, seen = [], [], set()
    for kind, name in uses:
        if (kind, name) in seen:
            continue
        seen.add((kind, name))
        if (kind, name) in got:
            continue                          # 同块窗口已给出，不重复计
        if kind != "reg":
            cabst.append({"scope": "cross:%s" % name,
                          "missing": "跨块只追寄存器操作数：栈槽 %s 需要跨块"
                                     "栈指针/帧基址值追踪（缺）" % name})
            continue
        if window is not None and window.get("barrier_before"):
            b = window["barrier_before"]
            cabst.append({"scope": "cross:%s" % name,
                          "missing": "同块窗口在 0x%x 截断（%s）：缺该指令语义，"
                                     "不能越过它回溯" % (b["addr"], b["reason"])})
            continue
        st = _cross_before(ctx, ix, blk, (kind, name), ins["addr"], memo)
        if st["status"] == "def":
            brs = st["branches"]
            depth = max(len(x) for x in brs) - 1
            cfacts.append({
                "direction": "before", "kind": kind, "operand": name,
                "at": st["addr"], "bytes": (ctx.ins_by_addr.get(st["addr"])
                                            or {}).get("bytes"),
                "branches": brs, "merged": st.get("merged", 1),
                "evidence": [
                    _ev("observed", "instruction",
                        "0x%x: %s" % (st["addr"],
                                      (ctx.ins_by_addr.get(st["addr"])
                                       or {}).get("bytes") or "?")),
                    _ev("derived", "cross_last_def",
                        "跨块倒扫：%d 条确定边分支、最深 %d 个基本块，合流处 %d 个确定"
                        "前驱给出同一地址（首支 %s）"
                        % (len(brs), depth, st.get("merged", 1),
                           "→".join("0x%x" % b for b in brs[0]))),
                ],
            })
        else:
            cabst.append({"scope": "cross:%s" % name,
                          "missing": _cross_missing(st)})
    return cfacts, cabst


# ── 构建 ─────────────────────────────────────────────────────────────
def build(path, section=".text", res=None, graph=None):
    res = res if res is not None else recdesc.descend(path, section)
    graph = graph if graph is not None else CG.build(path, section, res=res)
    ctx = CG._Ctx(path, res, section)
    calls = CG._call_insns(ctx)
    by_from = {e["from"]: e for e in graph["edges"]}
    ix, memo = _cross_index(res), {}
    decl = PD.read(path)
    pdwar = decl.get("dwarf")
    pd_bindings = []

    sites, counts, reasons = [], {
        "sites": 0, "direct": 0, "indirect": 0,
        "facts_before": 0, "facts_after": 0, "abstains": 0,
        "cross_facts": 0, "cross_abstains": 0, "cross_sites": 0,
        "evidence": {k: 0 for k in LEVELS},
        "cross_evidence": {k: 0 for k in LEVELS},
        "target_evidence": {k: 0 for k in LEVELS},
    }, {}
    cross_reasons = {}

    for ins, rec in calls:
        blk = ctx.block_by_addr.get(ins["addr"])
        fn = blk["function"] if blk else ins.get("origin")
        direct = rec.get("target") is not None
        if direct:
            state, items, tabstain = _target_provenance(ctx, rec["target"])
            graph_state = (by_from.get(ins["addr"]) or {}).get("state")
        else:
            state, items, graph_state = None, [], None
            tabstain = {"scope": "target",
                        "missing": "间接调用目标不可静态确定（寄存器/基址+索引）；"
                                   "缺：运行期目标；候选层见 --indirect-candidates"}
        facts, abstains, window = _operand_facts(ctx, ins, rec, blk)
        abstains = list(abstains)
        if tabstain:
            abstains.insert(0, tabstain)
        cfacts, cabst = ([], []) if blk is None else _cross_record(
            ctx, ix, memo, ins, rec, blk, facts, window)
        for f in facts:
            counts["facts_" + f["direction"]] += 1
            for e in f["evidence"]:
                counts["evidence"][e["level"]] += 1
        for f in cfacts:
            counts["cross_facts"] += 1
            for e in f["evidence"]:
                counts["cross_evidence"][e["level"]] += 1
        for e in items:
            counts["target_evidence"][e["level"]] += 1
        for a in abstains:
            counts["abstains"] += 1
            key = a["scope"].split(":")[0]
            reasons[key] = reasons.get(key, 0) + 1
        for a in cabst:
            counts["cross_abstains"] += 1
            cross_reasons[a["scope"].split(":")[0]] = \
                cross_reasons.get(a["scope"].split(":")[0], 0) + 1
        if cfacts or cabst:
            counts["cross_sites"] += 1
        site = {
            "from": ins["addr"], "bytes": ins["bytes"],
            "call_kind": "direct" if direct else "indirect",
            "function": fn,
            "function_declaration": _func_declaration(ctx, fn),
            "block": blk["start"] if blk else None,
            "state": state, "graph_state": graph_state,
            "target": rec.get("target"),
            "target_evidence": items,
            "facts": facts, "abstains": abstains, "window": window,
            "cross_facts": cfacts, "cross_abstains": cabst,
            "cross_block": ("traced" if cfacts else
                            ("abstained" if cabst else "same_block")),
        }
        # M8-U2：每个调用点都进分母。有可读形参声明时逐形参绑定；无声明/间接调用
        # 记 no_declaration/no_target 并 abstain——分母永远是全部站点，不因「没有
        # 来源」而消失（0 不能被当成结论）。逐点 param_binding 只在该点真有声明
        # 结构时落盘，避免把 11k 条同质弃权塞进站点明细。
        pb = PD.bind_site(site, pdwar)
        pd_bindings.append(pb)
        if pb["status"] not in ("no_declaration", "no_target"):
            site["param_binding"] = pb
        sites.append(site)
        counts["sites"] += 1
        counts["direct" if direct else "indirect"] += 1

    pd_counts = PD.summarize(pd_bindings)
    pd_summary = {
        "available": pdwar is not None,
        "rule": PARAM_RULE,
        "declared_source_audit": {
            k: {kk: vv for kk, vv in v.items() if kk != "detail"}
            for k, v in (decl.get("audit", {}).get("classes") or {}).items()
        },
        "counts": pd_counts,
        "note": (None if pdwar is not None else
                 "本样本没有可读的形参声明来源；参数绑定整体不可判定——"
                 "这不是「0 个参数」，也不能用 ABI 补齐"),
    }

    report = {
        "path": str(path), "section": section,
        "levels": LEVEL_LEGEND,
        "counts": counts,
        "abstain_reasons": reasons,
        "sites": sites,
        "cross_block": {
            "traced": True,
            "direction": "before（定义侧）；after（使用侧）不追",
            "rule": "只沿 recdesc 的 definite 边回溯；疑似/跨函数/目标未解出/间接"
                    "目标一律不当作边用",
            "merge": "合流点要求所有确定前驱给出同一定义地址，否则 abstain",
            "cycles": "回边（循环）在回溯栈上检测，遇环 abstain",
            "counts": {"facts": counts["cross_facts"],
                       "abstains": counts["cross_abstains"],
                       "sites": counts["cross_sites"],
                       "evidence": counts["cross_evidence"]},
            "abstain_reasons": cross_reasons,
            "transient_write": {
                "rule": _TRANSIENT_RULE, "call": _TRANSIENT_CALL,
                "falsify": _TRANSIENT_FALSIFY,
            },
        },
        "param_binding": pd_summary,
        "caveats": list(CAVEATS),
    }
    report["consistency"] = check_consistency(graph, report)
    return report


def check_consistency(graph, facts):
    """调用图三态 vs 事实层独立重算：逐点比对，矛盾单列（不以任何一方为准）。"""
    g = {e["from"]: e for e in graph["edges"]}
    f_direct = {s["from"]: s for s in facts["sites"] if s["call_kind"] == "direct"}
    f_ind = {s["from"]: s for s in facts["sites"] if s["call_kind"] == "indirect"}
    contr = []
    for frm, e in g.items():
        s = f_direct.get(frm)
        if s is None:
            contr.append({"from": frm, "field": "missing_in_facts",
                          "graph": e["state"], "facts": None,
                          "note": "调用图有该直接调用点，事实层缺失"})
        elif s["state"] != e["state"]:
            contr.append({"from": frm, "field": "state",
                          "graph": e["state"], "facts": s["state"],
                          "note": "三态判定不一致：图与事实层各按自己的证据"
                                  "重算，本工具不擅自选边"})
        if s is not None and s["target"] != e["to"]:
            contr.append({"from": frm, "field": "target",
                          "graph": e["to"], "facts": s["target"],
                          "note": "目标地址不一致"})
    for frm in f_direct:
        if frm not in g:
            contr.append({"from": frm, "field": "missing_in_graph",
                          "graph": None, "facts": f_direct[frm]["state"],
                          "note": "事实层有该直接调用点，调用图缺失"})
    for frm, s in f_ind.items():
        if s["state"] is not None:
            contr.append({"from": frm, "field": "indirect_state",
                          "graph": None, "facts": s["state"],
                          "note": "间接调用点不得出现在三态里"})
    expected = graph["counts"]["call_sites"]
    if facts["counts"]["sites"] != expected:
        contr.append({"from": None, "field": "site_count",
                      "graph": expected, "facts": facts["counts"]["sites"],
                      "note": "调用点总数不一致"})
    return {"ok": not contr, "checked": len(g) + len(f_ind),
            "graph_sites": len(g), "facts_sites": len(facts["sites"]),
            "contradictions": contr}


# ── 渲染 ─────────────────────────────────────────────────────────────
def render(report, limit=6):
    c = report["counts"]
    con = report["consistency"]
    lines = [
        "CALLFACTS: %s  section=%s" % (report["path"], report["section"]),
        "证据等级（每条证据只属一级，不混成「已确定」）:",
    ]
    for k in LEVELS:
        lines.append("  %-8s %s" % (k, report["levels"][k]))
    lines.append(
        "站点 %d（直接 %d ｜ 间接 %d）｜ before 事实 %d ｜ after 事实 %d ｜ "
        "abstain %d ｜ 证据 declared %d / observed %d / derived %d"
        % (c["sites"], c["direct"], c["indirect"], c["facts_before"],
           c["facts_after"], c["abstains"], c["evidence"]["declared"],
           c["evidence"]["observed"], c["evidence"]["derived"]))
    te = c["target_evidence"]
    lines.append(
        "目标证据 declared %d / observed %d / derived %d（与操作数证据分开计数）"
        % (te["declared"], te["observed"], te["derived"]))
    ce = c["cross_evidence"]
    lines.append(
        "跨块（只走确定边，只追定义侧）: 事实 %d ｜ 弃权 %d ｜ 涉及站点 %d ｜ "
        "跨块证据 observed %d / derived %d"
        % (c["cross_facts"], c["cross_abstains"], c["cross_sites"],
           ce["observed"], ce["derived"]))
    lines.append("一致性（与调用图三态逐点比对）: checked %d ｜ 矛盾 %d"
                 % (con["checked"], len(con["contradictions"])))
    pb = report.get("param_binding") or {}
    pc = pb.get("counts") or {}
    if pb.get("available"):
        lines.append(
            "参数绑定（只认文件声明，禁止 ABI）: 声明站点 %d ｜ 绑定形参 %d ｜ "
            "部分绑定 %d ｜ 弃权形参 %d ｜ 绑定寄存器段 %d ｜ 零形参声明 %d ｜ "
            "无声明站点 %d ｜ 间接 %d"
            % (pc.get("sites", 0) - pc.get("no_declaration_sites", 0)
               - pc.get("no_target_sites", 0), pc.get("params_bound", 0),
               pc.get("params_partial", 0), pc.get("params_abstained", 0),
               pc.get("bound_pieces", 0), pc.get("zero_params_sites", 0),
               pc.get("no_declaration_sites", 0), pc.get("no_target_sites", 0)))
    else:
        lines.append("参数绑定: 本样本无可用形参声明来源 → 整体不可判定"
                     "（不是 0 个参数）")
    for x in con["contradictions"][:10]:
        lines.append("  ✗ 0x%s %s: 图=%r 事实=%r（%s）"
                     % (("%x" % x["from"]) if x["from"] else "-",
                        x["field"], x["graph"], x["facts"], x["note"]))
    for s in report["sites"][:limit]:
        decl = s["function_declaration"]
        lines.append("  · 调用点 0x%x（函数 0x%x，函数域=%s[%s]，目标=%s）"
                     % (s["from"], s["function"] or 0, decl["level"],
                        "/".join(decl["sources"]) or "无声明",
                        s["state"] or "间接/未分类"))
        for e in s["target_evidence"]:
            lines.append("      目标证据 %-8s [%s] %s"
                         % (e["level"], e["source"], e["text"]))
        for f in s["facts"][:8]:
            ev = "；".join("%s[%s] %s" % (x["level"], x["source"], x["text"])
                          for x in f["evidence"])
            lines.append("      %-6s %-8s @0x%x  %s"
                         % (f["direction"], f["operand"], f["at"], ev))
        if len(s["facts"]) > 8:
            lines.append("      … 其余 %d 条事实见 --json" % (len(s["facts"]) - 8))
        for f in s.get("cross_facts") or []:
            ev = "；".join("%s[%s] %s" % (x["level"], x["source"], x["text"])
                          for x in f["evidence"])
            lines.append("      跨块 before %-8s @0x%x  %s" % (f["operand"], f["at"], ev))
        for a in s.get("cross_abstains") or []:
            lines.append("      跨块 abstain [%s] %s" % (a["scope"], a["missing"]))
        spb = s.get("param_binding")
        if spb:
            lines.append("      参数绑定 [%s] 目标=%s"
                         % (spb["status"],
                            ("0x%x" % spb["target"]) if spb.get("target") else "-"))
            for b in (spb.get("bound") or [])[:4]:
                for e in b.get("evidence") or []:
                    lines.append("        绑定 %-8s %s" % (b.get("name"), e["text"]))
                for q in b.get("binds") or []:
                    lines.append("          寄存器 %-4s ← 0x%x [%s] %s"
                                 % (q["reg"], q.get("def_at") or 0, q["from"],
                                    q.get("def_bytes") or ""))
            for b in (spb.get("partial") or [])[:2]:
                lines.append("        部分 %-8s %s" % (b.get("name"), b["missing"]))
            for a in (spb.get("abstains") or [])[:3]:
                lines.append("        弃权 %-8s %s" % (a.get("name") or "-",
                                                      a["missing"]))
        for a in s["abstains"][:4]:
            lines.append("      abstain [%s] %s" % (a["scope"], a["missing"]))
        if len(s["abstains"]) > 4:
            lines.append("      … 其余 %d 条 abstain 见 --json"
                         % (len(s["abstains"]) - 4))
    if len(report["sites"]) > limit:
        lines.append("  … 其余 %d 个站点见 --json" % (len(report["sites"]) - limit))
    lines.append("跨块数据流: %s（%s）"
                 % ("只沿确定边追定义侧" if report["cross_block"]["traced"]
                    else "未追", report["cross_block"]["rule"]))
    lines.append("caveats:")
    for x in report["caveats"]:
        lines.append("  ! %s" % x)
    return "\n".join(lines)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="rekit callfacts",
                                 description="跨函数参数传递的事实层（证据分级，不做 ABI 推断）")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    r = build(args.file, args.section)
    print(json.dumps(r, ensure_ascii=False, indent=2) if args.json else render(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
