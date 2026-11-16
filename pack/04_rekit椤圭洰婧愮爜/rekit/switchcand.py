#!/usr/bin/env python3
# rekit.switchcand — 跳转表候选层（M5-U2，默认关闭）
#
# 定位（按裁决 R49–R52 的隔离条款）：
#   本模块只回答「哪些间接 jmp 看起来是跳转表，证据到什么程度，如果按它展开会多出
#   哪些块」，不回答「控制流实际去哪」。候选与确定集严格隔离：
#     · 默认不运行；只有显式 --switch-candidates 才输出；
#     · 不改写 recdesc 的 res：不新增指令、不改 blocks、不改 cfg、不改 stats；
#     · 候选块数用独立口径（blocks_candidate = 既有 + 候选新增），与 CFG 的
#       blocks 并列显示，绝不合并计数；
#     · 候选目标一律单列并标注证据等级与依据。
#
# 与 R45 的关系（措辞已同步）：
#   R45 禁止的是「把猜测当已知」——把候选目标写进确定边、写成表达式里的 case、
#   或混进 CFG 的 definite/speculative 计数；
#   R45 不禁止「提出有证据的候选」——只要候选单列、带证据等级、带被拒理由，
#   且不影响任何既有确定数字。
#
# 识别的两种形态（都要求有可回指的结构，不是「看起来像」）：
#   Pattern B  rel32：lea B,[rip+table] → movsxd R,[B+idx*4] → add R,B → jmp R
#                    表项 = s32 偏移，目标 = table + 偏移
#   Pattern A  abs64：jmp qword [rip+table+idx*8]
#                    表项 = u64 绝对目标（仅当该二进制非 PIE 时才可能成立）
#
# 表长只认 guard（cmp idx,imm 后紧跟 ja/jae）：
#   实测反例：dyn_static 0x401870 的表在 8 项之后仍接着 .rodata 其它数据，
#   第 9 项解出的目标仍落在函数域内 —— 靠「首个非法项截断」会把数据当代码。
#   因此无 guard 时表长记为「未证明」，证据最多 medium，并显式写明扫描上限。
#
# 被拒理由必须可见：
#   1) 目标超出声明函数域（跨函数/数据）；
#   2) 目标落在已解出指令内部（错位/数据，不是指令边界）；
#   3) 目标无法解出指令；
#   4) 表项地址不在任何可读节内。
#   单条被拒写入 candidate["rejected"] 并截止扫描（后续项未证明，不猜）。
import struct
from bisect import bisect_right

from . import disasm, elf, pe

CAVEATS = [
    "候选层默认关闭，仅在 --switch-candidates 下输出；不进入确定边/表达式/CFG 口径",
    "表长优先取 cmp/ja 上界；无 guard 时表长未证明，证据最多 medium，且扫描有上限",
    "候选目标必须落在该函数权威声明的域内；跨函数/落在指令内部/不可解一律拒绝并记理由",
    "候选展开是独立 BFS，不改写 recdesc 的 res；候选块数单独记为 blocks_candidate",
    "Pattern A（绝对 8 字节表）只在非 PIE 时语义成立；PIE 下该形态视为证据不足",
    "M9 升格（promotion=promoted）只表示“表长有 guard + 表项完整 + 每个目标都是"
    "外部 objdump 确认的指令边界”；仍不进确定边（R45 不变），也不表示控制流实际走该边",
    "预算（step_budget/max_functions）按确定性指令步数计，不按墙钟；预算跳过的函数"
    "单列在 budget.skipped_detail（skip_type=skipped_budget），绝不当作“无候选”，"
    "候选/升格比率的分母只含已分析函数；整层未运行记 run_status=no_run，"
    "与预算跳过不同名、不同义",
]

EVIDENCE_HIGH, EVIDENCE_MEDIUM, EVIDENCE_LOW = "high", "medium", "low"

_MAX_BACKTRACK = 16        # 形态链回溯窗口（同块内指令数）
_MAX_BACKTRACK_ANY = 32    # guard 回溯窗口（函数级指令序，可跨块）
_MAX_SCAN_NO_GUARD = 64    # 无 guard 时最多扫这么多项
_ENTRY_SIZE = {"rel32": 4, "abs64": 8}


# ── 表读取：VA → 文件字节（跨节，不只 .text） ────────────────────────
class TableReader:
    """把 VA 读成文件字节；节外返回 None（不猜、不补零）。"""

    def __init__(self, path, data=None):
        self.data = data if data is not None else open(path, "rb").read()
        self.ranges = []      # (va_lo, va_hi, file_off)
        if self.data[:4] == b"\x7fELF":
            for s in elf.section_headers(self.data):
                if s["size"] > 0 and s["addr"]:
                    self.ranges.append((s["addr"], s["addr"] + s["size"],
                                        s["offset"]))
        elif self.data[:2] == b"MZ":
            r = pe.parse(path)
            for (va, vsize, rawptr, rawsize, _nm) in r["sections"]:
                if rawsize > 0:
                    # 文件里只有 rawsize 字节可读；vsize 多出的部分是零填充，
                    # 不当数据读（读零会造出假目标）。
                    self.ranges.append((va, va + rawsize, rawptr))
        self.ranges.sort()

    def read(self, va, n):
        for lo, hi, off in self.ranges:
            if lo <= va and va + n <= hi:
                pos = off + (va - lo)
                return self.data[pos:pos + n]
        return None


# ── 小工具 ───────────────────────────────────────────────────────────
def _reg_idx(op):
    return op["idx"] if op and op.get("t") == "reg" else None


def _decode(ins):
    """一条指令 → 语义记录；失败返回 (None, reason)。"""
    from . import expr
    try:
        return expr.decode(ins), None
    except expr.LiftError as e:
        return None, "%s（缺：%s）" % (e.reason, e.missing)


def _block_of(res, addr):
    for b in res["blocks"]:
        if addr in b["insns"]:
            return b
    return None


def _decoded_index(res):
    """(starts, ends)：用于判断地址是否落在已解出指令内部。"""
    ins = res["instructions"]
    return [i["addr"] for i in ins], [i["addr"] + i["length"] for i in ins]


def _inside_decoded(idx, addr):
    starts, ends = idx
    i = bisect_right(starts, addr) - 1
    if i >= 0 and starts[i] < addr < ends[i]:
        return starts[i], ends[i]
    return None


def _func_sets(res, func_addr, ctx=None):
    if ctx is not None:
        insns = ctx["by_origin"].get(func_addr, [])
        blks = ctx["blocks_by_func"].get(func_addr, [])
        seed = ctx["seeds_by_addr"].get(func_addr) or {}
    else:
        insns = [i for i in res["instructions"] if i.get("origin") == func_addr]
        blks = [b for b in res["blocks"] if b["function"] == func_addr]
        seeds = {s["addr"]: s for s in res["seeds"]}
        seed = seeds.get(func_addr) or {}
    lo = func_addr
    hi = seed.get("end")
    if hi is None and insns:
        hi = max(i["addr"] + i["length"] for i in insns)
    return insns, blks, seed, lo, hi


def build_context(res):
    """一次性建立全局索引，供全部函数复用（M10：消除 O(函数数 × 指令数)）。

    原实现每分析一个函数都要扫一遍 res["instructions"] 与 res["blocks"] 并重建
    decoded 映射（python310 实测 417 个函数 → 2.6 亿次 dict.get、纯扫描 78 秒）。
    这些索引与函数无关，只依赖 res，因此必须只建一次；分析函数只读本函数切片。
    """
    by_origin = {}
    for ins in res["instructions"]:
        by_origin.setdefault(ins.get("origin"), []).append(ins)
    blocks_by_func = {}
    for b in res["blocks"]:
        blocks_by_func.setdefault(b["function"], []).append(b)
    from . import recdesc
    data = open(res["path"], "rb").read()
    return {
        "by_origin": by_origin,                       # 函数 → 指令（按地址升序）
        "blocks_by_func": blocks_by_func,             # 函数 → 基本块
        "seeds_by_addr": {s["addr"]: s for s in res["seeds"]},
        "decoded": {i["addr"]: i for i in res["instructions"]},
        "idx": _decoded_index(res),
        # 文件字节/解码器/读表器都与函数无关，只建一次：原实现每个函数重读整个
        # 二进制（cc1 34MB × 1974 次 ≈ 67GB），是修复 O(F×N) 之后的第二大瓶颈。
        "data": data,
        "reader": TableReader(res["path"], data),
        "decoder": recdesc._Decoder(data, res["section"]),
    }


# ── 形态匹配 ─────────────────────────────────────────────────────────
def _match_rel32(recs, jpos):
    """lea B,[rip+table] → movsxd R,[B+idx*4] → add R,B → jmp R。"""
    jmp = recs[jpos][1]
    if not jmp or jmp.get("family") != "jmp":
        return None, "不是 jmp 指令"
    op = jmp.get("indirect")
    if not op or op.get("t") != "reg":
        return None, "jmp 目标不是寄存器（可能是 [rip+表] 形态或其它）"
    r = op["idx"]

    if jpos < 3:
        return None, "jmp 前不足 3 条指令，无法构成 lea/movsxd/add 链"
    add = recs[jpos - 1][1]
    if not (add and add.get("family") == "binop" and add.get("mnem") == "add"
            and _reg_idx(add.get("dst")) == r and _reg_idx(add.get("src")) is not None):
        return None, "jmp 前一条不是 `add R,B`（R 为 jmp 寄存器）"
    b = _reg_idx(add["src"])
    mov = recs[jpos - 2][1]
    if not (mov and mov.get("family") == "assign" and mov.get("mnem") == "movsxd"
            and _reg_idx(mov.get("dst")) == r):
        return None, "`add R,B` 前一条不是 `movsxd R,[...]`"
    mem = mov.get("src") or {}
    if mem.get("t") != "mem" or mem.get("base") != b or mem.get("index") is None \
            or mem.get("scale") != 4 or mem.get("seg"):
        return None, "movsxd 的源操作数不是 `[B + idx*4]`（表项宽度/基址不符）"

    # lea 可能被提到更早（同块内允许），从 movsxd 往前再找
    for k in range(jpos - 3, max(-1, jpos - 3 - _MAX_BACKTRACK), -1):
        lea = recs[k][1]
        if not lea:
            continue
        if lea.get("family") == "lea" and _reg_idx(lea.get("dst")) == b:
            src = lea.get("src") or {}
            if src.get("t") == "mem" and src.get("rip"):
                return {"kind": "rel32", "table": src["rip_target"],
                        "index_reg": mem["index"], "jmp_reg": r,
                        "base_reg": b,
                        "chain": [recs[k][0]["addr"], recs[jpos - 2][0]["addr"],
                                  recs[jpos - 1][0]["addr"], recs[jpos][0]["addr"]]}, None
            return None, "lea 的源不是 [rip+disp]（表基址不可静态确定）"
    return None, "找不到定义表基址的 `lea B,[rip+disp]`"


def _match_abs64(recs, jpos):
    """jmp qword [rip+table+idx*8]。"""
    jmp = recs[jpos][1]
    if not jmp or jmp.get("family") != "jmp":
        return None, "不是 jmp 指令"
    op = jmp.get("indirect")
    if not op or op.get("t") != "mem":
        return None, "jmp 目标不是内存（不是绝对指针表形态）"
    if not op.get("rip") or op.get("index") is None or op.get("scale") != 8:
        return None, "jmp 的内存操作数不是 [rip+idx*8]"
    return {"kind": "abs64", "table": op["rip_target"],
            "index_reg": op["index"], "jmp_reg": None, "base_reg": None,
            "chain": [recs[jpos][0]["addr"]]}, None


def _find_guard(recs, jpos, index_reg):
    """回溯 cmp idx,imm + ja/jae，返回 (count, addr, detail)。

    recs 是整个函数的指令序列（按地址升序），不是单块：实测 0x401870 的
    `cmp esi,7` 与 `ja` 落在间接 jmp 的前一块（guard 块），只在单块里找会漏。
    只取 jmp 之前最近的可用 guard，并把 guard 地址写进依据供审计。
    """
    for k in range(jpos - 1, max(-1, jpos - 1 - _MAX_BACKTRACK_ANY), -1):
        rec, ins = recs[k][1], recs[k][0]
        if not rec or rec.get("family") != "cmp":
            continue
        a, b = rec.get("a") or {}, rec.get("b") or {}
        if _reg_idx(a) == index_reg and b.get("t") == "imm":
            imm = b["value"]
        elif _reg_idx(b) == index_reg and a.get("t") == "imm":
            imm = a["value"]
        else:
            continue
        if k + 1 >= len(recs):
            continue
        nxt = recs[k + 1][1]
        if not (nxt and nxt.get("family") == "jcc"):
            continue
        cc = nxt.get("cc")
        if cc == 0x07:                      # ja：idx > imm 走默认分支 → [0, imm]
            return imm + 1, ins["addr"], "0x%x `cmp idx,0x%x` + `ja`" % (ins["addr"], imm)
        if cc == 0x03:                      # jae：idx >= imm 走默认分支 → [0, imm-1]
            return imm, ins["addr"], "0x%x `cmp idx,0x%x` + `jae`" % (ins["addr"], imm)
        return None, ins["addr"], "0x%x 的 cmp 后是 cc=0x%02x，不是可用的上界分支" \
            % (ins["addr"], cc)
    return None, None, "jmp 前回溯 %d 条未找到 `cmp idx,imm` + ja/jae" \
        % _MAX_BACKTRACK_ANY


# ── 表项扫描 ─────────────────────────────────────────────────────────
def _scan_entries(reader, table, count, kind, lo, hi, dec, idx):
    """逐项读表并校验目标。返回 (valid, rejected, truncated)。

    单条被拒即截止：后续项没有独立证据，继续扫等于猜。
    """
    es = _ENTRY_SIZE[kind]
    limit = count if count is not None else _MAX_SCAN_NO_GUARD
    valid, rejected = [], []
    truncated = False
    for i in range(limit):
        ent_va = table + i * es
        raw = reader.read(ent_va, es)
        if raw is None:
            rejected.append({"index": i, "entry": ent_va, "target": None,
                             "reason": "表项地址 0x%x 不在任何可读节内" % ent_va})
            truncated = True
            break
        if es == 4:
            tgt = table + struct.unpack("<i", raw)[0]
        else:
            tgt = struct.unpack("<Q", raw)[0]
        if not (lo <= tgt < hi):
            rejected.append({"index": i, "entry": ent_va, "target": tgt,
                             "reason": "目标 0x%x 超出声明函数域 0x%x..0x%x"
                                       "（跨函数/数据）" % (tgt, lo, hi)})
            truncated = True
            break
        inside = _inside_decoded(idx, tgt)
        if inside:
            rejected.append({"index": i, "entry": ent_va, "target": tgt,
                             "reason": "目标 0x%x 落在已解出指令 0x%x..0x%x 内部"
                                       "（错位/数据，不是指令边界）"
                                       % (tgt, inside[0], inside[1])})
            truncated = True
            break
        ins, err = dec.decode(tgt)
        if err:
            rejected.append({"index": i, "entry": ent_va, "target": tgt,
                             "reason": "目标 0x%x 无法解出指令（%s）" % (tgt, err)})
            truncated = True
            break
        valid.append({"index": i, "entry": ent_va, "target": tgt})
    return valid, rejected, truncated


# ── 候选扩展：独立 BFS，绝不写回 res ─────────────────────────────────
def _extend(res, func_addr, targets, lo, hi, dec, decoded):
    new = {}
    conflicts = []
    work = sorted(set(targets))
    while work:
        a = work.pop()
        while True:
            if a in decoded or a in new or not (lo <= a < hi):
                break
            ins, err = dec.decode(a)
            if err:
                conflicts.append({"addr": a, "reason": err})
                break
            new[a] = ins
            kind, tgt = recdesc_classify(ins)
            if kind in ("jcc_rel", "jcc_rel32", "loop_rel"):
                if tgt is not None and lo <= tgt < hi:
                    work.append(tgt)
                a += ins["length"]
                continue
            if kind == "jmp_rel":
                if tgt is not None and lo <= tgt < hi:
                    work.append(tgt)
                break
            if kind in ("ret", "hlt", "trap", "ud2", "jmp_ind"):
                break
            a += ins["length"]

    starts = set(t for t in targets if t in new)
    for a, ins in new.items():
        kind, tgt = recdesc_classify(ins)
        if tgt is not None and tgt in new:
            starts.add(tgt)
        if kind != "next" and kind not in ("call_rel", "call_ind"):
            nxt = a + ins["length"]
            if nxt in new:
                starts.add(nxt)
    starts = sorted(starts)
    return {
        "new_insns": len(new),
        "new_addrs": sorted(new),
        "new_block_starts": starts,
        "conflicts": conflicts,
    }


def recdesc_classify(ins):
    """薄包装：便于测试注入，不重复实现 M4 的分类规则。"""
    from . import recdesc
    return recdesc.classify(ins)


# ── 单个函数 ─────────────────────────────────────────────────────────
def analyze_function(res, func_addr, reader=None, boundary=None, ctx=None):
    """返回该函数的候选报告。绝不修改 res。

    boundary: 外部工具给出的指令边界集合（M9 升格判据），形如
      {"starts": iterable[int], "source": "GNU objdump 2.47 ..."}
    地址必须与 res 的 VA 同基准（PE 已减 ImageBase）。None 时不做升格判定，
    所有候选的 promotion.status = "not_checked"（默认行为不变）。
    ctx: build_context(res) 的结果；None 时本函数自建（单函数调用兼容），
      批量调用必须传 ctx，否则每次调用都重建全局索引（M10 之前的超时根因）。
    """
    from . import recdesc
    ctx = ctx or build_context(res)
    reader = reader or ctx["reader"]
    dec = ctx["decoder"]
    insns, blks, seed, lo, hi = _func_sets(res, func_addr, ctx)
    decoded = ctx["decoded"]
    idx = ctx["idx"]

    by_addr = {i["addr"]: i for i in insns}
    fn_addrs = sorted(by_addr)
    fn_pos = {a: k for k, a in enumerate(fn_addrs)}
    fn_recs = [(by_addr[a], _decode(by_addr[a])[0]) for a in fn_addrs]
    rep = {"function": func_addr, "range": [lo, hi],
           "boundary": "declared" if seed.get("end") else "unknown",
           "blocks_before": len(blks),
           "block_starts_before": sorted(b["start"] for b in blks),
           "candidates": [], "promoted": [],
           "unmatched": [], "rejected": [], "caveats": list(CAVEATS),
           "blocks_candidate": len(blks)}

    for b in blks:
        recs = []
        ok = True
        for a in b["insns"]:
            ins = by_addr.get(a)
            if ins is None:
                ok = False
                break
            rec, _err = _decode(ins)
            recs.append((ins, rec))
        if not ok:
            continue
        for jpos, (ins, _rec) in enumerate(recs):
            kind, _t = recdesc.classify(ins)
            if kind != "jmp_ind":
                continue
            cand, why_b = _match_rel32(recs, jpos)
            if cand is None:
                cand, why_a = _match_abs64(recs, jpos)
                if cand is None:
                    rep["unmatched"].append({
                        "jmp": ins["addr"],
                        "reason": "形态未识别：rel32 形态[%s]；abs64 形态[%s]"
                                  % (why_b, why_a)})
                    continue
            # guard 允许跨块：用函数级地址序回溯（形态链仍限同块）
            gpos = fn_pos.get(ins["addr"])
            count, guard_addr, guard_detail = (
                _find_guard(fn_recs, gpos, cand["index_reg"])
                if gpos is not None else (None, None, "函数级指令序列中找不到该 jmp"))
            valid, rejected, truncated = _scan_entries(
                reader, cand["table"], count, cand["kind"], lo, hi, dec, idx)

            basis = [
                "形态 %s：%s" % (cand["kind"], " → ".join("0x%x" % x
                                                        for x in cand["chain"])),
                "表基址 0x%x（%s）" % (cand["table"],
                                       "lea rip 相对" if cand["kind"] == "rel32"
                                       else "jmp rip 相对"),
                "表项 %d 字节，%s" % (_ENTRY_SIZE[cand["kind"]],
                                      "目标 = 表基址 + s32 偏移" if cand["kind"] == "rel32"
                                      else "目标 = u64 绝对地址"),
                ("表长 %d（guard 0x%x：%s）" % (count, guard_addr, guard_detail))
                if count is not None
                else ("表长未证明：%s；扫描至首个非法项，上限 %d"
                      % (guard_detail, _MAX_SCAN_NO_GUARD)),
            ]
            if seed.get("end") is None:
                basis.append("函数边界未声明：域按已解出指令外沿推断，可信度受限")
            if truncated:
                basis.append("扫描在首个非法项截止（后续项未证明）")

            if len(valid) < 2:
                rep["rejected"].append({
                    "jmp": ins["addr"], "table": cand["table"],
                    "reason": "有效目标 %d 项（<2），不足以构成跳转表" % len(valid),
                    "rejected_entries": rejected,
                    "basis": basis})
                continue

            tgts = [v["target"] for v in valid]
            dup = sorted(set(t for t in tgts if tgts.count(t) > 1))
            if dup:
                basis.append("重复目标：%s" % ", ".join("0x%x" % t for t in dup))

            if count is not None and not rejected and not truncated and len(valid) >= 4:
                level = EVIDENCE_HIGH
            elif len(valid) >= 4 or (count is not None and not rejected):
                level = EVIDENCE_MEDIUM
            else:
                level = EVIDENCE_LOW
            if truncated or len(valid) < 3:
                level = EVIDENCE_LOW if level == EVIDENCE_MEDIUM else level

            ext = _extend(res, func_addr, tgts, lo, hi, dec, decoded)
            # 目标若已是已解出指令且不在块首，会把既有块切成两块：单独计数
            blk_starts = {b["start"] for b in blks}
            nsplit = sum(1 for t in tgts if t in decoded
                         and decoded[t].get("origin") == func_addr
                         and t not in blk_starts)
            nnew = len(ext["new_block_starts"])
            if seed.get("end") is None:
                level = EVIDENCE_LOW
                basis.append("边界未声明：候选只能给形态，不能给函数域归属")

            # ── M9 升格：判据全部来自外部边界集合，不用我方解码结果自证 ──
            promote = {"status": "not_checked", "checks": {}, "reasons": []}
            if boundary is not None:
                bstarts = set(boundary.get("starts") or [])
                missing = [t for t in tgts if t not in bstarts]
                checks = {
                    "guard_proven": count is not None,
                    "table_complete": bool(count is not None and not rejected
                                           and not truncated),
                    "min_targets": len(tgts) >= 4,
                    "function_domain": all(lo <= t < hi for t in tgts),
                    "external_boundary": not missing,
                }
                reasons = []
                if not checks["guard_proven"]:
                    reasons.append("表长未证明（无 cmp/ja guard）")
                if not checks["table_complete"]:
                    reasons.append("表项有被拒或扫描被截断")
                if not checks["min_targets"]:
                    reasons.append("有效目标 <4（不足 4 项）")
                if not checks["function_domain"]:
                    reasons.append("存在目标超出声明函数域")
                if not checks["external_boundary"]:
                    reasons.append("外部 objdump 未把这些地址列为指令起点：%s"
                                   % ", ".join("0x%x" % t for t in missing[:8]))
                promote = {
                    "status": "promoted" if not reasons else "blocked",
                    "checks": checks, "reasons": reasons,
                    "source": boundary.get("source"),
                    "boundary_count": len(bstarts),
                }
                if not reasons:
                    basis.append("升格依据：表长有 guard + 表项完整 + %d 个目标"
                                 "均为外部 objdump 指令边界（%s）"
                                 % (len(tgts), boundary.get("source")))
                    rep["promoted"].append({
                        "jmp": ins["addr"], "table": cand["table"],
                        "kind": cand["kind"], "targets": tgts,
                        "guard": guard_addr, "source": boundary.get("source"),
                        "basis": list(basis),
                    })

            rep["candidates"].append({
                "jmp": ins["addr"], "kind": cand["kind"],
                "table": cand["table"], "entry_size": _ENTRY_SIZE[cand["kind"]],
                "count": count, "guard": guard_addr,
                "index_reg": cand["index_reg"], "jmp_reg": cand["jmp_reg"],
                "evidence": level, "basis": basis,
                "targets": tgts, "rejected_entries": rejected,
                "truncated": truncated, "promotion": promote,
                "new_insns": ext["new_insns"],
                "new_block_starts": ext["new_block_starts"],
                "blocks_before": len(blks),
                "blocks_candidate": len(blks) + nnew + nsplit,
                "conflicts": ext["conflicts"],
            })
            rep["blocks_candidate"] = max(
                rep["blocks_candidate"], len(blks) + nnew + nsplit)

    return rep


# ── 整个二进制 ───────────────────────────────────────────────────────
# 预算口径（M10）：确定性「指令步数」预算，不用墙钟时间。
#   单函数成本 = 该函数的指令条数 + 基本块数（只依赖输入，不依赖机器快慢，
#   因此同一 budget 在任何机器上跳过同一批函数，可复现）。
#
# 状态命名的硬约束（R106 / C2）：两种“没跑”必须用不同的名字，且自解释：
#   run_status = "ok"       本层已运行（本函数返回的报告恒为此值）；
#   run_status = "no_run"   整层未运行（超时/未启用），此时**没有**函数级统计，
#                           不得把函数数记成 skipped；
#   functions_skipped_budget = 因确定性预算/函数数上限而跳过的函数数（不是 no_run）；
#   禁止使用裸字段名 "skipped"：它同时被别的层用来表示“边界未声明”，同名不同义。
#   预算跳过单列，绝不当作「无候选」；候选/升格比率的分母只含 functions_analyzed。
RUN_STATUS_OK = "ok"
RUN_STATUS_NO_RUN = "no_run"
SKIP_TYPE_BUDGET = "skipped_budget"
_MAX_SKIP_DETAIL = 50


def analyze_binary(path, section=".text", res=None, boundary=None,
                   step_budget=None, max_functions=None):
    from . import recdesc
    res = res or recdesc.descend(path, section)
    ctx = build_context(res)
    reader = ctx["reader"]
    by_addr = ctx["decoded"]
    got = {}
    for b in res["blocks"]:
        for a in b["insns"]:
            ins = by_addr.get(a)
            if ins is None:
                continue
            kind, _t = recdesc.classify(ins)
            if kind == "jmp_ind":
                got[b["function"]] = got.get(b["function"], 0) + 1
    out = {"path": str(path), "section": section,
           "functions_with_indirect_jmp": len(got), "functions": [],
           "stats": {"candidates": 0, "high": 0, "medium": 0, "low": 0,
                     "promoted": 0, "blocked": 0, "not_checked": 0,
                     "unmatched": 0, "rejected": 0,
                     "new_insns": 0, "new_blocks": 0},
           "budget": {"run_status": RUN_STATUS_OK,
                      "step_budget": step_budget, "max_functions": max_functions,
                      "cost_model": "len(insns)+len(blocks)，与机器速度无关",
                      "steps_used": 0, "functions_analyzed": 0,
                      "functions_skipped_budget": 0,
                      "functions_no_run": 0,
                      "analysis_coverage": 1.0 if not got else 0.0,
                      "skipped_detail": [],
                      "status_semantics": {
                          "run_status": "ok=本层已运行；no_run=整层未运行"
                                        "（超时/未启用），此时没有函数级统计",
                          "functions_analyzed": "已分析函数数；候选/升格比率的唯一分母",
                          "functions_skipped_budget": "因确定性步数预算或函数数上限"
                                                      "而跳过的函数数（≠ 整层未运行）",
                          "functions_no_run": "整层未运行时的函数数；运行过则恒为 0",
                          "analysis_coverage": "analyzed / (analyzed + skipped_budget)，"
                                               "不含 no_run",
                      },
                      "scope_note": "stats 中候选/升格比率的分母只含 functions_analyzed；"
                                    "预算跳过单列（functions_skipped_budget），不当作"
                                    "“无候选”，也不并入确定集；整层未运行是 run_status="
                                    "no_run，与预算跳过不同名、不同义"},
           "caveats": list(CAVEATS)}
    detail = out["budget"]["skipped_detail"]
    for fn in sorted(got):
        insns, blks, _seed, _lo, _hi = _func_sets(res, fn, ctx)
        cost = len(insns) + len(blks)
        reason = None
        if max_functions is not None and \
                out["budget"]["functions_analyzed"] >= max_functions:
            reason = "function_batch_limit"
        elif step_budget is not None and \
                out["budget"]["steps_used"] + cost > step_budget:
            reason = "step_budget_exhausted"
        if reason is not None:
            out["budget"]["functions_skipped_budget"] += 1
            if len(detail) < _MAX_SKIP_DETAIL:
                detail.append({"function": fn, "cost": cost,
                               "skip_type": SKIP_TYPE_BUDGET, "reason": reason})
            continue
        out["budget"]["steps_used"] += cost
        out["budget"]["functions_analyzed"] += 1
        rep = analyze_function(res, fn, reader, boundary=boundary, ctx=ctx)
        if not (rep["candidates"] or rep["unmatched"] or rep["rejected"]):
            continue
        out["functions"].append(rep)
        out["stats"]["candidates"] += len(rep["candidates"])
        out["stats"]["unmatched"] += len(rep["unmatched"])
        out["stats"]["rejected"] += len(rep["rejected"])
        for c in rep["candidates"]:
            out["stats"][c["evidence"]] += 1
            out["stats"][c["promotion"]["status"]] += 1
            out["stats"]["new_insns"] += c["new_insns"]
            out["stats"]["new_blocks"] += len(c["new_block_starts"])
    total = out["budget"]["functions_analyzed"] + \
        out["budget"]["functions_skipped_budget"]
    out["budget"]["analysis_coverage"] = \
        (out["budget"]["functions_analyzed"] / total) if total else 1.0
    return out


def render_candidates(rep, single=False):
    if single:
        fns = [rep]
        stats = None
    else:
        fns = rep["functions"]
        stats = rep["stats"]
    lines = ["", "── 跳转表候选（非确定；仅 --switch-candidates 输出）──",
             "声明: 候选不进确定边 / 不进表达式默认输出 / 不进 CFG 确定口径；"
             "块数另记 blocks_candidate，与 CFG blocks 并列。"]
    if single:
        lines.append("函数 0x%x  域 0x%x..0x%x  boundary=%s  既有块 %d"
                     % (rep["function"], rep["range"][0], rep["range"][1],
                        rep["boundary"], rep["blocks_before"]))
    for r in fns:
        if not single:
            lines.append("函数 0x%x  域 0x%x..0x%x  既有块 %d"
                         % (r["function"], r["range"][0], r["range"][1],
                            r["blocks_before"]))
        for i, c in enumerate(r["candidates"], 1):
            lines.append("  候选 %d  %s  jmp@0x%x  表 0x%x  ｜ 证据 %s"
                         % (i, c["kind"], c["jmp"], c["table"], c["evidence"]))
            for x in c["basis"]:
                lines.append("      依据: %s" % x)
            lines.append("      候选目标: %s" % ", ".join(
                "0x%x" % t for t in c["targets"]))
            lines.append("      候选口径新增: 指令 +%d ｜ 块 %d → %d"
                         % (c["new_insns"], c["blocks_before"],
                            c["blocks_candidate"]))
            for e in c["rejected_entries"]:
                lines.append("      拒绝表项[%d]: %s"
                             % (e["index"], e["reason"]))
            for cf in c["conflicts"]:
                lines.append("      扩展冲突 0x%x: %s" % (cf["addr"], cf["reason"]))
        for u in r["unmatched"]:
            lines.append("  未识别间接跳转 0x%x：%s" % (u["jmp"], u["reason"]))
        for j in r["rejected"]:
            lines.append("  整条被拒 0x%x（表 0x%x）：%s"
                         % (j["jmp"], j["table"], j["reason"]))
            for e in j["rejected_entries"]:
                lines.append("      拒绝表项[%d]: %s" % (e["index"], e["reason"]))
        if not (r["candidates"] or r["unmatched"] or r["rejected"]):
            lines.append("  （无间接跳转）")
    if stats is not None:
        b = rep.get("budget") or {}
        lines.append("运行状态: %s ｜ 整层未运行函数数 %s"
                     % (b.get("run_status", "-"), b.get("functions_no_run", "-")))
        lines.append("汇总: 有间接 jmp 的函数 %d ｜ 已分析 %s ｜ 预算跳过 %s ｜ 分析覆盖率 %s"
                     % (rep["functions_with_indirect_jmp"],
                        b.get("functions_analyzed", "-"),
                        b.get("functions_skipped_budget", "-"),
                        ("%.4f" % b["analysis_coverage"]
                         if isinstance(b.get("analysis_coverage"), float) else "-")))
        lines.append("汇总: 候选 %d（high %d / medium %d / low %d）｜ 未识别 %d ｜ "
                     "整条被拒 %d ｜ 候选新增指令 %d / 块 %d"
                     % (stats["candidates"], stats["high"], stats["medium"],
                        stats["low"], stats["unmatched"], stats["rejected"],
                        stats["new_insns"], stats["new_blocks"]))
        lines.append("口径: 上列候选/升格比率的分母只含已分析函数；预算跳过单列，"
                     "不当作“无候选”，也不并入确定集"
                     + ("；skipped_detail 见 JSON" if b.get("functions_skipped_budget") else ""))
    lines.extend("  ! %s" % c for c in rep["caveats"])
    return "\n".join(lines)
