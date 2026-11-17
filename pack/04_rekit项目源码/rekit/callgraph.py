#!/usr/bin/env python3
# rekit.callgraph — 调用图 + 保守的跨过程观察（M6-U1）
#
# 只回答三件事，且每件事都有可回指的字节/结构证据：
#   1) 谁调用了谁：调用点 = 已解出指令里的全部 call（call_rel / call_ind）。
#      注意 recdesc.cfg.calls 只记录【块末】调用（M4 的 CFG 只看块终结符），
#      作为调用图会漏掉块内调用（cli-64.exe 实测 8 vs 153），故本模块全量扫描
#      指令，与 cfg.calls 是不同口径，各自单列、绝不混算。
#   2) 目标三态，占比必报（分母 = 直接调用点）：
#        decoded        目标已解出：落点是一条已解出指令（并区分是否函数入口）；
#        plt_or_import  目标在 PLT 或外部导入：落在 .plt/.plt.sec/.plt.got/.iplt
#                       节，或目标符号以 @plt 结尾，或目标函数体是单条
#                       jmp [IAT/GOT 槽]（槽地址可由 .rela.plt/.rela.dyn 或
#                       PE 导入表回指到符号名时给出名字；回指不到就只报槽地址）；
#        unresolved     目标未解析：既不在已解出指令里，也不在 PLT/导入槽上。
#   3) 保守观察：某寄存器/栈槽在调用点【同一基本块内】的定义与使用。
#      只报事实——before = 调用点前最后一次定义，after = 调用点后第一次使用；
#      不做 ABI 推断、不猜参数个数、不给参数命名、不跨块传播。
#
# 分级与隔离（沿用 R45 / R49–R52 的措辞）：
#   · 直接调用按确定边口径统计（目标已解出才算确定边；PLT/导入是确定事实但
#     无函数体；未解析只记调用点，不猜目标）；
#   · 间接调用一律走候选层：默认关闭，开启后单列、带证据等级（high/medium/low），
#     绝不并入上面的三态占比；
#   · 候选层的 high 只用于「间接调用点的内存操作数能静态定位到导入槽」这一事实，
#     不表示「调用目标是 xxx 函数」已被证明。
#
# 已知盲区（写进 CAVEATS）：
#   · 只覆盖已解出指令；未解码区域（VEX 伪编码/数据/其它节）里的调用不可见；
#   · 只在 --section 指定的节内递归下降，其它节里的函数体不在节点集合里；
#   · 间接调用（寄存器、基址+索引、虚表）目标不可静态确定，只给候选层；
#   · 不做类型/ABI/参数个数推断；观察窗口限定在同一基本块，跨块数据流一律不报；
#   · 环识别只对「函数级直接调用边」做 Tarjan SCC，不含间接/导入边。
import argparse
import json
import struct
import sys
from bisect import bisect_right

from . import elf, expr, pe, recdesc
from .errors import RekitError

CAVEATS = [
    "调用点只覆盖已解出指令；未解码区域里的调用不可见，也不在分母里",
    "cfg.calls 只记录块末调用；本模块全量扫描指令，两个口径单列、不合并",
    "直接调用按确定边统计，间接调用走候选层（默认关闭），两者不合并计数",
    "目标三态 decoded / plt_or_import / unresolved，占比分母是直接调用点",
    "参数观察只报事实：同块内调用点前最后定义、后首次使用；不跨块",
    "不做 ABI 推断：不猜参数个数、不给参数命名、不认定调用约定",
    "环识别只针对函数级直接调用边（Tarjan SCC），不含间接/导入边",
    "PLT/导入名字只有在槽地址能回指符号表/导入表时才给出，否则只报槽地址",
]

STATE_DECODED = "decoded"
STATE_PLT = "plt_or_import"
STATE_UNRESOLVED = "unresolved"
_STATES = (STATE_DECODED, STATE_PLT, STATE_UNRESOLVED)
_PLT_SECTIONS = (".plt", ".plt.sec", ".plt.got", ".iplt")

# legacy 前缀（段/地址长度/操作数长度/重复/锁）；REX 是 0x40..0x4F，单独判断。
# 判指令类别前必须先跳过它们（R71）：见 _call_insns 与 _Ctx._rip_mem。
_LEGACY_PREFIX = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
                            0x66, 0x67, 0xF0, 0xF2, 0xF3))


def _opcode_of(raw):
    """跳过 legacy 前缀与 REX 后的第一个 opcode 及其下标；raw 为 bytes。

    返回 (opcode, 下标)；全是被前缀字节时返回 (None, len(raw))。
    """
    i, n = 0, len(raw)
    while i < n and raw[i] in _LEGACY_PREFIX:
        i += 1
    if i < n and 0x40 <= raw[i] <= 0x4F:
        i += 1
    return (raw[i], i) if i < n else (None, i)


def _is_padding(raw_hex):
    """是否是无副作用填充（nop / int3 / endbr64；按 opcode 判，跳前缀）。"""
    b = bytes.fromhex(raw_hex.replace(" ", ""))
    i, n = 0, len(b)
    while i < n and b[i] in _LEGACY_PREFIX:
        i += 1
    if i >= n:
        return False
    if b[i] in (0x90, 0xCC):                       # nop / int3
        return True
    return b[i] == 0x0F and i + 1 < n and b[i + 1] in (0x1E, 0x1F)

EV_HIGH, EV_MEDIUM, EV_LOW = "high", "medium", "low"


# ── 地址/字节/符号上下文（只读文件字节） ──────────────────────────────
class _Ctx:
    def __init__(self, path, res, section):
        self.path = path
        self.res = res
        self.section = section
        self.data = open(path, "rb").read()
        self.is_elf = self.data[:4] == b"\x7fELF"
        self.ranges = []          # (va_lo, va_hi, file_off) 文件背书的可读区间
        self.sections = []        # (name, va, va+size)
        self.import_slots = {}    # va/rva -> "dll!name" / ".rela.plt 符号名"
        if self.is_elf:
            r = elf.parse(path)
            for s in elf.section_headers(self.data):
                # sh_addr==0 的节（.comment/.shstrtab 等）不占地址空间：
                # 把它们算进地址映射会把 0x0 误标成某个非装载节。
                if s["size"] > 0 and s["addr"]:
                    self.sections.append((s["name"], s["addr"],
                                          s["addr"] + s["size"]))
                    if s["offset"]:
                        self.ranges.append((s["addr"], s["addr"] + s["size"],
                                            s["offset"]))
            for (sec_name, _off, entries) in r.get("relocations") or []:
                for (r_offset, _ri, rtype, _tn, _si, sym_nm, _sv, _add) in entries:
                    if sym_nm and rtype in (6, 7):     # GLOB_DAT / JUMP_SLOT
                        self.import_slots.setdefault(r_offset, sym_nm)
            self.entry = struct.unpack_from("<Q", self.data, 24)[0]
        else:
            r = pe.parse(path)
            for (va, vsize, rawptr, rawsize, name) in r["sections"]:
                size = max(vsize, rawsize)
                self.sections.append((name, va, va + size))
                if rawsize:
                    self.ranges.append((va, va + rawsize, rawptr))
            self.import_slots = expr._import_names(path)
            self.entry = r["entry"]
        self.ranges.sort()
        self.seeds = {s["addr"]: s for s in res["seeds"]}
        self.ins_by_addr = {i["addr"]: i for i in res["instructions"]}
        self.block_by_addr = {}
        for b in res["blocks"]:
            for a in b["insns"]:
                self.block_by_addr[a] = b
        self.func_start = {f["addr"] for f in expr.list_functions(res)}
        self._func_insns = {}
        for i in res["instructions"]:
            self._func_insns.setdefault(i.get("origin"), []).append(i)
        self._thunk = {}

    # ---- 地址换算 ----
    def section_of(self, va):
        for name, lo, hi in self.sections:
            if lo <= va < hi:
                return name
        return None

    def read(self, va, n):
        k = bisect_right(self.ranges, (va, float("inf"), float("inf"))) - 1
        if k < 0:
            return None
        lo, hi, off = self.ranges[k]
        if lo <= va and va + n <= hi:
            return self.data[off + (va - lo):off + (va - lo) + n]
        return None

    def symbol_of(self, addr):
        seed = self.seeds.get(addr)
        if seed:
            for d in seed.get("details") or []:
                # fde@0x... 是种子来源标注，不是符号名；不给没证据的名字
                if d and not d.startswith(("range ", "0x", "fde@")):
                    return d
        return None

    # FF /2（call）与 FF /4（jmp）的 [rip+disp32] 识别（M7-U2，R71）
    def _rip_mem(self, va):
        """返回 (reg, 槽地址, 指令长度)；不是 FF 15/25 形态（[rip+disp32]）→ None。

        legacy 前缀与 REX 必须跳过：它们让 ModRM 与 disp 整体后移，按 raw 首字节
        判 FF 会把 `48 ff 25 …` 整条漏掉；disp 偏移也不能写死 +2。
        reg=2 是 call（FF /2），reg=4 是 jmp（FF /4）。
        """
        b = self.read(va, 15) or self.read(va, 6)
        if not b:
            return None
        i, n = 0, len(b)
        while i < n and b[i] in _LEGACY_PREFIX:
            i += 1
        if i < n and 0x40 <= b[i] <= 0x4F:
            i += 1
        if i + 6 > n or b[i] != 0xFF:
            return None
        modrm = b[i + 1]
        reg = (modrm >> 3) & 7
        if (modrm >> 6) != 0 or (modrm & 7) != 5 or reg not in (2, 4):
            return None
        disp = struct.unpack_from("<i", b, i + 2)[0]
        return reg, va + i + 6 + disp, i + 6

    def rip_mem_target(self, va):
        """FF 15/FF 25 形态：返回 [rip+disp] 的绝对目标（RVA/VA），否则 None。

        只认这两种编码（call/jmp qword ptr [rip+disp32]），不做全指令解码，
        因为目标可能落在未分析的节（.plt）里，没有已解边界可依赖。
        """
        r = self._rip_mem(va)
        return r[1] if r else None

    # ---- 导入跳板判定 ----
    def thunk_of(self, fn):
        """函数体是「无副作用填充* + 一条 jmp [槽]」且槽能回指导入 → (槽, 名字)。

        判据（M8-U0 / R71）：用 _rip_mem 跳前缀取 opcode 与 disp，不按首字节；
        前导只允许 endbr64 / nop / int3 这类填充——`lea rcx,[rip+x]; jmp [rip+y]`
        是「带参数的跳板」，有可观察效果，不在此列（cli-64 实测 2 处，保持不命名）。
        """
        if fn in self._thunk:
            return self._thunk[fn]
        self._thunk[fn] = None
        insns = self._func_insns.get(fn) or []
        if not insns:
            return None
        for ins in insns[:-1]:
            if not _is_padding(ins["bytes"]):
                return None
        r = self._rip_mem(insns[-1]["addr"])
        if not r or r[0] != 4:             # 必须是 jmp（FF /4），不是 call
            return None
        slot = r[1]
        if slot not in self.import_slots:
            return None
        self._thunk[fn] = (slot, self.import_slots[slot])
        return self._thunk[fn]

    def plt_stub_info(self, va):
        """.plt 桩：jmp [槽] → 返回 (槽, 名字|None)；槽读不到就 (None, None)。"""
        slot = self.rip_mem_target(va)
        if slot is None:
            return None, None
        return slot, self.import_slots.get(slot)


# ── 目标三态分类（直接调用） ─────────────────────────────────────────
def _classify(ctx, target):
    """返回 (state, evidence, label)。

    label 仅在目标能回指到名字时给出（导入名/符号名），否则 None——
    不给没证据的名字。
    """
    sec = ctx.section_of(target)
    if sec in _PLT_SECTIONS or (sec or "").startswith(".plt"):
        slot, nm = ctx.plt_stub_info(target)
        if slot is not None:
            return (STATE_PLT,
                    "目标落在 %s 节；桩 jmp [0x%x]%s" % (
                        sec, slot, (" → " + nm) if nm else "（槽未回指导入名）"),
                    nm)
        return STATE_PLT, "目标落在 %s 节（PLT 桩；桩结构未按 FF25 解出）" % sec, None
    if target in ctx.ins_by_addr:
        sym = ctx.symbol_of(target)
        if sym and sym.endswith("@plt"):
            return STATE_PLT, "目标符号 %s（@plt 后缀）" % sym, sym
        thunk = ctx.thunk_of(target)
        if thunk:
            return (STATE_PLT,
                    "目标是导入跳板：单条 jmp [0x%x] = %s" % thunk, thunk[1])
        if target in ctx.block_by_addr:
            blk = ctx.block_by_addr[target]
            where = ("函数入口" if target in ctx.func_start
                     else "函数 0x%x 的中部（非入口）" % (blk["function"] or 0))
            return (STATE_DECODED,
                    "目标是已解出指令（%s）%s" % (where, "，符号 " + sym if sym else ""),
                    sym)
        return STATE_DECODED, "目标是已解出指令（不在任何基本块内）", sym
    if ctx.ins_by_addr:
        return (STATE_UNRESOLVED,
                "目标 0x%x 不在已解出指令内（%s），也不是 PLT/导入槽"
                % (target, sec or "节外"), None)
    return STATE_UNRESOLVED, "目标 0x%x 无可判定信息" % target, None


# ── 间接调用候选层（默认关闭） ───────────────────────────────────────
def _indirect_candidate(ctx, ins, rec):
    ind = rec.get("indirect") or {}
    base = {"from": ins["addr"], "bytes": ins["bytes"],
            "form": _indirect_form(ind)}
    if ind.get("t") == "mem" and ind.get("rip"):
        slot = ind.get("rip_target")
        nm = ctx.import_slots.get(slot)
        if nm:
            return dict(base, target_slot=slot, target_label=nm,
                        evidence=EV_HIGH,
                        basis="rip 相对内存操作数静态定位到导入槽 0x%x = %s；"
                              "调用目标是外部导入（非本地函数）" % (slot, nm))
        sec = ctx.section_of(slot) if slot is not None else None
        return dict(base, target_slot=slot, target_label=None,
                    evidence=EV_MEDIUM,
                    basis="rip 相对内存操作数静态定位到 0x%x（%s），但槽内容未解析"
                          "（可能是函数指针表）；不猜被调函数"
                    % (slot, sec or "节外"))
    return dict(base, target_slot=None, target_label=None, evidence=EV_LOW,
                basis="寄存器/基址+索引间接：目标不可静态确定")


def _indirect_form(ind):
    if ind.get("t") == "mem":
        if ind.get("rip"):
            return "mem-rip"
        if ind.get("index") is not None:
            return "mem-base-index"
        return "mem-base"
    if ind.get("t") == "reg":
        return "reg:" + ind.get("name", "?")
    return "unknown"


# ── 保守观察：def/use（只读事实，不推断） ────────────────────────────
_REG = expr._REG64


def _slot_name(op):
    if op.get("t") != "mem" or op.get("rip") or op.get("index") is not None:
        return None
    base = op.get("base")
    if base not in (4, 5):            # rsp / rbp
        return None
    disp = op.get("disp") or 0
    return "[%s%+d]" % (_REG[base], disp)


def _mem_regs(op):
    out = []
    if op.get("t") != "mem":
        return out
    if op.get("base") is not None:
        out.append(_REG[op["base"]])
    if op.get("index") is not None:
        out.append(_REG[op["index"]])
    return out


def _effects(rec):
    """返回 (defs, uses, unknown)。操作数级事实，不做别名/类型推断。

    defs/uses 元素：("reg", 名字) 或 ("slot", "[rbp-0x8]")。
    unknown=True 表示该指令有未建模的隐式读写（intrinsic），观察窗口必须截断。
    """
    fam = rec["family"]
    d, u = [], []

    def def_op(op):
        if op is None:
            return
        if op.get("t") == "reg":
            d.append(("reg", op["name"]))
        else:
            s = _slot_name(op)
            if s:
                d.append(("slot", s))

    def use_op(op):
        if op is None:
            return
        if op.get("t") == "reg":
            u.append(("reg", op["name"]))
        else:
            for r in _mem_regs(op):
                u.append(("reg", r))
            s = _slot_name(op)
            if s:
                u.append(("slot", s))

    if fam == "assign":
        def_op(rec["dst"])
        use_op(rec["src"])
        if rec["dst"].get("t") == "mem":
            # 写内存要读地址寄存器；写寄存器不是"使用"该寄存器
            for r in _mem_regs(rec["dst"]):
                u.append(("reg", r))
    elif fam == "lea":
        # lea 只算地址，不解引用：只取地址寄存器，不把栈槽记成使用
        def_op(rec["dst"])
        for r in _mem_regs(rec["src"]):
            u.append(("reg", r))
    elif fam == "binop":
        def_op(rec["dst"])
        use_op(rec["dst"])
        use_op(rec["src"])
        use_op(rec.get("src2"))
    elif fam in ("unop", "shift"):
        def_op(rec["dst"])
        use_op(rec["dst"])
        if fam == "shift":
            use_op(rec.get("count"))
    elif fam in ("cmp", "test"):
        use_op(rec.get("a"))
        use_op(rec.get("b"))
    elif fam == "call":
        use_op(rec.get("indirect"))
    elif fam == "jmp":
        use_op(rec.get("indirect"))
    elif fam == "ret":
        u.append(("reg", "rsp"))
    elif fam in ("push", "pop"):
        if fam == "push":
            use_op(rec.get("src"))
        else:
            def_op(rec.get("dst"))
        u.append(("reg", "rsp"))
        d.append(("reg", "rsp"))
    elif fam == "leave":
        u.extend([("reg", "rbp"), ("reg", "rsp")])
        d.extend([("reg", "rsp"), ("reg", "rbp")])
    elif fam in ("setcc", "cmov"):
        def_op(rec.get("dst"))
        if fam == "cmov":
            use_op(rec.get("dst"))
            use_op(rec.get("src"))
    elif fam in ("bswap", "xchg"):
        for k in ("dst", "a", "b"):
            def_op(rec.get(k))
            use_op(rec.get(k))
    elif fam == "conv":
        u.extend([("reg", "rax"), ("reg", "rdx")])
        d.extend([("reg", "rax"), ("reg", "rdx")])
    elif fam in ("nop", "trap", "hlt", "ud2"):
        pass
    elif fam == "intrinsic":
        return d, u, True
    return d, u, False


def _observe_call(ctx, ins, rec, blk):
    """同块窗口内的 before 定义 / after 使用（只报事实）。"""
    insns = blk["insns"] if blk else []
    try:
        i = insns.index(ins["addr"])
    except ValueError:
        return {"from": ins["addr"], "window": None,
                "note": "调用点不在任何基本块内：不报前后观察"}
    before, seen_d = [], {}
    barrier_before = None
    n_before_decoded = 0
    for a in reversed(insns[:i]):
        prev = ctx.ins_by_addr.get(a)
        try:
            r = expr.decode(prev)
        except expr.LiftError as e:
            barrier_before = {"addr": a, "reason": e.reason}
            break
        dd, _uu, unknown = _effects(r)
        if unknown:
            barrier_before = {"addr": a,
                              "reason": "未建模隐式读写（%s），前向窗口截断"
                                        % (r.get("text") or "intrinsic")}
            break
        n_before_decoded += 1
        for kind, name in dd:
            if (kind, name) not in seen_d:
                seen_d[(kind, name)] = {"operand": name, "kind": kind,
                                        "at": a, "bytes": prev["bytes"]}
    # 排序只为输出稳定（不改变"最后定义/首次使用"的语义）
    before = sorted(seen_d.values(), key=lambda x: (x["kind"], x["operand"]))

    after, seen_u = [], set()
    barrier_after = None
    n_after_decoded = 0
    for a in insns[i + 1:]:
        nxt = ctx.ins_by_addr.get(a)
        try:
            r = expr.decode(nxt)
        except expr.LiftError as e:
            barrier_after = {"addr": a, "reason": e.reason}
            break
        _dd, uu, unknown = _effects(r)
        if unknown:
            barrier_after = {"addr": a,
                             "reason": "未建模隐式读写（%s），后向窗口截断"
                                       % (r.get("text") or "intrinsic")}
            break
        for kind, name in uu:
            if (kind, name) in seen_u:
                continue
            seen_u.add((kind, name))
            after.append({"operand": name, "kind": kind, "at": a,
                          "bytes": nxt["bytes"]})
        n_after_decoded += 1
    after.sort(key=lambda x: (x["at"], x["operand"]))
    rsp_moved = any(d["operand"] == "rsp" for d in before)
    return {
        "from": ins["addr"], "function": blk["function"] if blk else None,
        "block": blk["start"] if blk else None,
        "window": {"block_start": blk["start"] if blk else None,
                   "block_end": blk["end"] if blk else None,
                   "before_insns": len(insns[:i]) if blk else 0,
                   "after_insns": len(insns) - i - 1 if blk else 0,
                   "before_decoded": n_before_decoded,
                   "after_decoded": n_after_decoded,
                   "rsp_modified_before": rsp_moved,
                   "before_barrier": barrier_before,
                   "after_barrier": barrier_after},
        "before_defs": before, "after_uses": after,
        "note": "仅同块窗口内的操作数事实；不做 ABI 推断、不猜参数个数、不命名参数",
    }


# ── 图构建 ───────────────────────────────────────────────────────────
def _call_insns(ctx):
    """全部已解出的 call 指令（含块内，不只块末）。按地址排序。

    判据（M7-U2，R71）：跳过 legacy 前缀与 REX 后取 opcode——`e8` 是直接 call；
    `ff` 还须 ModRM.reg ∈ {2,3}（call r/m，组扩展位不受 REX.R 影响）。最后仍交
    expr.decode 复核 family=="call"，防止表外编码混入。不得按 raw 首字节判定：
    `41 ff d6`（call r14）、`43 ff 14 fe`（call [r14+r15*8]）、`67 e8` 都会被漏。
    """
    out = []
    for ins in ctx.res["instructions"]:
        raw = bytes.fromhex(ins["bytes"].replace(" ", ""))
        op, i = _opcode_of(raw)
        if op == 0xE8:
            pass
        elif op == 0xFF and i + 1 < len(raw):
            if ((raw[i + 1] >> 3) & 7) not in (2, 3):
                continue
        else:
            continue
        try:
            rec = expr.decode(ins)
        except expr.LiftError:
            continue
        if rec.get("family") == "call":
            out.append((ins, rec))
    out.sort(key=lambda x: x[0]["addr"])
    return out


def build(path, section=".text", res=None, indirect=False, observe=False):
    res = res if res is not None else recdesc.descend(path, section)
    ctx = _Ctx(path, res, section)
    calls = _call_insns(ctx)

    edges, ind_edges, observations = [], [], []
    counts = {"call_sites": len(calls), "direct": 0, "indirect": 0,
              STATE_DECODED: 0, STATE_PLT: 0, STATE_UNRESOLVED: 0}
    ind_counts = {EV_HIGH: 0, EV_MEDIUM: 0, EV_LOW: 0}

    for ins, rec in calls:
        blk = ctx.block_by_addr.get(ins["addr"])
        from_fn = blk["function"] if blk else ins.get("origin")
        if rec.get("target") is not None:
            counts["direct"] += 1
            state, evidence, label = _classify(ctx, rec["target"])
            counts[state] += 1
            edges.append({
                "from_fn": from_fn, "from": ins["addr"], "to": rec["target"],
                "to_fn": (rec["target"] if state == STATE_DECODED else None),
                "state": state, "evidence": evidence,
                "target_symbol": label,
                "to_section": ctx.section_of(rec["target"]),
                "bytes": ins["bytes"],
            })
        else:
            counts["indirect"] += 1
            c = _indirect_candidate(ctx, ins, rec)
            c["from_fn"] = from_fn
            ind_counts[c["evidence"]] += 1
            ind_edges.append(c)
        if observe:
            observations.append(_observe_call(ctx, ins, rec, blk))

    total_direct = counts["direct"] or 0
    ratios = {s: (counts[s] / total_direct if total_direct else None)
              for s in _STATES}

    # ---- 节点/环 ----
    nodes, cycles = _nodes_and_cycles(ctx, res, edges)
    report = {
        "path": str(path), "section": section,
        "entry": ctx.entry,
        "counts": counts, "ratios": ratios,
        "cfg_call_counts": res["cfg"]["call_counts"],
        "cfg_call_note": "recdesc.cfg.calls 只统计块末调用；与本模块的全量调用点"
                         "口径不同，不合并",
        "edges": edges,
        "indirect": {
            "enabled": bool(indirect),
            "candidates": ind_edges if indirect else [],
            "counts": ind_counts,
            "note": ("候选层已开启：单列、带证据等级，不并入三态占比"
                     if indirect else
                     "候选层默认关闭：%d 个间接调用点未计入统计；"
                     "加 --indirect-candidates 查看候选（不并入确定集）"
                     % counts["indirect"]),
        },
        "nodes": nodes, "cycles": cycles,
        "observations": observations if observe else None,
        "observe_note": ("只报同块窗口内的寄存器/栈槽定义与使用；"
                         "不做 ABI 推断、不猜参数个数、不给参数命名"
                         if observe else None),
        "caveats": list(CAVEATS),
    }
    return report


def _nodes_and_cycles(ctx, res, edges):
    """函数级节点 + 直接调用边上的 Tarjan SCC（自环/互递归）。"""
    fn_calls = {}
    nodes = {}
    for f in expr.list_functions(res):
        nodes[f["addr"]] = {
            "addr": f["addr"], "symbol": f["symbol"],
            "boundary": f["boundary"], "authority": f["authority"],
            "insns": f["insns"], "blocks": f["blocks"],
            "out_calls": 0, "in_calls": 0, "recursion": None, "scc": None,
        }
    for e in edges:
        f = e["from_fn"]
        if f is None:
            continue
        if f in nodes:
            nodes[f]["out_calls"] += 1
        t = e["to_fn"]
        if t is not None and t in nodes:
            nodes[t]["in_calls"] += 1
            fn_calls.setdefault(f, set()).add(t)

    sccs = _sccs(sorted(nodes), fn_calls)
    cycles = []
    for i, comp in enumerate(sccs):
        self_loop = any(m in fn_calls.get(m, ()) for m in comp)
        if len(comp) < 2 and not self_loop:
            continue
        kind = "self" if len(comp) == 1 else "mutual"
        cycles.append({"scc": i, "kind": kind, "size": len(comp),
                       "members": sorted(comp)})
        for m in comp:
            if m in nodes:
                nodes[m]["scc"] = i
                nodes[m]["recursion"] = "mutual" if len(comp) > 1 else "self"
    cycles.sort(key=lambda c: (-c["size"], c["members"][0]))
    for n in nodes.values():
        if n["out_calls"] == 0 and n["in_calls"] == 0:
            n["orphan"] = True
    return [nodes[a] for a in sorted(nodes)], cycles


def _sccs(nodes, succ):
    """Tarjan（迭代版，确定性顺序）。返回全部 SCC。"""
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
            ss = sorted(succ.get(v, ()))
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
                out.append(sorted(comp))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
    return out


# ── 渲染 ─────────────────────────────────────────────────────────────
def _pct(x):
    return "n/a" if x is None else "%.2f%%" % (100 * x)


def render(report, max_tree=120):
    c, r = report["counts"], report["ratios"]
    lines = [
        "CALLGRAPH: %s  section=%s  entry=0x%x"
        % (report["path"], report["section"], report["entry"]),
        "调用点 共 %d（直接 %d ｜ 间接 %d；两口径不合并）"
        % (c["call_sites"], c["direct"], c["indirect"]),
        "直接调用目标三态（分母 = 直接 %d）:" % c["direct"],
        "  %-16s %5d  %s" % ("已解出 decoded", c[STATE_DECODED],
                             _pct(r[STATE_DECODED])),
        "  %-16s %5d  %s" % ("PLT/外部导入", c[STATE_PLT],
                             _pct(r[STATE_PLT])),
        "  %-16s %5d  %s" % ("未解析 unresolved", c[STATE_UNRESOLVED],
                             _pct(r[STATE_UNRESOLVED])),
    ]
    ic = report["indirect"]["counts"]
    if report["indirect"]["enabled"]:
        lines.append("间接调用候选层（单列，不进上面占比）: "
                     "high %d / medium %d / low %d"
                     % (ic[EV_HIGH], ic[EV_MEDIUM], ic[EV_LOW]))
    else:
        lines.append("间接调用候选层: 默认关闭（%d 个调用点未计入）"
                     % c["indirect"])
    cfg = report["cfg_call_counts"]
    lines.append("注: recdesc.cfg.calls 只记块末调用（definite %d / unresolved %d / "
                 "undecoded %d），与全量口径不同，不合并"
                 % (cfg.get("definite", 0), cfg.get("unresolved", 0),
                    cfg.get("undecoded", 0)))
    nodes = report["nodes"]
    callers = [n for n in nodes if n["out_calls"]]
    lines.append("函数节点 %d ｜ 有出边 %d ｜ 有入边 %d ｜ 孤立（无调用关系）%d"
                 % (len(nodes), len(callers),
                    sum(1 for n in nodes if n["in_calls"]),
                    sum(1 for n in nodes if n.get("orphan"))))
    # 三态样例（带证据文本，便于对读）
    for st, label in ((STATE_DECODED, "已解出"),
                      (STATE_PLT, "PLT/导入"),
                      (STATE_UNRESOLVED, "未解析")):
        sample = [e for e in report["edges"] if e["state"] == st][:3]
        for e in sample:
            lines.append("  · [%s] 0x%x → 0x%x  %s"
                         % (label, e["from"], e["to"], e["evidence"]))
    # 环
    if report["cycles"]:
        lines.append("环: %d 组" % len(report["cycles"]))
        for cy in report["cycles"][:10]:
            kind = "自递归" if cy["kind"] == "self" else "互递归"
            lines.append("  · %s SCC#%d 大小 %d: %s"
                         % (kind, cy["scc"], cy["size"],
                            ", ".join("0x%x" % m for m in cy["members"][:8])
                            + (" …" if cy["size"] > 8 else "")))
    else:
        lines.append("环: 无（函数级直接调用边未发现自环/互递归）")
    lines.extend(_render_tree(report, max_tree))
    if report["observations"] is not None:
        lines.extend(_render_observations(report["observations"]))
    lines.append("caveats:")
    for x in report["caveats"]:
        lines.append("  ! %s" % x)
    return "\n".join(lines)


def _render_tree(report, max_tree):
    """从入口与各无入边函数起渲染调用树；visited 防环，节点数/深度双上限。"""
    succ = {}
    for e in report["edges"]:
        if e["to_fn"] is not None:
            succ.setdefault(e["from_fn"], []).append(e["to_fn"])
    roots = [report["entry"]] if report["entry"] in succ else []
    roots += [n["addr"] for n in report["nodes"]
              if n["in_calls"] == 0 and n["out_calls"] > 0
              and n["addr"] not in roots]
    lines = ["调用树（直接边，visited 防环，节点上限 %d）:" % max_tree]
    if not roots:
        lines.append("  （无直接调用边）")
        return lines
    visited, emitted = set(), 0
    for root in roots:
        if emitted >= max_tree:
            lines.append("  … 截断（达到节点上限 %d；其余根未展开）" % max_tree)
            return lines
        stack = [(root, 0)]
        while stack:
            fn, depth = stack.pop()
            if emitted >= max_tree:
                lines.append("  … 截断（达到节点上限 %d）" % max_tree)
                return lines
            emitted += 1
            lines.append("  %s%s 0x%x%s" % (
                "  " * depth, "└→" if depth else "▶", fn,
                "  [已展开过：不再重复展开]" if fn in visited else ""))
            if fn in visited or depth >= 12:
                continue
            visited.add(fn)
            for t in reversed(sorted(set(succ.get(fn, ())))):
                stack.append((t, depth + 1))
    if report["cycles"]:
        lines.append("  （环上的节点只展开一次；环清单见上）")
    return lines


def _render_observations(obs, limit=40):
    lines = ["跨过程观察（保守：同块窗口内的事实；不推断 ABI）:"]
    for o in obs[:limit]:
        if not o.get("window"):
            lines.append("  · 0x%x：%s" % (o["from"], o.get("note")))
            continue
        lines.append("  · 调用点 0x%x（函数 0x%x / 块 0x%x）"
                     % (o["from"], o["function"] or 0, o["block"] or 0))
        if o["before_defs"]:
            for d in o["before_defs"][:6]:
                lines.append("      before %-8s ← 0x%x  %s"
                             % (d["operand"], d["at"], d["bytes"]))
        else:
            lines.append("      before: 同块内无可解码的定义")
        if o["after_uses"]:
            for u in o["after_uses"][:6]:
                lines.append("      after  %-8s → 0x%x  %s"
                             % (u["operand"], u["at"], u["bytes"]))
        else:
            lines.append("      after : 同块内无可解码的使用")
        w = o["window"]
        if w.get("rsp_modified_before"):
            lines.append("      注: 窗口内 rsp 被改写；栈槽按指令里原样地址表达式记录，"
                         "未重算实际位置")
        for key in ("before_barrier", "after_barrier"):
            if w.get(key):
                lines.append("      窗口截断: 0x%x %s"
                             % (w[key]["addr"], w[key]["reason"]))
    if len(obs) > limit:
        lines.append("  … 其余 %d 个调用点见 --json" % (len(obs) - limit))
    return lines


# ── CLI ──────────────────────────────────────────────────────────────
def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rekit callgraph",
        description="调用图 + 保守跨过程观察（三态占比；间接调用走候选层）")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--indirect-candidates", action="store_true",
                    help="输出间接调用候选层（默认关闭；单列、带证据等级，"
                         "不并入三态占比）")
    ap.add_argument("--observe", action="store_true",
                    help="输出跨过程观察（同块内调用点前的定义/后的使用；"
                         "不做 ABI 推断）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        with open(args.file, "rb"):
            pass
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    try:
        rep = build(args.file, args.section, indirect=args.indirect_candidates,
                    observe=args.observe)
    except ValueError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except (struct.error, IndexError, RekitError) as e:
        print("rekit: %s: 解析失败(%s: %s)"
              % (args.file, type(e).__name__, e), file=sys.stderr)
        return 3
    print(json.dumps(rep, ensure_ascii=False, indent=2) if args.json
          else render(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
