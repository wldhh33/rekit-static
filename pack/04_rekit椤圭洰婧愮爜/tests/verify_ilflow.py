#!/usr/bin/env python3
# tests/verify_ilflow.py — M18 .NET IL 控制流层外部独立重算
#
# 期望值全部来自独立来源，不取自被测实现：
#   (a) dncil 独立解码每条指令的操作数并计算分支目标（code-relative），
#       先做全量聚合对账（分支形态/目标落点/EH 子句/调用指令/ token 表），
#       再对报告存储的方法逐条比对分支目标与 EH 结构；
#   (b) dnfile 独立读 MethodDef/MemberRef/MethodSpec/TypeRef/AssemblyRef 行，
#       核对本层 internal 目标（行号/名/宿主）、external 声明（类型/程序集）、
#       MethodSpec 底层行与泛型实参个数；
#   (c) 未解析的 row_out_of_range 必须真的越过 dnfile 表行数；
#   (d) 可失败自证：空比对必须判 FAIL；目标落点 +1 / 外部类型名改一字 / 删一个
#       EH 子句 / 调用 token 改越界行 / MethodDef token 行 1→2 后目标名必须随
#       dnfile 第 2 行变化，检查器必须抓住；干净输入必须 PASS。
#
# 样本：受控 FlowSample.dll（csc）、FilterSample.dll（ilasm，含 filter/fault/calli）、
#       真实 CoreCLR System.Console.dll、真实 Framework mscorlib.dll。
# 真实样本：全量聚合对账覆盖所有有体方法；逐条明细比对覆盖报告存储的前 N 个
# 有体方法（N 在输出里显式给出）。
# 工具缺失 → SKIP（不算 PASS）；任何 FAIL → 退出 1。
#
# 口径备注（2026-11-16 修正，写死）：
#   - dncil 的 `ins.offset` 与分支操作数都相对“方法体切片起点”（含头），
#     本层 IL offset 相对代码区起点，故两者都必须减去 `body.header_size`；
#   - dncil 的 EH 偏移已经是 code-relative，`filter_start=-1` 表示无 filter；
#   - dnfile 对行数为 0 的表不创建属性（如 FilterSample 无 MethodSpec），
#     因此所有表读取必须走 getattr(..., None)；
#   - 任何比对的分母为 0 一律 FAIL，不得空对空 PASS。
import collections
import json
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import dotnet as DN                     # noqa: E402
from rekit import ilflow as IF                     # noqa: E402

FLOW = os.path.join(WORK, "samples", "m18", "_gen", "FlowSample.dll")
FILTER = os.path.join(WORK, "samples", "m18", "_gen", "FilterSample.dll")
CONSOLE = r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\7.0.20\System.Console.dll"
MSCORLIB = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
OUT_JSON = os.path.join(WORK, "evidence_m18_ilflow.json")
REAL_LIMIT = 2000            # 真实样本逐方法明细比对的抽样上限（有体方法）

# 固定集合：来自 ECMA-335，不读被测实现的常量
BR_OPS = {"br.s", "brfalse.s", "brtrue.s", "beq.s", "bge.s", "bgt.s",
          "ble.s", "blt.s", "bne.un.s", "bge.un.s", "bgt.un.s",
          "ble.un.s", "blt.un.s",
          "br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt",
          "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un",
          "leave", "leave.s", "switch"}
CALL_OPS = {"call", "callvirt", "newobj", "ldftn", "ldvirtftn", "jmp", "calli"}
EH_KIND = {0: "catch", 1: "filter", 2: "finally", 4: "fault"}
TAG_TABLE = {0: "TypeDef", 1: "TypeRef", 2: "TypeSpec"}
TOKEN_TABLE = {0x06: "MethodDef", 0x0A: "MemberRef", 0x2B: "MethodSpec",
               0x11: "StandAloneSig"}

CHECKS = []


def _add(cid, name, status, detail):
    CHECKS.append({"id": cid, "name": name, "status": status,
                   "detail": detail})
    print("[%s] %s %s :: %s" % (status, cid, name, detail))


def _guard(n, what):
    """空比对保护：分母为 0 返回 False（调用方必须 FAIL）。"""
    if n <= 0:
        print("  !! 空比对：%s 的分母为 0，不得判 PASS" % what)
        return False
    return True


# ── dncil 侧 ────────────────────────────────────────────────────────
def _dncil_body(data, pe, rva):
    from dncil.cil.body.reader import read_method_body_from_bytes
    off = pe.get_offset_from_rva(rva)
    return read_method_body_from_bytes(data[off:off + 0x40000])


def _dncil_code_size(body):
    return int(body.code_size)


def _dncil_insn_offsets(body):
    """code-relative 指令起点集合（去掉方法体头长度）。"""
    h = body.header_size
    return {i.offset - h for i in body.instructions}


def _dncil_branches(body):
    """{code_offset: (opcode, [code_target,...])}。

    dncil 的 `ins.offset` 与分支操作数都相对方法体切片起点（含头），
    这里统一减去 header_size。
    """
    h = body.header_size
    out = {}
    for ins in body.instructions:
        name = ins.opcode.name.lower()
        if name not in BR_OPS:
            continue
        if name == "switch":
            vals = [v - h for v in ins.operand]
        else:
            vals = [ins.operand - h]
        out[ins.offset - h] = (name, vals)
    return out


def _dncil_eh(body):
    return sorted((EH_KIND.get(int(e.exception_type), "unknown"),
                   e.try_start, e.try_end, e.handler_start, e.handler_end,
                   None if int(e.filter_start) < 0 else e.filter_start)
                  for e in body.exception_handlers)


def _ref_form(name):
    if name == "switch":
        return "switch"
    if name in ("leave", "leave.s"):
        return "leave_short" if name.endswith(".s") else "leave_long"
    return "short" if name.endswith(".s") else "long"


def _ref_check(target, insn_offsets, code_size):
    if target in insn_offsets:
        return "instruction"
    if 0 <= target < code_size:
        return "inside_instruction"
    return "outside_method"


def _ours_branches(detail):
    return {s["offset"]: (s["opcode"], [t["value"] for t in s["targets"]])
            for s in detail["branch_sites"]}


def _ours_eh(detail):
    return sorted((c["kind"], c["try"][0], c["try"][1], c["handler"][0],
                   c["handler"][1],
                   c["filter"][0] if c["filter"] else None)
                  for c in detail["eh"])


# ── dnfile 侧（独立映射）────────────────────────────────────────────
def _rows(table):
    return table.rows if table is not None else []


def _table(md, name):
    """dnfile 对 0 行表不建属性，必须 getattr。"""
    return getattr(md, name, None)


def _method_owner_map(md):
    names, owner = {}, {}
    rows = _rows(_table(md, "MethodDef"))
    for i, r in enumerate(rows, 1):
        names[i] = str(r.Name)
    td = _rows(_table(md, "TypeDef"))
    # 嵌套类型全名独立拼接：用 NestedClass 表（与 dotnet.py 不同代码路径）
    parent = {}
    for n in _rows(_table(md, "NestedClass")):
        parent[n.NestedClass.row_index] = n.EnclosingClass.row_index

    def full(i, depth=0):
        r = td[i - 1]
        ns, nm = str(r.TypeNamespace), str(r.TypeName)
        base = (ns + "." + nm) if ns else nm
        p = parent.get(i)
        if p and depth < 8:
            return full(p, depth + 1) + "+" + nm
        return base

    td_full = {i: full(i) for i in range(1, len(td) + 1)}
    for t in td:
        for x in (t.MethodList or []):
            rid = getattr(x, "row_index", x)
            owner[rid] = td_full[td.index(t) + 1]
    return names, owner, td_full


def _typeref_map(md):
    out = {}
    for i, r in enumerate(_rows(_table(md, "TypeRef")), 1):
        ns, nm = str(r.TypeNamespace), str(r.TypeName)
        full = (ns + "." + nm) if ns else nm
        scope = r.ResolutionScope.row if r.ResolutionScope else None
        asm = str(scope.Name) if scope is not None and hasattr(scope, "Name") \
            else None
        out[i] = (full, asm)
    return out


def _comp(b, off):
    b0 = b[off]
    if b0 & 0x80 == 0:
        return b0, off + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | b[off + 1], off + 2
    return ((b0 & 0x1F) << 24) | int.from_bytes(b[off + 1:off + 4], "big"), \
        off + 4


def _ts_base(sig):
    """独立解码 TypeSpec 基类型：仅覆盖 GENERICINST/CLASS/VALUETYPE/SZARRAY。"""
    if not sig:
        return None
    tag = sig[0]
    if tag == 0x15:
        p = 2 if len(sig) > 1 and sig[1] in (0x11, 0x12) else 1
        raw, _ = _comp(sig, p)
        return TAG_TABLE[raw & 3], raw >> 2
    if tag in (0x11, 0x12):
        raw, _ = _comp(sig, 1)
        return TAG_TABLE[raw & 3], raw >> 2
    if tag == 0x1D:
        return _ts_base(sig[1:])
    return None


def _memberref_map(md):
    tr_index = {id(r): i for i, r in enumerate(_rows(_table(md, "TypeRef")), 1)}
    td_index = {id(r): i for i, r in enumerate(_rows(_table(md, "TypeDef")), 1)}
    out = {}
    for i, r in enumerate(_rows(_table(md, "MemberRef")), 1):
        parent = r.Class.row
        pname = type(parent).__name__
        if pname == "TypeRefRow":
            out[i] = ("TypeRef", (str(r.Name), tr_index.get(id(parent))))
        elif pname == "TypeDefRow":
            out[i] = ("TypeDef", (str(r.Name), td_index.get(id(parent))))
        elif pname == "TypeSpecRow":
            sig = bytes(parent.Signature.value)
            out[i] = ("TypeSpec", (str(r.Name), _ts_base(sig), sig.hex()))
        elif pname == "MethodDefRow":
            out[i] = ("MethodDef", (str(r.Name), None))
        else:
            out[i] = (pname, (str(r.Name), None, None))
    return out


class _Maps:
    """一次构建 dnfile 侧的独立映射，供主流程与自证共用。"""

    def __init__(self, path):
        import dnfile
        md = dnfile.dnPE(path).net.mdtables
        self.names, self.owner, self.td_full = _method_owner_map(md)
        self.typeref = _typeref_map(md)
        self.mr = _memberref_map(md)
        self.ms_rows = _rows(_table(md, "MethodSpec"))
        self.counts = {
            "MethodDef": len(_rows(_table(md, "MethodDef"))),
            "MemberRef": len(self.mr),
            "MethodSpec": len(self.ms_rows),
            "TypeRef": len(self.typeref)}

    def token_problems(self, site, key):
        """对一个调用点给出“与 dnfile 不一致”的问题列表（空 = 一致）。"""
        bad = []
        table, row = int(key, 16) >> 24, int(key, 16) & 0xFFFFFF
        if table == 0x06:                    # MethodDef
            if site["status"] != "internal":
                bad.append("%s：MethodDef token 应为 internal，实为 %s"
                           % (key, site["status"]))
            elif row not in self.names:
                bad.append("%s：dnfile 无 MethodDef[%d]" % (key, row))
            else:
                t = site["target"]
                if (t["name"], t["owner_type"]) != \
                        (self.names[row], self.owner.get(row)):
                    bad.append("%s：本层=%r dnfile=%r"
                               % (key, (t["name"], t["owner_type"]),
                                  (self.names[row], self.owner.get(row))))
        elif table == 0x0A:                  # MemberRef
            bad.extend(self.memberref_problems(site, key, row))
        elif table == 0x2B:                  # MethodSpec
            if row > len(self.ms_rows):
                return bad + ["%s：dnfile 无 MethodSpec[%d]" % (key, row)]
            r = self.ms_rows[row - 1]
            blob = bytes(r.Instantiation.value)
            cnt = None
            if blob:
                try:
                    cnt, _ = _comp(blob, 1 if blob[0] == 0x0A else 0)
                except Exception:
                    cnt = None
            u = r.Method.row
            ukind = type(u).__name__
            if ukind == "MethodDefRow":
                under = r.Method.row_index
                t = site["target"]
                if site["status"] != "internal" or t is None:
                    bad.append("%s：MethodSpec→MethodDef 应 internal，实为 %s"
                               % (key, site["status"]))
                elif t["row"] != under or t["name"] != self.names.get(under):
                    bad.append("%s：底层本层=%r dnfile=%r"
                               % (key, (t["row"], t["name"]),
                                  (under, self.names.get(under))))
            elif ukind == "MemberRefRow":
                bad.extend(self.memberref_problems(site, key,
                                                   r.Method.row_index))
            else:
                bad.append("%s：MethodSpec 底层表 %s 未覆盖" % (key, ukind))
            if site.get("generic", {}).get("generic_arg_count") != cnt:
                bad.append("%s：泛型实参个数本层=%r dnfile=%r"
                           % (key, (site.get("generic") or {})
                              .get("generic_arg_count"), cnt))
        elif table == 0x11:                  # StandAloneSig
            if site["status"] != "unresolved" or \
                    site["reason"] != "token_kind_mismatch":
                bad.append("%s：StandAloneSig 应报 token_kind_mismatch，"
                           "实为 %s/%s" % (key, site["status"], site["reason"]))
        else:
            bad.append("%s：未覆盖的 token 表 0x%02X" % (key, table))
        return bad

    def memberref_problems(self, site, key, row):
        """MemberRef 行独立核对（MethodSpec 的底层 MemberRef 也走这里）。"""
        bad = []
        if row not in self.mr:
            return ["%s：dnfile 无 MemberRef[%d]" % (key, row)]
        pkind, info = self.mr[row]
        if pkind == "TypeRef":
            mname, prow = info
            if site["status"] == "internal":
                t = site["target"]
                if t is None or t["name"] != mname:
                    bad.append("%s：internal 成员名本层=%r dnfile=%r"
                               % (key, (site["target"] or {}).get("name"),
                                  mname))
                elif prow and self.owner.get(t["row"]) != \
                        self.typeref[prow][0]:
                    bad.append("%s：internal 宿主本层=%r TypeRef=%r"
                               % (key, self.owner.get(t["row"]),
                                  self.typeref[prow][0]))
            elif site["status"] == "external":
                e = site["external"]
                want = self.typeref[prow] if prow else (None, None)
                if (e["member"], e["type"], e["assembly"]) != \
                        (mname, want[0], want[1]):
                    bad.append("%s：本层=%r dnfile=%r"
                               % (key, (e["member"], e["type"], e["assembly"]),
                                  (mname, want[0], want[1])))
            else:
                bad.append("%s：TypeRef 父未解析 %s/%s"
                           % (key, site["status"], site["reason"]))
        elif pkind == "TypeDef":
            mname, tdrow = info
            t = site["target"]
            if site["status"] != "internal" or t is None:
                bad.append("%s：TypeDef 父应 internal，实为 %s/%s"
                           % (key, site["status"], site["reason"]))
            elif t["name"] != mname or \
                    (tdrow and self.owner.get(t["row"]) !=
                     self.td_full[tdrow]):
                bad.append("%s：本层=%r dnfile=%r"
                           % (key, (t["name"], self.owner.get(t["row"])),
                              (mname, self.td_full.get(tdrow))))
        elif pkind == "TypeSpec":
            mname, base, sig = info
            t = site["target"]
            if site["status"] == "external":
                e = site["external"]
                want = None
                if base and base[0] == "TypeRef":
                    want = self.typeref.get(base[1], (None, None))[0]
                if e["member"] != mname or (want and e["type"] != want):
                    bad.append("%s：本层=%r TypeSpec 基=%r/%r"
                               % (key, (e["member"], e["type"]), base, sig))
            elif site["status"] == "internal":
                if base is None or base[0] != "TypeDef":
                    bad.append("%s：internal 但 TypeSpec 基=%r（%s）"
                               % (key, base, sig))
                elif t is None or t["name"] != mname or \
                        self.owner.get(t["row"]) != self.td_full.get(base[1]):
                    bad.append("%s：本层=%r TypeSpec 基=%r"
                               % (key, (site["target"] or {}).get("name"),
                                  self.td_full.get(base[1])))
            elif site["reason"] != "bad_parent":
                bad.append("%s：TypeSpec 父未解析原因=%r（sig=%s）"
                           % (key, site["reason"], sig))
        elif pkind == "MethodDef":
            if site["status"] != "unresolved" or \
                    site["reason"] != "unsupported_parent":
                bad.append("%s：MethodDef 父应 unsupported_parent，"
                           "实为 %s/%s" % (key, site["status"],
                                           site["reason"]))
        elif site["status"] != "unresolved":
            bad.append("%s：父类型 %s 应不可解析，实为 %s"
                       % (key, pkind, site["status"]))
        return bad


# ── 样本上下文：一次构建，四处比对复用 ──────────────────────────────
class _Ctx:
    def __init__(self, path, limit):
        import dnfile
        self.path = path
        self.rep = IF.build(path, limit=limit if limit else 10 ** 9)
        self.dn = DN.build(path, detail_methods=None, detail_insns=None)
        self.data = open(path, "rb").read()
        op = DN.open_tables(path)
        self.resolver = IF.Resolver(
            op["tables"], (self.rep.get("assembly") or {}).get("name"))
        self.pe = dnfile.dnPE(path)
        self.by_token = {m["token"]: m for m in self.dn["methods"]
                         if m.get("body_status") == "ok"}

    def __getitem__(self, key):
        return getattr(self, key)

    def body(self, m):
        return _dncil_body(self.data, self.pe, m["rva"])


# ── 比对 ────────────────────────────────────────────────────────────
def _cmp_branch_denoms(ctx, tag):
    """dncil 全量独立算分支：形态数、目标数、落点三分类。"""
    d = ctx["rep"]["denominators"]
    forms, checks = collections.Counter(), collections.Counter()
    total = excluded = 0
    errors = []
    for m in ctx["dn"]["methods"]:
        if m.get("body_status") != "ok":
            continue
        il = m.get("il") or {}
        if not (il.get("instructions") or []):
            continue
        if il.get("undecodable_at") is not None:
            excluded += 1
            continue
        try:
            body = ctx.body(m)
        except Exception as e:
            errors.append("%s：dncil 读取失败 %s" % (m.get("token"), e))
            continue
        code_size = _dncil_code_size(body)
        offs = _dncil_insn_offsets(body)
        for _off, (name, targets) in _dncil_branches(body).items():
            forms[_ref_form(name)] += 1
            for t in targets:
                total += 1
                checks[_ref_check(t, offs, code_size)] += 1
    pub_forms = collections.Counter(d.get("branch_by_form") or {})
    pub_checks = collections.Counter(d.get("target_checks") or {})
    pub_checks.pop("decode_error", None)
    ok = (not errors and total > 0 and forms == pub_forms
          and total == d.get("targets_total") and checks == pub_checks
          and d.get("targets_decode_error", 0) == 0)
    detail = ("dncil 全量：分支形态 %r / 目标 %d（%r） vs 本层 %r / %d（%r）；"
              "部分方法排除 %d；%s"
              % (dict(forms), total, dict(checks), dict(pub_forms),
                 d.get("targets_total"), dict(pub_checks), excluded,
                 "全部一致" if ok else "不一致"))
    if errors:
        detail += "；错误：" + "; ".join(errors[:3])
    return ok, detail


def _cmp_branches_sites(ctx, tag, require_sites=True):
    """逐方法比对分支偏移与目标值（报告存储的方法）。"""
    bad, n_methods, n_sites = [], 0, 0
    for sm in ctx["rep"]["methods"]:
        m = ctx["by_token"].get(sm["token"])
        if m is None:
            bad.append("%s：dnfile 有体方法里找不到" % sm["token"])
            continue
        try:
            body = ctx.body(m)
        except Exception as e:
            bad.append("%s：dncil 读取失败 %s" % (sm["token"], e))
            continue
        ours, ref = _ours_branches(sm), _dncil_branches(body)
        n_sites += sum(len(v[1]) for v in ref.values())
        if ours != ref:
            bad.append("%s %s：本层=%r dncil=%r"
                       % (sm["token"], sm["name"], ours, ref))
        n_methods += 1
        if len(bad) >= 4:
            break
    ok = not bad and _guard(n_methods, "逐方法分支比对") and \
        (n_sites > 0 or not require_sites)
    return ok, ("逐方法比对 %d 个方法 / %d 个目标（%s）；%s"
                % (n_methods, n_sites, tag,
                   "全部一致" if ok else "; ".join(bad[:3]) or "空比对"))


def _ref_blocks(body):
    """独立按规则重算基本块与边（不调用被测实现）。

    规则：leader = 方法体首指令 ∪ 落在指令边界的跳转目标 ∪ 分支/switch 的下一条
    ∪ EH 边界（try/handler/filter 起止，且必须是指令起点）；终结符 = 条件/无条件
    跳转、leave、ret/throw/rethrow/endfinally/endfilter（switch 不终结，另补
    fallthrough）；边四类：fallthrough / branch / leave / switch。
    """
    h = body.header_size
    insns = sorted(i.offset - h for i in body.instructions)
    if not insns:
        return None
    code_size = int(body.code_size)
    offs = set(insns)
    names = {i.offset - h: i.opcode.name.lower() for i in body.instructions}
    pos = {o: i for i, o in enumerate(insns)}
    br = _dncil_branches(body)
    leaders = {0}
    for off, (_name, targets) in br.items():
        k = pos[off] + 1
        leaders.add(insns[k] if k < len(insns) else code_size)
        leaders.update(t for t in targets if t in offs)
    for e in body.exception_handlers:
        for v in (e.try_start, e.try_end, e.handler_start, e.handler_end,
                  e.filter_start):
            v = int(v)
            if v in offs:
                leaders.add(v)
    leaders = sorted(x for x in leaders if x in offs)
    if not leaders:
        return None
    uncond = {"br", "br.s", "leave", "leave.s", "jmp"}
    term_set = uncond | {"ret", "throw", "rethrow", "endfinally", "endfilter"}
    blocks, edges, terms = [], [], []
    nxt = {leaders[i]: (leaders[i + 1] if i + 1 < len(leaders) else None)
           for i in range(len(leaders))}
    # 基本块：遇到 leader 或终结符即收块（终结符后的指令进入新块，哪怕不可达）
    groups, cur = [], []
    for o in insns:
        if o in leaders and cur:
            groups.append(cur)
            cur = []
        cur.append(o)
        if names[o] in term_set:
            groups.append(cur)
            cur = []
    if cur:
        groups.append(cur)
    for i, bl in enumerate(groups):
        s = bl[0]
        end = groups[i + 1][0] if i + 1 < len(groups) else code_size
        blocks.append((s, end))
        last = names[bl[-1]]
        terms.append(last if last in term_set else None)
        if last == "switch":
            for c, t in enumerate(br[bl[-1]][1]):
                if t in offs:
                    edges.append((s, t, "switch", c))
            if nxt[s] is not None:
                edges.append((s, nxt[s], "fallthrough", None))
        elif last in uncond:
            kind = "leave" if last in ("leave", "leave.s") else "branch"
            for t in br[bl[-1]][1]:
                if t in offs:
                    edges.append((s, t, kind, None))
        elif last in BR_OPS:                     # 条件跳转：taken + fallthrough
            for t in br[bl[-1]][1]:
                if t in offs:
                    edges.append((s, t, "branch", None))
            if nxt[s] is not None:
                edges.append((s, nxt[s], "fallthrough", None))
        elif last not in term_set and nxt[s] is not None:
            edges.append((s, nxt[s], "fallthrough", None))
    reach, stack = set(), [0]
    while stack:
        b = stack.pop()
        if b in reach:
            continue
        reach.add(b)
        for f, t, _k, _c in edges:
            if f == b and t not in reach:
                stack.append(t)
    return {"blocks": blocks, "terms": terms, "edges": edges,
            "reach": [b in reach for b, _e in blocks]}


def _cmp_blocks_denoms(ctx):
    d = ctx["rep"]["denominators"]
    n_blocks = n_edges = n_unreach = 0
    kinds = collections.Counter()
    errors, skipped = [], 0
    for m in ctx["dn"]["methods"]:
        if m.get("body_status") != "ok":
            continue
        il = m.get("il") or {}
        if not (il.get("instructions") or []):
            continue
        if il.get("undecodable_at") is not None:
            skipped += 1
            continue
        try:
            ref = _ref_blocks(ctx.body(m))
        except Exception as e:
            errors.append("%s：%s" % (m.get("token"), e))
            continue
        if ref is None:
            skipped += 1
            continue
        n_blocks += len(ref["blocks"])
        n_edges += len(ref["edges"])
        n_unreach += sum(1 for r in ref["reach"] if not r)
        kinds.update(k for _f, _t, k, _c in ref["edges"])
    pub = collections.Counter(d.get("edges_by_kind") or {})
    ok = (not errors and d.get("methods_partial") == 0
          and n_blocks == d.get("blocks_total")
          and n_edges == d.get("edges_total")
          and n_unreach == d.get("unreachable_blocks")
          and kinds == pub)
    return ok, ("dncil 独立切块：块 %d / 边 %d（%r）/ 不可达 %d vs 本层 %d / %d / %d"
                "（%r）；部分方法排除 %d；%s"
                % (n_blocks, n_edges, dict(kinds), n_unreach,
                   d.get("blocks_total"), d.get("edges_total"),
                   d.get("unreachable_blocks"), dict(pub), skipped,
                   "全部一致" if ok else "不一致"
                   + ("；部分方法使全量口径不可比" if d.get("methods_partial")
                      else "")))


def _cmp_blocks_sites(ctx, tag):
    bad, n_methods, n_blocks = [], 0, 0
    for sm in ctx["rep"]["methods"]:
        m = ctx["by_token"].get(sm["token"])
        if m is None:
            bad.append("%s：dnfile 有体方法里找不到" % sm["token"])
            continue
        ref = _ref_blocks(ctx.body(m))
        if ref is None:
            continue
        ours = ([(b["start"], b["end"]) for b in sm["blocks"]],
                [b["terminator"] for b in sm["blocks"]],
                sorted((e["from"], e["to"], e["kind"], e["case"])
                       for e in sm["edges"]),
                [b["reachable_from_entry"] for b in sm["blocks"]])
        theirs = (ref["blocks"], ref["terms"], sorted(ref["edges"]),
                  ref["reach"])
        n_blocks += len(ref["blocks"])
        if ours != theirs:
            bad.append("%s %s：块/边/可达与独立重算不一致" % (sm["token"],
                                                             sm["name"]))
        n_methods += 1
        if len(bad) >= 4:
            break
    ok = not bad and _guard(n_methods, "逐方法块/边比对")
    return ok, ("块/边逐方法比对 %d 个方法 / %d 块（%s）；%s"
                % (n_methods, n_blocks, tag,
                   "全部一致" if ok else "; ".join(bad[:3]) or "空比对"))


def _cmp_eh_denoms(ctx):
    d = ctx["rep"]["denominators"]
    kinds, total, empty = collections.Counter(), 0, 0
    errors = []
    for m in ctx["dn"]["methods"]:
        if m.get("body_status") != "ok":
            continue
        il = m.get("il") or {}
        if not (il.get("instructions") or []):
            empty += 1
            continue
        try:
            body = ctx.body(m)
        except Exception as e:
            errors.append("%s：dncil 读取失败 %s" % (m.get("token"), e))
            continue
        for e in body.exception_handlers:
            kinds[EH_KIND.get(int(e.exception_type), "unknown")] += 1
            total += 1
    pub = collections.Counter(d.get("eh_by_kind") or {})
    ok = (not errors and kinds == pub and total == d.get("eh_clauses"))
    return ok, ("dncil 全量：EH 子句 %d（%r） vs 本层 %d（%r）；空体方法排除 %d；%s"
                % (total, dict(kinds), d.get("eh_clauses"), dict(pub), empty,
                   "全部一致" if ok else "不一致"))


def _cmp_eh_sites(ctx, tag):
    bad, n_methods, n_clauses = [], 0, 0
    for sm in ctx["rep"]["methods"]:
        m = ctx["by_token"].get(sm["token"])
        if m is None:
            bad.append("%s：dnfile 有体方法里找不到" % sm["token"])
            continue
        try:
            body = ctx.body(m)
        except Exception as e:
            bad.append("%s：dncil 读取失败 %s" % (sm["token"], e))
            continue
        ours, ref = _ours_eh(sm), _dncil_eh(body)
        n_clauses += len(ref)
        if ours != ref:
            bad.append("%s %s：本层=%r dncil=%r"
                       % (sm["token"], sm["name"], ours, ref))
        n_methods += 1
        if len(bad) >= 4:
            break
    ok = not bad and _guard(n_methods, "逐方法 EH 比对") and \
        (n_clauses > 0 or tag != "flow")
    return ok, ("EH 逐方法比对 %d 个方法 / %d 条子句（%s）；%s"
                % (n_methods, n_clauses, tag,
                   "全部一致" if ok else "; ".join(bad[:3]) or "空比对"))


def _cmp_call_denoms(ctx):
    """dncil 全量独立数调用指令与 token 表分布。"""
    d = ctx["rep"]["denominators"]
    ops, tables = collections.Counter(), collections.Counter()
    total = excluded = 0
    errors = []
    for m in ctx["dn"]["methods"]:
        if m.get("body_status") != "ok":
            continue
        il = m.get("il") or {}
        if not (il.get("instructions") or []):
            continue
        if il.get("undecodable_at") is not None:
            excluded += 1
            continue
        try:
            body = ctx.body(m)
        except Exception as e:
            errors.append("%s：dncil 读取失败 %s" % (m.get("token"), e))
            continue
        for ins in body.instructions:
            name = ins.opcode.name.lower()
            if name not in CALL_OPS:
                continue
            total += 1
            ops[name] += 1
            tok = int(getattr(ins.operand, "value", ins.operand)) & 0xFFFFFFFF
            tables[TOKEN_TABLE.get(tok >> 24, "table_0x%02x" % (tok >> 24))] \
                += 1
    pub_ops = collections.Counter(d.get("call_by_opcode") or {})
    pub_tables = collections.Counter(d.get("token_by_table") or {})
    ok = (not errors and total > 0 and total == d.get("call_total")
          and ops == pub_ops and tables == pub_tables)
    return ok, ("dncil 全量：调用 %d（%r）/ token 表 %r vs 本层 %d（%r）/ %r；"
                "部分方法排除 %d；%s"
                % (total, dict(ops), dict(tables), d.get("call_total"),
                   dict(pub_ops), dict(pub_tables), excluded,
                   "全部一致" if ok else "不一致"))


def _cmp_tokens_sites(ctx, tag, maps):
    bad, n_methods, n_sites = [], 0, 0
    seen = set()
    for sm in ctx["rep"]["methods"]:
        n_methods += 1
        for s in sm["call_sites"]:
            n_sites += 1
            key = s["token"]
            if key is None or key in seen:
                continue
            seen.add(key)
            bad.extend(maps.token_problems(s, key))
            if len(bad) >= 5:
                break
        if len(bad) >= 5:
            break
    ok = not bad and _guard(n_methods, "逐方法 token 比对")
    return ok, ("token 独立核对 %d 个方法 / %d 个调用点（去重 %d 个 token；"
                "表行数 %r）；%s"
                % (n_methods, n_sites, len(seen), maps.counts,
                   "全部一致" if ok else "; ".join(bad[:3]) or "空比对"))


def _cmp_unresolved_rows(ctx, maps):
    """row_out_of_range 必须真的越过 dnfile 对应表的行数。"""
    sizes = dict(maps.counts)
    sizes["TypeDef"] = len(maps.td_full)
    bad, n = [], 0
    for sm in ctx["rep"]["methods"]:
        for s in sm["call_sites"]:
            if s["status"] != "unresolved" or s["reason"] != "row_out_of_range":
                continue
            n += 1
            row = int(s["token"], 16) & 0xFFFFFF
            size = sizes.get(s["token_table"], -1)
            if size < 0 or row <= size:
                bad.append("%s：row=%d 未越过 %s 行数=%d"
                           % (s["token"], row, s["token_table"], size))
    return not bad, ("row_out_of_range 独立复核 %d 个（同表行数已计入）；%s"
                     % (n, "全部一致" if not bad else "; ".join(bad[:3])))


# ── 主流程 ──────────────────────────────────────────────────────────
def run_sample(tag, path, limit):
    if not os.path.exists(path):
        _add("%s-status" % tag, "样本存在性", "SKIP", "样本不存在：%s" % path)
        return None
    ctx = _Ctx(path, limit)
    rep = ctx["rep"]
    d = rep["denominators"]
    ok = (rep["status"] == "ok" and d.get("identity_ok") is True
          and d.get("token_identity_ok") is True
          and d.get("target_identity_ok") is True
          and d.get("eh_identity_ok") is True)
    _add("%s-status" % tag, "状态与分母恒等式", "PASS" if ok else "FAIL",
         "status=%s 方法=%d 有体=%d 分析=%d 部分=%d 空=%d 失败=%d；调用=%d"
         "(internal=%d external=%d unresolved=%d)；分支=%d 目标=%d；EH=%d；"
         "块=%d 边=%d"
         % (rep["status"], d["methods_total"], d["methods_with_body"],
            d["methods_analyzed"], d["methods_partial"], d["methods_empty"],
            d["method_errors"], d["call_total"], d["tokens_internal"],
            d["tokens_external"], d["tokens_unresolved"], d["branch_total"],
            d["targets_total"], d["eh_clauses"], d["blocks_total"],
            d["edges_total"]))
    tagtxt = "全量存储" if not limit else "存储前 %d 个有体方法" % limit

    o, x = _cmp_branch_denoms(ctx, tagtxt)
    _add("%s-branch-denom" % tag, "dncil 全量分支分母", "PASS" if o else "FAIL",
         x)
    o, x = _cmp_branches_sites(ctx, tagtxt, require_sites=True)
    _add("%s-branch" % tag, "dncil 逐方法分支目标", "PASS" if o else "FAIL", x)
    o, x = _cmp_blocks_denoms(ctx)
    _add("%s-blocks-denom" % tag, "dncil 独立切块分母", "PASS" if o else "FAIL",
         x)
    o, x = _cmp_blocks_sites(ctx, tagtxt)
    _add("%s-blocks" % tag, "dncil 逐方法块/边/可达", "PASS" if o else "FAIL",
         x)
    o, x = _cmp_eh_denoms(ctx)
    _add("%s-eh-denom" % tag, "dncil 全量 EH 分母", "PASS" if o else "FAIL", x)
    o, x = _cmp_eh_sites(ctx, tagtxt)
    _add("%s-eh" % tag, "dncil 逐方法 EH 结构", "PASS" if o else "FAIL", x)
    o, x = _cmp_call_denoms(ctx)
    _add("%s-call-denom" % tag, "dncil 全量调用分母", "PASS" if o else "FAIL",
         x)
    maps = _Maps(path)
    o, x = _cmp_tokens_sites(ctx, tagtxt, maps)
    _add("%s-token" % tag, "dnfile 独立 token 解析", "PASS" if o else "FAIL", x)
    o, x = _cmp_unresolved_rows(ctx, maps)
    _add("%s-unres" % tag, "未解析行号越界复核", "PASS" if o else "FAIL", x)
    return rep


def selfproof():
    """检查器必须能失败：干净 PASS，篡改 FAIL，空比对 FAIL。"""
    rep = IF.build(FLOW, limit=10 ** 9)
    ctx = _Ctx(FLOW, 0)
    maps = _Maps(FLOW)
    stored = {m["token"]: m for m in rep["methods"]}
    m = next(x for x in ctx["dn"]["methods"] if x["name"] == "LongBranch")
    sm = stored[m["token"]]
    ours, ref = _ours_branches(sm), _dncil_branches(ctx.body(m))
    clean = ours == ref
    mut = {k: (v[0], [x + 1 for x in v[1]]) for k, v in ours.items()}
    shift = mut == ref
    # token：干净通过，外部类型名 + "X" 必须被检出
    m2 = next(x for x in ctx["rep"]["methods"]
              if x["name"] == "CallExternal")
    ext = next(s for s in m2["call_sites"] if s["status"] == "external")
    tok_clean = not maps.token_problems(ext, ext["token"])
    tampered = json.loads(json.dumps(ext))
    tampered["external"]["type"] += "X"
    tok_bad = bool(maps.token_problems(tampered, tampered["token"]))
    # EH：干净通过，删一条必须被检出
    m3 = next(x for x in ctx["rep"]["methods"] if x["name"] == "Guarded")
    dm3 = ctx["by_token"][m3["token"]]
    eh_clean = _ours_eh(m3) == _dncil_eh(ctx.body(dm3))
    eh_bad = _ours_eh({"eh": m3["eh"][:-1]}) == _dncil_eh(ctx.body(dm3))
    # 块/边：干净通过，少一块必须被检出
    refb = _ref_blocks(ctx.body(dm3))
    oursb = ([(b["start"], b["end"]) for b in m3["blocks"]],
             [b["terminator"] for b in m3["blocks"]],
             sorted((e["from"], e["to"], e["kind"], e["case"])
                    for e in m3["edges"]),
             [b["reachable_from_entry"] for b in m3["blocks"]])
    blk_clean = oursb == (refb["blocks"], refb["terms"],
                          sorted(refb["edges"]), refb["reach"])
    blk_bad = oursb[0][:-1] != refb["blocks"]
    # 空比对保护
    guard_ok = (not _guard(0, "selfproof-empty")) and _guard(1, "selfproof-one")
    # 字节级篡改：分支位移 +1 → inside；调用 token 行越界 → row_out_of_range
    tmpdir = tempfile.mkdtemp(prefix="rekit_m18_")
    try:
        body0 = ctx.body(m)
        off0, (name0, _v0) = next(iter(sorted(_dncil_branches(body0).items())))
        nxt = off0 + (2 if name0.endswith(".s") else 5)
        code_size0 = _dncil_code_size(body0)
        offs0 = _dncil_insn_offsets(body0)
        inner = next(o for o in range(1, code_size0)
                     if o not in offs0 and o > nxt)
        inside = os.path.join(tmpdir, "inside.dll")
        shutil.copyfile(FLOW, inside)
        buf = bytearray(open(inside, "rb").read())
        struct.pack_into("<b" if name0.endswith(".s") else "<i",
                         buf, sm["code_off"] + off0 + 1, inner - nxt)
        open(inside, "wb").write(buf)
        r2 = IF.build(inside, limit=10 ** 9)
        t2 = next(x for x in r2["methods"] if x["token"] == sm["token"])
        site0 = next(s for s in t2["branch_sites"] if s["offset"] == off0)
        inside_seen = (site0["targets"][0]["check"] == "inside_instruction")

        over = os.path.join(tmpdir, "over.dll")
        shutil.copyfile(FLOW, over)
        buf = bytearray(open(over, "rb").read())
        struct.pack_into("<I", buf, m2["code_off"] + 1, 0x0AFFFFFF)
        open(over, "wb").write(buf)
        r3 = IF.build(over, limit=10 ** 9)
        t3 = next(x for x in r3["methods"] if x["token"] == m2["token"])
        over_seen = (t3["call_sites"][0]["status"] == "unresolved"
                     and t3["call_sites"][0]["reason"] == "row_out_of_range")

        # MethodDef token 行 1→2：内部目标名必须随字节变化，
        # 且变化后的名字必须等于 dnfile 第 2 行、且不等于第 1 行。
        m4 = next(x for x in ctx["rep"]["methods"] if x["name"] == "Caller")
        s4 = next(s for s in m4["call_sites"] if s["token"] == "0x06000001")
        rowf = os.path.join(tmpdir, "row.dll")
        shutil.copyfile(FLOW, rowf)
        buf = bytearray(open(rowf, "rb").read())
        struct.pack_into("<I", buf, m4["code_off"] + s4["offset"] + 1,
                         0x06000002)
        open(rowf, "wb").write(buf)
        r4 = IF.build(rowf, limit=10 ** 9)
        t4 = next(x for x in r4["methods"] if x["token"] == m4["token"])
        s5 = next(s for s in t4["call_sites"]
                  if s["offset"] == s4["offset"])
        row_seen = (s5["status"] == "internal"
                    and s5["target"]["row"] == 2
                    and s5["target"]["name"] == maps.names[2]
                    and s5["target"]["name"] != maps.names[1])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    ok = (clean and not shift and tok_clean and tok_bad and eh_clean
          and not eh_bad and blk_clean and blk_bad and guard_ok
          and inside_seen and over_seen and row_seen)
    _add("selfproof", "比对器可失败自证", "PASS" if ok else "FAIL",
         "分支 干净=%s 目标+1=%s；token 干净=%s 改名=%s；EH 干净=%s 删一条=%s；"
         "块 干净=%s 少一块=%s；空比对保护=%s；字节篡改 inside=%s row_oob=%s "
         "methoddef_row=%s（期望 T/F/T/T/T/F/T/T/T/T/T/T）"
         % (clean, shift, tok_clean, tok_bad, eh_clean, eh_bad, blk_clean,
            blk_bad, guard_ok, inside_seen, over_seen, row_seen))


def main():
    try:
        import dnfile
        import dncil  # noqa: F401
    except Exception as e:
        print("SKIP: 缺少 dnfile/dncil（%s）" % e)
        return 0
    import logging
    logging.disable(logging.CRITICAL)

    reports = {}
    for tag, path, limit in (("flow", FLOW, None),
                             ("filter", FILTER, None),
                             ("console", CONSOLE, REAL_LIMIT),
                             ("mscorlib", MSCORLIB, REAL_LIMIT)):
        rep = run_sample(tag, path, limit)
        if rep is not None:
            reports[tag] = rep

    selfproof()

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    payload = {"schema": 1, "status": "fail" if failed else "pass",
               "checks": CHECKS,
               "denominators": {k: v["denominators"]
                                for k, v in reports.items()}}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    n_fail = len(failed)
    n_skip = sum(1 for c in CHECKS if c["status"] == "SKIP")
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=%d → %s"
          % (len(CHECKS), len(CHECKS) - n_fail - n_skip, n_fail, n_skip,
             "FAIL" if n_fail else "PASS"))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
