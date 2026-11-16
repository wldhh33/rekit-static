#!/usr/bin/env python3
# rekit.ilflow — M18 .NET IL 控制流与调用关系层
#
# 上游：M17 rekit.dotnet（CLI 头/元数据表/方法体/IL 边界）。
# 本层只做两件事：
#   1) 把 call/callvirt/newobj/ldftn/ldvirtftn/jmp 的 token 解析成
#      internal（本模块 MethodDef）/ external（被引程序集/模块，不加载）/
#      unresolved（逐条原因，不猜）；
#   2) 把分支（短/长/switch/leave）、基本块、边、EH 子句结构化成可核对的分母。
#
# 三条硬规则：
#   - token 只按声明解析：不加载被引程序集，不按“同名”代入另一版本的方法；
#   - 分支目标必须落在真实指令边界上，落在指令内部/方法体外逐条单列；
#   - EH 只建模结构、不造边：handler/filter 入口由运行时派发，finally/fault
#     在展开时执行，IL 里没有静态边；造边会把“可能到达”伪装成“跳转”。
import argparse
import bisect
import collections
import json
import struct
import sys

from . import dotnet as DN

SCHEMA = 1

CALL_OPS = {"call", "callvirt", "newobj", "ldftn", "ldvirtftn", "jmp", "calli"}
SHORT_BR = {"br.s", "brfalse.s", "brtrue.s", "beq.s", "bge.s", "bgt.s",
            "ble.s", "blt.s", "bne.un.s", "bge.un.s", "bgt.un.s",
            "ble.un.s", "blt.un.s"}
LONG_BR = {"br", "brfalse", "brtrue", "beq", "bge", "bgt", "ble", "blt",
           "bne.un", "bge.un", "bgt.un", "ble.un", "blt.un"}
LEAVE = {"leave", "leave.s"}
UNCOND = {"br", "br.s"} | LEAVE
TERMINATORS = {"ret", "throw", "rethrow", "endfinally", "endfilter", "jmp"} \
    | UNCOND
COND_BR = (SHORT_BR | LONG_BR) - UNCOND   # 无条件 br/leave 不在其中

REASONS = ("row_out_of_range", "missing_assembly", "signature_mismatch",
           "token_kind_mismatch", "member_not_found", "bad_parent",
           "unsupported_parent", "no_signature", "invalid_token")
STATUSES = ("internal", "external", "unresolved")
TARGET_CHECKS = ("instruction", "inside_instruction", "outside_method")
EDGE_KINDS = ("branch", "fallthrough", "switch", "leave")

CROSS_LAYER = [
    {"layer": "dotnet", "status": "upstream",
     "reason": "本层消费 M17 的 CLI 头/元数据表/MethodDef.RVA/IL 边界；"
               "token 解析复用同一份表，不重新猜布局"},
    {"layer": "map", "status": "applicable",
     "reason": "方法体代码区仍用节表 RVA→文件偏移定位；IL 目标本身是 code offset"},
    {"layer": "pe", "status": "applicable",
     "reason": "PE 头/节/数据目录是上游输入"},
    {"layer": "iat", "status": "not_applicable",
     "reason": "IL 调用目标是元数据 token，不是 IAT thunk；P/Invoke 另走 ImplMap"},
    {"layer": "disasm", "status": "not_applicable",
     "reason": "方法体是 CLI 字节码，不是 x86"},
    {"layer": "recdesc", "status": "not_applicable",
     "reason": "递归下降/基本块以 x86 指令为输入；IL 的块规则不同（栈式/EH 声明）"},
    {"layer": "expr", "status": "not_applicable",
     "reason": "表达式恢复建立在 x86 指令与操作数上"},
    {"layer": "callgraph", "status": "not_applicable",
     "reason": "x86 调用图以代码地址为点；本层以 MethodDef/MemberRef token 为点，"
               "两者不能直接拼接"},
    {"layer": "callfacts", "status": "not_applicable",
     "reason": "参数传递事实来自 x86 调用点；IL 调用体内没有寄存器/栈帧实参"},
    {"layer": "sitejoin", "status": "not_applicable",
     "reason": "拼接对象是 x86 调用图/参数/文本，IL 没有这些层"},
    {"layer": "strxref", "status": "not_applicable",
     "reason": "字面量在 #US，ldstr 用 token；不在数据节"},
    {"layer": "datarefs", "status": "not_applicable",
     "reason": "对象声明来自 ELF/DWARF；IL 的字段/类型引用是 token"},
    {"layer": "coverage", "status": "not_applicable",
     "reason": "覆盖率分母是 x86 指令"},
    {"layer": "switchcand", "status": "not_applicable",
     "reason": "x86 跳转表候选识别不适用于 IL switch（自带绝对目标表）"},
    {"layer": "vexaudit", "status": "not_applicable",
     "reason": "VEX 前缀是 x86 编码"},
    {"layer": "paramdecl", "status": "not_applicable",
     "reason": "DWARF 形参声明；.NET 参数在签名 blob，本层不解码签名语义"},
    {"layer": "struct", "status": "not_applicable",
     "reason": "DWARF 类型层；.NET 类型在 TypeDef/签名 blob"},
    {"layer": "gopclntab", "status": "not_applicable",
     "reason": "Go 专用"},
    {"layer": "funcreport", "status": "not_applicable",
     "reason": "六层 x86 合成入口；对 .NET 返回 not_applicable"},
]

CALIBER = [
    "token 目标只按声明解析：MethodDef 直接定位；MemberRef 按父"
    "（TypeDef/TypeRef/TypeSpec/ModuleRef）与签名 blob 精确匹配；MethodSpec 先解"
    "底层 MethodDef/MemberRef 再报泛型实参个数。",
    "不加载被引程序集：external 只说明声明指向的程序集/类型/成员，没有 MethodDef "
    "行号；不按同名把另一版本的方法代入。",
    "未解析逐条给原因：row_out_of_range / missing_assembly / signature_mismatch / "
    "token_kind_mismatch / member_not_found / bad_parent / unsupported_parent / "
    "no_signature / invalid_token。",
    "分支目标 = offset + size + 有符号位移（switch 为下一条指令 + 4 字节表项）；"
    "落点分 instruction / inside_instruction / outside_method，逐条单列。",
    "基本块 leader：方法入口、每个有效分支目标、分支/switch 的下一条指令、"
    "终结指令的下一条指令、EH 子句的 try/handler/filter 边界（必须落在指令边界）。",
    "终结指令：ret/throw/rethrow/endfinally/endfilter/jmp/br/br.s/leave/leave.s；"
    "条件分支产生 branch + fallthrough 两条边。",
    "EH 只建模结构、不建模成边：handler/filter 入口由运行时派发，finally/fault "
    "在 leave/异常展开时执行，IL 没有静态边；强加边会污染可达性。",
    "IL 与 x86 的差异：栈式语义、无标志位、switch 是绝对目标表、leave 退出保护区、"
    "endfinally/endfilter 无静态后继；块规则不能照搬 x86。",
    "分母先行：所有比例在分母之后；分母为 0 时比例写 None。",
]

CAVEATS = [
    "受控样本是 csc 编译的 C# 与 ilasm 手写 IL；只覆盖本机编译器实际生成的 IL 子集"
    "（C# 5 无 filter，filter/fault/calli 由手写 IL 补），不能代表真实程序集分布。",
    "external 目标未加载被引程序集：没有目标 MethodDef 行号，也不验证版本/重定向。",
    "MemberRef 签名按 blob 字节精确比较；泛型实例化的签名可能与定义不同，"
    "此时记 signature_mismatch，不按名字猜目标。",
    "calli 的 token 是 StandAloneSig（签名），本轮不按签名推断调用目标。",
    "EH 是结构信息，不是边；块的 reachable_from_entry 只统计显式分支/顺序流。",
    "不可达块保留并单列，不丢弃；静态块/边不等于运行时执行路径。",
    "IL 在 undecodable_at 之后不分析，方法记 partial；其余分母只统计已解出前缀。",
]


# ── 通用 ────────────────────────────────────────────────────────────
def _tok(t):
    return "0x%08x" % t


def _hx(b):
    return None if b is None else b.hex()


class Resolver:
    """token → 目标。只读元数据表；不加载任何被引程序集。"""

    def __init__(self, tables, assembly_name):
        self.t = tables
        self.assembly_name = assembly_name
        self.cache = {}
        self.type_cache = {}
        self.parent_counts = collections.Counter()
        self._build_type_maps()

    # -- 基础读取 ----------------------------------------------------
    def _s(self, idx):
        return self.t.string(idx)["value"]

    def _blob(self, idx):
        return self.t.blob(idx)["value"]

    def _build_type_maps(self):
        self.nested = {}
        for row, r in self.t.rows(0x29):
            self.nested[r["NestedClass"]] = r["EnclosingClass"]
        self.typedef_full = {}
        for row in range(1, self.t.row_counts.get(0x02, 0) + 1):
            full = self._typedef_full(row)
            if full is not None:
                self.typedef_full[full] = row
        # TypeDef 方法区间
        starts = []
        for row, r in self.t.rows(0x02):
            starts.append((r["MethodList"], row))
        starts.sort()
        total = self.t.row_counts.get(0x06, 0)
        self.td_ranges = {}
        for i, (start, row) in enumerate(starts):
            end = starts[i + 1][0] - 1 if i + 1 < len(starts) else total
            if start < 1:
                start = 1
            if end > total:
                end = total
            self.td_ranges[row] = (start, end)
        # 方法 → 所属类型
        self.method_owner = {}
        for row, (start, end) in self.td_ranges.items():
            full = self._typedef_full(row)
            for mr in range(start, end + 1):
                self.method_owner[mr] = (row, full)

    def _typedef_full(self, row, depth=0):
        if depth > 8:
            return None
        td = self.t.row(0x02, row)
        if td is None:
            return None
        name = self._s(td["TypeName"])
        ns = self._s(td["TypeNamespace"])
        if name is None:
            return None
        if row in self.nested:
            outer = self._typedef_full(self.nested[row], depth + 1)
            return None if outer is None else outer + "+" + name
        return ("%s.%s" % (ns, name)) if ns else name

    def _typeref_name(self, row, depth=0):
        if depth > 8:
            return None, None
        tr = self.t.row(0x01, row)
        if tr is None:
            return None, None
        name = self._s(tr["TypeName"])
        ns = self._s(tr["TypeNamespace"])
        if name is None:
            return None, None
        sc = DN._decode_coded("ResolutionScope", tr["ResolutionScope"])
        if sc is not None and sc["kind"] == "TypeRef":
            outer, _ = self._typeref_name(sc["row"], depth + 1)
            return (None if outer is None else outer + "+" + name), ns
        return (("%s.%s" % (ns, name)) if ns else name), ns

    def _asmref(self, row):
        ar = self.t.row(0x23, row)
        if ar is None:
            return None
        return {"name": self._s(ar["Name"]),
                "version": "%d.%d.%d.%d" % (ar["Major"], ar["Minor"],
                                            ar["Build"], ar["Rev"])}

    def _moduleref(self, row):
        mr = self.t.row(0x1A, row)
        return None if mr is None else self._s(mr["Name"])

    def _method_info(self, row):
        md = self.t.row(0x06, row)
        if md is None:
            return None
        return {"row": row, "name": self._s(md["Name"]), "rva": md["RVA"],
                "signature": self._blob(md["Signature"])}

    # -- ResolutionScope / TypeRef -----------------------------------
    def _scope(self, raw, depth=0):
        if depth > 8:
            return {"status": "unresolved", "reason": "bad_parent",
                    "detail": "ResolutionScope 嵌套超过 8 层或成环"}
        c = DN._decode_coded("ResolutionScope", raw)
        if c is None:
            return {"status": "unresolved", "reason": "token_kind_mismatch",
                    "detail": "ResolutionScope 解码为空"}
        kind, row = c["kind"], c["row"]
        if kind == "invalid" or kind not in ("Module", "ModuleRef",
                                             "AssemblyRef", "TypeRef"):
            return {"status": "unresolved", "reason": "token_kind_mismatch",
                    "detail": "ResolutionScope tag=%d 不是合法作用域" % c["tag"]}
        if kind == "Module":
            return {"status": "internal", "root": "Module", "row": row,
                    "assembly": self.assembly_name, "module": None,
                    "detail": "ResolutionScope=Module[%d]（本模块）" % row}
        if kind == "ModuleRef":
            if row == 0:
                return {"status": "internal", "root": "ModuleRef", "row": 0,
                        "assembly": self.assembly_name, "module": None,
                        "detail": "ResolutionScope=ModuleRef[0]（本模块）"}
            name = self._moduleref(row)
            if name is None:
                return {"status": "unresolved", "reason": "missing_assembly",
                        "detail": "ModuleRef[%d] 行不存在" % row}
            if not name:
                return {"status": "unresolved", "reason": "missing_assembly",
                        "detail": "ModuleRef[%d].Name 缺失" % row}
            return {"status": "external", "root": "ModuleRef", "row": row,
                    "assembly": None, "module": name,
                    "detail": "ResolutionScope=ModuleRef[%d]（模块 %s，未加载）"
                              % (row, name)}
        if kind == "AssemblyRef":
            if row == 0:
                return {"status": "internal", "root": "AssemblyRef", "row": 0,
                        "assembly": self.assembly_name, "module": None,
                        "detail": "ResolutionScope=AssemblyRef[0]（本程序集）"}
            ar = self._asmref(row)
            if ar is None:
                return {"status": "unresolved", "reason": "missing_assembly",
                        "detail": "AssemblyRef[%d] 行不存在" % row}
            if not ar["name"]:
                return {"status": "unresolved", "reason": "missing_assembly",
                        "detail": "AssemblyRef[%d].Name 缺失" % row}
            return {"status": "external", "root": "AssemblyRef", "row": row,
                    "assembly": ar["name"], "module": None,
                    "version": ar["version"],
                    "detail": "ResolutionScope=AssemblyRef[%d]（%s %s，未加载）"
                              % (row, ar["name"], ar["version"])}
        # TypeRef：嵌套类型，根作用域决定内外
        tr = self.t.row(0x01, row)
        if tr is None:
            return {"status": "unresolved", "reason": "row_out_of_range",
                    "detail": "嵌套 TypeRef[%d] 行不存在" % row}
        return self._scope(tr["ResolutionScope"], depth + 1)

    def _typeref_info(self, row):
        if row in self.type_cache:
            return self.type_cache[row]
        tr = self.t.row(0x01, row)
        if tr is None:
            out = {"status": "unresolved", "reason": "row_out_of_range",
                   "detail": "TypeRef[%d] 行不存在" % row,
                   "path": ["TypeRef[%d]" % row]}
            self.type_cache[row] = out
            return out
        full, ns = self._typeref_name(row)
        scope = self._scope(tr["ResolutionScope"])
        if full is None:
            out = {"status": "unresolved", "reason": "bad_parent",
                   "detail": "TypeRef[%d] 名称/嵌套链不可解析" % row,
                   "path": ["TypeRef[%d]" % row]}
        else:
            out = {"status": scope["status"],
                   "reason": scope.get("reason"),
                   "detail": scope.get("detail"),
                   "type": {"namespace": ns, "name": full.split("+")[-1],
                            "full_name": full},
                   "assembly": scope.get("assembly"),
                   "version": scope.get("version"),
                   "module": scope.get("module"),
                   "scope_root": scope.get("root"),
                   "path": ["TypeRef[%d]" % row]}
        self.type_cache[row] = out
        return out

    # -- TypeSpec ----------------------------------------------------
    def _parse_type_base(self, b, off=0, depth=0):
        if depth > 8 or off >= len(b):
            return {"status": "unresolved", "reason": "bad_parent",
                    "detail": "TypeSpec 签名嵌套过深或截断"}
        tag = b[off]
        if tag in (0x11, 0x12):                      # VALUETYPE / CLASS
            try:
                raw, _ = DN._compressed(b, off + 1)
            except ValueError as e:
                return {"status": "unresolved", "reason": "no_signature",
                        "detail": "TypeSpec 类型编码截断：%s" % e}
            return self._coded_type(raw, depth + 1)
        if tag == 0x15:                              # GENERICINST
            # GENERICINST (CLASS|VALUETYPE) TypeDefOrRefOrSpecEncoded
            # GenArgCount Type* — 先跳过 0x11/0x12 再读压缩 coded token
            p = off + 1
            if p >= len(b) or b[p] not in (0x11, 0x12):
                return {"status": "unresolved", "reason": "bad_parent",
                        "detail": "TypeSpec GENERICINST 后不是 CLASS/VALUETYPE"
                                  "（首字节 0x%02x）" % (b[p] if p < len(b)
                                                        else 0)}
            try:
                raw, _ = DN._compressed(b, p + 1)
            except ValueError as e:
                return {"status": "unresolved", "reason": "no_signature",
                        "detail": "TypeSpec GENERICINST 截断：%s" % e}
            return self._coded_type(raw, depth + 1)
        if tag in (0x1D, 0x14, 0x0F, 0x10):          # SZARRAY/ARRAY/PTR/BYREF
            return self._parse_type_base(b, off + 1, depth + 1)
        if tag in (0x13, 0x1E):                      # VAR / MVAR
            return {"status": "unresolved", "reason": "bad_parent",
                    "detail": "TypeSpec 基类型是泛型变量（0x%02x），"
                              "静态无法确定声明类型" % tag}
        return {"status": "unresolved", "reason": "bad_parent",
                "detail": "TypeSpec 首字节 0x%02x 不含 TypeDefOrRef" % tag}

    def _coded_type(self, raw, depth=0):
        tag = raw & 3
        row = raw >> 2
        kinds = {0: "TypeDef", 1: "TypeRef", 2: "TypeSpec"}
        kind = kinds.get(tag)
        if kind is None or row == 0:
            return {"status": "unresolved", "reason": "bad_parent",
                    "detail": "TypeDefOrRefOrSpec tag=%d row=%d 非法"
                              % (tag, row)}
        if kind == "TypeSpec":
            return self._typespec_base(row, depth + 1)
        return {"status": "ok", "kind": kind, "row": row,
                "path": ["%s[%d]" % (kind, row)]}

    def _typespec_base(self, row, depth=0):
        ts = self.t.row(0x1B, row)
        if ts is None:
            return {"status": "unresolved", "reason": "row_out_of_range",
                    "detail": "TypeSpec[%d] 行不存在" % row}
        blob = self._blob(ts["Signature"])
        if blob is None:
            return {"status": "unresolved", "reason": "no_signature",
                    "detail": "TypeSpec[%d] 签名 blob 缺失" % row}
        out = self._parse_type_base(blob, 0, depth)
        if out.get("status") == "ok":
            out["path"] = ["TypeSpec[%d]" % row] + out.get("path", [])
        return out

    # -- 成员查找 ----------------------------------------------------
    def _lookup_typedef_member(self, td_row, name, sig, generic, path):
        start, end = self.td_ranges.get(td_row, (0, 0))
        td_full = self._typedef_full(td_row)
        named = []
        for r in range(start, end + 1):
            info = self._method_info(r)
            if info is None or info["name"] != name:
                continue
            named.append(info)
        if sig is None:
            return self._unresolved(
                "no_signature", path + ["TypeDef[%d]" % td_row],
                "MemberRef[Name=%s] 的签名 blob 缺失，无法比较" % name)
        for info in named:
            if info["signature"] == sig:
                return {
                    "status": "internal", "reason": None, "detail": None,
                    "resolution_path": path + ["TypeDef[%d]" % td_row,
                                               "MethodDef[%d]" % info["row"]],
                    "target": {"kind": "MethodDef", "row": info["row"],
                               "token": _tok(0x06000000 | info["row"]),
                               "name": info["name"], "owner_row": td_row,
                               "owner_type": td_full, "rva": info["rva"],
                               "has_body": info["rva"] != 0},
                    "external": None, "generic": generic,
                }
        if named:
            return self._unresolved(
                "signature_mismatch", path + ["TypeDef[%d]" % td_row],
                "同名方法 %d 个（行 %s），但签名 blob 无一相等；不按名字猜"
                % (len(named), ",".join(str(x["row"]) for x in named[:4])))
        return self._unresolved(
            "member_not_found", path + ["TypeDef[%d]" % td_row],
            "类型 %s（TypeDef[%d]）的方法区间 %d..%d 内没有 Name=%s"
            % (td_full, td_row, start, end, name))

    # -- token 解析 --------------------------------------------------
    def _unresolved(self, reason, path, detail):
        return {"status": "unresolved", "reason": reason, "detail": detail,
                "resolution_path": path, "target": None, "external": None,
                "generic": False}

    def resolve_token(self, token):
        if token in self.cache:
            return self.cache[token]
        out = self._resolve_token(token)
        self.cache[token] = out
        return out

    def _resolve_token(self, token):
        if token == 0:
            return self._unresolved("invalid_token", ["0x00000000"],
                                    "token 为 0")
        table = token >> 24
        row = token & 0xFFFFFF
        path = []
        if table == 0x06:
            info = self._method_info(row)
            path = ["MethodDef[%d]" % row]
            if info is None:
                return self._unresolved(
                    "row_out_of_range", path,
                    "MethodDef 行 %d 超出 1..%d"
                    % (row, self.t.row_counts.get(0x06, 0)))
            owner, owner_full = self.method_owner.get(row, (None, None))
            return {"status": "internal", "reason": None, "detail": None,
                    "resolution_path": path,
                    "target": {"kind": "MethodDef", "row": row,
                               "token": _tok(token), "name": info["name"],
                               "owner_row": owner, "owner_type": owner_full,
                               "rva": info["rva"],
                               "has_body": info["rva"] != 0},
                    "external": None, "generic": False}
        if table == 0x0A:
            return self._memberref(row, False, [])
        if table == 0x2B:
            ms = self.t.row(0x2B, row)
            path = ["MethodSpec[%d]" % row]
            if ms is None:
                return self._unresolved(
                    "row_out_of_range", path,
                    "MethodSpec 行 %d 超出 1..%d"
                    % (row, self.t.row_counts.get(0x2B, 0)))
            under = DN._decode_coded("MethodDefOrRef", ms["Method"])
            if under is None or under["kind"] == "invalid":
                return self._unresolved(
                    "token_kind_mismatch", path,
                    "MethodSpec.Method 不是 MethodDefOrRef")
            if under["kind"] == "MethodDef":
                base = self._resolve_token(0x06000000 | under["row"])
                base = {k: v for k, v in base.items()}
            elif under["kind"] == "MemberRef":
                base = self._memberref(under["row"], True, [])
            else:
                return self._unresolved(
                    "token_kind_mismatch", path,
                    "MethodSpec.Method 指向 %s" % under["kind"])
            blob = self._blob(ms["Instantiation"])
            count = None
            if blob:
                # INSTANTIATION 前缀 0x0A（GENRICINST），其后才是 GenArgCount
                off = 1 if blob[0] == 0x0A else 0
                try:
                    count, _ = DN._compressed(blob, off)
                except ValueError:
                    count = None
            out = dict(base)
            out["resolution_path"] = path + out.get("resolution_path", [])
            out["generic"] = {"method_spec_row": row,
                              "generic_arg_count": count,
                              "underlying_status": base["status"]}
            return out
        if table == 0x11:
            return self._unresolved(
                "token_kind_mismatch", ["StandAloneSig[%d]" % row],
                "calli 的操作数是 StandAloneSig（签名），不是方法 token；"
                "本轮不按签名推断调用目标")
        return self._unresolved(
            "token_kind_mismatch", ["table 0x%02x[%d]" % (table, row)],
            "token 表 0x%02x 不是方法 token（允许 0x06 MethodDef / "
            "0x0A MemberRef / 0x2B MethodSpec）" % table)

    def _memberref(self, row, generic, path_prefix):
        mr = self.t.row(0x0A, row)
        path = list(path_prefix) + ["MemberRef[%d]" % row]
        if mr is None:
            return self._unresolved(
                "row_out_of_range", path,
                "MemberRef 行 %d 超出 1..%d"
                % (row, self.t.row_counts.get(0x0A, 0)))
        name = self._s(mr["Name"])
        sig = self._blob(mr["Signature"])
        if name is None:
            return self._unresolved("no_signature", path,
                                    "MemberRef[%d].Name 缺失" % row)
        parent = DN._decode_coded("MemberRefParent", mr["Class"])
        if parent is None or parent["kind"] == "invalid":
            return self._unresolved(
                "token_kind_mismatch", path,
                "MemberRefParent tag=%s 不是合法父"
                % (None if parent is None else parent["tag"]))
        kind, prow = parent["kind"], parent["row"]
        if kind == "TypeDef":
            if self.t.row(0x02, prow) is None:
                return self._unresolved(
                    "row_out_of_range", path + ["TypeDef[%d]" % prow],
                    "TypeDef 行 %d 不存在" % prow)
            self.parent_counts["typedef"] += 1
            return self._lookup_typedef_member(prow, name, sig, generic,
                                               path)
        if kind == "TypeRef":
            info = self._typeref_info(prow)
            self.parent_counts["typeref"] += 1
            self.parent_counts["typeref_" + info["status"]] += 1
            if info["status"] == "unresolved":
                return self._unresolved(
                    info["reason"], path + info.get("path", []),
                    "%s（TypeRef[%d]）" % (info.get("detail"), prow))
            if info["status"] == "internal":
                full = info["type"]["full_name"]
                td = self.typedef_full.get(full)
                if td is None:
                    return self._unresolved(
                        "member_not_found", path + info.get("path", []),
                        "TypeRef[%d] 的作用域是本模块，但本模块 TypeDef 里没有 %s"
                        % (prow, full))
                return self._lookup_typedef_member(td, name, sig, generic,
                                                   path + info.get("path", []))
            return self._external(path + info.get("path", []),
                                  info["type"]["full_name"], name, generic,
                                  assembly=info.get("assembly"),
                                  version=info.get("version"),
                                  module=info.get("module"),
                                  parent_kind="TypeRef")
        if kind == "TypeSpec":
            self.parent_counts["typespec"] += 1
            base = self._typespec_base(prow)
            if base["status"] != "ok":
                self.parent_counts["typespec_unresolved"] += 1
                return self._unresolved(
                    base["reason"], path + base.get("path", []),
                    base.get("detail"))
            if base["kind"] == "TypeDef":
                self.parent_counts["typespec_internal"] += 1
                return self._lookup_typedef_member(
                    base["row"], name, sig, generic,
                    path + base.get("path", []))
            info = self._typeref_info(base["row"])
            if info["status"] == "unresolved":
                self.parent_counts["typespec_unresolved"] += 1
                return self._unresolved(
                    info["reason"], path + base.get("path", [])
                    + info.get("path", []),
                    info.get("detail"))
            if info["status"] == "internal":
                self.parent_counts["typespec_internal"] += 1
                full = info["type"]["full_name"]
                td = self.typedef_full.get(full)
                if td is None:
                    return self._unresolved(
                        "member_not_found", path + base.get("path", []),
                        "TypeSpec 基类型 %s 在本模块找不到 TypeDef" % full)
                return self._lookup_typedef_member(
                    td, name, sig, generic,
                    path + base.get("path", []) + info.get("path", []))
            self.parent_counts["typespec_external"] += 1
            return self._external(
                path + base.get("path", []) + info.get("path", []),
                info["type"]["full_name"], name, generic,
                assembly=info.get("assembly"),
                version=info.get("version"),
                module=info.get("module"),
                parent_kind="TypeSpec")
        if kind == "ModuleRef":
            self.parent_counts["moduleref"] += 1
            mod = self._moduleref(prow)
            if not mod:
                return self._unresolved(
                    "missing_assembly", path + ["ModuleRef[%d]" % prow],
                    "ModuleRef[%d] 缺失 Name" % prow)
            return self._external(path + ["ModuleRef[%d]" % prow],
                                  None, name, generic, assembly=None,
                                  module=mod, parent_kind="ModuleRef")
        if kind == "MethodDef":
            return self._unresolved(
                "unsupported_parent",
                path + ["MethodDef[%d]" % prow],
                "MemberRef 的父是 MethodDef（vararg 调用站点签名），本轮不展开")
        return self._unresolved(
            "token_kind_mismatch", path,
            "MemberRefParent 指向 %s" % kind)

    def _external(self, path, type_full, member, generic, assembly=None,
                  module=None, parent_kind=None, version=None):
        if not assembly and not module:
            return self._unresolved(
                "missing_assembly", path,
                "外部成员 %s 没有可声明的程序集/模块" % member)
        return {"status": "external", "reason": None,
                "detail": "声明指向外部程序集/模块；本轮不加载，没有目标 MethodDef 行号",
                "resolution_path": path,
                "target": None,
                "external": {"assembly": assembly, "version": version,
                             "module": module,
                             "type": type_full, "member": member,
                             "parent_kind": parent_kind},
                "generic": generic}

    def resolve_type_token(self, token):
        if token == 0:
            return {"status": "unresolved", "reason": "invalid_token",
                    "detail": "catch 类型 token 为 0", "type": None,
                    "external": None, "resolution_path": []}
        table, row = token >> 24, token & 0xFFFFFF
        if table == 0x02:
            td = self.t.row(0x02, row)
            if td is None:
                return {"status": "unresolved", "reason": "row_out_of_range",
                        "detail": "TypeDef 行 %d 不存在" % row,
                        "type": None, "external": None,
                        "resolution_path": ["TypeDef[%d]" % row]}
            full = self._typedef_full(row)
            return {"status": "internal", "reason": None, "detail": None,
                    "type": {"namespace": self._s(td["TypeNamespace"]),
                             "name": self._s(td["TypeName"]),
                             "full_name": full},
                    "external": None,
                    "resolution_path": ["TypeDef[%d]" % row]}
        if table == 0x01:
            info = self._typeref_info(row)
            return {"status": info["status"], "reason": info.get("reason"),
                    "detail": info.get("detail"),
                    "type": info.get("type"),
                    "external": (None if info["status"] != "external" else
                                 {"assembly": info.get("assembly"),
                                  "module": info.get("module")}),
                    "resolution_path": info.get("path", [])}
        if table == 0x1B:
            base = self._typespec_base(row)
            if base["status"] != "ok":
                return {"status": "unresolved", "reason": base["reason"],
                        "detail": base.get("detail"), "type": None,
                        "external": None,
                        "resolution_path": base.get("path", [])}
            if base["kind"] == "TypeDef":
                return self.resolve_type_token(0x02000000 | base["row"])
            if base["kind"] == "TypeRef":
                return self.resolve_type_token(0x01000000 | base["row"])
            return self.resolve_type_token(0x1B000000 | base["row"])
        return {"status": "unresolved", "reason": "token_kind_mismatch",
                "detail": "catch token 表 0x%02x 不是类型 token" % table,
                "type": None, "external": None,
                "resolution_path": ["table 0x%02x[%d]" % (table, row)]}


# ── 分支 / 块 ──────────────────────────────────────────────────────
def _prefix_len(name):
    """opcode 前缀字节数：0xFE 双字节前缀为 2，其余为 1。"""
    return 1 if name in _OP1_NAMES else 2 if name in _OP2_NAMES else 1


_OP1_NAMES = {v[0] for v in DN.OP1.values()}
_OP2_NAMES = {v[0] for v in DN.OP2.values()}


def _branch_form(name):
    if name == "switch":
        return "switch"
    if name in LEAVE:
        return "leave_short" if name.endswith(".s") else "leave_long"
    if name in SHORT_BR:
        return "short"
    if name in LONG_BR:
        return "long"
    return None


def _decode_branch(ins, code):
    """返回 (form, next_off, targets, error)。目标为绝对 code offset。"""
    name = ins["opcode"]
    form = _branch_form(name)
    if form is None:
        return None, None, [], None
    off, size = ins["offset"], ins["size"]
    next_off = off + size
    prefix = _prefix_len(name)
    raw = code[off + prefix:off + size]
    if form == "switch":
        if len(raw) < 4:
            return form, next_off, [], "switch 操作数不足 4 字节"
        n = struct.unpack("<i", raw[:4])[0]
        if n < 0 or 4 + 4 * n > len(raw):
            return form, next_off, [], "switch 计数 %d 与操作数字节 %d 不符" \
                % (n, len(raw))
        targets = [next_off + struct.unpack("<i", raw[4 + 4 * i:8 + 4 * i])[0]
                   for i in range(n)]
        return form, next_off, targets, None
    if form in ("short", "leave_short"):
        if len(raw) != 1:
            return form, next_off, [], "短跳转操作数不是 1 字节"
        return form, next_off, [next_off + struct.unpack("<b", raw)[0]], None
    if len(raw) != 4:
        return form, next_off, [], "长跳转操作数不是 4 字节"
    return form, next_off, [next_off + struct.unpack("<i", raw)[0]], None


def _check_target(target, insn_offsets, insn_bounds, code_size):
    """目标落点三分类。insn_bounds 只含真实指令起始 offset（不含 code_size）。"""
    if target in insn_bounds:
        return "instruction", target, None
    if 0 <= target < code_size:
        i = bisect.bisect_right(insn_offsets, target) - 1
        return ("inside_instruction", None,
                insn_offsets[i] if i >= 0 else None)
    return "outside_method", None, None


def _region_hits(off, clauses):
    """返回覆盖 off 的 (子句 id, 段类型) 列表；段类型固定为 try/handler/filter。

    leave 的合法性只用它判断：目标不得落在“不包含 leave 的保护区”内
    （禁止跳进保护区），但允许留在仍包含 leave 的外层 try 里——mscorlib
    里 515→627 这类（内层 finally 的 try 退出、仍在外层 try 内）是合法 IL。
    注意 handler 段的“段类型”是 handler，子句种类（catch/filter/finally）另取。
    """
    out = []
    for c in clauses:
        t0, t1 = c["try"]
        h0, h1 = c["handler"]
        if t0 is not None and t0 <= off < t1:
            out.append((c["id"], "try"))
        if h0 is not None and h0 <= off < h1:
            out.append((c["id"], "handler"))
        if c["filter"] and c["filter"][0] is not None and \
                c["filter"][0] <= off < h0:
            out.append((c["id"], "filter"))
    return out


def _eh_structure(m, resolver, boundaries, code_size, raw_clauses):
    clauses = []
    for i, c in enumerate(raw_clauses):
        t0 = c.get("try_offset")
        t1 = None if t0 is None else t0 + (c.get("try_length") or 0)
        h0 = c.get("handler_offset")
        h1 = None if h0 is None else h0 + (c.get("handler_length") or 0)
        f0 = c.get("filter_offset")
        kind = c.get("kind") or "unknown"
        bounds = [x for x in (t0, t1, h0, h1, f0) if x is not None]
        boundary_ok = all((x in boundaries) or (x == code_size) for x in bounds)
        range_ok = (t0 is not None and t1 is not None and h0 is not None
                    and h1 is not None
                    and 0 <= t0 < t1 <= code_size
                    and 0 <= h0 < h1 <= code_size
                    and (f0 is None or 0 <= f0 <= h0))
        catch = None
        if c.get("class_token"):
            tr = resolver.resolve_type_token(c["class_token"])
            catch = {"token": _tok(c["class_token"]),
                     "status": tr["status"], "reason": tr.get("reason"),
                     "type": tr.get("type"), "external": tr.get("external"),
                     "resolution_path": tr.get("resolution_path", [])}
        nesting = sum(
            1 for j, o in enumerate(raw_clauses) if j != i
            and (o.get("try_offset") or 0) <= t0
            and t1 <= (o.get("try_offset") or 0) + (o.get("try_length") or 0)
            and not ((o.get("try_offset") or 0) == t0
                     and (o.get("try_length") or 0) == (t1 - t0)))
        clauses.append({
            "id": i, "kind": kind, "flags": c.get("flags"),
            "try": [t0, t1],
            "handler": [h0, h1],
            "filter": [f0, h0] if f0 is not None else None,
            "boundary_ok": boundary_ok, "range_ok": range_ok,
            "nesting_depth": nesting, "catch": catch,
        })
    return clauses


def _analyze_method(m, data, resolver, keep_detail):
    """返回 (summary_counts, detail or None, errors)。"""
    body = m.get("body") or {}
    out = {
        "insn_count": 0, "branch_total": 0, "branch_by_form": {},
        "switch_count": 0, "switch_cases": 0,
        "targets_total": 0, "target_checks": {k: 0 for k in TARGET_CHECKS},
        "leave_into_region": 0, "leave_exits_finally": 0, "leave_in_filter": 0,
        "call_total": 0, "call_by_opcode": {}, "token_by_table": {},
        "token_status": {k: 0 for k in STATUSES},
        "unresolved_reason": {}, "call_sites": [],
        "eh_clauses": 0, "eh_by_kind": {}, "eh_bad_boundary": 0,
        "eh_bad_range": 0, "catch_status": {}, "eh": [],
        "blocks": 0, "edges": 0, "edges_by_kind": {},
        "unreachable": 0, "leave_edges": 0,
    }
    insns = (m.get("il") or {}).get("instructions") or []
    code_off = body.get("code_off")
    code_size = body.get("code_size") or 0
    if code_off is None or code_size <= 0 or not insns:
        return out, None, []
    code = data[code_off:code_off + code_size]
    insn_offsets = [i["offset"] for i in insns]
    insn_bounds = set(insn_offsets)
    boundaries = set(insn_offsets)
    boundaries.add(code_size)
    by_offset = {i["offset"]: i for i in insns}
    out["insn_count"] = len(insns)

    # ── EH 结构（先算，块要用边界）─────────────────────────────────
    raw_clauses = body.get("eh_clauses") or []
    clauses = _eh_structure(m, resolver, boundaries, code_size, raw_clauses)
    out["eh"] = clauses
    out["eh_clauses"] = len(clauses)
    for c in clauses:
        out["eh_by_kind"][c["kind"]] = out["eh_by_kind"].get(c["kind"], 0) + 1
        if not c["boundary_ok"]:
            out["eh_bad_boundary"] += 1
        if not c["range_ok"]:
            out["eh_bad_range"] += 1
        if c.get("catch"):
            st = c["catch"]["status"]
            out["catch_status"][st] = out["catch_status"].get(st, 0) + 1

    handler_starts = {c["handler"][0] for c in clauses
                      if c["handler"][0] is not None}
    filter_starts = {c["filter"][0] for c in clauses
                     if c["filter"] and c["filter"][0] is not None}

    # ── 分支目标 / 调用 token ─────────────────────────────────────
    branch_sites = []
    call_sites = []
    valid_targets = set()
    for ins in insns:
        name = ins["opcode"]
        if name in CALL_OPS:
            out["call_total"] += 1
            out["call_by_opcode"][name] = out["call_by_opcode"].get(
                name, 0) + 1
            token = None
            if ins.get("operand_len") == 4 and len(ins.get("operand_hex") or "") == 8:
                token = int(ins["operand_hex"][6:8] + ins["operand_hex"][4:6]
                            + ins["operand_hex"][2:4] + ins["operand_hex"][0:2],
                            16)
            if token is None:
                res = {"status": "unresolved", "reason": "invalid_token",
                       "detail": "操作数不是 4 字节 token",
                       "resolution_path": [], "target": None,
                       "external": None, "generic": False}
                table = None
            else:
                table = token >> 24
                res = resolver.resolve_token(token)
            tname = {0x06: "MethodDef", 0x0A: "MemberRef",
                     0x2B: "MethodSpec", 0x11: "StandAloneSig"}.get(
                         table, "table_0x%02x" % table if table else None)
            out["token_by_table"][tname] = out["token_by_table"].get(
                tname, 0) + 1
            out["token_status"][res["status"]] += 1
            if res["status"] == "unresolved":
                r = res["reason"]
                out["unresolved_reason"][r] = out["unresolved_reason"].get(r, 0) + 1
            call_sites.append({
                "offset": ins["offset"], "opcode": name,
                "token": _tok(token) if token is not None else None,
                "token_table": tname, "status": res["status"],
                "reason": res.get("reason"), "detail": res.get("detail"),
                "target": res.get("target"),
                "external": res.get("external"),
                "generic": res.get("generic"),
                "resolution_path": res.get("resolution_path", []),
            })
            continue
        form = _branch_form(name)
        if form is None:
            continue
        out["branch_total"] += 1
        out["branch_by_form"][form] = out["branch_by_form"].get(form, 0) + 1
        form2, next_off, targets, err = _decode_branch(ins, code)
        if form == "switch":
            out["switch_count"] += 1
            out["switch_cases"] += len(targets)
        site = {"offset": ins["offset"], "opcode": name, "form": form,
                "next": next_off, "targets": [], "error": err}
        if err:
            out["targets_total"] += len(targets)
            site["targets"].append({"value": None, "check": "decode_error",
                                    "detail": err})
            out["target_checks"].setdefault("decode_error", 0)
            out["target_checks"]["decode_error"] += 1
            branch_sites.append(site)
            continue
        for ci, t in enumerate(targets):
            out["targets_total"] += 1
            check, insn_off, containing = _check_target(
                t, insn_offsets, insn_bounds, code_size)
            out["target_checks"][check] += 1
            if check == "instruction":
                valid_targets.add(t)
            item = {"case_index": ci if form == "switch" else None,
                    "value": t, "check": check,
                    "insn_offset": insn_off, "containing_offset": containing}
            if name in LEAVE:
                lhits = _region_hits(ins["offset"], clauses)
                lregions = {cid for cid, _k in lhits}
                lkinds = {k for _cid, k in lhits}
                enters = sorted({cid for cid, _k in _region_hits(t, clauses)
                                 if cid not in lregions})
                exits_fin = sorted({cid for cid, k in lhits
                                    if k == "handler"
                                    and clauses[cid]["kind"] in ("finally",
                                                                 "fault")
                                    and not (clauses[cid]["handler"][0] <= t
                                             < clauses[cid]["handler"][1])})
                item["leave_regions"] = sorted(lregions)
                item["leave_region_kinds"] = sorted(lkinds)
                item["enters_regions"] = enters
                item["exits_finally_regions"] = exits_fin
                item["inside_exited_region"] = bool(enters)
                if enters:
                    out["leave_into_region"] += 1
                if exits_fin:
                    out["leave_exits_finally"] += 1
                if "filter" in lkinds:
                    out["leave_in_filter"] += 1
            site["targets"].append(item)
        if name == "switch" and next_off in boundaries:
            valid_targets.add(next_off)
        branch_sites.append(site)

    # ── leader / 块 ───────────────────────────────────────────────
    leaders = {0}
    leaders |= valid_targets
    for site in branch_sites:
        if site["next"] in boundaries:
            leaders.add(site["next"])
    for ins in insns:
        if ins["opcode"] in TERMINATORS:
            nxt = ins["offset"] + ins["size"]
            if nxt in boundaries:
                leaders.add(nxt)
    for c in clauses:
        for x in (c["try"][0], c["try"][1], c["handler"][0], c["handler"][1],
                  c["filter"][0] if c["filter"] else None):
            if x is None:
                continue
            if x in boundaries:
                leaders.add(x)
    leaders = sorted(x for x in leaders if x in by_offset)
    if not leaders:
        return out, None, []

    blocks = []
    cur = []
    leader_set = set(leaders)
    for ins in insns:
        if ins["offset"] in leader_set and cur:
            blocks.append(cur)
            cur = []
        cur.append(ins)
        if ins["opcode"] in TERMINATORS:
            blocks.append(cur)
            cur = []
    if cur:
        blocks.append(cur)

    block_index = {}
    for bi, b in enumerate(blocks):
        block_index[b[0]["offset"]] = bi

    edge_list = []
    target_blocks = collections.Counter()
    branch_target_starts = set(valid_targets)

    for bi, b in enumerate(blocks):
        last = b[-1]
        name = last["opcode"]
        start = b[0]["offset"]
        next_off = last["offset"] + last["size"]
        if name in COND_BR:
            form2, nxt, targets, err = _decode_branch(last, code)
            for t in (targets if not err else []):
                if t in block_index:
                    edge_list.append({"from": start, "to": t,
                                      "kind": "branch", "case": None})
                    target_blocks[bi] += 1
            if next_off in block_index:
                edge_list.append({"from": start, "to": next_off,
                                  "kind": "fallthrough", "case": None})
                target_blocks[bi] += 1
        elif name == "switch":
            form2, nxt, targets, err = _decode_branch(last, code)
            for ci, t in enumerate(targets if not err else []):
                if t in block_index:
                    edge_list.append({"from": start, "to": t,
                                      "kind": "switch", "case": ci})
                    target_blocks[bi] += 1
            if next_off in block_index:
                edge_list.append({"from": start, "to": next_off,
                                  "kind": "fallthrough", "case": None})
                target_blocks[bi] += 1
        elif name in ("br", "br.s", "leave", "leave.s"):
            form2, nxt, targets, err = _decode_branch(last, code)
            kind = "leave" if name in LEAVE else "branch"
            for t in (targets if not err else []):
                if t in block_index:
                    edge_list.append({"from": start, "to": t,
                                      "kind": kind, "case": None})
                    target_blocks[bi] += 1
        elif name in TERMINATORS:
            pass
        else:
            if next_off in block_index:
                edge_list.append({"from": start, "to": next_off,
                                  "kind": "fallthrough", "case": None})
                target_blocks[bi] += 1

    # 可达性
    succ = collections.defaultdict(list)
    for e in edge_list:
        succ[e["from"]].append(e["to"])
    seen = set()
    stack = [0]
    while stack:
        s = stack.pop()
        if s in seen or s not in block_index:
            continue
        seen.add(s)
        stack.extend(succ.get(s, []))
    unreachable = 0
    block_details = []
    fallthrough_leaders = {site["next"] for site in branch_sites}
    for ins in insns:
        if ins["opcode"] in TERMINATORS:
            fallthrough_leaders.add(ins["offset"] + ins["size"])
    leave_targets = {t["value"] for site in branch_sites
                     if site["opcode"] in LEAVE
                     for t in site["targets"] if t["check"] == "instruction"}
    # 区域：块被 EH 边界切开，按区间重叠列出（嵌套时多个）
    for bi, b in enumerate(blocks):
        s = b[0]["offset"]
        e = b[-1]["offset"] + b[-1]["size"]
        regs = []
        for c in clauses:
            spans = [(c["try"][0], c["try"][1]),
                     (c["handler"][0], c["handler"][1])]
            if c["filter"]:
                spans.append((c["filter"][0], c["filter"][1]))
            if any(a < e and s < z for a, z in spans if a is not None
                   and z is not None):
                regs.append(c["id"])
        if s == 0:
            entry = "method"
        elif s in handler_starts:
            entry = "eh_handler"
        elif s in filter_starts:
            entry = "eh_filter"
        elif s in leave_targets:
            entry = "leave_target"
        elif s in branch_target_starts:
            entry = "branch"
        elif s in fallthrough_leaders:
            entry = "fallthrough"
        else:
            entry = "other"
        reach = s in seen
        if not reach:
            unreachable += 1
        if keep_detail:
            block_details.append({
                "start": s, "end": e, "insn_count": len(b),
                "insns": [i["offset"] for i in b],
                "terminator": b[-1]["opcode"]
                if b[-1]["opcode"] in TERMINATORS else None,
                "regions": regs, "entry": entry,
                "reachable_from_entry": reach,
            })
    out["blocks"] = len(blocks)
    out["edges"] = len(edge_list)
    out["unreachable"] = unreachable
    for e in edge_list:
        out["edges_by_kind"][e["kind"]] = out["edges_by_kind"].get(
            e["kind"], 0) + 1

    detail = None
    if keep_detail:
        detail = {
            "instruction_count": len(insns),
            "branches": {"total": out["branch_total"],
                         "by_form": out["branch_by_form"],
                         "switch": out["switch_count"],
                         "switch_cases": out["switch_cases"],
                         "targets": out["targets_total"],
                         "target_checks": out["target_checks"],
                         "leave_into_region": out["leave_into_region"],
                         "leave_exits_finally": out["leave_exits_finally"],
                         "leave_in_filter": out["leave_in_filter"]},
            "branch_sites": branch_sites,
            "call_sites": call_sites,
            "eh": clauses,
            "blocks": block_details,
            "edges": edge_list,
            "reachability": {"blocks": len(blocks),
                             "reachable": len(blocks) - unreachable,
                             "unreachable": unreachable},
        }
    return out, detail, []


# ── 构建 ────────────────────────────────────────────────────────────
def build(path, limit=40):
    rep = DN.build(path, detail_methods=None, detail_insns=None)
    if rep.get("status") != DN.STATUS_OK:
        return {"schema": SCHEMA, "path": str(path),
                "status": rep.get("status"), "reason": rep.get("reason"),
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER}
    op = DN.open_tables(path)
    if op.get("status") != DN.STATUS_OK:
        return {"schema": SCHEMA, "path": str(path),
                "status": op.get("status"), "reason": op.get("reason"),
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER}
    tables = op["tables"]
    data = op["data"]
    resolver = Resolver(tables, (rep.get("assembly") or {}).get("name"))

    den = collections.Counter()
    token_status = collections.Counter()
    token_table = collections.Counter()
    unresolved_reason = collections.Counter()
    call_by_opcode = collections.Counter()
    branch_by_form = collections.Counter()
    target_checks = collections.Counter()
    eh_by_kind = collections.Counter()
    catch_status = collections.Counter()
    edges_by_kind = collections.Counter()
    methods = []
    method_errors = []
    analyzed = partial = empty = 0

    for m in rep["methods"]:
        if m.get("body_status") != "ok":
            continue
        il = m.get("il") or {}
        insns = il.get("instructions") or []
        if not insns:
            empty += 1
            continue
        if il.get("undecodable_at") is not None:
            partial += 1
        else:
            analyzed += 1
        keep = len(methods) < limit
        try:
            out, detail, errs = _analyze_method(m, data, resolver, keep)
        except Exception as e:                    # 单方法失败不阻断
            method_errors.append({
                "token": m.get("token"), "name": m.get("name"),
                "error": "%s: %s" % (type(e).__name__, e)})
            continue
        den["branch_total"] += out["branch_total"]
        for k, v in out["branch_by_form"].items():
            branch_by_form[k] += v
        den["switch_count"] += out["switch_count"]
        den["switch_cases"] += out["switch_cases"]
        den["targets_total"] += out["targets_total"]
        for k, v in out["target_checks"].items():
            target_checks[k] += v
        den["leave_into_region"] += out["leave_into_region"]
        den["leave_exits_finally"] += out["leave_exits_finally"]
        den["leave_in_filter"] += out["leave_in_filter"]
        den["call_total"] += out["call_total"]
        for k, v in out["call_by_opcode"].items():
            call_by_opcode[k] += v
        for k, v in out["token_by_table"].items():
            token_table[k] += v
        for k, v in out["token_status"].items():
            token_status[k] += v
        for k, v in out["unresolved_reason"].items():
            unresolved_reason[k] += v
        den["eh_clauses"] += out["eh_clauses"]
        for k, v in out["eh_by_kind"].items():
            eh_by_kind[k] += v
        den["eh_bad_boundary"] += out["eh_bad_boundary"]
        den["eh_bad_range"] += out["eh_bad_range"]
        for k, v in out["catch_status"].items():
            catch_status[k] += v
        den["blocks_total"] += out["blocks"]
        den["edges_total"] += out["edges"]
        den["unreachable_blocks"] += out["unreachable"]
        for k, v in out["edges_by_kind"].items():
            edges_by_kind[k] += v
        if detail is not None:
            item = {
                "row": m.get("row"), "token": m.get("token"),
                "name": m.get("name"),
                "owner_row": m.get("owner_row"),
                "owner_type": resolver.method_owner.get(
                    m.get("row"), (None, None))[1],
                "rva": m.get("rva"),
                "code_off": (m.get("body") or {}).get("code_off"),
                "code_size": (m.get("body") or {}).get("code_size"),
                "partial": il.get("undecodable_at") is not None,
                "undecodable_at": il.get("undecodable_at"),
            }
            item.update(detail)
            methods.append(item)

    dm = rep["denominators"]
    den["methods_total"] = dm["methoddef_rows"]
    den["methods_with_body"] = dm["body_ok"]
    den["methods_analyzed"] = analyzed
    den["methods_partial"] = partial
    den["methods_empty"] = empty
    den["methods_identity_ok"] = (analyzed + partial + empty
                                  == dm["body_ok"])
    den["methods_with_eh"] = dm["methods_with_eh"]
    den["eh_clauses_declared"] = dm["eh_clauses"]
    den["tokens_internal"] = token_status.get("internal", 0)
    den["tokens_external"] = token_status.get("external", 0)
    den["tokens_unresolved"] = token_status.get("unresolved", 0)
    den["targets_valid"] = target_checks.get("instruction", 0)
    den["targets_inside_instruction"] = target_checks.get(
        "inside_instruction", 0)
    den["targets_outside_method"] = target_checks.get("outside_method", 0)
    den["targets_decode_error"] = target_checks.get("decode_error", 0)
    den["token_identity_ok"] = (
        den["tokens_internal"] + den["tokens_external"]
        + den["tokens_unresolved"] == den["call_total"])
    den["target_identity_ok"] = (
        den["targets_valid"] + den["targets_inside_instruction"]
        + den["targets_outside_method"] + den["targets_decode_error"]
        == den["targets_total"])
    den["eh_identity_ok"] = (
        sum(eh_by_kind.values()) == den["eh_clauses"])
    den["block_identity_ok"] = (
        den["blocks_total"] == den["unreachable_blocks"]
        + (den["blocks_total"] - den["unreachable_blocks"]))
    den["edge_identity_ok"] = (
        sum(edges_by_kind.values()) == den["edges_total"])
    den["identity_ok"] = bool(
        den["methods_identity_ok"] and den["token_identity_ok"]
        and den["target_identity_ok"] and den["eh_identity_ok"]
        and den["block_identity_ok"] and den["edge_identity_ok"]
        and not method_errors)
    den["method_errors"] = len(method_errors)

    total = den["call_total"]
    den["ratios"] = {
        "internal_over_tokens": (den["tokens_internal"] / total
                                 if total else None),
        "external_over_tokens": (den["tokens_external"] / total
                                 if total else None),
        "unresolved_over_tokens": (den["tokens_unresolved"] / total
                                   if total else None),
        "targets_valid_over_total": (den["targets_valid"]
                                     / den["targets_total"]
                                     if den["targets_total"] else None),
        "eh_boundary_ok_over_clauses": (
            (den["eh_clauses"] - den["eh_bad_boundary"]) / den["eh_clauses"]
            if den["eh_clauses"] else None),
        "blocks_reachable_over_total": (
            (den["blocks_total"] - den["unreachable_blocks"])
            / den["blocks_total"] if den["blocks_total"] else None),
    }
    den = dict(den)
    for key in ("call_total", "targets_total", "branch_total",
                "switch_count", "switch_cases", "eh_clauses",
                "blocks_total", "edges_total", "unreachable_blocks",
                "leave_into_region", "leave_exits_finally", "leave_in_filter",
                "eh_bad_boundary", "eh_bad_range"):
        den.setdefault(key, 0)
    den["call_by_opcode"] = dict(call_by_opcode)
    den["token_by_table"] = dict(token_table)
    den["unresolved_by_reason"] = dict(unresolved_reason)
    den["branch_by_form"] = dict(branch_by_form)
    den["target_checks"] = dict(target_checks)
    den["eh_by_kind"] = dict(eh_by_kind)
    den["catch_tokens_by_status"] = dict(catch_status)
    den["edges_by_kind"] = dict(edges_by_kind)
    den["parent_counts"] = dict(resolver.parent_counts)

    return {
        "schema": SCHEMA, "path": str(path), "status": DN.STATUS_OK,
        "reason": None,
        "assembly": rep.get("assembly"),
        "caliber": CALIBER, "caveats": list(CAVEATS),
        "cross_layer": CROSS_LAYER,
        "scope": {
            "methods_stored": len(methods), "limit": limit,
            "note": "--limit 只影响逐方法明细（blocks/branch_sites/"
                    "call_sites/eh）；所有分母统计全部有体方法",
        },
        "denominators": den,
        "methods": methods,
        "method_errors": method_errors,
    }


# ── 渲染 / CLI ──────────────────────────────────────────────────────
def render(rep, out=sys.stdout):
    p = out.write
    p("file   : %s\n" % rep.get("path"))
    p("status : %s%s\n" % (rep.get("status"),
                           "" if not rep.get("reason")
                           else "  (%s)" % rep["reason"]))
    if rep.get("status") != DN.STATUS_OK:
        return
    a = rep.get("assembly") or {}
    p("asm    : %s %s\n" % (a.get("name"), a.get("version")))
    d = rep["denominators"]
    p("\n[分母]\n")
    p("  方法: MethodDef %d = 有体 %d + 无体 %d；分析 %d + 部分 %d + 空 %d"
      "（恒等 %s）\n"
      % (d["methods_total"], d["methods_with_body"],
         d["methods_total"] - d["methods_with_body"],
         d["methods_analyzed"], d["methods_partial"], d["methods_empty"],
         d["methods_identity_ok"]))
    p("  分支指令 %d（%s）；switch %d / case %d\n"
      % (d["branch_total"],
         ", ".join("%s=%d" % kv for kv in sorted(d["branch_by_form"].items()))
         or "无", d["switch_count"], d["switch_cases"]))
    tc = d["target_checks"]
    p("  分支目标 %d：instruction %d / inside_instruction %d / "
      "outside_method %d / decode_error %d（恒等 %s）\n"
      % (d["targets_total"], tc.get("instruction", 0),
         tc.get("inside_instruction", 0), tc.get("outside_method", 0),
         tc.get("decode_error", 0), d["target_identity_ok"]))
    p("  调用指令 %d（%s）\n"
      % (d["call_total"],
         ", ".join("%s=%d" % kv for kv in sorted(d["call_by_opcode"].items()))
         or "无"))
    p("  token: internal %d / external %d / unresolved %d（恒等 %s）\n"
      % (d["tokens_internal"], d["tokens_external"],
         d["tokens_unresolved"], d["token_identity_ok"]))
    if d["unresolved_by_reason"]:
        p("  未解析原因: %s\n"
          % ", ".join("%s=%d" % kv for kv in
                      sorted(d["unresolved_by_reason"].items())))
    p("  token 表: %s\n"
      % (", ".join("%s=%d" % kv for kv in sorted(d["token_by_table"].items()))
         or "无"))
    p("  EH: 子句 %d（%s）；坏边界 %d / 坏区间 %d；catch token %s\n"
      % (d["eh_clauses"],
         ", ".join("%s=%d" % kv for kv in sorted(d["eh_by_kind"].items()))
         or "无", d["eh_bad_boundary"], d["eh_bad_range"],
         ", ".join("%s=%d" % kv for kv in
                   sorted(d["catch_tokens_by_status"].items())) or "无"))
    p("  块 %d / 边 %d（%s）/ 不可达块 %d；leave 跳入保护区 %d"
      "（从 finally/fault 跳出 %d、位于 filter 内 %d）\n"
      % (d["blocks_total"], d["edges_total"],
         ", ".join("%s=%d" % kv for kv in sorted(d["edges_by_kind"].items()))
         or "无", d["unreachable_blocks"], d["leave_into_region"],
         d["leave_exits_finally"], d["leave_in_filter"]))
    p("  父解析: %s\n"
      % (", ".join("%s=%d" % kv for kv in
                   sorted(d["parent_counts"].items())) or "无"))
    p("\n[比例]（分母见上）\n")
    for k, v in d["ratios"].items():
        p("  %s = %s\n" % (k, "None" if v is None else "%.6f" % v))
    p("\n[方法明细]（存储 %d 个；%s）\n"
      % (len(rep["methods"]), rep["scope"]["note"]))
    for m in rep["methods"]:
        p("  %s %s.%s  insn=%d blocks=%d edges=%d\n"
          % (m["token"], m.get("owner_type"), m["name"],
             m["instruction_count"], m["reachability"]["blocks"],
             len(m["edges"])))
    if rep.get("method_errors"):
        p("\n[方法分析失败] %d 条\n" % len(rep["method_errors"]))
        for e in rep["method_errors"][:5]:
            p("  %s %s: %s\n" % (e["token"], e["name"], e["error"]))


def main(argv):
    ap = argparse.ArgumentParser(
        prog="rekit ilflow",
        description=".NET IL 控制流与调用关系层（token 解析/分支目标/块/EH 结构）")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40,
                    help="存储逐方法明细的个数（不影响分母）")
    args = ap.parse_args(argv)
    rep = build(args.file, limit=max(0, args.limit))
    if args.json:
        json.dump(rep, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    else:
        render(rep)
    return 0 if rep.get("status") == DN.STATUS_OK else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
