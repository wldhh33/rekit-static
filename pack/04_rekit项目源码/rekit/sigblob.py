#!/usr/bin/env python3
# rekit.sigblob — M19 .NET 签名语义层（只解 #Blob 内的签名）
#
# 回答的问题：这条方法/字段/调用点的签名「说了什么类型」。
# 上游：M17 rekit.dotnet（CLI 头 / 元数据表 / #Blob 堆）。
#
# 口径（与 outputs/m19_sigblob/spec.md 一一对应）：
#   1) 只解三类调用点：MethodDef.Signature / MemberRef.Signature /
#      StandAloneSig.Signature；Field(0x04).Signature 只做长度与边界。
#   2) 分母先行：每张表 rows = no_blob_index + has_blob_index；
#      has = readable + unreadable；readable = decoded + undecoded；
#      decoded = clean + with_unknown。恒等式全部写进报告，False 即异常。
#   3) 「没有」与「没读到」分开：索引 0 记 no_blob_index；有索引但堆读不出
#      按 no_blob_heap / blob_index_out_of_range / blob_length_invalid /
#      blob_truncated 逐类计数。
#   4) 类型编码未知一律 unknown 并写明缺什么（element_type_0xNN /
#      coded_index_tag_N / row_out_of_range:<Table> / name_missing），
#      不按附近字节或表名猜一个「看起来像」的类型。
#   5) 不做类型布局、不算字段 RVA、不读特性、不反编译；TypeSpec 只写 token。
import argparse
import collections
import json
import sys

from . import dotnet as DN

SCHEMA = 1
MAX_DEPTH = 64
MAX_PARAMS = 0x10000

TABLES = (("MethodDef", 0x06), ("MemberRef", 0x0A),
          ("StandAloneSig", 0x11), ("Field", 0x04))

# 带 blob 但本轮不解读的表：只报「有 blob 引用的行数」，防止「没读」被当成「没有」
OUT_OF_SCOPE = (
    (0x0B, "Constant", ["Value"]),
    (0x0C, "CustomAttribute", ["Value"]),
    (0x0D, "FieldMarshal", ["NativeType"]),
    (0x0E, "DeclSecurity", ["PermissionSet"]),
    (0x17, "Property", ["Type"]),
    (0x1B, "TypeSpec", ["Signature"]),
    (0x20, "Assembly", ["PublicKey"]),
    (0x23, "AssemblyRef", ["PublicKeyOrToken", "HashValue"]),
    (0x26, "File", ["HashValue"]),
)

# ECMA-335 II.23.1.16 元素类型（名字与 SRM PrimitiveTypeCode 一致）
PRIMITIVES = {
    0x01: "Void", 0x02: "Boolean", 0x03: "Char", 0x04: "SByte",
    0x05: "Byte", 0x06: "Int16", 0x07: "UInt16", 0x08: "Int32",
    0x09: "UInt32", 0x0A: "Int64", 0x0B: "UInt64", 0x0C: "Single",
    0x0D: "Double", 0x0E: "String", 0x16: "TypedReference",
    0x18: "IntPtr", 0x19: "UIntPtr", 0x1C: "Object",
}

CALL_CONV = {0x00: "Default", 0x01: "CDecl", 0x02: "StdCall",
             0x03: "ThisCall", 0x04: "FastCall", 0x05: "VarArgs"}

CROSS_LAYER = [
    {"layer": "dotnet", "status": "upstream",
     "reason": "本层消费 M17 的 CLI 头 / 元数据表 / #Blob 堆定位；"
               "签名长度与 M17 的 signature_len 独立重算后逐行相等才放行"},
    {"layer": "ilflow", "status": "sibling",
     "reason": "M18 只把签名 blob 当字节做 MemberRef 精确匹配；本层解语义，"
               "但不改 M18 的匹配判据，也不按签名反推调用目标"},
    {"layer": "map", "status": "not_applicable",
     "reason": "签名是元数据堆内容，不是 PE 节内代码/数据布局"},
    {"layer": "disasm", "status": "not_applicable",
     "reason": "方法体是 CLI 字节码，不是 x86 指令"},
    {"layer": "recdesc", "status": "not_applicable",
     "reason": "递归下降以 x86 指令为输入"},
    {"layer": "expr", "status": "not_applicable",
     "reason": "表达式恢复建立在 x86 指令与寄存器上"},
    {"layer": "callgraph", "status": "not_applicable",
     "reason": "x86 调用图以代码地址为点；IL 以 token 为点"},
    {"layer": "strxref", "status": "not_applicable",
     "reason": "字面量在 #US，不在数据节"},
    {"layer": "datarefs", "status": "not_applicable",
     "reason": "对象声明来自 ELF/DWARF；.NET 引用是元数据 token"},
    {"layer": "paramdecl", "status": "not_applicable",
     "reason": "DWARF 形参声明；.NET 参数类型在本层签名里，二者不互相代入"},
    {"layer": "struct", "status": "not_applicable",
     "reason": "DWARF 类型布局层；本层只写类型名字与形状，不做布局"},
    {"layer": "funcreport", "status": "not_applicable",
     "reason": "六层 x86 合成入口；对 .NET 返回 not_applicable"},
]

CALIBER = [
    "只解 MethodDef / MemberRef / StandAloneSig 的 Signature；Field(0x04)"
    " 只做长度与边界，不解类型语义。",
    "分流按 blob 首字节低 6 位：0x06 FIELD、0x07 LOCAL_SIG 只记长度与边界"
    "（field_sig_length_only / local_sig_length_only），不并入 undecoded；"
    "其余按方法签名解。",
    "方法签名按 ECMA-335 II.23.2：CallConv（低 4 位 0–5，0x10 GENERIC、"
    "0x20 HASTHIS、0x40 EXPLICITTHIS）→ 可选泛型参数数 → 参数数 → 返回类型 → "
    "参数类型；VARARG 的 0x41 SENTINEL 只移动 required_param_count，不丢字节。",
    "压缩整数按 II.23.2 的 1/2/4 字节编码；非法首字节记 bad_compressed_int；"
    "参数数大于剩余字节记 truncated_signature，不按参数数继续读。",
    "类型文法：基元 / class / valuetype / szarray / array / ptr / byref / "
    "genericinst / var / mvar / fnptr / modreq / modopt / pinned / TypeSpec 引用；"
    "递归深度上限 64，超过记 depth_exceeded（不是 unknown）。",
    "canonical 文本两套实现共用：基元名与 SRM PrimitiveTypeCode 同名；"
    "class [TD]Ns.Name / class [TR]Ns.Name / valuetype [TR]Ns.Name；嵌套类型拼成 "
    "Outer+Inner；TypeSpec 只写 spec@0x1Bxxxxxx，不解其 blob。",
    "unknown 政策：元素类型字节不认识、coded tag 非法、行号越界、名字读不出，"
    "一律产出 kind=unknown 并写 missing 原因，不按名称或邻近字节猜。",
    "签名必须把 blob 消耗到恰好结束（consumed == blob_len）才算 decoded；"
    "剩余字节归 trailing_bytes 并计为 undecoded。",
    "分母先行：每张表 rows = no_blob_index + has_blob_index；"
    "has = readable + unreadable；readable = decoded + undecoded；"
    "decoded = clean + with_unknown。比例在分母之后，分母为 0 写 None。",
    "范围外但带 blob 的表（Constant / CustomAttribute / FieldMarshal / "
    "DeclSecurity / Property / TypeSpec / Assembly / AssemblyRef / File）"
    "只报有 blob 引用的行数，不解读。",
]

CAVEATS = [
    "本层只回答「签名说了什么类型」：不做类型布局（字段顺序/大小/对齐）、"
    "不算字段 RVA、不读 CustomAttribute、不反编译。",
    "TypeSpec 引用只写 token（spec@0x1Bxxxxxx），不递归解 TypeSpec 的 blob；"
    "泛型实例化的真实形状可能藏在 TypeSpec 里，本层不代替 M17 展开。",
    "Field(0x04)、MemberRef 的字段签名、StandAloneSig 的 LOCAL_SIG 只做长度与"
    "边界，不解类型；它们的类型语义属于后续层。",
    "unknown 是「本层编码表里没有」，不是「该类型不存在」；missing 字段写明"
    "缺什么。不按类型名/表名猜。",
    "canonical 文本不含程序集名：跨程序集同名类型在本层不区分，"
    "本条只在同一行内比较时使用。",
    "参数名/默认值不来自签名；签名里没有参数名，本层也不读 Param 表。",
    "受控样本只覆盖本机编译器实际生成的签名子集（无 mixed-mode、无混淆器变形），"
    "不代表真实世界程序集分布；真实样本同跑并单列 unknown。",
    "非 .NET 文件 / CLI 头缺失 / 表流不可解析时返回对应 status，不产生分母。",
]


class SigError(Exception):
    """签名解码失败：reason 是分类键，detail 是给诊断的原文。"""

    def __init__(self, reason, detail=None):
        Exception.__init__(self, reason)
        self.reason = reason
        self.detail = detail


# ── 类型名解析（TypeDef / TypeRef）──────────────────────────────────
class TypeResolver:
    """行号 → 全名。嵌套链独立拼接，缺失时给 missing，不返回空串。"""

    def __init__(self, tables):
        self.t = tables
        self.nested = {}
        for row, r in tables.rows(0x29):
            self.nested[r["NestedClass"]] = r["EnclosingClass"]
        self._td = {}
        self._tr = {}

    def typedef(self, row, depth=0):
        if row in self._td:
            return self._td[row]
        if depth > 8:
            out = {"missing": "nested_depth", "row": row}
            self._td[row] = out
            return out
        r = self.t.row(0x02, row)
        if r is None:
            out = {"missing": "row_out_of_range:TypeDef", "row": row}
        else:
            name = self.t.string(r["TypeName"])["value"]
            ns = self.t.string(r["TypeNamespace"])["value"]
            if name is None or ns is None:
                out = {"missing": "name_missing", "row": row}
            elif row in self.nested:
                outer = self.typedef(self.nested[row], depth + 1)
                if "missing" in outer:
                    out = {"missing": outer["missing"], "row": row}
                else:
                    out = {"name": outer["name"] + "+" + name, "row": row}
            else:
                out = {"name": ("%s.%s" % (ns, name)) if ns else name,
                       "row": row}
        self._td[row] = out
        return out

    def typeref(self, row, depth=0):
        if row in self._tr:
            return self._tr[row]
        if depth > 8:
            out = {"missing": "nested_depth", "row": row}
            self._tr[row] = out
            return out
        r = self.t.row(0x01, row)
        if r is None:
            out = {"missing": "row_out_of_range:TypeRef", "row": row}
        else:
            name = self.t.string(r["TypeName"])["value"]
            ns = self.t.string(r["TypeNamespace"])["value"]
            if name is None or ns is None:
                out = {"missing": "name_missing", "row": row}
            else:
                sc = DN._decode_coded("ResolutionScope", r["ResolutionScope"])
                if sc is not None and sc["kind"] == "TypeRef":
                    outer = self.typeref(sc["row"], depth + 1)
                    if "missing" in outer:
                        out = {"missing": outer["missing"], "row": row}
                    else:
                        out = {"name": outer["name"] + "+" + name, "row": row}
                else:
                    out = {"name": ("%s.%s" % (ns, name)) if ns else name,
                           "row": row}
        self._tr[row] = out
        return out

    def reference(self, raw):
        """TypeDefOrRefOrSpecEncoded（2 位 tag）→ (ref, missing)。"""
        tag = raw & 3
        row = raw >> 2
        if tag == 0:
            n = self.typedef(row)
            if "missing" in n:
                return None, n["missing"]
            return {"kind": "TypeDef", "table": "TD", "row": row,
                    "name": n["name"]}, None
        if tag == 1:
            n = self.typeref(row)
            if "missing" in n:
                return None, n["missing"]
            return {"kind": "TypeRef", "table": "TR", "row": row,
                    "name": n["name"]}, None
        if tag == 2:
            return {"kind": "TypeSpec", "table": None, "row": row,
                    "name": "spec@0x1B%06x" % row}, None
        return None, "coded_index_tag_%d" % tag


def _ref_token(ref):
    if ref["kind"] == "TypeSpec":
        return ref["name"]
    return "[%s]%s" % (ref["table"], ref["name"])


# ── 解码上下文 ──────────────────────────────────────────────────────
class Ctx:
    def __init__(self, resolver):
        self.resolver = resolver
        self.unknowns = []
        self.unknown_by_missing = collections.Counter()
        self.anomalies = collections.Counter()

    def begin(self):
        self.unknowns = []

    def unknown(self, missing, b, start, off):
        raw = b[start:off].hex()
        self.unknowns.append({"missing": missing, "raw": raw, "offset": start})
        self.unknown_by_missing[missing] += 1
        return {"kind": "unknown", "missing": missing, "raw": raw,
                "offset": start}

    def anomaly(self, name):
        self.anomalies[name] += 1


def _cint(b, off):
    try:
        return DN._compressed(b, off)
    except ValueError as e:
        raise SigError("bad_compressed_int", str(e))


def _csint(b, off):
    """ECMA 压缩有符号整数（符号扩展到 32 位）。"""
    v, nxt = _cint(b, off)
    bits = {1: 7, 2: 14, 4: 29}.get(nxt - off)
    if bits is not None and v & (1 << (bits - 1)):
        v -= (1 << bits)
    return v, nxt


def _canon_unknown(node):
    return "unknown(%s)" % node["missing"]


# ── 类型解码 ────────────────────────────────────────────────────────
def decode_type(ctx, b, off, depth=0):
    if depth > MAX_DEPTH:
        raise SigError("depth_exceeded", "类型递归超过 %d 层" % MAX_DEPTH)
    start = off
    if off >= len(b):
        raise SigError("truncated_signature", "类型编码在 blob 末尾截断")
    tag = b[off]
    off += 1

    if tag in PRIMITIVES:
        name = PRIMITIVES[tag]
        return {"kind": "primitive", "element": "0x%02x" % tag,
                "name": name, "canonical": name}, off

    if tag in (0x11, 0x12):                       # VALUETYPE / CLASS
        raw, off = _cint(b, off)
        ref, missing = ctx.resolver.reference(raw)
        label = "valuetype" if tag == 0x11 else "class"
        if ref is None:
            node = ctx.unknown(missing, b, start, off)
            return {"kind": label, "element": "0x%02x" % tag,
                    "reference": None, "base": node,
                    "canonical": _canon_unknown(node)}, off
        return {"kind": label, "element": "0x%02x" % tag,
                "reference": ref["kind"], "row": ref["row"],
                "name": ref["name"],
                "canonical": _ref_token(ref) if ref["kind"] == "TypeSpec"
                else "%s %s" % (label, _ref_token(ref))}, off

    if tag == 0x1D:                               # SZARRAY
        el, off = decode_type(ctx, b, off, depth + 1)
        return {"kind": "szarray", "element": el,
                "canonical": el["canonical"] + "[]"}, off

    if tag == 0x14:                               # ARRAY
        el, off = decode_type(ctx, b, off, depth + 1)
        rank, off = _cint(b, off)
        nsizes, off = _cint(b, off)
        sizes = []
        for _ in range(nsizes):
            v, off = _cint(b, off)
            sizes.append(v)
        nlb, off = _cint(b, off)
        lbs = []
        for _ in range(nlb):
            v, off = _csint(b, off)
            lbs.append(v)
        canon = "%s[r=%d" % (el["canonical"], rank)
        if sizes:
            canon += ";s=" + ",".join(str(v) for v in sizes)
        if lbs:
            canon += ";lb=" + ",".join(str(v) for v in lbs)
        canon += "]"
        return {"kind": "array", "element": el, "rank": rank,
                "sizes": sizes, "lower_bounds": lbs,
                "canonical": canon}, off

    if tag in (0x0F, 0x10):                       # PTR / BYREF
        el, off = decode_type(ctx, b, off, depth + 1)
        kind = "ptr" if tag == 0x0F else "byref"
        suffix = "*" if tag == 0x0F else "&"
        return {"kind": kind, "element": el,
                "canonical": el["canonical"] + suffix}, off

    if tag == 0x15:                               # GENERICINST
        if off >= len(b):
            raise SigError("truncated_signature", "GENERICINST 后无基类型编码")
        base = b[off]
        off += 1
        if base not in (0x11, 0x12):
            node = ctx.unknown("genericinst_base_0x%02x" % base,
                               b, start, off)
            off = _skip_generic_args(ctx, b, off, node, depth)
            return node, off
        raw, off = _cint(b, off)
        ref, missing = ctx.resolver.reference(raw)
        label = "valuetype" if base == 0x11 else "class"
        return _generic_inst(ctx, b, off, start, ref, missing, label, depth)

    if tag == 0x13:                               # VAR
        n, off = _cint(b, off)
        return {"kind": "var", "index": n, "canonical": "!%d" % n}, off

    if tag == 0x1E:                               # MVAR
        n, off = _cint(b, off)
        return {"kind": "mvar", "index": n, "canonical": "!!%d" % n}, off

    if tag == 0x1B:                               # FNPTR
        sub, off = decode_method_sig(ctx, b, off, depth + 1, exact=False)
        return {"kind": "fnptr", "signature": sub,
                "canonical": "fnptr(%s)" % sub["canonical"]}, off

    if tag in (0x1F, 0x20):                       # CMOD_REQD / CMOD_OPT
        raw, off = _cint(b, off)
        ref, missing = ctx.resolver.reference(raw)
        el, off = decode_type(ctx, b, off, depth + 1)
        key = "modreq" if tag == 0x1F else "modopt"
        if ref is None:
            prefix = "unknown(%s)" % missing
        else:
            prefix = "%s(%s)" % (key, _ref_token(ref))
        return {"kind": key, "modifier": ref, "element": el,
                "canonical": prefix + el["canonical"]}, off

    if tag == 0x45:                               # PINNED
        ctx.anomaly("pinned_in_method_sig")
        el, off = decode_type(ctx, b, off, depth + 1)
        return {"kind": "pinned", "element": el,
                "canonical": "pinned(%s)" % el["canonical"]}, off

    node = ctx.unknown("element_type_0x%02x" % tag, b, start, off)
    return node, off


def _generic_inst(ctx, b, off, start, ref, missing, label, depth):
    count, off = _cint(b, off)
    if count > MAX_PARAMS:
        raise SigError("param_count_exceeded", "泛型实参 %d" % count)
    if count > len(b) - off:
        raise SigError("truncated_signature",
                       "泛型实参 %d > 剩余字节 %d" % (count, len(b) - off))
    args = []
    for _ in range(count):
        a, off = decode_type(ctx, b, off, depth + 1)
        args.append(a)
    if ref is None:
        base = ctx.unknown(missing, b, start, off)
        canon = "%s<%s>" % (_canon_unknown(base),
                            ",".join(a["canonical"] for a in args))
        return {"kind": "genericinst", "label": label, "base": base,
                "generic_args": args, "canonical": canon}, off
    head = _ref_token(ref) if ref["kind"] == "TypeSpec" \
        else "%s %s" % (label, _ref_token(ref))
    return {"kind": "genericinst", "label": label, "base": ref,
            "generic_args": args,
            "canonical": "%s<%s>" % (head,
                                     ",".join(a["canonical"]
                                              for a in args))}, off


def _skip_generic_args(ctx, b, off, base_node, depth):
    """GENERICINST 基类型未知时，仍把 count/args 读完以保持字节边界。"""
    count, off = _cint(b, off)
    if count > MAX_PARAMS:
        raise SigError("param_count_exceeded", "泛型实参 %d" % count)
    if count > len(b) - off:
        raise SigError("truncated_signature",
                       "泛型实参 %d > 剩余字节 %d" % (count, len(b) - off))
    for _ in range(count):
        _t, off = decode_type(ctx, b, off, depth + 1)
    return off


# ── 方法签名解码 ────────────────────────────────────────────────────
def decode_method_sig(ctx, b, off, depth=0, exact=True):
    if depth > MAX_DEPTH:
        raise SigError("depth_exceeded", "签名递归超过 %d 层" % MAX_DEPTH)
    start = off
    if off >= len(b):
        raise SigError("truncated_signature", "方法签名没有 CallConv 字节")
    cc = b[off]
    off += 1
    flavor = cc & 0x0F
    if (cc & 0x80) or flavor > 5:
        raise SigError("not_method_signature",
                       "CallConv 0x%02x 不是方法调用约定" % cc)
    hasthis = 1 if cc & 0x20 else 0
    explicit = 1 if cc & 0x40 else 0
    generic = 1 if cc & 0x10 else 0
    gpc = 0
    if generic:
        gpc, off = _cint(b, off)
    pcount, off = _cint(b, off)
    if pcount > MAX_PARAMS:
        raise SigError("param_count_exceeded", "参数数 %d" % pcount)
    if pcount > len(b) - off:
        raise SigError("truncated_signature",
                       "参数数 %d > 剩余字节 %d" % (pcount, len(b) - off))
    ret, off = decode_type(ctx, b, off, depth + 1)
    params = []
    required = None
    sentinel = False
    for _ in range(pcount):
        if off < len(b) and b[off] == 0x41:
            off += 1
            sentinel = True
            required = len(params)
            if flavor != 0x05:
                ctx.anomaly("sentinel_in_nonvararg")
        t, off = decode_type(ctx, b, off, depth + 1)
        params.append(t)
    if exact and off != len(b):
        raise SigError("trailing_bytes", "%d 字节未消耗" % (len(b) - off))
    req = required if required is not None else pcount
    canon = ("sig cc=%s hasthis=%d explicit=%d generic=%d gpc=%d req=%d "
             "ret=%s params=[%s]"
             % (CALL_CONV.get(flavor, "0x%02x" % flavor), hasthis, explicit,
                generic, gpc, req, ret["canonical"],
                ",".join(p["canonical"] for p in params)))
    return {"call_conv": CALL_CONV.get(flavor, "0x%02x" % flavor),
            "has_this": hasthis, "explicit_this": explicit,
            "generic": generic, "generic_param_count": gpc,
            "param_count": pcount, "required_param_count": req,
            "sentinel": sentinel, "return": ret, "params": params,
            "consumed": off - start, "canonical": canon}, off


# ── 行分析 ──────────────────────────────────────────────────────────
def _kind_of(first):
    if first is None:
        return "empty"
    low = first & 0x3F
    if low == 0x06:
        return "field"
    if low == 0x07:
        return "local"
    return "method"


def _reason_key(missing):
    if missing is None:
        return None
    return missing.split(":", 1)[0].strip()


def analyze_blob(ctx, table, blob):
    """返回 (kind, status, reason, detail, signature)。"""
    first = blob[0] if blob else None
    kind = _kind_of(first)
    if table == "Field":
        if first is None:
            ctx.anomaly("empty_field_signature")
        elif kind != "field":
            ctx.anomaly("field_row_non_field_signature")
        return {"kind": "field", "status": "length_only",
                "reason": "field_length_only",
                "detail": "字段签名只做长度与边界", "signature": None}
    if first is None:
        return {"kind": kind, "status": "undecoded",
                "reason": "truncated_signature",
                "detail": "blob 长度为 0", "signature": None}
    if table == "MethodDef" and kind != "method":
        return {"kind": kind, "status": "undecoded",
                "reason": "not_method_signature",
                "detail": "MethodDef 签名首字节 0x%02x 不是方法调用约定" % first,
                "signature": None}
    if table == "MemberRef" and kind == "field":
        return {"kind": "field", "status": "length_only",
                "reason": "field_sig_length_only",
                "detail": "MemberRef 字段签名只做长度与边界",
                "signature": None}
    if table == "StandAloneSig" and kind == "local":
        return {"kind": "local", "status": "length_only",
                "reason": "local_sig_length_only",
                "detail": "LOCAL_SIG 只做长度与边界", "signature": None}
    if table == "StandAloneSig" and kind == "field":
        return {"kind": "field", "status": "length_only",
                "reason": "field_sig_length_only",
                "detail": "StandAloneSig 字段签名只做长度与边界",
                "signature": None}
    ctx.begin()
    try:
        sig, _off = decode_method_sig(ctx, blob, 0, exact=True)
    except SigError as e:
        return {"kind": "method", "status": "undecoded", "reason": e.reason,
                "detail": e.detail, "signature": None}
    return {"kind": "method", "status": "decoded", "reason": None,
            "detail": None, "signature": sig}


# ── 分母 ────────────────────────────────────────────────────────────
def _blank_den():
    return {
        "rows": 0, "rows_read": 0,
        "no_blob_index": 0, "has_blob_index": 0,
        "blob_readable": 0, "blob_unreadable": 0,
        "unreadable_by_reason": {},
        "decoded": 0, "undecoded": 0, "undecoded_by_reason": {},
        "decoded_clean": 0, "decoded_with_unknown": 0,
        "method_decoded": 0, "field_sig_length_only": 0,
        "local_sig_length_only": 0,
    }


def _blank_field_den():
    return {
        "rows": 0, "rows_read": 0,
        "no_blob_index": 0, "has_blob_index": 0,
        "blob_readable": 0, "blob_unreadable": 0,
        "unreadable_by_reason": {},
        "length_only": 0, "non_field_signature": 0,
        "note": "Field 签名只做长度与边界，不做类型语义",
    }


def _bump(counter, key):
    counter[key] = counter.get(key, 0) + 1


def _token(tid, row):
    return "0x%08x" % ((tid << 24) | row)


def _method_owners(tables, resolver):
    starts = []
    for row, r in tables.rows(0x02):
        starts.append((r["MethodList"], row))
    starts.sort()
    total = tables.row_counts.get(0x06, 0)
    owner = {}
    for i, (start, row) in enumerate(starts):
        end = starts[i + 1][0] - 1 if i + 1 < len(starts) else total
        start = max(1, start)
        end = min(end, total)
        name = resolver.typedef(row).get("name")
        for m in range(start, end + 1):
            owner[m] = name
    return owner


def _memberref_parent(tables, resolver, raw):
    c = DN._decode_coded("MemberRefParent", raw)
    if c is None:
        return None
    if c["kind"] in ("TypeDef", "TypeRef"):
        n = (resolver.typedef(c["row"]) if c["kind"] == "TypeDef"
             else resolver.typeref(c["row"]))
        return {"kind": c["kind"], "row": c["row"], "name": n.get("name")}
    if c["kind"] == "TypeSpec":
        return {"kind": "TypeSpec", "row": c["row"],
                "name": "spec@0x1B%06x" % c["row"]}
    return {"kind": c["kind"], "row": c["row"], "name": None}


# ── 构建 ────────────────────────────────────────────────────────────
def _bad(path, status, reason):
    return {"schema": SCHEMA, "path": str(path), "status": status,
            "reason": reason, "caliber": CALIBER, "caveats": list(CAVEATS),
            "cross_layer": CROSS_LAYER}


def build(path, limit=40):
    op = DN.open_tables(path)
    if op.get("status") != DN.STATUS_OK:
        return _bad(path, op.get("status"), op.get("reason"))
    tables, data = op["tables"], op["data"]
    resolver = TypeResolver(tables)
    ctx = Ctx(resolver)
    owners = _method_owners(tables, resolver)

    den = {name: _blank_den() for name, _tid in TABLES if name != "Field"}
    den["Field"] = _blank_field_den()
    items = {"methods": [], "memberrefs": [], "standalonesigs": [],
             "fields": []}
    stored = collections.Counter()
    list_of = {"MethodDef": "methods", "MemberRef": "memberrefs",
               "StandAloneSig": "standalonesigs", "Field": "fields"}
    keep_all = limit is None

    for name, tid in TABLES:
        d = den[name]
        d["rows"] = tables.row_counts.get(tid, 0)
        for row, r in tables.rows(tid):
            d["rows_read"] += 1
            idx = r["Signature"]
            if idx == 0:
                d["no_blob_index"] += 1
                continue
            d["has_blob_index"] += 1
            span = tables.blob_span(idx)
            name_value = (tables.string(r["Name"])["value"]
                          if "Name" in r else None)
            keep = keep_all or stored[list_of[name]] < limit
            base_item = {
                "row": row, "token": _token(tid, row), "name": name_value,
                "blob_index": idx, "blob_off": span["off"],
                "blob_len": span["len"],
            }
            if name == "MethodDef":
                base_item["owner"] = owners.get(row)
            if name == "MemberRef":
                base_item["parent"] = _memberref_parent(
                    tables, resolver, r["Class"])
            if span["missing"] is not None:
                d["blob_unreadable"] += 1
                key = _reason_key(span["missing"])
                _bump(d["unreadable_by_reason"], key)
                if keep:
                    base_item.update({"status": "unreadable", "reason": key,
                                      "detail": span["missing"],
                                      "blob_hex": None,
                                      "kind": None, "signature": None,
                                      "unknown": []})
                    items[list_of[name]].append(base_item)
                    stored[list_of[name]] += 1
                continue
            d["blob_readable"] += 1
            blob = data[span["off"]:span["end"]]
            out = analyze_blob(ctx, name, blob)
            if name == "Field":
                d["length_only"] += 1
                if out["kind"] != "field":
                    d["non_field_signature"] += 1
            else:
                if out["status"] == "decoded":
                    d["decoded"] += 1
                    d["method_decoded"] += 1
                    if ctx.unknowns:
                        d["decoded_with_unknown"] += 1
                    else:
                        d["decoded_clean"] += 1
                elif out["status"] == "length_only":
                    d["decoded"] += 1
                    if out["reason"] == "field_sig_length_only":
                        d["field_sig_length_only"] += 1
                    else:
                        d["local_sig_length_only"] += 1
                    if ctx.unknowns:
                        d["decoded_with_unknown"] += 1
                    else:
                        d["decoded_clean"] += 1
                else:
                    d["undecoded"] += 1
                    _bump(d["undecoded_by_reason"], out["reason"])
            if not keep:
                continue
            base_item.update({
                "blob_hex": blob.hex(), "status": out["status"],
                "reason": out["reason"], "detail": out["detail"],
                "kind": out["kind"], "signature": out["signature"],
                "unknown": list(ctx.unknowns) if out["status"] == "decoded"
                else [],
            })
            items[list_of[name]].append(base_item)
            stored[list_of[name]] += 1

    # 范围外表：只报有 blob 引用的行数
    out_of_scope = {}
    for tid, tname, cols in OUT_OF_SCOPE:
        entry = {"table": "0x%02x" % tid, "rows":
                 tables.row_counts.get(tid, 0), "blob_columns": cols,
                 "rows_with_blob": 0, "by_column": {c: 0 for c in cols}}
        if tid in tables.row_counts:
            for _row, r in tables.rows(tid):
                hit = False
                for c in cols:
                    if r.get(c):
                        entry["by_column"][c] += 1
                        hit = True
                if hit:
                    entry["rows_with_blob"] += 1
        out_of_scope[tname] = entry

    # 恒等式与比例
    identities = []
    for name in ("MethodDef", "MemberRef", "StandAloneSig"):
        d = den[name]
        d["identity_rows_ok"] = (
            d["rows_read"] == d["rows"]
            and d["rows"] == d["no_blob_index"] + d["has_blob_index"])
        d["identity_read_ok"] = (
            d["has_blob_index"] == d["blob_readable"]
            + d["blob_unreadable"])
        d["identity_decode_ok"] = (
            d["blob_readable"] == d["decoded"] + d["undecoded"])
        d["identity_unknown_ok"] = (
            d["decoded"] == d["decoded_clean"] + d["decoded_with_unknown"])
        identities.extend([d["identity_rows_ok"], d["identity_read_ok"],
                           d["identity_decode_ok"],
                           d["identity_unknown_ok"]])
        d["ratios"] = {
            "decoded_over_readable": (
                d["decoded"] / d["blob_readable"] if d["blob_readable"]
                else None),
            "undecoded_over_readable": (
                d["undecoded"] / d["blob_readable"] if d["blob_readable"]
                else None),
            "unknown_over_decoded": (
                d["decoded_with_unknown"] / d["decoded"] if d["decoded"]
                else None),
        }
    fd = den["Field"]
    fd["identity_rows_ok"] = (
        fd["rows_read"] == fd["rows"]
        and fd["rows"] == fd["no_blob_index"] + fd["has_blob_index"])
    fd["identity_read_ok"] = (
        fd["has_blob_index"] == fd["blob_readable"] + fd["blob_unreadable"])
    fd["identity_length_ok"] = fd["blob_readable"] == fd["length_only"]
    identities.extend([fd["identity_rows_ok"], fd["identity_read_ok"],
                       fd["identity_length_ok"]])
    identities.append(fd["non_field_signature"] == 0)

    method_sites = (den["MethodDef"]["method_decoded"]
                    + den["MemberRef"]["method_decoded"]
                    + den["StandAloneSig"]["method_decoded"])
    field_sites = (den["MemberRef"]["field_sig_length_only"]
                   + den["StandAloneSig"]["field_sig_length_only"])
    local_sites = den["StandAloneSig"]["local_sig_length_only"]
    decoded_all = sum(den[k]["decoded"] for k in
                      ("MethodDef", "MemberRef", "StandAloneSig"))
    undecoded_all = sum(den[k]["undecoded"] for k in
                        ("MethodDef", "MemberRef", "StandAloneSig"))
    readable_all = sum(den[k]["blob_readable"] for k in
                       ("MethodDef", "MemberRef", "StandAloneSig"))
    unknown_decoded = sum(den[k]["decoded_with_unknown"] for k in
                          ("MethodDef", "MemberRef", "StandAloneSig"))

    counts = {
        "method_signature_sites": method_sites,
        "method_signatures_decoded": method_sites,
        "field_signature_sites": field_sites,
        "local_signature_sites": local_sites,
        "call_sites_decoded": decoded_all,
        "call_sites_undecoded": undecoded_all,
        "readable_total": readable_all,
        "decoded_with_unknown": unknown_decoded,
        "unknown_nodes": sum(ctx.unknown_by_missing.values()),
        "unknown_by_missing": dict(ctx.unknown_by_missing),
        "anomalies": dict(ctx.anomalies),
        "items_stored": {k: len(v) for k, v in items.items()},
    }
    overall_identity = bool(all(identities))
    den["identity_ok"] = overall_identity
    den["ratios"] = {
        "decoded_over_readable": (decoded_all / readable_all
                                  if readable_all else None),
        "undecoded_over_readable": (undecoded_all / readable_all
                                    if readable_all else None),
        "unknown_over_decoded": (unknown_decoded / decoded_all
                                 if decoded_all else None),
    }

    return {
        "schema": SCHEMA, "path": str(path), "status": DN.STATUS_OK,
        "reason": None,
        "scope": {
            "limit": limit, "items_stored": {k: len(v)
                                             for k, v in items.items()},
            "note": "--limit 只影响逐行明细条数；所有分母统计全部行",
        },
        "call_sites": {
            "MethodDef": {"rows": den["MethodDef"]["rows"],
                          "decoded": den["MethodDef"]["method_decoded"],
                          "undecoded": den["MethodDef"]["undecoded"]},
            "MemberRef": {"rows": den["MemberRef"]["rows"],
                          "decoded": den["MemberRef"]["method_decoded"],
                          "undecoded": den["MemberRef"]["undecoded"]},
            "StandAloneSig": {"rows": den["StandAloneSig"]["rows"],
                              "decoded": den["StandAloneSig"]
                              ["method_decoded"],
                              "undecoded": den["StandAloneSig"]["undecoded"]},
        },
        "denominators": den,
        "out_of_scope_tables": out_of_scope,
        "methods": items["methods"],
        "memberrefs": items["memberrefs"],
        "standalonesigs": items["standalonesigs"],
        "fields": items["fields"],
        "counts": counts,
        "caliber": CALIBER, "caveats": list(CAVEATS),
        "cross_layer": CROSS_LAYER,
    }


# ── 渲染 / CLI ──────────────────────────────────────────────────────
def _pct(v):
    return "None" if v is None else "%.4f%%" % (v * 100.0)


def render(rep, out=sys.stdout):
    p = out.write
    p("file   : %s\n" % rep.get("path"))
    p("status : %s%s\n" % (rep.get("status"),
                           "" if not rep.get("reason")
                           else "  (%s)" % rep["reason"]))
    if rep.get("status") != DN.STATUS_OK:
        return
    for name in ("MethodDef", "MemberRef", "StandAloneSig", "Field"):
        d = rep["denominators"][name]
        p("[%s] rows=%d no_blob=%d has_blob=%d readable=%d unreadable=%d\n"
          % (name, d["rows"], d["no_blob_index"], d["has_blob_index"],
             d["blob_readable"], d["blob_unreadable"]))
        if name == "Field":
            p("  length_only=%d non_field_signature=%d ids=%s\n"
              % (d["length_only"], d["non_field_signature"],
                 d["identity_rows_ok"] and d["identity_read_ok"]
                 and d["identity_length_ok"]))
            continue
        p("  decoded=%d (clean=%d with_unknown=%d) undecoded=%d "
          "decoded_rate=%s\n"
          % (d["decoded"], d["decoded_clean"], d["decoded_with_unknown"],
             d["undecoded"], _pct(d["ratios"]["decoded_over_readable"])))
        if d["undecoded_by_reason"]:
            p("  undecoded_by_reason=%s\n" % d["undecoded_by_reason"])
        if d["unreadable_by_reason"]:
            p("  unreadable_by_reason=%s\n" % d["unreadable_by_reason"])
    c = rep["counts"]
    p("method_sites=%d field_sites=%d local_sites=%d unknown_nodes=%d\n"
      % (c["method_signature_sites"], c["field_signature_sites"],
         c["local_signature_sites"], c["unknown_nodes"]))
    p("overall decoded_rate=%s identity_ok=%s\n"
      % (_pct(rep["denominators"]["ratios"]["decoded_over_readable"]),
         rep["denominators"]["identity_ok"]))


def main(argv):
    ap = argparse.ArgumentParser(
        prog="rekit sigblob",
        description=".NET 签名语义层（MethodDef/MemberRef/StandAloneSig 的 #Blob）")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40,
                    help="存储逐行明细的条数（不影响分母）")
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
