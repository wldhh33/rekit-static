#!/usr/bin/env python3
# rekit.layout — M20 .NET 类型布局与字段 RVA
#
# 回答的问题（只回答元数据里写明的三样）：
#   1) FieldLayout.Offset：显式布局字段的偏移；
#   2) ClassLayout.PackingSize / ClassSize：类型声明的打包与总大小；
#   3) FieldRVA.RVA → 文件偏移 → 数据字节：静态字段的初始数据。
# 上游：M17 rekit.dotnet（CLI 头 / 元数据表 / 节表）、M19 rekit.sigblob
#       （字段签名里的元素类型，仅用于推导 FieldRVA 数据长度）。
#
# 口径（与 outputs/m20_layout/spec.md 一一对应）：
#   1) 静态可证 = 元数据里写明的值：FieldLayout.Offset、ClassLayout 的
#      PackingSize/ClassSize、FieldRVA 的 RVA 与其指向的数据字节。
#      sequential/auto 的字段偏移是运行期按布局规则推导的，本层**不计算**，
#      只在显式提供运行期 oracle 时单列为 runtime_derived（static_conclusion=False）。
#   2) 分母先行：三张表各给二分恒等式；未解码原因逐类计数；
#      “没有”（索引 0 / 表缺失）与“没读到”（越界/堆缺失/截断）分开。
#   3) FieldRVA 的数据长度不写在元数据里：取自字段签名的基元尺寸，或
#      valuetype 的 ClassLayout.ClassSize。两者都推不出 → unknown 并写明缺什么，
#      不按邻近字段/常见大小猜。
#   4) RVA 只用节表换算成文件偏移；越界/落在未初始化尾部/超出文件逐类记录。
#   5) 不读 CustomAttribute（StructLayout 特性不是本层输入）、不反编译、
#      不算实例字段的引用布局、不做 NativeAOT。
import argparse
import collections
import hashlib
import json
import sys

from . import dotnet as DN
from . import sigblob as SB

SCHEMA = 1

TABLES = (("FieldLayout", 0x10), ("ClassLayout", 0x0F), ("FieldRVA", 0x1D))

LAYOUT_MASK = 0x18
LAYOUT_NAMES = {0x00: "auto", 0x08: "sequential", 0x10: "explicit"}
FIELD_STATIC = 0x0010

# 元素类型 → 静态大小（只有这些能在不看运行期的情况下定长）
PRIM_SIZES = {
    "Boolean": 1, "Char": 2, "SByte": 1, "Byte": 1,
    "Int16": 2, "UInt16": 2, "Int32": 4, "UInt32": 4,
    "Int64": 8, "UInt64": 8, "Single": 4, "Double": 8,
}

CROSS_LAYER = [
    {"layer": "dotnet", "status": "upstream",
     "reason": "本层消费 M17 的 CLI 头 / 元数据表 / 节表；表行与列值由 M17 "
               "Tables 读出，本层不另写一份表解析"},
    {"layer": "sigblob", "status": "upstream",
     "reason": "FieldRVA 数据长度只看字段签名的元素类型：基元取固定尺寸，"
               "valuetype 取该 TypeDef 的 ClassLayout.ClassSize。M19 只做长度"
               "与边界，不解字段类型，故本层自建最小类型读取"},
    {"layer": "struct", "status": "not_applicable",
     "reason": "struct 层读 ELF/DWARF 的原生类型布局；.NET 布局在元数据表里，"
               "两者的字段模型与对齐规则不同，不互相代入"},
    {"layer": "datarefs", "status": "not_applicable",
     "reason": "对象声明来自 ELF/DWARF；FieldRVA 是元数据里的静态数据指针"},
    {"layer": "map", "status": "not_applicable",
     "reason": "map 层看 PE 节内映射；FieldRVA 的 RVA 只是换算输入，"
               "本层不产出节内代码/数据归属结论"},
    {"layer": "disasm", "status": "not_applicable",
     "reason": "数据字节不是 x86 指令"},
    {"layer": "ilflow", "status": "sibling",
     "reason": "M18 只消费方法体与 token；类型布局不改变 IL 结构与调用目标"},
    {"layer": "funcreport", "status": "not_applicable",
     "reason": "六层 x86 合成入口；对 .NET 返回 not_applicable"},
]

CALIBER = [
    "静态可证三样：FieldLayout.Offset、ClassLayout.PackingSize/ClassSize、"
    "FieldRVA 的 RVA→文件偏移→数据字节；逐行给出，不抽样。",
    "sequential/auto 的字段偏移不在本层计算：它们由运行期按布局规则推导，"
    "只在受控样本上用 Marshal.OffsetOf/SizeOf 单列为 runtime_derived，"
    "并标 static_conclusion=False。",
    "分母先行：FieldLayout rows = field_ref_ok + field_ref_missing；"
    "field_ref_ok = clean + with_unknown。ClassLayout 把 field_ref 换成 "
    "parent_ref。FieldRVA：rows = field_ref_ok + field_ref_missing；"
    "field_ref_ok = length_known + length_unknown；"
    "length_known = data_ok + rva_unmapped + data_truncated。",
    "「没有」与「没读到」分开：索引 0 行记 *_index_zero；表不存在记 "
    "table_absent；行数大于可读行记 rows_unread。",
    "FieldRVA 数据长度：字段签名基元取固定尺寸；valuetype 取 TypeDef 的 "
    "ClassLayout.ClassSize；TypeRef/无 ClassLayout/ClassSize=0/指针/引用类型"
    "一律 unknown 并写 missing 键，禁止按常见大小猜。",
    "RVA 换算只用节表（vaddr <= rva < vaddr+vsize 且 delta < rawsize）；"
    "失败按 rva_not_in_any_section / rva_in_uninitialized_tail / "
    "file_offset_out_of_range 分类，不假设节名。",
    "ClassLayout.PackingSize=0 / ClassSize=0 是「未指定」的声明值，照抄，"
    "不代换默认值；运行期 size 只在 oracle 段出现。",
    "布局标志取自 TypeDef.Flags & 0x18（auto/sequential/explicit）；"
    "FieldLayout 落在非 explicit 类型、offset 超 ClassSize、FieldRVA 落在"
    "非 static 字段，均记 anomaly，不删行也不改值。",
]

CAVEATS = [
    "本层只回答元数据写明的布局与 RVA：不做实例字段的引用布局、不读 "
    "StructLayout/FieldOffset 特性、不反编译、不做 NativeAOT。",
    "sequential/auto 偏移是运行期推导，不是本层结论；runtime_derived 段的"
    "数字来自受控样本的 CLR（Marshal.OffsetOf / Marshal.SizeOf(Type)），"
    "只用于显示边界，不参与静态分母。",
    "FieldRVA 的数据长度不是元数据字段：由字段类型推导，推不出即 unknown。"
    "unknown 表示「本层缺信息」，不是「该字段没有数据」。",
    "数据字节按文件中的原始顺序给出（小端存储），不做类型解释；"
    "数组语义（元素个数）本层不判断。",
    "真实程序集里 FieldRVA 常指向同一模块的 __StaticArrayInitTypeSize=N "
    "私有类型，可定长；若指向别的模块的类型则只能 unknown。",
    "受控样本只覆盖本机 ilasm/csc 能生成的布局子集（无 mixed-mode、"
    "无混淆器变形），不代表真实世界分布；真实样本同跑并单列 unknown。",
    "非 .NET 文件 / CLI 头缺失 / 表流不可解析时返回对应 status，不产生分母。",
]


def _tok(tid, row):
    return "0x%08x" % ((tid << 24) | row)


def _bump(c, k):
    c[k] = c.get(k, 0) + 1


def _bad(path, status, reason):
    return {"schema": SCHEMA, "path": str(path), "status": status,
            "reason": reason, "caliber": list(CALIBER),
            "caveats": list(CAVEATS), "cross_layer": CROSS_LAYER}


def _layout_of(flags):
    return LAYOUT_NAMES.get(flags & LAYOUT_MASK, "unknown:0x%02x"
                            % (flags & LAYOUT_MASK))


class LayoutCtx:
    """FieldRVA 长度推导的上下文：ClassLayout 索引 + 类型名解析。"""

    def __init__(self, tables, data):
        self.t = tables
        self.data = data
        self.resolver = SB.TypeResolver(tables)
        self.class_layout = {}
        self.class_layout_dup = collections.Counter()
        for row, r in tables.rows(0x0F):
            p = r["Parent"]
            if p in self.class_layout:
                self.class_layout_dup[p] += 1
            else:
                self.class_layout[p] = {"row": row,
                                        "packing_size": r["PackingSize"],
                                        "class_size": r["ClassSize"]}
        self.anomalies = collections.Counter()
        for p, n in self.class_layout_dup.items():
            _bump(self.anomalies, "duplicate_classlayout_parent:TD%d" % p)
        self._owners = self._field_owners()

    def _field_owners(self):
        starts = sorted((r["FieldList"], row) for row, r in self.t.rows(0x02))
        owners = {}
        total = self.t.row_counts.get(0x04, 0)
        for i, (start, row) in enumerate(starts):
            end = starts[i + 1][0] - 1 if i + 1 < len(starts) else total
            for f in range(max(1, start), end + 1):
                owners[f] = row
        return owners

    def field_owner(self, frow):
        return self._owners.get(frow)

    def typedef(self, row):
        return self.resolver.typedef(row) if row else None

    def field_name(self, frow):
        r = self.t.row(0x04, frow)
        if r is None:
            return None
        return self.t.string(r["Name"])["value"]

    def field_static(self, frow):
        r = self.t.row(0x04, frow)
        return None if r is None else bool(r["Flags"] & FIELD_STATIC)

    def field_type(self, frow):
        """返回 (node, missing)。node 是 sigblob.decode_type 的类型节点。"""
        r = self.t.row(0x04, frow)
        if r is None:
            return None, "field_row_out_of_range"
        span = self.t.blob_span(r["Signature"])
        if span["missing"] is not None:
            return None, "field_signature_unreadable:%s" % span["missing"]
        blob = self.data[span["off"]:span["end"]] if span["off"] is not None \
            else b""
        if not blob:
            return None, "field_signature_empty"
        if blob[0] & 0x3F != 0x06:
            return None, "field_signature_not_field:0x%02x" % blob[0]
        if len(blob) < 2:
            return None, "field_signature_truncated"
        ctx = SB.Ctx(self.resolver)
        node, _off = SB.decode_type(ctx, blob, 1, 0)
        return node, None

    def data_length(self, frow):
        """返回 (length, source, missing, type_label, type_row)。"""
        node, missing = self.field_type(frow)
        if missing is not None:
            return None, None, missing, None, None
        kind = node.get("kind")
        if kind == "primitive":
            name = node.get("name")
            if name in PRIM_SIZES:
                return PRIM_SIZES[name], "primitive:%s" % name, None, name, None
            return (None, None, "primitive_platform_size:%s" % name, name, None)
        if kind == "valuetype":
            label = node.get("name") or node.get("canonical")
            if node.get("reference") != "TypeDef" or node.get("row") is None:
                return None, None, "valuetype_not_typedef", label, None
            cl = self.class_layout.get(node["row"])
            if cl is None:
                return (None, None, ("valuetype_without_classlayout:TD%d"
                                     % node["row"]), label, node["row"])
            if cl["class_size"] <= 0:
                return (None, None, ("valuetype_class_size_zero:TD%d"
                                     % node["row"]), label, node["row"])
            return (cl["class_size"],
                    "valuetype_class_size:TD%d" % node["row"], None,
                    label, node["row"])
        if kind == "unknown":
            return (None, None, "field_type_unknown:%s" % node.get("missing"),
                    None, None)
        return None, None, "non_blittable_type:%s" % kind, kind, None


def build(path, limit=40, runtime=None):
    """runtime: {full_type_name: {"size": int|None, "fields": {...}}} 或 None。"""
    op = DN.open_tables(path)
    if op.get("status") != DN.STATUS_OK:
        return _bad(path, op.get("status"), op.get("reason"))
    tables, data = op["tables"], op["data"]
    file_len = len(data)
    sections = op["sections"]
    ctx = LayoutCtx(tables, data)
    keep_all = limit is None

    den = {
        "FieldLayout": {
            "rows": 0, "rows_read": 0,
            "field_ref_ok": 0, "field_ref_missing": 0,
            "missing_by_reason": {},
            "decoded": 0, "decoded_clean": 0, "decoded_with_unknown": 0,
            "unknown_by_reason": {},
        },
        "ClassLayout": {
            "rows": 0, "rows_read": 0,
            "parent_ref_ok": 0, "parent_ref_missing": 0,
            "missing_by_reason": {},
            "decoded": 0, "decoded_clean": 0, "decoded_with_unknown": 0,
            "unknown_by_reason": {},
        },
        "FieldRVA": {
            "rows": 0, "rows_read": 0,
            "field_ref_ok": 0, "field_ref_missing": 0,
            "missing_by_reason": {},
            "length_known": 0, "length_unknown": 0,
            "unknown_by_reason": {},
            "data_ok": 0, "rva_unmapped": 0, "data_truncated": 0,
            "undecoded_by_reason": {},
            "length_by_source": {},
        },
    }
    items = {"fieldlayouts": [], "classlayouts": [], "fieldrvas": []}
    stored = collections.Counter()
    stats = collections.Counter()
    static_offsets_by_owner = collections.defaultdict(dict)
    list_of = {"FieldLayout": "fieldlayouts", "ClassLayout": "classlayouts",
               "FieldRVA": "fieldrvas"}

    # ── FieldLayout ────────────────────────────────────────────────
    d = den["FieldLayout"]
    seen_fields = collections.Counter()
    d["rows"] = tables.row_counts.get(0x10, 0)
    for row, r in tables.rows(0x10):
        d["rows_read"] += 1
        frow = r["Field"]
        item = {"row": row, "token": _tok(0x10, row),
                "offset": r["Offset"], "field_row": frow,
                "field_token": _tok(0x04, frow) if frow else None,
                "field_name": None, "owner_row": None, "owner_token": None,
                "owner_type": None, "owner_layout": None,
                "status": "unknown", "unknown": []}
        keep = keep_all or stored["fieldlayouts"] < limit
        if frow == 0:
            d["field_ref_missing"] += 1
            _bump(d["missing_by_reason"], "field_index_zero")
            item["unknown"].append({"missing": "field_index_zero"})
            if keep:
                items["fieldlayouts"].append(item)
                stored["fieldlayouts"] += 1
            continue
        if tables.row(0x04, frow) is None:
            d["field_ref_missing"] += 1
            _bump(d["missing_by_reason"], "field_row_out_of_range")
            item["unknown"].append({"missing": "field_row_out_of_range"})
            if keep:
                items["fieldlayouts"].append(item)
                stored["fieldlayouts"] += 1
            continue
        d["field_ref_ok"] += 1
        seen_fields[frow] += 1
        if seen_fields[frow] > 1:
            _bump(ctx.anomalies, "duplicate_fieldlayout:Field%d" % frow)
        item["field_name"] = ctx.field_name(frow)
        owner = ctx.field_owner(frow)
        item["owner_row"] = owner
        item["owner_token"] = _tok(0x02, owner) if owner else None
        if owner is None:
            _bump(d["unknown_by_reason"], "owner_type_missing")
            item["unknown"].append({"missing": "owner_type_missing"})
        else:
            tr = tables.row(0x02, owner)
            name = ctx.typedef(owner)
            item["owner_type"] = name.get("name") if name else None
            if tr is None or "missing" in (name or {}):
                _bump(d["unknown_by_reason"], "owner_type_name_missing")
                item["unknown"].append(
                    {"missing": "owner_type_name_missing"})
            layout = _layout_of(tr["Flags"]) if tr is not None else None
            item["owner_layout"] = layout
            stats["owner_layout:%s" % layout] += 1
            static_offsets_by_owner[owner][item["field_name"]] = r["Offset"]
            if layout != "explicit":
                _bump(ctx.anomalies,
                      "fieldlayout_on_%s" % (layout or "unknown"))
            cl = ctx.class_layout.get(owner)
            if cl is not None and cl["class_size"] > 0 \
                    and r["Offset"] >= cl["class_size"]:
                _bump(ctx.anomalies, "offset_beyond_class_size")
        if item["unknown"]:
            d["decoded_with_unknown"] += 1
            item["status"] = "decoded_with_unknown"
        else:
            d["decoded_clean"] += 1
            item["status"] = "decoded"
        if keep:
            items["fieldlayouts"].append(item)
            stored["fieldlayouts"] += 1

    # ── ClassLayout ────────────────────────────────────────────────
    d = den["ClassLayout"]
    d["rows"] = tables.row_counts.get(0x0F, 0)
    for row, r in tables.rows(0x0F):
        d["rows_read"] += 1
        prow = r["Parent"]
        item = {"row": row, "token": _tok(0x0F, row),
                "packing_size": r["PackingSize"],
                "class_size": r["ClassSize"], "parent_row": prow,
                "parent_token": _tok(0x02, prow) if prow else None,
                "type": None, "layout": None,
                "class_size_source": ("declared" if r["ClassSize"] > 0
                                      else "unspecified_zero"),
                "status": "unknown", "unknown": []}
        keep = keep_all or stored["classlayouts"] < limit
        if prow == 0:
            d["parent_ref_missing"] += 1
            _bump(d["missing_by_reason"], "parent_index_zero")
            item["unknown"].append({"missing": "parent_index_zero"})
            if keep:
                items["classlayouts"].append(item)
                stored["classlayouts"] += 1
            continue
        tr = tables.row(0x02, prow)
        if tr is None:
            d["parent_ref_missing"] += 1
            _bump(d["missing_by_reason"], "parent_row_out_of_range")
            item["unknown"].append({"missing": "parent_row_out_of_range"})
            if keep:
                items["classlayouts"].append(item)
                stored["classlayouts"] += 1
            continue
        d["parent_ref_ok"] += 1
        name = ctx.typedef(prow)
        item["type"] = name.get("name") if name else None
        item["layout"] = _layout_of(tr["Flags"])
        stats["classlayout:%s" % item["layout"]] += 1
        if r["PackingSize"]:
            stats["classlayout_packing_nonzero"] += 1
        if r["ClassSize"]:
            stats["classlayout_size_nonzero"] += 1
        if item["type"] is None:
            _bump(d["unknown_by_reason"], "parent_type_name_missing")
            item["unknown"].append({"missing": "parent_type_name_missing"})
        if item["unknown"]:
            d["decoded_with_unknown"] += 1
            item["status"] = "decoded_with_unknown"
        else:
            d["decoded_clean"] += 1
            item["status"] = "decoded"
        if keep:
            items["classlayouts"].append(item)
            stored["classlayouts"] += 1

    # ── FieldRVA ───────────────────────────────────────────────────
    d = den["FieldRVA"]
    d["rows"] = tables.row_counts.get(0x1D, 0)
    for row, r in tables.rows(0x1D):
        d["rows_read"] += 1
        frow = r["Field"]
        rva = r["RVA"]
        item = {"row": row, "token": _tok(0x1D, row), "rva": rva,
                "field_row": frow,
                "field_token": _tok(0x04, frow) if frow else None,
                "field_name": None, "owner_type": None,
                "field_type": None, "field_type_row": None,
                "file_off": None, "length": None, "length_source": None,
                "data_hex": None, "data_sha256": None,
                "status": "undecoded", "reason": None, "detail": None,
                "unknown": []}
        keep = keep_all or stored["fieldrvas"] < limit
        if frow == 0:
            d["field_ref_missing"] += 1
            _bump(d["missing_by_reason"], "field_index_zero")
            item.update(status="undecoded", reason="field_index_zero",
                        detail="Field 索引为 0")
            if keep:
                items["fieldrvas"].append(item)
                stored["fieldrvas"] += 1
            continue
        if tables.row(0x04, frow) is None:
            d["field_ref_missing"] += 1
            _bump(d["missing_by_reason"], "field_row_out_of_range")
            item.update(status="undecoded", reason="field_row_out_of_range",
                        detail="Field 行号越界")
            if keep:
                items["fieldrvas"].append(item)
                stored["fieldrvas"] += 1
            continue
        d["field_ref_ok"] += 1
        item["field_name"] = ctx.field_name(frow)
        owner = ctx.field_owner(frow)
        if owner is not None:
            name = ctx.typedef(owner)
            item["owner_type"] = name.get("name") if name else None
        if ctx.field_static(frow) is False:
            _bump(ctx.anomalies, "fieldrva_on_non_static:Field%d" % frow)
        length, source, missing, type_label, type_row = ctx.data_length(frow)
        item["field_type"] = type_label
        item["field_type_row"] = type_row
        if missing is not None:
            d["length_unknown"] += 1
            _bump(d["unknown_by_reason"], missing.split(":", 1)[0])
            item.update(status="decoded_with_unknown",
                        reason="length_unknown", detail=missing,
                        unknown=[{"missing": missing}])
            if keep:
                items["fieldrvas"].append(item)
                stored["fieldrvas"] += 1
            continue
        d["length_known"] += 1
        _bump(d["length_by_source"], source.split(":", 1)[0])
        item["length"] = length
        item["length_source"] = source
        if rva == 0:
            d["rva_unmapped"] += 1
            _bump(d["undecoded_by_reason"], "rva_zero")
            item.update(status="undecoded", reason="rva_zero",
                        detail="RVA 为 0")
            if keep:
                items["fieldrvas"].append(item)
                stored["fieldrvas"] += 1
            continue
        off, why = DN._rva_to_off(rva, sections, file_len)
        if off is None:
            d["rva_unmapped"] += 1
            _bump(d["undecoded_by_reason"], why)
            item.update(status="undecoded", reason=why,
                        detail="RVA 0x%x 无法换算到文件" % rva)
            if keep:
                items["fieldrvas"].append(item)
                stored["fieldrvas"] += 1
            continue
        item["file_off"] = off
        if off + length > file_len:
            d["data_truncated"] += 1
            _bump(d["undecoded_by_reason"], "data_truncated")
            item.update(status="undecoded", reason="data_truncated",
                        detail="%d 字节数据越过文件末尾（文件 %d）"
                               % (length, file_len))
            if keep:
                items["fieldrvas"].append(item)
                stored["fieldrvas"] += 1
            continue
        blob = data[off:off + length]
        d["data_ok"] += 1
        stats["fieldrva_bytes_total"] += length
        item.update(status="decoded", reason=None, detail=None,
                    data_hex=blob.hex(),
                    data_sha256=hashlib.sha256(blob).hexdigest())
        if keep:
            items["fieldrvas"].append(item)
            stored["fieldrvas"] += 1

    # ── 恒等式 ─────────────────────────────────────────────────────
    identities = []
    fl = den["FieldLayout"]
    fl["decoded"] = fl["decoded_clean"] + fl["decoded_with_unknown"]
    fl["identity_rows_ok"] = (fl["rows_read"] == fl["rows"])
    fl["identity_ref_ok"] = (
        fl["rows_read"] == fl["field_ref_ok"] + fl["field_ref_missing"])
    fl["identity_unknown_ok"] = (
        fl["field_ref_ok"] == fl["decoded_clean"]
        + fl["decoded_with_unknown"])
    identities += [fl["identity_rows_ok"], fl["identity_ref_ok"],
                   fl["identity_unknown_ok"]]

    cl = den["ClassLayout"]
    cl["decoded"] = cl["decoded_clean"] + cl["decoded_with_unknown"]
    cl["identity_rows_ok"] = (cl["rows_read"] == cl["rows"])
    cl["identity_ref_ok"] = (
        cl["rows_read"] == cl["parent_ref_ok"] + cl["parent_ref_missing"])
    cl["identity_unknown_ok"] = (
        cl["parent_ref_ok"] == cl["decoded_clean"]
        + cl["decoded_with_unknown"])
    identities += [cl["identity_rows_ok"], cl["identity_ref_ok"],
                   cl["identity_unknown_ok"]]

    fr = den["FieldRVA"]
    fr["undecoded"] = (fr["rva_unmapped"] + fr["data_truncated"]
                       + fr["field_ref_missing"])
    fr["identity_rows_ok"] = (fr["rows_read"] == fr["rows"])
    fr["identity_ref_ok"] = (
        fr["rows_read"] == fr["field_ref_ok"] + fr["field_ref_missing"])
    fr["identity_length_ok"] = (
        fr["field_ref_ok"] == fr["length_known"] + fr["length_unknown"])
    fr["identity_data_ok"] = (
        fr["length_known"] == fr["data_ok"] + fr["rva_unmapped"]
        + fr["data_truncated"])
    identities += [fr["identity_rows_ok"], fr["identity_ref_ok"],
                   fr["identity_length_ok"], fr["identity_data_ok"]]

    for name in ("FieldLayout", "ClassLayout"):
        dd = den[name]
        dd["ratios"] = {
            "unknown_over_decoded": (
                dd["decoded_with_unknown"] / dd["decoded"]
                if dd["decoded"] else None),
        }
    fr["ratios"] = {
        "data_over_length_known": (
            fr["data_ok"] / fr["length_known"] if fr["length_known"] else None),
        "unknown_over_rows": (fr["length_unknown"] / fr["rows_read"]
                              if fr["rows_read"] else None),
    }
    identity_ok = bool(all(identities))
    den["identity_ok"] = identity_ok

    # ── 运行期推导段（只在调用方显式提供 oracle 时出现）────────────
    rt = {"available": False,
          "reason": "runtime_oracle_not_supplied",
          "source": "受控样本 CLR：Marshal.OffsetOf / Marshal.SizeOf(Type)",
          "static_conclusion": False,
          "boundary": ("sequential/auto 偏移由运行期按布局规则推导，"
                       "本段只作边界展示，不参与静态分母，"
                       "也不改写 FieldLayout/ClassLayout 的静态结论"),
          "types": []}
    if runtime:
        rt["available"] = True
        rt["reason"] = None
        runtime_by_type = runtime.get("types") or {}
        for row, r in tables.rows(0x02):
            name = ctx.typedef(row)
            full = name.get("name") if name else None
            if not full or full not in runtime_by_type:
                continue
            info = runtime_by_type[full]
            cl_row = ctx.class_layout.get(row)
            static_size = cl_row["class_size"] if cl_row else None
            entry = {
                "type": full, "typedef_row": row,
                "layout": _layout_of(r["Flags"]),
                "class_size_static": static_size,
                "size_runtime": info.get("size"),
                "size_match": (None if static_size in (None, 0)
                               or info.get("size") is None
                               else static_size == info.get("size")),
                "size_error": info.get("size_error"),
                "fields": [],
            }
            static_offsets = dict(static_offsets_by_owner.get(row) or {})
            for fname, rt_off in sorted((info.get("fields") or {}).items()):
                s_off = static_offsets.get(fname)
                entry["fields"].append({
                    "name": fname, "offset_runtime": rt_off,
                    "offset_static": s_off,
                    "match": (None if s_off is None or rt_off is None
                              else s_off == rt_off),
                })
            rt["types"].append(entry)

    counts = {
        "fieldlayout_rows": fl["rows"],
        "fieldlayout_offsets": fl["decoded"],
        "fieldlayout_explicit_owners": stats["owner_layout:explicit"],
        "fieldlayout_other_owners": (
            stats["owner_layout:auto"] + stats["owner_layout:sequential"]),
        "classlayout_rows": cl["rows"],
        "classlayout_explicit": stats["classlayout:explicit"],
        "classlayout_sequential": stats["classlayout:sequential"],
        "classlayout_auto": stats["classlayout:auto"],
        "classlayout_packing_nonzero": stats["classlayout_packing_nonzero"],
        "classlayout_size_nonzero": stats["classlayout_size_nonzero"],
        "fieldrva_rows": fr["rows"],
        "fieldrva_data_ok": fr["data_ok"],
        "fieldrva_bytes_total": stats["fieldrva_bytes_total"],
        "fieldrva_length_by_source": dict(fr["length_by_source"]),
        "unknown_by_reason": dict(fr["unknown_by_reason"]),
        "anomalies": dict(ctx.anomalies),
        "items_stored": {k: len(v) for k, v in items.items()},
        "runtime_derived_types": len(rt["types"]),
    }

    return {
        "schema": SCHEMA, "path": str(path), "status": DN.STATUS_OK,
        "reason": None,
        "scope": {"limit": limit,
                  "items_stored": counts["items_stored"],
                  "note": "--limit 只影响逐行明细条数；分母统计覆盖全部行"},
        "denominators": den,
        "counts": counts,
        "fieldlayouts": items["fieldlayouts"],
        "classlayouts": items["classlayouts"],
        "fieldrvas": items["fieldrvas"],
        "runtime_derived": rt,
        "static_conclusion": {
            "includes": ["FieldLayout.Offset",
                         "ClassLayout.PackingSize",
                         "ClassLayout.ClassSize",
                         "FieldRVA.RVA->file_off->data_bytes"],
            "excludes": ["sequential/auto 字段偏移",
                         "运行期 size（ClassSize=0 时）",
                         "实例字段的引用布局"],
        },
        "caliber": list(CALIBER), "caveats": list(CAVEATS),
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
    for name in ("FieldLayout", "ClassLayout", "FieldRVA"):
        d = rep["denominators"][name]
        p("[%s] rows=%d rows_read=%d\n" % (name, d["rows"], d["rows_read"]))
        if name == "FieldLayout":
            p("  field_ref_ok=%d missing=%d decoded=%d (clean=%d "
              "with_unknown=%d) %s\n"
              % (d["field_ref_ok"], d["field_ref_missing"], d["decoded"],
                 d["decoded_clean"], d["decoded_with_unknown"],
                 d["missing_by_reason"]))
        elif name == "ClassLayout":
            p("  parent_ref_ok=%d missing=%d decoded=%d (clean=%d "
              "with_unknown=%d) %s\n"
              % (d["parent_ref_ok"], d["parent_ref_missing"], d["decoded"],
                 d["decoded_clean"], d["decoded_with_unknown"],
                 d["missing_by_reason"]))
        else:
            p("  field_ref_ok=%d missing=%d length_known=%d unknown=%d "
              "data_ok=%d unmapped=%d truncated=%d\n"
              % (d["field_ref_ok"], d["field_ref_missing"],
                 d["length_known"], d["length_unknown"], d["data_ok"],
                 d["rva_unmapped"], d["data_truncated"]))
            if d["unknown_by_reason"]:
                p("  unknown_by_reason=%s\n" % d["unknown_by_reason"])
            if d["undecoded_by_reason"]:
                p("  undecoded_by_reason=%s\n" % d["undecoded_by_reason"])
            p("  data_rate=%s\n"
              % _pct(d["ratios"]["data_over_length_known"]))
    c = rep["counts"]
    p("offsets=%d class_sizes=%d (explicit=%d sequential=%d auto=%d) "
      "fieldrva_bytes=%d anomalies=%s\n"
      % (c["fieldlayout_offsets"], c["classlayout_rows"],
         c["classlayout_explicit"], c["classlayout_sequential"],
         c["classlayout_auto"], c["fieldrva_bytes_total"],
         c["anomalies"] or "{}"))
    rt = rep["runtime_derived"]
    p("runtime_derived: available=%s types=%d static_conclusion=False\n"
      % (rt["available"], len(rt["types"])))
    p("identity_ok=%s\n" % rep["denominators"]["identity_ok"])


def main(argv):
    ap = argparse.ArgumentParser(
        prog="rekit layout",
        description=".NET 类型布局与字段 RVA（FieldLayout/ClassLayout/FieldRVA）")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40,
                    help="存储逐行明细的条数（不影响分母）")
    ap.add_argument("--runtime", default="",
                    help="运行期 oracle JSON（{types:{全名:{size,fields}}}）；"
                         "只用于受控样本，结果标 runtime_derived")
    args = ap.parse_args(argv)
    runtime = None
    if args.runtime:
        with open(args.runtime, "r", encoding="utf-8") as f:
            runtime = json.load(f)
    rep = build(args.file, limit=max(0, args.limit), runtime=runtime)
    if args.json:
        json.dump(rep, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    else:
        render(rep)
    return 0 if rep.get("status") == DN.STATUS_OK else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
