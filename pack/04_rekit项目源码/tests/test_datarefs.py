#!/usr/bin/env python3
# tests/test_datarefs.py — M16 非字符串数据引用层单测
#
# 覆盖：分母恒等式、对象接受判据、拒收分类、引用形态、三档归因不合并、
# 指针槽分列、.bss 无文件字节、PE/ELF 差异（格式层拒收不进分母）、
# 无声明来源状态、确定性、只读、CLI、未解出指令不误当“没有引用”。
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import datarefs as DR          # noqa: E402
from rekit import expr                   # noqa: E402
from rekit import recdesc                # noqa: E402

FIX = os.path.join(HERE, "m16_fixtures", "datarefs_full.exe")
DYN = os.path.join(HERE, "fixtures", "dyn_static")
MINIDLL = os.path.join(HERE, "fixtures", "minidll.dll")

DENOM_KEYS = {"declared_candidates", "accepted", "rejected_total",
              "by_rejection", "duplicates", "identity_ok",
              "format_rejections", "format_rejections_note",
              "with_code_ref", "with_pointer_edge", "without_ref",
              "object_code_ref_ratio"}
OBJECT_KEYS = {"start", "end", "size", "name", "section", "tier",
               "file_backed", "content_hex", "content_note", "declaration",
               "sources"}
SITE_KEYS = {"addr", "bytes", "mnem", "function", "block", "form",
             "operand_index", "arith", "target", "tier"}


@pytest.fixture(scope="module")
def pe():
    return DR.build(FIX)


@pytest.fixture(scope="module")
def dyn():
    return DR.build(DYN)


def _walk_sources(obj):
    if isinstance(obj, dict):
        if "layer" in obj and "field" in obj:
            yield obj
        for v in obj.values():
            yield from _walk_sources(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_sources(v)


def _data_section_names(rep):
    return {s["name"] for s in rep["sections"]}


# ── 结构与分母 ──────────────────────────────────────────────────────
def test_schema_and_identity(pe):
    assert pe["schema"] == DR.SCHEMA == 1
    assert pe["status"] == "ok"
    d = pe["denominator"]
    assert DENOM_KEYS <= set(d)
    assert d["identity_ok"] is True
    assert d["declared_candidates"] == (d["accepted"] + d["rejected_total"]
                                        + d["duplicates"])
    assert 0 <= d["with_code_ref"] <= d["accepted"]
    assert 0 <= d["with_pointer_edge"] <= d["accepted"]
    assert 0 <= d["without_ref"] <= d["accepted"]
    # 比例只在 accepted>0 时出现，且分母是 accepted
    assert d["object_code_ref_ratio"] == d["with_code_ref"] / d["accepted"]


def test_forms_and_tiers_are_fixed_sets(pe):
    assert set(pe["forms"]) == set(DR.FORMS)
    assert set(pe["tiers"]) == set(DR.TIERS)
    assert sum(pe["forms"].values()) > 0


def test_caliber_written_down(pe):
    c = pe["caliber"]
    for key in ("object_definition", "min_size", "alignment", "sections",
                "after_window", "forms", "pointer_slots"):
        assert key in c, key
        assert c[key], key
    assert pe["caveats"]


# ── 对象定义（只认声明）────────────────────────────────────────────
def test_objects_only_from_declarations(pe):
    names = {o["name"] for o in pe["objects"]}
    assert {"g_counter", "g_table", "g_ptrs", "g_msg", "g_zero"} <= names
    secs = _data_section_names(pe)
    for o in pe["objects"]:
        assert OBJECT_KEYS <= set(o)
        assert o["size"] >= DR.MIN_SIZE
        assert o["section"] in secs
        assert o["start"] + o["size"] <= o["end"] + 1
        assert o["tier"] in ("declared_symbol", "declared_dwarf")
        assert o["sources"], "对象必须带声明来源"


def test_alignment_and_size_rules(pe):
    for o in pe["objects"]:
        assert o["start"] % (8 if o["size"] >= 8 else 4) == 0, o


def test_bss_object_has_no_file_bytes(pe):
    gz = next(o for o in pe["objects"] if o["name"] == "g_zero")
    assert gz["file_backed"] is False
    assert gz["content_hex"] is None
    assert "无文件字节" in gz["content_note"]
    # .data 对象有文件字节预览
    gc = next(o for o in pe["objects"] if o["name"] == "g_counter")
    assert gc["file_backed"] is True
    assert gc["content_hex"] == "07000000"


def test_dwarf_type_chain_size(pe):
    gm = next(o for o in pe["objects"] if o["name"] == "g_msg")
    assert gm["size"] == 11              # const char[11]
    assert "array_type" in gm["declaration"]


def test_rejections_counted_by_class(pe):
    d = pe["denominator"]
    assert set(d["by_rejection"]) <= set(DR.REJECT_CLASSES)
    assert d["rejected_total"] == sum(d["by_rejection"].values())
    # 2026-11-21 起样本由固定构建目录 + -fdebug-prefix-map 生成：单 CU、
    # 无 CRT 调试信息，声明候选全部可接受，故拒收为 0。拒收**分类**判据
    # 不依赖样本的偶然构成，由下面 test_static_addr_classification 直接覆盖。
    assert d["by_rejection"] == {}
    assert d["rejected_total"] == 0


def test_static_addr_classification():
    """位置形式判据：只有 DW_OP_addr 能当静态地址；其余分类逐类可查。"""
    ok = DR._static_addr({"location": {"kind": "expr",
                                       "expr": b"\x03" + (0x2010).to_bytes(8, "little")},
                          "addr_size": 8})
    assert ok[0] == 0x2010 and ok[1] == "DW_OP_addr"
    for kind in ("loclist", "implicit", "absent"):
        got = DR._static_addr({"location": {"kind": kind}, "addr_size": 8})
        assert got[0] is None and got[1] == "location_not_static", kind
    empty = DR._static_addr({"location": {"kind": "expr", "expr": b""},
                             "addr_size": 8})
    assert empty[1] == "location_unresolved"
    fbreg = DR._static_addr({"location": {"kind": "expr", "expr": b"\x91\x04"},
                             "addr_size": 8})
    assert fbreg[1] == "location_unresolved"


def test_format_rejections_not_in_denominator(pe):
    d = pe["denominator"]
    # PE COFF 符号没有尺寸字段：单列，不进对象分母
    assert d["format_rejections"]["coff_symbols"] > 0
    assert d["format_rejections"]["export_table"] == 0
    assert d["declared_candidates"] == 5
    assert "不进对象分母" in d["format_rejections_note"]


# ── 引用点与三档归因 ────────────────────────────────────────────────
def test_sites_have_form_and_arith(pe):
    assert pe["sites"]
    for s in pe["sites"]:
        assert SITE_KEYS <= set(s)
        assert s["form"] in DR.FORMS
        assert s["tier"] in DR.TIERS + (None,)
        assert s["arith"]


def test_three_tiers_not_merged(pe):
    seen = {t: [] for t in ("object_start", "inside_object", "after_object")}
    for s in pe["sites"]:
        if s["tier"] in seen:
            seen[s["tier"]].append(s)
    assert seen["object_start"], "样例应有精确命中"
    assert seen["inside_object"], "样例应有落在对象内部"
    assert seen["after_object"], "样例应有落在对象之后"
    for s in seen["object_start"]:
        assert s["offset"] is None
    for s in seen["inside_object"]:
        assert 0 < s["offset"] < s["object_size"]
    for s in seen["after_object"]:
        assert 0 <= s["offset"] < DR.AFTER_WINDOW


def test_seg_disp_has_no_target(pe):
    assert pe["forms"]["seg_disp"] >= 1
    seg = [s for s in pe["sites"] if s["form"] == "seg_disp"]
    assert seg
    for s in seg:
        assert s["target"] is None
        assert s["tier"] is None


def test_register_forms_have_no_static_target(pe):
    reg = [s for s in pe["sites"] if s["form"] in ("base_disp", "base_index")]
    assert reg
    for s in reg:
        assert s["target"] is None


def test_pointer_slots_separated(pe):
    edges = pe["pointer_edges"]
    inside = pe["pointer_values_inside"]
    assert any(e["from"] == 0x2020 and e["to"] == 0x2000 for e in edges)
    assert any(v["from"] == 0x2028 and v["to"] == 0x6024 for v in inside)
    assert all(e["to"] in {o["start"] for o in pe["objects"]} for e in edges)


def test_evidence_sources_layers(pe):
    got = list(_walk_sources(pe))
    assert got
    for src in got:
        assert src["layer"] == "datarefs", src


# ── ELF 真实样本 ────────────────────────────────────────────────────
def test_elf_sample_denominator(dyn):
    assert dyn["status"] == "ok"
    d = dyn["denominator"]
    assert d["accepted"] > 0
    assert d["identity_ok"] is True
    assert d["declared_candidates"] == (d["accepted"] + d["rejected_total"]
                                        + d["duplicates"])
    assert set(d["by_rejection"]) <= set(DR.REJECT_CLASSES)


def test_elf_objects_not_in_text(dyn):
    secs = _data_section_names(dyn)
    assert ".text" not in secs
    for o in dyn["objects"]:
        assert o["section"] in secs
        assert o["section"] != ".text"


# ── 缺失来源 ────────────────────────────────────────────────────────
def test_no_declaration_source_is_explicit():
    rep = DR.build(MINIDLL)
    assert rep["status"] == "no_declaration_source"
    assert "不是“没有数据引用”" in rep["reason"]
    assert rep["denominator"]["accepted"] == 0
    assert all(not s["can_declare_size"] or not s["present"]
               for s in rep["sources"].values())


# ── 确定性与只读 ────────────────────────────────────────────────────
def test_abbrev_cache_not_keyed_by_object_id():
    """abbrev 表缓存不得以对象地址（id）为键。

    修复前 key=(id(data), offset, len(data))：上一份节字节被回收后地址会被
    复用，两份等长（PE 节按文件对齐补齐到同一长度）的 .debug_abbrev 会命中
    同一 key，把别人的表当成这一份的 → 同一文件偶发解析失败。这里在 id 形状
    的键上放一条毒条目，正确实现必须无视它。
    """
    from rekit import paramdecl as PD
    data = bytes([0x01, 0x11, 0x00, 0x00, 0x00])   # code=1, tag, 无子, 终结
    poison_key = (id(data), 0, len(data))
    cache = PD._abbrev_table.__defaults__[0]
    cache[poison_key] = {"毒": "id 键条目"}
    try:
        table = PD._abbrev_table(data, 0)
        assert "毒" not in table
        assert 1 in table
    finally:
        cache.pop(poison_key, None)


def test_dwarf_present_but_unreadable_not_reported_as_no_source(monkeypatch):
    """DWARF 节存在但解析失败 ≠ 没有声明来源；后者是“结构性没有”，
    前者是“缺证据（可修）”，reason 必须分开。"""
    real = DR.PD.read

    def fake(path):
        if os.path.abspath(path) == os.path.abspath(MINIDLL):
            return {"audit": {"format": "PE", "classes": {"dwarf": {
                "present": True, "readable": False,
                "note": "DWARF 解析失败：abbrev truncated"}}},
                "dwarf": None}
        return real(path)

    monkeypatch.setattr(DR.PD, "read", fake)
    rep = DR.build(MINIDLL)
    assert rep["status"] == "no_declaration_source"
    assert "声明来源存在但不可用" in rep["reason"]
    assert "abbrev truncated" in rep["reason"]
    assert "没有任何能给出尺寸的声明来源" not in rep["reason"]


def test_deterministic():
    a = DR.build(FIX)
    b = DR.build(FIX)
    assert a == b


def test_injected_res_not_mutated():
    res = recdesc.descend(FIX)
    before = json.dumps(res, sort_keys=True)
    DR.build(FIX, res=res)
    assert json.dumps(res, sort_keys=True) == before


def test_unlifted_not_silently_zero(monkeypatch):
    real = expr.decode

    def boom(_ins):
        raise expr.LiftError("测试注入", "不是真实缺口")

    monkeypatch.setattr(expr, "decode", boom)
    rep = DR.build(FIX)
    assert rep["status"] == "ok"
    assert rep["unlifted"]
    assert all(u["reason"] == "测试注入" for u in rep["unlifted"])
    monkeypatch.setattr(expr, "decode", real)


# ── CLI / 渲染 ──────────────────────────────────────────────────────
def test_cli_and_render(capsys):
    rc = DR.main([FIX, "--json"])
    assert rc == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["schema"] == DR.SCHEMA
    text = DR.render(rep)
    assert "先报分母" in text
    assert "格式层拒收" in text
    assert "归因分档" in text
    assert "落在对象内部" in text
    assert DR.main([FIX]) == 0
    assert "== datarefs 分母（先报分母）==" in capsys.readouterr().out
    assert DR.main([os.path.join(HERE, "no_such_file.bin")]) == 2
