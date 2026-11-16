#!/usr/bin/env python3
# tests/test_dotnet.py — M17 .NET 程序集结构层单测
#
# 覆盖：状态与恒等式、类型/方法分母、方法体定位（tiny/fat/EH）、IL 指令边界
# （switch/操作数尺寸/未知 opcode）、#US 字面量、泛型、跨层“不适用”显式、
# 缺失声明链（无 CLI 头 / BSJB 坏 / 元数据截断 / RVA 坏）、CLI、确定性、只读。
import json
import os
import shutil
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import dotnet as DN          # noqa: E402
from rekit import funcreport as FR      # noqa: E402
from rekit import pe                    # noqa: E402

SAMPLE = os.path.join(WORK, "samples", "m17", "_gen", "RekitSample.dll")
MINIPE = os.path.join(HERE, "minipe.exe")


@pytest.fixture(scope="module")
def sample():
    return DN.build(SAMPLE, detail_methods=None, detail_insns=None)


def _method(rep, name, owner_row=None):
    for m in rep["methods"]:
        if m["name"] == name and (owner_row is None
                                  or m["owner_row"] == owner_row):
            return m
    raise AssertionError("找不到方法 %s owner=%r" % (name, owner_row))


def _sections(path):
    r = pe.parse(path)
    return [{"index": h["index"], "name": h["name"], "vaddr": h["vaddr"],
             "vsize": h["vsize"], "rawptr": h["rawptr"],
             "rawsize": h["rawsize"], "chars": h["chars"]}
            for h in r["section_headers"]], r


def _tables(path):
    data = open(path, "rb").read()
    sections, r = _sections(path)
    cli_off, _ = DN._rva_to_off(r["dirs"][DN.CLI_DIR][0], sections, len(data))
    meta_rva = struct.unpack_from("<I", data, cli_off + 8)[0]
    meta_off, _ = DN._rva_to_off(meta_rva, sections, len(data))
    meta_size = struct.unpack_from("<I", data, cli_off + 12)[0]
    meta = DN._read_metadata_root(data, meta_off, meta_size, len(data))
    stream = DN._stream(meta, "#~") or DN._stream(meta, "#-")
    heaps = DN._heaps(data, meta)
    return DN.Tables(data, stream["file_off"], stream["size"], heaps), data, r


def _rewrite(tmp_path, name, mutate):
    dst = str(tmp_path / name)
    shutil.copyfile(SAMPLE, dst)
    with open(dst, "rb") as f:
        data = bytearray(f.read())
    mutate(data, dst)
    with open(dst, "wb") as f:
        f.write(data)
    return dst


# ── 结构与分母 ──────────────────────────────────────────────────────
def test_status_schema_identity(sample):
    assert sample["schema"] == DN.SCHEMA == 1
    assert sample["status"] == "ok"
    d = sample["denominators"]
    assert d["identity_ok"] is True
    assert d["methoddef_rows"] == (d["methods_with_rva"]
                                   + d["methods_without_rva"]) == 18
    assert d["methods_with_rva"] == 15
    assert d["without_rva_by_reason"] == {"abstract": 2, "pinvoke": 1,
                                          "runtime": 0, "native": 0,
                                          "unclassified": 0}
    assert d["rva_mapped"] == 15 and d["rva_unmapped"] == 0
    assert d["body_ok"] == 15
    assert d["tiny_bodies"] == 12 and d["fat_bodies"] == 3
    assert d["methods_with_eh"] == 1 and d["eh_clauses"] == 2
    assert d["il_decoded"] == 15 and d["il_undecodable"] == 0
    assert d["il_instructions"] == 119
    assert d["body_ratio"] == 15 / 18
    assert d["il_boundary_ratio"] == 1.0


def test_types_denominators(sample):
    d = sample["denominators"]
    assert d["types_typedef_rows"] == 6
    assert d["types_pseudo_module"] == 1
    assert d["types_named"] == 5
    assert d["types_nested"] == 0
    assert d["interface_impls"] == 1
    names = {(t["namespace"], t["name"]) for t in sample["types"]}
    assert ("Rekit.Sample", "MathUtil") in names
    assert ("Rekit.Sample", "Repository`1") in names
    mod = [t for t in sample["types"] if t["kind"] == "pseudo_module"]
    assert len(mod) == 1 and mod[0]["name"] == "<Module>"
    counts = {t["name"]: t["method_count"] for t in sample["types"]}
    assert counts == {"<Module>": 0, "MathUtil": 6, "Repository`1": 5,
                      "Shape": 3, "IWorker": 1, "Widget": 3}
    ext = {t["name"]: t["extends_text"] for t in sample["types"]}
    assert ext["Widget"] == "Rekit.Sample.Shape"
    assert ext["Repository`1"] == "System.Object"   # TypeRef 也要给出可读名


def test_no_body_reasons(sample):
    pin = _method(sample, "GetCurrentProcessId")
    assert pin["rva"] == 0 and pin["body_status"] == "no_body_rva_zero"
    assert pin["body_reason"] == "pinvoke"
    areas = [m for m in sample["methods"] if m["name"] == "Area"]
    assert sorted(m["body_reason"] or "ok" for m in areas) == ["abstract", "ok"]


# ── 方法体定位与 IL 边界 ────────────────────────────────────────────
def test_body_location_and_add_il(sample):
    m = _method(sample, "Add", owner_row=2)
    body = m["body"]
    assert m["rva"] == 0x2058
    assert body["kind"] == "tiny" and body["header_size"] == 1
    assert body["code_off"] == body["header_off"] + 1
    assert body["code_size"] == 16
    data = open(SAMPLE, "rb").read()
    code = data[body["code_off"]:body["code_off"] + body["code_size"]]
    assert code[-1] == 0x2A                     # ret
    got = [(i["offset"], i["size"], i["opcode"], i["operand_hex"])
           for i in m["il"]["instructions"]]
    assert got == [
        (0, 5, "ldsfld", "02000004"),
        (5, 1, "ldc.i4.1", ""),
        (6, 1, "add", ""),
        (7, 5, "stsfld", "02000004"),
        (12, 1, "ldarg.0", ""),
        (13, 1, "ldarg.1", ""),
        (14, 1, "add", ""),
        (15, 1, "ret", ""),
    ]
    assert m["il"]["tail_bytes"] == 0


def test_il_switch_and_r8_operand_sizes(sample):
    cls = _method(sample, "Classify")
    sw = [i for i in cls["il"]["instructions"] if i["opcode"] == "switch"]
    assert len(sw) == 1
    assert sw[0]["offset"] == 3 and sw[0]["size"] == 25
    assert sw[0]["operand_len"] == 24
    assert len(sw[0]["operand_hex"]) == 32       # 预览截断到 16 字节
    scale = _method(sample, "Scale")
    r8 = [i for i in scale["il"]["instructions"] if i["opcode"] == "ldc.r8"]
    assert [i["size"] for i in r8] == [9, 9]
    assert r8[0]["operand_hex"] == "0000000000000c40"    # 3.5
    # 每个方法：指令边界连续，最后一条恰好落在 code_size
    for m in sample["methods"]:
        if not m["body"]:
            continue
        ins = m["il"]["instructions"]
        pos = 0
        for i in ins:
            assert i["offset"] == pos
            pos += i["size"]
        assert pos == m["body"]["code_size"]
        assert m["il"]["tail_bytes"] == 0


def test_eh_clauses(sample):
    m = _method(sample, "Area", owner_row=6)
    body = m["body"]
    assert body["kind"] == "fat" and body["header_size"] == 12
    kinds = [c["kind"] for c in body["eh_clauses"]]
    assert kinds == ["catch", "finally"]
    for c in body["eh_clauses"]:
        assert 0 <= c["try_offset"] < body["code_size"]
        assert 0 <= c["handler_offset"] < body["code_size"]
    assert body["eh_clauses"][0]["class_token"] is not None
    assert body["eh_clauses"][1]["class_token"] is None


def test_us_strings(sample):
    us = sample["strings_us"]
    assert us["entries"] == 10 and us["reserved_empty"] == 1
    assert us["non_empty"] == 9
    assert "rekit-dotnet-sample" in us["previews"]
    assert "negative widget" in us["previews"]
    ldstr = sum(1 for m in sample["methods"]
                for i in m["il"]["instructions"] if i["opcode"] == "ldstr")
    assert ldstr == us["non_empty"]       # 本样本每个字面量各用一次


def test_generics(sample):
    g = sample["generics"]
    assert g["generic_param_rows"] == 1
    p = g["params"][0]
    assert p["name"] == "T" and p["number"] == 0
    assert p["owner"] == {"kind": "TypeDef", "tag": 0, "row": 3}
    assert g["type_specs"] == 2
    assert g["method_specs"] == 0
    assert g["constraints"] == 0


# ── 跨层关系 ────────────────────────────────────────────────────────
def test_cross_layer_is_explicit(sample):
    by = {c["layer"]: c for c in sample["cross_layer"]}
    for name in ("iat", "disasm", "recdesc", "callgraph", "callfacts",
                 "strxref", "datarefs", "coverage", "funcreport"):
        assert by[name]["status"] == "not_applicable"
        assert by[name]["reason"].strip()
    assert by["map"]["status"] == "partially_applicable"
    assert by["pe"]["status"] == "applicable"
    assert by["fingerprint"]["status"] == "applicable"


# ── 缺声明链（不按常见布局补）──────────────────────────────────────
def test_not_dotnet_native_pe():
    rep = DN.build(MINIPE)
    assert rep["status"] == DN.STATUS_NOT_DOTNET
    assert "CLI" in rep["reason"]
    assert DN.probe(MINIPE)["is_cli"] is False
    assert DN.probe(SAMPLE)["is_cli"] is True


def test_cli_dir_zeroed(tmp_path):
    _, r = _sections(SAMPLE)
    off = r["dirs_off"] + 4 + DN.CLI_DIR * 8

    def mut(data, _dst):
        data[off:off + 8] = b"\x00" * 8

    rep = DN.build(_rewrite(tmp_path, "nocli.dll", mut))
    assert rep["status"] == DN.STATUS_NOT_DOTNET


def test_bad_bsjb(tmp_path):
    tables, data, r = _tables(SAMPLE)
    sections, _ = _sections(SAMPLE)
    cli_off, _ = DN._rva_to_off(r["dirs"][DN.CLI_DIR][0], sections, len(data))
    meta_rva = struct.unpack_from("<I", data, cli_off + 8)[0]
    meta_off, _ = DN._rva_to_off(meta_rva, sections, len(data))

    def mut(d, _dst):
        d[meta_off:meta_off + 4] = b"\x00" * 4

    rep = DN.build(_rewrite(tmp_path, "badsig.dll", mut))
    assert rep["status"] == DN.STATUS_NO_META
    assert "BSJB" in rep["reason"]


def test_truncated_metadata(tmp_path):
    tables, data, r = _tables(SAMPLE)
    sections, _ = _sections(SAMPLE)
    cli_off, _ = DN._rva_to_off(r["dirs"][DN.CLI_DIR][0], sections, len(data))
    meta_rva = struct.unpack_from("<I", data, cli_off + 8)[0]
    meta_off, _ = DN._rva_to_off(meta_rva, sections, len(data))

    def mut(d, _dst):
        # 声明版本串长度 0x7FFFFFFF：越界即报缺，不按剩余字节猜
        struct.pack_into("<I", d, meta_off + 12, 0x7FFFFFFF)

    rep = DN.build(_rewrite(tmp_path, "trunc.dll", mut))
    assert rep["status"] == DN.STATUS_TRUNCATED
    assert "版本串" in rep["reason"]


def test_bad_method_rva(tmp_path):
    tables, data, _r = _tables(SAMPLE)
    row_off = tables.table_offsets[0x06] + tables.row_sizes[0x06] * 1

    def mut(d, _dst):
        struct.pack_into("<I", d, row_off, 0x7FFFFF00)

    rep = DN.build(_rewrite(tmp_path, "badvra.dll", mut))
    d = rep["denominators"]
    assert rep["status"] == "ok"
    assert d["methods_with_rva"] == 15
    assert d["rva_unmapped"] == 1 and d["rva_mapped"] == 14
    assert d["body_ok"] == 14
    assert d["identity_ok"] is True
    bad = _method(rep, "Add", owner_row=2)
    assert bad["body_status"] == "rva_unmapped"
    assert "section" in bad["body_reason"]


def test_unknown_opcode_is_reported(tmp_path):
    base = DN.build(SAMPLE)
    m = _method(base, "Add", owner_row=2)
    last = m["body"]["code_off"] + m["body"]["code_size"] - 1

    def mut(d, _dst):
        d[last] = 0xFF

    rep = DN.build(_rewrite(tmp_path, "badop.dll", mut))
    d = rep["denominators"]
    assert d["il_undecodable"] == 1
    assert d["il_decoded"] == 14
    assert d["identity_ok"] is True
    bad = _method(rep, "Add", owner_row=2)
    assert bad["il"]["instruction_count"] == 7
    assert bad["il"]["undecodable_at"] == {"offset": 15,
                                           "reason": "unknown_opcode",
                                           "byte": "ff"}


# ── funcreport / CLI / 只读 / 确定性 ────────────────────────────────
def test_funcreport_not_applicable():
    rep = FR.build(SAMPLE, 0x06000002)
    assert rep["status"] == "not_applicable"
    assert all(s["evidence_state"] != "present"
               for s in rep["sections"].values())
    reason = rep["sections"]["identity"]["reason"]
    assert "rekit dotnet" in reason
    sel = FR.build_selection(SAMPLE)
    assert sel["status"] == "not_applicable"
    assert "rekit dotnet" in sel["sections"]["identity"]["reason"]


def test_cli_json(capsys):
    rc = DN.main([SAMPLE, "--json", "--limit", "3", "--detail-methods", "1"])
    out = capsys.readouterr().out
    assert rc == 0
    rep = json.loads(out)
    assert rep["status"] == "ok"
    assert len(rep["methods"]) == 18
    stored = [m for m in rep["methods"] if m["il"]["stored"]]
    assert len(stored) == 1
    assert all(m["il"]["instruction_count"] > 0
               for m in rep["methods"] if m["body"])


def test_il_token_cli(capsys):
    rc = DN.main([SAMPLE, "--il-token", "0x06000002"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "IL_0000 +5 ldsfld" in out
    assert "IL_000f +1 ret" in out


def test_deterministic_and_readonly(sample):
    st = os.stat(SAMPLE)
    again = DN.build(SAMPLE, detail_methods=None, detail_insns=None)
    assert again["denominators"] == sample["denominators"]
    a = [(i["offset"], i["size"], i["opcode"])
         for i in _method(again, "Classify")["il"]["instructions"]]
    b = [(i["offset"], i["size"], i["opcode"])
         for i in _method(sample, "Classify")["il"]["instructions"]]
    assert a == b
    assert os.stat(SAMPLE).st_mtime == st.st_mtime
