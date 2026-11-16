#!/usr/bin/env python3
# tests/test_ilflow.py — M18 .NET IL 控制流与调用关系层单测
#
# 覆盖：token 三态与原因、分支目标三分类（含字节级篡改复现）、基本块/边规则、
# EH 结构（不建边）、leave 语义、分母恒等式、非 .NET 透传、确定性/只读、CLI。
# 真实样本（mscorlib/System.Console）在 tests/verify_ilflow.py 里做独立来源比对。
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import dotnet as DN          # noqa: E402
from rekit import ilflow as IF         # noqa: E402

FLOW = os.path.join(WORK, "samples", "m18", "_gen", "FlowSample.dll")
FILTER = os.path.join(WORK, "samples", "m18", "_gen", "FilterSample.dll")
MINIPE = os.path.join(HERE, "minipe.exe")


@pytest.fixture(scope="module")
def flow():
    return IF.build(FLOW)


@pytest.fixture(scope="module")
def filt():
    return IF.build(FILTER)


def _find(rep, name, owner=None):
    for m in rep["methods"]:
        if m["name"] == name and (owner is None or m["owner_type"] == owner):
            return m
    raise AssertionError("找不到方法 %s owner=%r" % (name, owner))


def _rewrite(tmp_path, src, name, mutate):
    dst = str(tmp_path / name)
    shutil.copyfile(src, dst)
    with open(dst, "rb") as f:
        data = bytearray(f.read())
    mutate(data)
    with open(dst, "wb") as f:
        f.write(data)
    return dst


def _patch_u32(data, off, value):
    struct.pack_into("<I", data, off, value & 0xFFFFFFFF)


def _patch_i32(data, off, value):
    struct.pack_into("<i", data, off, value)


# ── 分母与恒等式 ────────────────────────────────────────────────────
def test_schema_and_identity(flow):
    assert flow["schema"] == IF.SCHEMA == 1
    assert flow["status"] == "ok"
    d = flow["denominators"]
    for key in ("identity_ok", "methods_identity_ok", "token_identity_ok",
                "target_identity_ok", "eh_identity_ok", "block_identity_ok",
                "edge_identity_ok"):
        assert d[key] is True, key
    assert d["method_errors"] == 0
    assert d["methods_total"] == 20
    assert d["methods_with_body"] == 19
    assert (d["methods_analyzed"], d["methods_partial"],
            d["methods_empty"]) == (19, 0, 0)
    assert d["methods_total"] == d["methods_with_body"] + 1
    assert flow["scope"]["methods_stored"] == 19


def test_denominator_first_ratios(flow):
    d = flow["denominators"]
    # 所有比例都在分母之后；分母非零时比例按分母复算
    assert d["ratios"]["internal_over_tokens"] == pytest.approx(
        d["tokens_internal"] / d["call_total"])
    assert d["ratios"]["external_over_tokens"] == pytest.approx(
        d["tokens_external"] / d["call_total"])
    assert d["ratios"]["targets_valid_over_total"] == pytest.approx(
        d["targets_valid"] / d["targets_total"])
    assert d["ratios"]["blocks_reachable_over_total"] == pytest.approx(
        (d["blocks_total"] - d["unreachable_blocks"]) / d["blocks_total"])


# ── token 解析：三态与原因 ─────────────────────────────────────────
def test_token_internal_methoddef(flow):
    s = _find(flow, "Caller")["call_sites"][0]
    assert (s["opcode"], s["token"], s["status"]) == ("call", "0x06000001",
                                                      "internal")
    assert s["token_table"] == "MethodDef"
    assert s["target"]["kind"] == "MethodDef"
    assert s["target"]["row"] == 1
    assert s["target"]["name"] == "Callee"
    assert s["target"]["owner_type"] == "Rekit.Flow.Ops"
    assert s["target"]["has_body"] is True
    assert s["external"] is None


def test_token_internal_via_typeref_and_base(flow):
    # 同模块接口 ICalc：MemberRef 父是 TypeRef(ResolutionScope=Module) → internal
    s = _find(flow, "Use")["call_sites"][0]
    assert s["opcode"] == "callvirt" and s["status"] == "internal"
    assert s["target"]["name"] == "Apply"
    # base.M 调用：MethodDef 直接命中
    s = _find(flow, "M", "Rekit.Flow.Derived")["call_sites"][0]
    assert s["status"] == "internal" and s["target"]["name"] == "M"
    assert s["target"]["owner_type"] == "Rekit.Flow.Base"


def test_token_external_memberref(flow):
    sites = _find(flow, "CallExternal")["call_sites"]
    by_tok = {s["token"]: s for s in sites}
    add = by_tok["0x0a000005"]
    assert add["status"] == "external"
    assert add["external"]["type"] == "System.Collections.Generic.List`1"
    assert add["external"]["member"] == "Add"
    assert add["external"]["assembly"] == "mscorlib"
    assert add["external"]["version"] == "4.0.0.0"
    assert add["external"]["parent_kind"] == "TypeSpec"
    assert add["target"] is None
    ctor = by_tok["0x0a000004"]
    assert ctor["status"] == "external" and ctor["opcode"] == "newobj"
    assert ctor["external"]["type"] == "System.Collections.Generic.List`1"


def test_token_methodspec(flow):
    s = _find(flow, "ForwardInt")["call_sites"][0]
    assert s["token"] == "0x2b000001"
    assert s["status"] == "internal"
    assert s["target"]["name"] == "Forward"
    assert s["generic"]["method_spec_row"] == 1
    assert s["generic"]["generic_arg_count"] == 1
    assert s["generic"]["underlying_status"] == "internal"
    # 计数：MethodSpec 计入 token_by_table，且解析后仍算 internal
    d = flow["denominators"]
    assert d["token_by_table"] == {"MemberRef": 10, "MethodDef": 6,
                                   "MethodSpec": 1}


def test_token_counts_flow(flow):
    d = flow["denominators"]
    assert d["call_total"] == 17
    assert d["call_by_opcode"] == {"call": 9, "callvirt": 4, "ldftn": 1,
                                   "newobj": 3}
    assert (d["tokens_internal"], d["tokens_external"],
            d["tokens_unresolved"]) == (8, 9, 0)
    assert d["tokens_internal"] + d["tokens_external"] + \
        d["tokens_unresolved"] == d["call_total"]


def test_token_unresolved_reason_calli(filt):
    d = filt["denominators"]
    assert d["call_total"] == 2
    assert (d["tokens_internal"], d["tokens_external"],
            d["tokens_unresolved"]) == (1, 0, 1)
    assert d["unresolved_by_reason"] == {"token_kind_mismatch": 1}
    assert d["token_by_table"] == {"MethodDef": 1, "StandAloneSig": 1}
    s = [s for s in _find(filt, "Calli")["call_sites"]
         if s["opcode"] == "calli"][0]
    assert s["status"] == "unresolved"
    assert s["reason"] == "token_kind_mismatch"
    assert "StandAloneSig" in s["detail"]
    assert s["target"] is None and s["external"] is None


# ── 分支目标 ────────────────────────────────────────────────────────
def test_branch_forms_and_targets(flow):
    d = flow["denominators"]
    assert d["branch_total"] == 6
    assert d["branch_by_form"] == {"long": 1, "short": 3, "leave_short": 2}
    assert d["targets_total"] == 6
    assert d["target_checks"]["instruction"] == 6
    assert d["target_checks"]["inside_instruction"] == 0
    assert d["target_checks"]["outside_method"] == 0
    loop = _find(flow, "Loop")
    got = [(s["offset"], s["opcode"], s["form"], s["next"],
            [t["value"] for t in s["targets"]])
           for s in loop["branch_sites"]]
    assert got == [(4, "br.s", "short", 6, [19]),
                   (21, "blt.s", "short", 23, [6])]
    lb = _find(flow, "LongBranch")
    assert lb["branch_sites"][0]["form"] == "long"
    assert lb["branch_sites"][0]["targets"][0]["value"] == 326


def test_branch_forms_filter(filt):
    d = filt["denominators"]
    assert d["branch_by_form"] == {"leave_short": 4, "short": 1}
    assert d["target_checks"]["instruction"] == 5
    assert d["target_checks"]["inside_instruction"] == 0
    assert d["target_checks"]["outside_method"] == 0
    assert d["switch_count"] == 0


# ── 基本块 / 边 ────────────────────────────────────────────────────
def test_block_partition_invariants(flow, filt):
    for rep in (flow, filt):
        for m in rep["methods"]:
            bs = m["blocks"]
            assert bs and bs[0]["start"] == 0
            assert bs[-1]["end"] == m["code_size"]
            assert sum(b["insn_count"] for b in bs) == m["instruction_count"]
            for a, b in zip(bs, bs[1:]):
                assert a["end"] == b["start"]
            starts = {b["start"] for b in bs}
            for e in m["edges"]:
                assert e["from"] in starts and e["to"] in starts
            for b in bs:
                assert b["insns"] == sorted(b["insns"])
                assert b["insns"][0] == b["start"]
                assert b["end"] - b["start"] >= len(b["insns"])
            # 每个分支目标若是 instruction，必须是某块起点
            for site in m["branch_sites"]:
                for t in site["targets"]:
                    if t["check"] == "instruction":
                        assert t["value"] in starts


def test_block_leaders_and_edges(flow):
    loop = _find(flow, "Loop")
    assert [(b["start"], b["end"], b["entry"]) for b in loop["blocks"]] == [
        (0, 6, "method"), (6, 19, "branch"), (19, 23, "branch"),
        (23, 25, "fallthrough")]
    kinds = sorted(e["kind"] for e in loop["edges"])
    assert kinds == ["branch", "branch", "fallthrough", "fallthrough"]
    # 无条件 br.s 只有 taken 边，不得有 fallthrough（M18 修复的回归守卫）
    assert [e for e in loop["edges"] if e["from"] == 0] == [
        {"from": 0, "to": 19, "kind": "branch", "case": None}]
    d = flow["denominators"]
    assert d["blocks_total"] == 30
    assert d["edges_total"] == 11
    assert d["edges_by_kind"] == {"branch": 4, "fallthrough": 5, "leave": 2}


def test_unreachable_are_eh_entries(flow, filt):
    d = flow["denominators"]
    assert d["unreachable_blocks"] == 3
    g = _find(flow, "Guarded")
    handlers = [b for b in g["blocks"] if b["entry"] == "eh_handler"]
    assert len(handlers) == 3
    assert all(b["reachable_from_entry"] is False for b in handlers)
    assert filt["denominators"]["unreachable_blocks"] == 6


# ── EH 结构 ─────────────────────────────────────────────────────────
def test_eh_structure_flow(flow):
    g = _find(flow, "Guarded")
    assert [c["kind"] for c in g["eh"]] == ["catch", "catch", "finally"]
    assert [c["nesting_depth"] for c in g["eh"]] == [1, 1, 0]
    assert all(c["boundary_ok"] and c["range_ok"] for c in g["eh"])
    assert g["eh"][0]["catch"]["status"] == "external"
    assert g["eh"][0]["catch"]["type"]["name"] == \
        "System.InvalidOperationException"
    assert g["eh"][1]["catch"]["type"]["name"] == "System.Exception"
    assert g["eh"][2]["catch"] is None
    d = flow["denominators"]
    assert d["eh_clauses"] == 3
    assert d["eh_by_kind"] == {"catch": 2, "finally": 1}
    assert d["catch_tokens_by_status"] == {"external": 2}
    assert d["eh_bad_boundary"] == 0 and d["eh_bad_range"] == 0


def test_eh_structure_filter_fault(filt):
    d = filt["denominators"]
    assert d["eh_clauses"] == 2
    assert d["eh_by_kind"] == {"fault": 1, "filter": 1}
    m = _find(filt, "Filter")
    kinds = {c["kind"]: c for c in m["eh"]}
    assert "filter" in kinds
    fc = kinds["filter"]
    assert fc["filter"] is not None
    assert fc["filter"][0] < fc["handler"][0]
    assert fc["catch"] is None
    # EH 只建模结构：handler 入口没有静态边，块保留但不可达
    entries = {b["start"] for b in m["blocks"]}
    assert fc["handler"][0] in entries


def test_region_hits_unit():
    clauses = [{"id": 0, "kind": "finally", "try": [0, 10],
                "handler": [10, 20], "filter": None}]
    assert IF._region_hits(5, clauses) == [(0, "try")]
    assert IF._region_hits(10, clauses) == [(0, "handler")]
    assert IF._region_hits(19, clauses) == [(0, "handler")]
    assert IF._region_hits(20, clauses) == []


def test_leave_semantics(flow, filt):
    for rep in (flow, filt):
        d = rep["denominators"]
        assert d["leave_into_region"] == 0
        assert d["leave_exits_finally"] == 0
        assert d["leave_in_filter"] == 0
    # Filter 的 leave 都跳到方法尾；不允许跳进 filter/handler
    for s in _find(filt, "Filter")["branch_sites"]:
        if s["opcode"].startswith("leave"):
            t = s["targets"][0]
            assert t["check"] == "instruction"
            assert t["enters_regions"] == []
    # 每个 leave 边都指向真实块起点
    for rep in (flow, filt):
        for m in rep["methods"]:
            starts = {b["start"] for b in m["blocks"]}
            for e in m["edges"]:
                if e["kind"] == "leave":
                    assert e["to"] in starts


# ── 字节级篡改：三类目标落点 / token 原因 ──────────────────────────
def test_mutation_branch_inside(tmp_path):
    m = _find(IF.build(FLOW), "LongBranch")
    code_off = m["code_off"]
    # brfalse 在 offset 1（1 字节 opcode），4 字节操作数从 offset 2 起：6+319=325
    dst = _rewrite(tmp_path, FLOW, "inside.dll",
                   lambda d: _patch_i32(d, code_off + 2, 319))
    rep = IF.build(dst)
    sites = _find(rep, "LongBranch")["branch_sites"]
    t = sites[0]["targets"][0]
    assert t["value"] == 325
    assert t["check"] == "inside_instruction"
    assert t["containing_offset"] == 324
    d = rep["denominators"]
    assert d["target_checks"]["inside_instruction"] == 1
    assert d["target_checks"]["instruction"] == 5
    assert d["target_identity_ok"] is True


def test_mutation_branch_outside(tmp_path):
    m = _find(IF.build(FLOW), "LongBranch")
    dst = _rewrite(tmp_path, FLOW, "outside.dll",
                   lambda d: _patch_i32(d, m["code_off"] + 2, 322))  # 328
    rep = IF.build(dst)
    t = _find(rep, "LongBranch")["branch_sites"][0]["targets"][0]
    assert t["value"] == 328 and t["check"] == "outside_method"
    d = rep["denominators"]
    assert d["target_checks"]["outside_method"] == 1
    assert d["target_checks"]["instruction"] == 5


def test_mutation_token_row_out_of_range(tmp_path):
    m = _find(IF.build(FLOW), "CallExternal")
    dst = _rewrite(tmp_path, FLOW, "tok_row.dll",
                   lambda d: _patch_u32(d, m["code_off"] + 0 + 1, 0x0AFFFFFF))
    rep = IF.build(dst)
    site = _find(rep, "CallExternal")["call_sites"][0]
    assert site["status"] == "unresolved"
    assert site["reason"] == "row_out_of_range"
    d = rep["denominators"]
    assert d["unresolved_by_reason"] == {"row_out_of_range": 1}
    assert d["token_identity_ok"] is True
    assert d["call_total"] == 17


def test_mutation_token_kind_mismatch(tmp_path):
    m = _find(IF.build(FLOW), "CallExternal")
    dst = _rewrite(tmp_path, FLOW, "tok_kind.dll",
                   lambda d: _patch_u32(d, m["code_off"] + 0 + 1, 0x70000001))
    rep = IF.build(dst)
    site = _find(rep, "CallExternal")["call_sites"][0]
    assert site["status"] == "unresolved"
    assert site["reason"] == "token_kind_mismatch"
    assert rep["denominators"]["unresolved_by_reason"] == {
        "token_kind_mismatch": 1}


# ── 边界与 CLI ──────────────────────────────────────────────────────
def test_not_dotnet_passthrough():
    rep = IF.build(MINIPE)
    assert rep["status"] == DN.STATUS_NOT_DOTNET
    assert rep["reason"] and "CLI" in rep["reason"]
    assert "denominators" not in rep
    assert rep["schema"] == IF.SCHEMA


def test_determinism_and_readonly():
    before = hashlib.sha256(open(FLOW, "rb").read()).hexdigest()
    a = IF.build(FLOW, limit=40)
    b = IF.build(FLOW, limit=40)
    assert json.dumps(a, sort_keys=True, ensure_ascii=False) == \
        json.dumps(b, sort_keys=True, ensure_ascii=False)
    after = hashlib.sha256(open(FLOW, "rb").read()).hexdigest()
    assert before == after


def test_limit_only_affects_detail():
    full = IF.build(FLOW, limit=40)
    small = IF.build(FLOW, limit=1)
    assert len(small["methods"]) == 1
    assert small["denominators"]["call_total"] == \
        full["denominators"]["call_total"]
    assert small["denominators"]["blocks_total"] == \
        full["denominators"]["blocks_total"]


def test_cli_json_and_exit_codes():
    env = dict(os.environ)
    env["PYTHONPATH"] = WORK
    out = subprocess.run(
        [sys.executable, "-m", "rekit", "ilflow", FLOW, "--json",
         "--limit", "3"], cwd=WORK, env=env, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    rep = json.loads(out.stdout)
    assert rep["schema"] == 1 and rep["status"] == "ok"
    assert len(rep["methods"]) == 3
    bad = subprocess.run(
        [sys.executable, "-m", "rekit", "ilflow", MINIPE], cwd=WORK, env=env,
        capture_output=True, text=True)
    assert bad.returncode == 2
    assert "not_dotnet" in bad.stdout


def test_cross_layer_and_caveats(flow):
    by = {c["layer"]: c for c in flow["cross_layer"]}
    assert by["dotnet"]["status"] == "upstream"
    assert by["disasm"]["status"] == "not_applicable"
    assert by["callgraph"]["status"] == "not_applicable"
    assert by["map"]["status"] == "applicable"
    assert flow["caveats"] and all(isinstance(x, str) for x in flow["caveats"])
