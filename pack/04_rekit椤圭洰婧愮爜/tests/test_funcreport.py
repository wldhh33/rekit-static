#!/usr/bin/env python3
# tests/test_funcreport.py — M15 单函数报告层单测
#
# 覆盖：结构/状态合法性、来源层白名单、模块只读导入、缺失语义、同源渲染、
# 非 ok 状态、确定性、CLI、层失败不静默、注入对象只读。
import ast
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import callfacts as CF          # noqa: E402
from rekit import callgraph as CG          # noqa: E402
from rekit import expr                     # noqa: E402
from rekit import funcreport as FR         # noqa: E402
from rekit import recdesc                  # noqa: E402
from rekit import strxref as SX            # noqa: E402

MINIDLL = os.path.join(HERE, "fixtures", "minidll.dll")
FULL = os.path.join(HERE, "m15_fixtures", "funcreport_full")
GO = os.path.join(WORK, "samples", "m9", "elf_medium_synth_go_stripped")

_KEYS = {
    "identity": {"addr", "symbol", "insns", "blocks", "sources"},
    "boundary": {"boundary", "authority", "end", "sources", "end_by_source",
                 "conflicts"},
    "blocks_and_edges": {"blocks", "edges", "cfg_calls", "note"},
    "expressions": {"stats", "verdict", "abstains", "blocks", "stack_slots",
                    "text"},
    "calls": {"direct", "indirect", "counts", "note"},
    "strings_and_data": {"strings", "data_refs", "scope_note"},
    "parameters": {"own_declaration", "caller_bindings", "counts", "note"},
}


def _first_func(path):
    res = recdesc.descend(path)
    fs = expr.list_functions(res)
    assert fs, "样本没有已解出函数：%s" % path
    return fs[0]["addr"], res


def _walk_sources(obj):
    if isinstance(obj, dict):
        if "layer" in obj and "field" in obj:
            yield obj
        for v in obj.values():
            yield from _walk_sources(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_sources(v)


@pytest.fixture(scope="module")
def minidll():
    addr, _ = _first_func(MINIDLL)
    return FR.build(MINIDLL, addr)


def test_schema_sections_states(minidll):
    assert minidll["schema"] == FR.SCHEMA == 2
    assert set(minidll["sections"]) == set(FR.SECTION_ORDER)
    for name, s in minidll["sections"].items():
        assert s["evidence_state"] in FR.EVIDENCE_STATES, name
        assert s["scope"], "段 %s 缺 scope" % name
        if s["evidence_state"] != "present":
            assert s["reason"], "段 %s 非 present 却无 reason" % name
        missing = _KEYS[name] - set(s)
        assert not missing, "段 %s 缺键 %s" % (name, missing)
    # absence_summary 覆盖每个非 present 段
    rows = {(r["section"], r["field"]) for r in minidll["absence_summary"]}
    for name in FR.SECTION_ORDER:
        if minidll["sections"][name]["evidence_state"] != "present":
            assert (name, FR._SECTION_FIELD[name]) in rows, name


def test_sources_layer_whitelist(minidll):
    got = list(_walk_sources(minidll))
    assert got, "报告里没有任何来源标注"
    for src in got:
        assert src["layer"] in FR.ALLOWED_LAYERS, src


def test_module_imports_read_only():
    path = os.path.join(WORK, "rekit", "funcreport.py")
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1:
                mods.update(a.name for a in node.names)
            else:
                mods.add(node.module or "")
        elif isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
    allowed = {"argparse", "json", "sys", "recdesc", "expr", "callgraph",
               "callfacts", "strxref", "paramdecl", "datarefs", "dotnet"}
    assert mods <= allowed, "非白名单导入: %s" % (mods - allowed)
    assert "subprocess" not in src
    assert "import disasm" not in src
    assert "import coverage" not in src
    assert "import struct" not in src


def test_no_dwarf_is_missing_source(minidll):
    p = minidll["sections"]["parameters"]
    assert p["evidence_state"] == "missing_source"
    assert "不是 0 个参数" in p["reason"]
    rows = [r for r in minidll["absence_summary"]
            if r["section"] == "parameters"]
    assert rows and rows[0]["field"] == "own_declaration"


def test_same_source_render(minidll):
    rt = json.loads(json.dumps(minidll))
    assert rt == minidll
    assert FR.render(rt) == FR.render(minidll)
    text = FR.render(minidll)
    for name in FR.SECTION_ORDER:
        assert ("== %s ==" % name) in text
    assert "缺：" in text
    assert "确实没有：" in text
    # 本层不生成省略号代替数量/缺失
    for line in text.splitlines():
        if "显示 " in line:
            assert "…" not in line


def test_not_found_and_not_a_function_start():
    rep = FR.build(MINIDLL, 0xDEADBEEF)
    assert rep["status"] == "function_not_found"
    assert rep["sections"]["identity"]["reason"]
    res = recdesc.descend(FULL)
    origins = {f["addr"] for f in expr.list_functions(res)}
    inner = next(i["addr"] for i in res["instructions"]
                 if i.get("origin") in origins and i["addr"] not in origins)
    rep2 = FR.build(FULL, inner, res=res)
    assert rep2["status"] == "not_a_function_start"
    assert "内部指令" in rep2["sections"]["identity"]["reason"]


def test_deterministic():
    addr, _ = _first_func(MINIDLL)
    a = FR.build(MINIDLL, addr)
    b = FR.build(MINIDLL, addr)
    assert a == b


def test_cli(capsys):
    addr, _ = _first_func(MINIDLL)
    rc = FR.main([MINIDLL, "--func", hex(addr), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "ok"
    assert out["function"]["addr"] == addr
    rc2 = FR.main([MINIDLL, "--json"])
    assert rc2 == 0
    sel = json.loads(capsys.readouterr().out)
    assert sel["status"] == "function_not_specified"
    assert sel["sections"]["identity"]["candidates"]
    assert "请用 --func" in sel["sections"]["identity"]["note"]
    assert FR.main([MINIDLL, "--func", "zzz"]) == 2


def test_layer_failure_not_silent(monkeypatch):
    addr, _ = _first_func(MINIDLL)

    def boom(*a, **k):
        raise RuntimeError("boom-callgraph")

    monkeypatch.setattr(CG, "build", boom)
    rep = FR.build(MINIDLL, addr)
    assert rep["status"] == "ok"
    assert any(e["layer"] == "callgraph" for e in rep["layer_errors"])
    assert rep["sections"]["calls"]["evidence_state"] == "missing_source"
    assert "层调用失败" in rep["sections"]["calls"]["reason"]
    # 其余层仍产出
    assert rep["sections"]["identity"]["evidence_state"] == "present"
    assert rep["sections"]["expressions"]["evidence_state"] in \
        ("present", "abstained")
    assert "layer_errors" in FR.render(rep)


def test_injected_objects_not_mutated():
    addr, res = _first_func(MINIDLL)
    graph = CG.build(MINIDLL, res=res)
    facts = CF.build(MINIDLL, res=res, graph=graph)
    sxref = SX.build(MINIDLL, res=res, facts=facts, graph=graph)
    before = [json.dumps(x, sort_keys=True)
              for x in (res, graph, facts, sxref)]
    rep = FR.build(MINIDLL, addr, res=res, graph=graph, facts=facts,
                   sxref=sxref)
    after = [json.dumps(x, sort_keys=True)
             for x in (res, graph, facts, sxref)]
    assert before == after, "funcreport 写回了注入层对象"
    assert rep["status"] == "ok"
