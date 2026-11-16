# tests/test_struct.py — M5-U3：控制流结构化输出
#
# 断言分四层（对应验收口径）：
#   1) 默认关闭：不带 --structured 时 CLI/JSON 里没有结构段，既有输出不变；
#   2) 可回溯：每个可达块在结构化输出里出现且仅出现一次，节点引用的块/边
#      必须真实存在于 recdesc 的 CFG 里（check_traceable → violations==0）；
#   3) 分级：if/loop 照实识别；switch 只在候选证据为 high 时渲染，
#      证据不足必须降级成 goto 并写明原因；
#   4) 不可结构化的形态（不可约循环、条件不可判、goto 密集）单独统计、
#      如实标注，不允许为了好看强行套 if/loop。
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import expr, recdesc, struct as S, switchcand  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
DYN = os.path.join(HERE, "fixtures", "dyn_static")
BINLS = os.path.join(HERE, "fixtures", "bin_ls.elf")

_cache = {}


def _res(path):
    key = ("res", path)
    if key not in _cache:
        _cache[key] = recdesc.descend(path)
    return _cache[key]


def _cand(path, func):
    key = ("cand", path, func)
    if key not in _cache:
        _cache[key] = switchcand.analyze_function(_res(path), func)
    return _cache[key]


# ── 1. 默认关闭 ──────────────────────────────────────────────────────
def test_cli_default_has_no_struct_section(capsys):
    """不加 --structured 时既有输出不得出现任何结构段（默认关闭）。"""
    assert expr.main([CLI]) == 0
    out = capsys.readouterr().out
    assert "控制流结构化" not in out
    assert "// STRUCT" not in out


def test_cli_default_json_has_no_structured_key(capsys):
    assert expr.main([CLI, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "structured" not in out


def test_cli_structured_adds_section(capsys):
    assert expr.main([DYN, "--func", "0x401870", "--structured"]) == 0
    out = capsys.readouterr().out
    assert "// STRUCT 0x401870" in out
    assert "blocks=23 reachable=23 emitted=23" in out
    assert "可回溯违规 0 项" in out


def test_cli_structured_json_key(capsys):
    assert expr.main([DYN, "--func", "0x401870", "--structured", "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert "structured" in r
    assert r["structured"]["stats"]["blocks_emitted"] == 23


# ── 2. 可回溯 ────────────────────────────────────────────────────────
def _walk(n, acc):
    if isinstance(n, dict):
        acc.append(n)
        for k in ("children", "then", "else", "body", "inner"):
            _walk(n.get(k), acc)
    elif isinstance(n, list):
        for x in n:
            _walk(x, acc)


def test_every_function_has_zero_violations():
    """全样本逐函数：块引用/边引用/完备性都必须是 0 违规。"""
    for path in (CLI, BINLS):
        rep = S.structure_binary(_res(path), None, False)
        assert rep["stats"]["violations"] == 0, path
        for f in rep["functions"]:
            assert f["violations"] == 0, (path, hex(f["function"]))


def test_blocks_appear_exactly_once():
    """渲染文本里每个 L_0x 只出现一次（块不重复输出）。"""
    r = S.structure_function(_res(DYN), 0x401870, _cand(DYN, 0x401870))
    text = S.render_function(r)
    labels = [ln.strip().split(":")[0] for ln in text.splitlines()
              if ln.strip().startswith("L_0x") and ":" in ln]
    assert labels, "结构文本里没有块标签"
    assert len(labels) == len(set(labels)), "有块被重复输出"
    assert len(labels) == r["stats"]["blocks_reachable"]


def test_nodes_reference_real_blocks_and_edges():
    """每个节点带的 block/edges 必须真实存在于 recdesc 的 CFG。"""
    g = S._cfg(_res(DYN), 0x401870)
    r = S.structure_function(_res(DYN), 0x401870, _cand(DYN, 0x401870))
    nodes = []
    _walk(r["tree"], nodes)
    for n in nodes:
        if n.get("kind") in ("if", "while", "do_while", "for", "switch",
                             "break", "continue"):
            assert n.get("block") in g["blocks"] or n.get("header") in g["blocks"]
        for e in n.get("edges") or []:
            assert e["from"] in g["blocks"]
            if e["to"] is not None:
                assert e["to"] in g["blocks"]
                assert e["to"] in g["succ"][e["from"]], "边不在 CFG 里"


def test_emitted_equals_reachable():
    for path in (CLI, BINLS):
        rep = S.structure_binary(_res(path), None, False)
        for f in rep["functions"]:
            if not f["blocks"]:
                continue
            r = S.structure_function(_res(path), f["function"])
            st = r["stats"]
            assert st["blocks_emitted"] == st["blocks_reachable"], \
                (path, hex(f["function"]), st["blocks_emitted"], st["blocks_reachable"])


# ── 3. if / loop / switch 分级 ────────────────────────────────────────
def test_cli_while_loop_recognized():
    r = S.structure_function(_res(CLI), 0x1E5C)
    assert r["stats"]["while"] == 1
    text = S.render_function(r)
    assert "while (" in text
    assert "循环出口" in text or "break" in text


def test_self_loop_header_kept_inside_body():
    """自环（header 同时是 latch）不能让 body 落到循环外。"""
    r = S.structure_function(_res(DYN), 0x401480)   # btree_release_tree_recursively
    lines = [ln.strip() for ln in S.render_function(r).splitlines()]
    i_while = next(i for i, x in enumerate(lines) if x.startswith("while ("))
    i_blk = next(i for i, x in enumerate(lines) if x.startswith("L_0x4014a0:"))
    assert i_while < i_blk, "自环的头块必须渲染在循环体内"


def test_switch_rendered_when_evidence_high():
    r = S.structure_function(_res(DYN), 0x401870, _cand(DYN, 0x401870))
    assert r["stats"]["switch"] == 1
    assert r["stats"]["switch_downgraded"] == 0
    text = S.render_function(r)
    assert "switch (rsi)" in text and "evidence=high" in text
    assert "case 0: goto L_0x" in text


def test_switch_case_targets_come_from_candidates():
    cand = _cand(DYN, 0x401870)
    targets = {t for c in cand["candidates"] for t in c["targets"]}
    r = S.structure_function(_res(DYN), 0x401870, cand)
    nodes = []
    _walk(r["tree"], nodes)
    sw = [n for n in nodes if n.get("kind") == "switch"]
    assert len(sw) == 1
    for c in sw[0]["cases"]:
        assert c["target"] in targets


def test_switch_downgraded_when_evidence_not_high():
    """证据不足必须降级成 goto 并写明原因，不许渲染 switch。"""
    import copy
    cand = copy.deepcopy(_cand(DYN, 0x401870))   # 不污染缓存的 high 报告
    cand["candidates"][0]["evidence"] = "medium"
    r = S.structure_function(_res(DYN), 0x401870, cand)
    assert r["stats"]["switch"] == 0
    assert r["stats"]["switch_downgraded"] == 1
    nodes = []
    _walk(r["tree"], nodes)
    reasons = [n.get("reason") or "" for n in nodes]
    assert any("候选证据 medium" in x and "不渲染 switch" in x for x in reasons)


def test_no_candidates_keeps_goto_with_reason():
    r = S.structure_function(_res(DYN), 0x401870, None)
    assert r["stats"]["switch"] == 0
    text = S.render_function(r)
    assert "无候选" in text and "保留 goto" in text


# ── 4. 不可结构化单独统计 ────────────────────────────────────────────
def test_irreducible_blocks_annotated():
    rep = S.structure_binary(_res(BINLS), None, False)
    assert rep["stats"]["irreducible_blocks"] > 0
    assert rep["stats"]["irreducible_functions"] > 0


def test_irreducible_function_reason_visible():
    rep = S.structure_binary(_res(BINLS), None, False)
    bad = [f for f in rep["functions"] if f["goto_dense"] and f["blocks"] > 3]
    assert bad, "bin_ls 里应有 goto 密集函数"
    r = S.structure_function(_res(BINLS), bad[0]["function"])
    text = S.render_function(r)
    assert "不可约循环" in text or "未结构化" in text or "goto" in text


def test_cond_unknown_is_counted_and_explained():
    rep = S.structure_binary(_res(CLI), None, False)
    assert rep["stats"]["cond_unknown"] > 0
    for f in rep["functions"]:
        r = S.structure_function(_res(CLI), f["function"])
        if r["stats"]["cond_unknown"]:
            assert "条件不可判" in S.render_function(r)
            return
    pytest.fail("没有 cond_unknown>0 的函数，统计与标注不一致")


def test_goto_dense_threshold_is_explicit():
    """goto 占比 > 30% 才标密集；阈值写在 stats 里，不做暗箱判断。"""
    r = S.structure_function(_res(DYN), 0x401870, _cand(DYN, 0x401870))
    st = r["stats"]
    assert abs(st["goto_ratio"] - st["goto"] / st["blocks_total"]) < 1e-9
    assert st["goto_dense"] == (st["goto_ratio"] > 0.30)


# ── 5. 文本必须带可回指标记 ──────────────────────────────────────────
def test_render_carries_block_and_edge_markers():
    r = S.structure_function(_res(DYN), 0x401870, _cand(DYN, 0x401870))
    text = S.render_function(r)
    assert "blk 0x401870" in text
    assert "edges=" in text and "join=" in text
    assert "可回指 recdesc.blocks" in text


def test_render_switch_marks_candidate_layer():
    r = S.structure_function(_res(DYN), 0x401870, _cand(DYN, 0x401870))
    text = S.render_function(r)
    assert "候选层口径" in text and "未提升为表达式" in text


def test_structure_binary_skips_undeclared_by_default():
    """默认只结构化权威声明边界的函数；include_inferred 才纳入推断域。"""
    res = _res(CLI)
    declared = [f for f in expr.list_functions(res) if f["boundary"] == "declared"]
    rep = S.structure_binary(res, None, False)
    assert len(rep["functions"]) == len(declared)
    rep2 = S.structure_binary(res, None, True)
    assert len(rep2["functions"]) > len(rep["functions"])
