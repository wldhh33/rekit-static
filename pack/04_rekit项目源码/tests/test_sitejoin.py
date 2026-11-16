#!/usr/bin/env python3
# test_sitejoin.py — M7-U1 三层拼接（调用图 / 参数事实层 / 结构化文本）单元测试
#
# 覆盖四类硬要求：
#   1) 对齐键唯一且可解释（键覆盖账目、块内第 j 个调用可回指）；
#   2) 冲突单列并归因（注入 state/缺站点/缺块/坏文本/declared 证据，必须被检出）；
#   3) 能失败：两层同时删掉同一调用点时必须报 call_site_missing；M7-U2 修正
#      带前缀 call 漏检后，真实数据上的缺口应恒为 0（数字见下）；
#   4) 只读：check() 前后入参深相等。
import copy
import json

import pytest

from rekit import callfacts as CF, callgraph as CG, cli, expr, recdesc, sitejoin

SAMPLE = "tests/fixtures/cli-64.exe"
SAMPLE_ELF = "tests/fixtures/bin_ls.elf"


@pytest.fixture(scope="module")
def built():
    res = recdesc.descend(SAMPLE)
    graph = CG.build(SAMPLE, res=res)
    facts = CF.build(SAMPLE, res=res, graph=graph)
    funcs = sorted({s["function"] for s in facts["sites"]},
                   key=lambda x: (x is None, x or 0))
    sidx = sitejoin.struct_index(res, funcs)
    rep = sitejoin.build(SAMPLE, res=res, graph=graph, facts=facts, sidx=sidx)
    return {"res": res, "graph": graph, "facts": facts, "sidx": sidx, "rep": rep}


@pytest.fixture(scope="module")
def built_elf():
    res = recdesc.descend(SAMPLE_ELF)
    graph = CG.build(SAMPLE_ELF, res=res)
    facts = CF.build(SAMPLE_ELF, res=res, graph=graph)
    return sitejoin.build(SAMPLE_ELF, res=res, graph=graph, facts=facts)


def _direct_site(facts):
    return next(s for s in facts["sites"] if s["call_kind"] == "direct")


# ── 0. C2：状态名自解释，禁止与预算跳过的 "skipped" 同名 ─────────────
def test_struct_index_status_names_are_self_describing(built):
    vocab = {"ok", "not_declared", "no_decoded_instructions", "no_function"}
    for st in built["sidx"].values():
        assert st["status"] in vocab
        assert st["status"] != "skipped"   # 反证：改回裸 skipped 即失败


# ── 1. 键唯一且可解释 ────────────────────────────────────────────────
def test_key_unique_accounting(built):
    c = built["rep"]["counts"]
    assert c["keys"] == c["key_unique"]
    assert c["duplicate_keys"] == 0
    assert c["keys"] == len(built["facts"]["sites"])
    assert c["keys"] == c["facts_sites"]


def test_key_coverage_matches_decoded_calls(built):
    c = built["rep"]["counts"]
    assert c["decoded_calls"] == c["keys"] + c["call_site_missing"]
    assert c["key_coverage_ok"] is True
    assert built["rep"]["key"]["coverage_ok"] is True


def test_every_key_reaches_all_three_layers(built):
    for s in built["rep"]["sites"]:
        assert set(s) >= {"key", "graph", "facts", "struct"}
        assert s["graph"]["kind"] in ("direct_edge", "indirect_no_edge",
                                     "missing")
        assert s["facts"] is not None
        assert s["struct"]["status"]


def test_aligned_line_is_locatable(built):
    aligned = [s for s in built["rep"]["sites"]
               if s["struct"]["status"] == "aligned"]
    assert aligned, "cli-64 应当全部对齐"
    for s in aligned:
        st = s["struct"]
        lines, nbody = sitejoin._text_lines(
            built["sidx"][s["function"]]["blocks"][s["block"]])
        assert 0 <= st["line_index"] < len(lines)
        assert st["slice"] == sitejoin._slice(st["line_index"], nbody)
        # 行号必须回指到该调用自己的语句（直接调用核对目标地址，间接调用核对 (*…))
        if s["facts"]["call_kind"] == "direct":
            assert ("0x%x" % (s["facts"]["target"] or 0)) in st["line_text"]
        else:
            assert "(*" in st["line_text"]


def test_block_call_counts_consistent(built):
    bad = [x for x in built["rep"]["conflicts"]
           if x["kind"] == "struct_line_count_mismatch"]
    assert bad == []


# ── 2. 冲突单列并归因 ────────────────────────────────────────────────
def test_no_hard_conflict_on_cli64(built):
    c = built["rep"]["counts"]
    assert c["hard_conflicts"] == 0
    assert c["conflicts"] == 0


def test_every_conflict_has_attribution(built_elf):
    kinds = set(sitejoin._KIND_ATTR)
    for c in built_elf["conflicts"]:
        assert c["kind"] in kinds
        assert c["attribution"] in sitejoin.ATTRIBUTION
        assert c["detail"]


def test_injected_state_mismatch(built):
    facts = copy.deepcopy(built["facts"])
    s = _direct_site(facts)
    s["state"] = "unresolved" if s["state"] != "unresolved" else "decoded"
    r = sitejoin.check(built["graph"], facts, built["sidx"])
    hit = [c for c in r["conflicts"] if c["kind"] == "state_mismatch"
           and c["key"] == s["from"]]
    assert hit and hit[0]["attribution"] == "layer_bug"


def test_injected_missing_graph_edge(built):
    graph = copy.deepcopy(built["graph"])
    s = _direct_site(built["facts"])
    graph["edges"] = [e for e in graph["edges"] if e["from"] != s["from"]]
    r = sitejoin.check(graph, built["facts"], built["sidx"])
    hit = [c for c in r["conflicts"] if c["kind"] == "graph_edge_missing"]
    assert any(c["key"] == s["from"] for c in hit)


def test_injected_missing_facts_site(built):
    facts = copy.deepcopy(built["facts"])
    s = _direct_site(facts)
    facts["sites"] = [x for x in facts["sites"] if x["from"] != s["from"]]
    r = sitejoin.check(built["graph"], facts, built["sidx"])
    hit = [c for c in r["conflicts"] if c["kind"] == "facts_site_missing"]
    assert any(c["key"] == s["from"] for c in hit)


def test_injected_duplicate_key(built):
    graph = copy.deepcopy(built["graph"])
    graph["edges"].append(copy.deepcopy(graph["edges"][0]))
    r = sitejoin.check(graph, built["facts"], built["sidx"])
    dup = [c for c in r["conflicts"] if c["kind"] == "duplicate_key"]
    assert dup and dup[0]["attribution"] == "data_anomaly"


def test_injected_broken_struct_text(built):
    sidx = copy.deepcopy(built["sidx"])
    s = _direct_site(built["facts"])
    node = sidx[s["function"]]["blocks"][s["block"]]
    lines, _n = sitejoin._text_lines(node)
    for i, ln in enumerate(lines):
        if sitejoin._is_call_line(ln):
            if i < len(node.get("lines") or []):
                node["lines"][i] = "/* 文本被破坏 */"
            else:
                node["term"][i - len(node["lines"])] = "/* 文本被破坏 */"
            break
    r = sitejoin.check(built["graph"], built["facts"], sidx)
    hard = [c for c in r["conflicts"] if c["attribution"] == "layer_bug"
            and c["kind"].startswith("struct_")]
    assert hard


def test_injected_missing_block(built):
    sidx = copy.deepcopy(built["sidx"])
    s = _direct_site(built["facts"])
    sidx[s["function"]]["blocks"].pop(s["block"])
    r = sitejoin.check(built["graph"], built["facts"], sidx)
    hit = [c for c in r["conflicts"] if c["kind"] == "struct_block_missing"]
    assert any(c["key"] == s["from"] for c in hit)


def test_injected_declared_operand_evidence(built):
    facts = copy.deepcopy(built["facts"])
    s = next(x for x in facts["sites"] if x["facts"])
    s["facts"][0]["evidence"].append(
        {"level": "declared", "source": "fake", "text": "注入的伪造声明"})
    r = sitejoin.check(built["graph"], facts, built["sidx"])
    assert [c for c in r["conflicts"] if c["kind"] == "operand_declared"]


# ── 3. 键覆盖：M7-U2 修正后应为 0；注入仍必须被检出 ─────────────────
def test_prefix_call_gap_fixed_on_real_data(built_elf):
    """M7-U2 重定标：bin_ls 的 13 条带前缀 call 已进入两层，覆盖账平。

    keys 1141 → 1154（+13 间接）；直接边 1116 不变；间接 25 → 38。
    """
    c = built_elf["counts"]
    assert c["call_site_missing"] == 0
    assert c["key_coverage_ok"] is True
    assert c["decoded_calls"] == c["keys"] == c["facts_sites"]
    assert (c["keys"], c["graph_edges"], c["graph_indirect_no_edge"]) == \
        (1154, 1116, 38)
    assert not [x for x in built_elf["conflicts"]
                if x["kind"] == "call_site_missing"]


def test_injected_both_layers_missing_is_reported(built):
    """键覆盖账不是空转：两层同时删掉同一直接调用点，必须报 call_site_missing。"""
    addr = _direct_site(built["facts"])["from"]
    g = copy.deepcopy(built["graph"])
    f = copy.deepcopy(built["facts"])
    g["edges"] = [e for e in g["edges"] if e["from"] != addr]
    f["sites"] = [s for s in f["sites"] if s["from"] != addr]
    r = sitejoin.check(g, f, built["sidx"], res=built["res"])
    hit = [c for c in r["conflicts"]
           if c["kind"] == "call_site_missing" and c["key"] == addr]
    assert hit and hit[0]["attribution"] == "layer_bug"


# ── 4. 只读 ──────────────────────────────────────────────────────────
def test_check_is_read_only(built):
    g = copy.deepcopy(built["graph"])
    f = copy.deepcopy(built["facts"])
    s = copy.deepcopy(built["sidx"])
    g0, f0, s0 = (json.dumps(g, sort_keys=True, default=str),
                  json.dumps(f, sort_keys=True, default=str),
                  json.dumps(s, sort_keys=True, default=str))
    sitejoin.check(g, f, s, res=built["res"])
    assert json.dumps(g, sort_keys=True, default=str) == g0
    assert json.dumps(f, sort_keys=True, default=str) == f0
    assert json.dumps(s, sort_keys=True, default=str) == s0


def test_build_is_read_only(built):
    g = copy.deepcopy(built["graph"])
    f = copy.deepcopy(built["facts"])
    s = copy.deepcopy(built["sidx"])
    g0 = json.dumps(g, sort_keys=True, default=str)
    f0 = json.dumps(f, sort_keys=True, default=str)
    s0 = json.dumps(s, sort_keys=True, default=str)
    rep = sitejoin.build(SAMPLE, res=built["res"], graph=g, facts=f, sidx=s)
    assert rep["read_only"]["graph"] and rep["read_only"]["facts"]
    assert json.dumps(g, sort_keys=True, default=str) == g0
    assert json.dumps(f, sort_keys=True, default=str) == f0
    assert json.dumps(s, sort_keys=True, default=str) == s0


# ── CLI 分派 ─────────────────────────────────────────────────────────
def test_cli_json_dispatch(capsys):
    rc = cli.main(["sitejoin", SAMPLE, "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    rep = json.loads(out)
    assert rep["key"]["rule"] and rep["counts"]["keys"] > 0
