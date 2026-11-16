# tests/test_callfacts.py — M6-U2：跨函数参数传递的事实层
#
# 断言按验收五条组织：
#   1) 证据分 declared / observed / derived 三级且逐条分开，不混成一个"已确定"；
#      操作数事实（寄存器/栈槽的值位置）不得带 declared 级证据；
#   2) 不做 ABI 推断：不产出参数列表、不猜个数/名字，统一 abstain 写缺什么；
#   3) 跨块（M8-U1）：只沿确定边追定义侧，结论单独存放（cross_facts），
#      不得混进同块事实；疑似边/间接目标/循环一律 abstain 并写缺什么；
#      R76：call 的 rsp 写按持久写处理，窗口内含 call 的 rsp 槽事实必须 abstain；
#   4) 与调用图三态逐点比对，矛盾单列；注入不一致必须被检出；
#   5) CLI 接线 + 只读性（默认 callgraph/expr 输出不受影响）。
import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import callfacts as CF, callgraph as CG, cli, recdesc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
BINLS = os.path.join(HERE, "fixtures", "bin_ls.elf")
DYN = os.path.join(HERE, "fixtures", "dyn_static")

_cache = {}


def _res(path):
    if ("res", path) not in _cache:
        _cache[("res", path)] = recdesc.descend(path)
    return _cache[("res", path)]


def _facts(path):
    if ("f", path) not in _cache:
        _cache[("f", path)] = CF.build(path, res=_res(path))
    return _cache[("f", path)]


def _site(r, addr):
    return next(s for s in r["sites"] if s["from"] == addr)


# ── 1. 证据分级：不混成一个"已确定" ──────────────────────────────────
@pytest.mark.parametrize("path", [CLI, BINLS, DYN])
def test_counts_are_self_consistent(path):
    r = _facts(path)
    c = r["counts"]
    facts = [f for s in r["sites"] for f in s["facts"]]
    assert c["facts_before"] == sum(1 for f in facts if f["direction"] == "before")
    assert c["facts_after"] == sum(1 for f in facts if f["direction"] == "after")
    assert c["abstains"] == sum(len(s["abstains"]) for s in r["sites"])
    for lvl in CF.LEVELS:
        assert c["evidence"][lvl] == sum(
            1 for f in facts for e in f["evidence"] if e["level"] == lvl)
        assert c["target_evidence"][lvl] == sum(
            1 for s in r["sites"] for e in s["target_evidence"]
            if e["level"] == lvl)
    assert c["sites"] == c["direct"] + c["indirect"] == len(r["sites"])
    cf = [f for s in r["sites"] for f in s.get("cross_facts") or []]
    ca = [a for s in r["sites"] for a in s.get("cross_abstains") or []]
    assert c["cross_facts"] == len(cf)
    assert c["cross_abstains"] == len(ca)
    assert c["cross_sites"] == sum(1 for s in r["sites"]
                                   if s.get("cross_facts")
                                   or s.get("cross_abstains"))
    for lvl in CF.LEVELS:
        assert c["cross_evidence"][lvl] == sum(
            1 for f in cf for e in f["evidence"] if e["level"] == lvl)


@pytest.mark.parametrize("path", [CLI, BINLS, DYN])
def test_operand_facts_have_no_declared_evidence(path):
    """寄存器/栈槽的值位置只有 observed+derived：声明级证据不能贴到值上。"""
    for s in _facts(path)["sites"]:
        for f in s["facts"] + (s.get("cross_facts") or []):
            levels = [e["level"] for e in f["evidence"]]
            assert levels == ["observed", "derived"], (hex(f["at"]), levels)
            assert all(e["source"] and e["text"] for e in f["evidence"])
    assert _facts(path)["counts"]["evidence"]["declared"] == 0


def test_evidence_items_have_single_level_and_known_legend():
    r = _facts(CLI)
    assert set(r["levels"]) == set(CF.LEVELS)
    for k, v in r["levels"].items():
        assert k in ("declared", "observed", "derived") and v


def test_pe_target_splits_declared_iat_and_derived_thunk():
    s = _site(_facts(CLI), 0x1167)
    items = {(e["level"], e["source"]) for e in s["target_evidence"]}
    assert ("declared", "iat") in items
    assert ("derived", "thunk_shape") in items
    # declared 条目只讲导入表事实，derived 条目才讲"跳板"判定
    decl = [e for e in s["target_evidence"] if e["level"] == "declared"]
    assert any("VCRUNTIME140.dll!memset" in e["text"] for e in decl)
    assert all("跳板" not in e["text"] for e in decl)


def test_elf_target_splits_section_and_reloc():
    s = _site(_facts(BINLS), 0x475A)
    items = {(e["level"], e["source"]) for e in s["target_evidence"]}
    assert ("declared", "section") in items
    assert ("declared", "reloc") in items
    assert ("observed", "stub_bytes") in items
    assert s["state"] == "plt_or_import"


def test_dyn_static_plt_without_reloc_is_derived_not_named():
    s = _site(_facts(DYN), 0x404819)
    assert s["state"] == "plt_or_import"
    assert any(e["level"] == "derived" and e["source"] == "stub_parse"
               for e in s["target_evidence"])
    assert not any(e["source"] == "reloc" for e in s["target_evidence"])


# ── 2. 不做 ABI 推断 ─────────────────────────────────────────────────
def test_no_argument_list_and_explicit_abstain_kept():
    r = _facts(CLI)
    for s in r["sites"]:
        assert "params" not in s and "args" not in s
        assert any(a["scope"] == "full_argument_set" for a in s["abstains"])
    text = CF.render(r)
    assert "禁止 ABI 推断" in text
    assert "不判定哪些寄存器/栈槽是参数" in text
    for s in r["sites"]:
        for f in s["facts"]:
            assert set(f) == {"direction", "kind", "operand", "at", "bytes",
                              "evidence"}


def test_indirect_sites_have_no_state_and_abstain_target():
    r = _facts(CLI)
    ind = [s for s in r["sites"] if s["call_kind"] == "indirect"]
    assert ind
    for s in ind:
        assert s["state"] is None
        assert s["target"] is None
        assert any(a["scope"] == "target" for a in s["abstains"])


# ── 3. 跨块只走确定边 + R76 对暂态写的判据 ───────────────────────────
def test_cross_block_uses_only_definite_edges():
    """跨块分支的每一跳都必须是 recdesc 标为 definite 的边，且沿途块无非确定入边。"""
    res = _res(DYN)
    definite = {(e["from"], e["to"]) for e in res["cfg"]["edges"]["definite"]}
    blk_of = {}
    for b in res["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    nondet_in = set()
    for cls in ("speculative", "cross_function", "undecoded", "unresolved"):
        for e in res["cfg"]["edges"][cls]:
            nondet_in.add(e["to"])
    seen = 0
    for s in _facts(DYN)["sites"]:
        for f in s.get("cross_facts") or []:
            assert f["direction"] == "before" and f["kind"] == "reg"
            for br in f["branches"]:
                assert br[0] == s["block"], "分支必须从调用点所在块起"
                assert br[-1] == blk_of[f["at"]]["start"], "分支末端必须是定义块"
                assert len(set(br)) == len(br), "分支不得成环"
                for i in range(1, len(br)):
                    assert (br[i], br[i - 1]) in definite, \
                        ("非确定边被当作路径", hex(br[i]), hex(br[i - 1]))
                    assert br[i - 1] not in nondet_in
                    seen += 1
    assert seen > 0, "dyn_static 应至少解出一条跨块分支"


def test_cross_block_abstains_say_what_is_missing():
    r = _facts(DYN)
    abst = [a for s in r["sites"] for a in s.get("cross_abstains") or []]
    assert abst, "dyn_static 应有跨块弃权"
    for a in abst:
        assert a["scope"].startswith("cross:") and "缺" in a["missing"]
    # 循环/间接目标/入口三类原因必须能被指名，而不是笼统一句"不可判定"
    text = " ".join(a["missing"] for a in abst)
    assert "函数入口" in text or "非确定入边" in text or "合流" in text


def test_cross_block_loop_abstains_and_names_the_cycle():
    """循环回边必须 abstain，且文案点名「回边/不动点」；嵌套失败要传播根因。"""
    res = _res(DYN)
    ctx = CG._Ctx(DYN, res, ".text")
    ix = CF._cross_index(res)
    backs = [e for e in res["cfg"]["edges"]["definite"]
             if e["to"] <= e["from"] and e["to"] in ix["start_of"]]
    assert backs, "dyn_static 的确定边里应有回边（否则这条判据无从验证）"
    hit = None
    for e in backs:
        blk = ix["start_of"][e["to"]]
        for op in ("r15", "r14", "r13", "r12"):
            key = ("reg", op)
            st = CF._cross_merge(ctx, ix, blk, key, {}, {key}, 0)
            if st["status"] != "def":
                hit = CF._cross_missing(st)
                break
        if hit:
            break
    assert hit, "应有操作数在环上找不到定义（回溯必须 abstain）"
    assert "回边" in hit and "不动点" in hit, hit


def test_cross_block_facts_stay_out_of_same_block_list():
    r = _facts(DYN)
    blk_of = {}
    for b in _res(DYN)["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    for s in r["sites"]:
        same = {(f["kind"], f["operand"]) for f in s["facts"]
                if f["direction"] == "before"}
        for f in s.get("cross_facts") or []:
            assert (f["kind"], f["operand"]) not in same, "跨块结论与同块事实重复"
            assert blk_of[f["at"]]["start"] != s["block"], "跨块事实的定义不能在同块"
            assert s["cross_block"] == "traced"


def test_r76_call_write_to_rsp_is_persistent_not_exempt():
    """R76：call 写 rsp 且复原不可判定 → 窗口内含 call 的 rsp 槽事实必须 abstain。"""
    s = _site(_facts(CLI), 0x1340)
    slots = {f["operand"] for f in s["facts"] if f["kind"] == "slot"}
    assert "[rsp+96]" not in slots
    a = next(x for x in s["abstains"] if x["scope"] == "slot:[rsp+96]")
    assert "0x1313" in a["missing"] and "call" in a["missing"]
    assert "栈平衡契约" in a["missing"] and "缺" in a["missing"]


def test_r76_rule_is_documented_with_falsification():
    blk = _facts(CLI)["cross_block"]["transient_write"]
    assert "暂态写" in blk["rule"] and "T1" in blk["rule"]
    assert "ret imm16" in blk["call"] and "ABI 推断" in blk["call"]
    assert "证伪" in blk["falsify"] and "ret 8" in blk["falsify"]


def test_operand_facts_stay_inside_call_block():
    r = _facts(CLI)
    blk_of = {}
    for b in _res(CLI)["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    for s in r["sites"]:
        b = blk_of[s["from"]]
        for f in s["facts"]:
            assert b["start"] <= f["at"] <= b["end"]
            if f["direction"] == "before":
                assert f["at"] < s["from"]
            else:
                assert f["at"] > s["from"]


def test_rsp_rewrite_invalidates_slot_facts():
    s = _site(_facts(CLI), 0x1061)
    slots = {f["operand"] for f in s["facts"] if f["kind"] == "slot"}
    abst = {a["scope"] for a in s["abstains"]}
    assert "[rsp+16]" not in slots
    assert "slot:[rsp+16]" in abst
    a = next(x for x in s["abstains"] if x["scope"] == "slot:[rsp+16]")
    assert "0x1052" in a["missing"] and "缺" in a["missing"]


def test_function_declaration_levels_are_separated():
    s = _site(_facts(CLI), 0x1061)
    assert s["function_declaration"]["level"] == "declared"
    assert "pdata" in s["function_declaration"]["sources"]
    d = _facts(DYN)
    derived = [x for x in d["sites"]
               if x["function_declaration"]["level"] == "derived"]
    assert derived, "dyn_static 应有只靠启发式种子的函数"
    for x in derived[:50]:
        srcs = set(x["function_declaration"]["sources"])
        assert srcs <= {"prologue_scan"} or not srcs


# ── 4. 与调用图三态一致 ──────────────────────────────────────────────
@pytest.mark.parametrize("path", [CLI, BINLS, DYN])
def test_consistency_with_callgraph(path):
    r = _facts(path)
    con = r["consistency"]
    assert con["ok"] is True
    assert con["contradictions"] == []
    assert con["checked"] == r["counts"]["sites"]
    assert con["graph_sites"] == len(CG.build(path, res=_res(path))["edges"])


def test_consistency_detects_injected_state_mismatch():
    r = copy.deepcopy(_facts(CLI))
    graph = CG.build(CLI, res=_res(CLI))
    target = next(s for s in r["sites"] if s["call_kind"] == "direct")
    target["state"] = "unresolved" if target["state"] != "unresolved" \
        else "decoded"
    con = CF.check_consistency(graph, r)
    assert con["ok"] is False
    assert any(x["field"] == "state" and x["from"] == target["from"]
               for x in con["contradictions"])


def test_consistency_detects_missing_site():
    r = copy.deepcopy(_facts(CLI))
    graph = CG.build(CLI, res=_res(CLI))
    r["sites"] = [s for s in r["sites"]
                  if s["from"] != graph["edges"][0]["from"]]
    r["counts"]["sites"] -= 1
    con = CF.check_consistency(graph, r)
    fields = {x["field"] for x in con["contradictions"]}
    assert {"missing_in_facts", "site_count"} & fields


def test_register_facts_match_callgraph_observe():
    """同一调用点在 --observe 与本层的寄存器结论必须一致（槽只可更保守）。"""
    r = _facts(CLI)
    g = CG.build(CLI, res=_res(CLI), observe=True)
    o_by = {o["from"]: o for o in g["observations"]}
    for s in r["sites"]:
        o = o_by[s["from"]]
        for d, key in (("before", "before_defs"), ("after", "after_uses")):
            fb = {f["operand"] for f in s["facts"]
                  if f["direction"] == d and f["kind"] == "reg"}
            ob = {x["operand"] for x in o[key] if x["kind"] == "reg"}
            assert fb == ob, (hex(s["from"]), d, fb ^ ob)
            fs = {f["operand"] for f in s["facts"]
                  if f["direction"] == d and f["kind"] == "slot"}
            os_ = {x["operand"] for x in o[key] if x["kind"] == "slot"}
            assert fs <= os_, (hex(s["from"]), d, sorted(fs - os_))


# ── 5. CLI 接线与只读性 ──────────────────────────────────────────────
def test_cli_dispatches_callfacts(capsys):
    assert cli.main(["callfacts", CLI, "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["counts"]["sites"] == 153 and r["consistency"]["ok"] is True


def test_callgraph_default_output_has_no_facts(capsys):
    assert CG.main([CLI, "--json"]) == 0
    g = json.loads(capsys.readouterr().out)
    assert "facts" not in g and "sites" not in g


def test_build_does_not_mutate_res():
    res = _res(CLI)
    before = (len(res["instructions"]), len(res["blocks"]),
              dict(res["stats"]))
    CF.build(CLI, res=res)
    after = (len(res["instructions"]), len(res["blocks"]), dict(res["stats"]))
    assert before == after
