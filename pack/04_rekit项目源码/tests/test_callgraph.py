# tests/test_callgraph.py — M6-U1：调用图 + 保守的跨过程观察
#
# 断言按验收五条组织：
#   1) 直接调用是确定边口径；间接调用走候选层，默认关闭、单列、带证据等级，
#      两者不合并统计（账目必须对平）；
#   2) 观察只报事实：同块窗口内的前定义/后使用；明确写"不做 ABI 推断"；
#   3) 三态 decoded / plt_or_import / unresolved，占比与计数自洽；
#   4) 自递归/互递归可识别并标注，渲染有 visited + 节点上限，不会递归爆掉；
#   5) CLI 接线走子命令，既有 expr/recdesc 默认输出不受影响。
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import callgraph as CG, cli, expr, recdesc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
BINLS = os.path.join(HERE, "fixtures", "bin_ls.elf")
DYN = os.path.join(HERE, "fixtures", "dyn_static")

_cache = {}

# 独立前缀解析（R71：判断指令类别不得看 raw 首字节，测试代码同样适用）
_LEGACY = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67,
                     0xF0, 0xF2, 0xF3))


def _opcode(b):
    raw = bytes.fromhex(b.replace(" ", ""))
    i, n = 0, len(raw)
    while i < n and raw[i] in _LEGACY:
        i += 1
    if i < n and 0x40 <= raw[i] <= 0x4F:
        i += 1
    return raw[i] if i < n else None


def _res(path):
    key = ("res", path)
    if key not in _cache:
        _cache[key] = recdesc.descend(path)
    return _cache[key]


def _rep(path, **kw):
    key = ("rep", path, tuple(sorted(kw.items())))
    if key not in _cache:
        _cache[key] = CG.build(path, res=_res(path), **kw)
    return _cache[key]


# ── 1. 直接/间接隔离 ─────────────────────────────────────────────────
def test_cli_default_indirect_layer_off(capsys):
    assert CG.main([CLI]) == 0
    out = capsys.readouterr().out
    assert "默认关闭" in out
    assert "候选层已开启" not in out
    assert "已解出 decoded" in out
    assert "PLT/外部导入" in out
    assert "未解析 unresolved" in out


def test_json_default_indirect_empty(capsys):
    assert CG.main([CLI, "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["indirect"]["enabled"] is False
    assert r["indirect"]["candidates"] == []
    assert r["counts"]["indirect"] > 0
    assert r["observations"] is None


def test_indirect_candidates_listed_with_evidence():
    r = _rep(CLI, indirect=True)
    ind = r["indirect"]
    assert ind["enabled"] is True
    assert len(ind["candidates"]) == r["counts"]["indirect"]
    assert all(c["evidence"] in ("high", "medium", "low")
               for c in ind["candidates"])
    assert sum(ind["counts"].values()) == len(ind["candidates"])
    # 候选层不得产生确定边：edges 只有直接调用
    assert len(r["edges"]) == r["counts"]["direct"]
    assert all(_opcode(e["bytes"]) == 0xE8 for e in r["edges"])


@pytest.mark.parametrize("path", [CLI, BINLS, DYN])
def test_state_accounting(path):
    r = _rep(path, indirect=True)
    c = r["counts"]
    assert c["call_sites"] == c["direct"] + c["indirect"]
    assert (c["decoded"] + c["plt_or_import"] + c["unresolved"]) == c["direct"]
    assert len(r["edges"]) == c["direct"]
    assert all(e["state"] in ("decoded", "plt_or_import", "unresolved")
               for e in r["edges"])
    if c["direct"]:
        assert abs(sum(r["ratios"].values()) - 1.0) < 1e-9


def test_each_direct_call_site_once():
    """直接调用点 = 已解出指令里的 E8（call rel32），逐点一条、不重不漏。"""
    for path in (BINLS, DYN):
        res = _res(path)
        e8 = {i["addr"] for i in res["instructions"]
              if _opcode(i["bytes"]) == 0xE8}
        r = _rep(path)
        from_edges = [e["from"] for e in r["edges"]]
        assert len(from_edges) == len(set(from_edges)), "同一调用点被重复计入"
        assert set(from_edges) == e8, "直接调用点与 E8 指令集合不一致：%s" % path


def test_cfg_calls_reported_separately():
    """recdesc.cfg.calls 只记块末调用，必须单列且注明口径不同。"""
    r = _rep(CLI)
    assert r["cfg_call_counts"]["definite"] == 8      # 回归钉子（负向基线同源）
    assert r["counts"]["call_sites"] > 10 * r["cfg_call_counts"]["definite"]
    assert "块末" in r["cfg_call_note"]


# ── 2. 三态判据可复核 ────────────────────────────────────────────────
def test_decoded_targets_are_decoded_instructions():
    res = _res(DYN)
    ins = {i["addr"] for i in res["instructions"]}
    for e in _rep(DYN)["edges"]:
        if e["state"] == "decoded":
            assert e["to"] in ins, (hex(e["from"]), hex(e["to"]))
            assert e["to_fn"] == e["to"]


def test_pe_import_thunk_edge_is_named_and_not_decoded_state():
    r = _rep(CLI)
    e = next(x for x in r["edges"] if x["from"] == 0x1167)
    assert e["state"] == "plt_or_import"
    assert "导入跳板" in e["evidence"]
    assert "VCRUNTIME140.dll!memset" in e["evidence"]
    assert e["target_symbol"] == "VCRUNTIME140.dll!memset"
    assert e["to_fn"] is None          # 外部导入不是本地函数边


def test_elf_plt_edge_is_named_from_relocation():
    e = next(x for x in _rep(BINLS)["edges"] if x["from"] == 0x475A)
    assert e["state"] == "plt_or_import"
    assert e["to_section"] == ".plt"
    assert "jmp [0x26d80]" in e["evidence"]
    assert "__assert_fail" in e["evidence"]


def test_unresolved_edges_carry_reason_and_are_not_plt():
    un = [e for e in _rep(DYN)["edges"] if e["state"] == "unresolved"]
    assert un, "dyn_static 应有未解析目标（目标落在 .init/0x0）"
    for e in un:
        assert "不在已解出指令内" in e["evidence"]
        assert not (e["to_section"] or "").startswith(".plt")


# ── 3. 环识别与渲染安全 ──────────────────────────────────────────────
def test_self_recursion_annotated():
    r = _rep(BINLS)
    self_nodes = {n["addr"] for n in r["nodes"] if n["recursion"] == "self"}
    assert self_nodes, "bin_ls 应有自递归函数"
    assert 0x7990 in self_nodes
    assert any(c["kind"] == "self" and c["members"] == [0x7990]
               for c in r["cycles"])


def test_mutual_recursion_and_node_flags_consistent():
    r = _rep(DYN)
    nodes = {n["addr"]: n for n in r["nodes"]}
    assert any(c["kind"] == "mutual" for c in r["cycles"])
    for cy in r["cycles"]:
        for m in cy["members"]:
            assert m in nodes, hex(m)
            assert nodes[m]["recursion"] in ("self", "mutual")
            assert nodes[m]["scc"] == cy["scc"]
    assert all(n["recursion"] is None for n in r["nodes"] if n["scc"] is None)


def test_tree_render_terminates_and_is_deterministic():
    r = _rep(BINLS)
    t1 = CG.render(r)
    t2 = CG.render(r)
    assert t1 == t2, "渲染不确定（遍历顺序不稳定）"
    assert "调用树" in t1 and "visited 防环" in t1
    assert "节点上限" in t1
    assert len(t1) < 60000, "渲染体积异常（疑似环未截断）"


def test_tree_has_visited_guard_marker():
    t = CG.render(_rep(CLI))
    assert "已展开过" in t or "无直接调用边" in t


# ── 4. 保守观察 ──────────────────────────────────────────────────────
def test_observe_off_by_default():
    assert _rep(CLI)["observations"] is None
    assert _rep(BINLS)["observations"] is None


def test_observe_reports_facts_only():
    r = _rep(CLI, observe=True)
    assert "不做 ABI 推断" in r["observe_note"]
    o = next(x for x in r["observations"] if x["from"] == 0x1061)
    assert {"rdi", "rsi"} <= {d["operand"] for d in o["before_defs"]}
    assert all({"operand", "at", "bytes"} <= set(d) for d in o["before_defs"])
    assert any(u["operand"] == "rax" for u in o["after_uses"])
    # before 的定义地址必须早于调用点
    assert all(d["at"] < o["from"] for d in o["before_defs"])


def test_observe_window_is_bounded_to_same_block():
    r = _rep(CLI, observe=True)
    blk_of = {}
    for b in _res(CLI)["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    for o in r["observations"]:
        w = o["window"]
        assert w, o
        b = blk_of[o["from"]]
        assert w["block_start"] == b["start"] and w["block_end"] == b["end"]
        for d in o["before_defs"]:
            assert b["start"] <= d["at"] < o["from"]
        for u in o["after_uses"]:
            assert o["from"] < u["at"] <= b["end"]


def test_observe_marks_rsp_movement():
    """rsp 在窗口内被改写时要显式标注，栈槽按原样表达式记录（不重算）。"""
    objs = _rep(CLI, observe=True)["observations"]
    o = next(x for x in objs if any(d["operand"] == "rsp"
                                    for d in x["before_defs"]))
    assert o["window"]["rsp_modified_before"] is True
    text = CG.render(_rep(CLI, observe=True))
    assert "栈槽按指令里原样地址表达式记录" in text


# ── 5. CLI 接线与只读性 ──────────────────────────────────────────────
def test_unified_cli_dispatches_callgraph(capsys):
    assert cli.main(["callgraph", CLI, "--json"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert "counts" in r and "edges" in r


def test_expr_default_output_unchanged(capsys):
    assert expr.main([CLI]) == 0
    out = capsys.readouterr().out
    assert "CALLGRAPH" not in out and "调用图" not in out


def test_build_does_not_mutate_res():
    res = _res(CLI)
    before = (len(res["instructions"]), len(res["blocks"]),
              dict(res["cfg"]["counts"]), dict(res["stats"]))
    CG.build(CLI, res=res, indirect=True, observe=True)
    after = (len(res["instructions"]), len(res["blocks"]),
             dict(res["cfg"]["counts"]), dict(res["stats"]))
    assert before == after
