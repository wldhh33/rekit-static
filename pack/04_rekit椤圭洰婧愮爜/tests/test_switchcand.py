# tests/test_switchcand.py — M5-U2：跳转表候选层的隔离与证据
#
# 断言分四层（对应裁决的硬性条件）：
#   1) 默认关闭：不带 --switch-candidates 时，CLI/JSON 里没有任何候选字段；
#   2) 候选形态：0x401870 必须识别出 rel32 表（0x476020）、8 项、证据 high；
#   3) 不污染确定集：候选跑前/跑后 res 的 stats/blocks/instructions 与伪 C 文本
#      sha256 逐项不变，且与 fixtures/definite_baseline.json 冻结值一致；
#   4) 被拒理由可见：伪造表项指向跨函数/指令内部/不可解时，必须带 reason。
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import coverage, disasm, expr, recdesc, switchcand  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
DYN = os.path.join(HERE, "fixtures", "dyn_static")
BASELINE = os.path.join(HERE, "baselines", "definite_baseline.json")
REL = {"cli-64.exe": "tests/fixtures/cli-64.exe",
       "bin_ls.elf": "tests/fixtures/bin_ls.elf",
       "dyn_static": "tests/fixtures/dyn_static"}

_cache = {}


def _state(rel):
    """{rel: (res, snap)}；同一进程内只算一次（dyn_static 较重）。"""
    if rel in _cache:
        return _cache[rel]
    path = os.path.join(WORK, rel)
    res = recdesc.descend(path)
    b = expr.lift_binary(path, res=res)
    texts = [expr.lift_function(res, f["function"])["text"] for f in b["functions"]]
    snap = {
        "recdesc": dict(res["stats"]),
        "expr": {"functions_total": b["functions_total"],
                 "lifted": b["functions_lifted"],
                 # C2：这里必须写全名——expr 的“跳过”是边界未声明，
                 # 与 switchcand 的“预算跳过”不是同一件事。
                 "skipped_undeclared_boundary": b["functions_skipped"],
                 "insns": b["stats"]["insns"],
                 "lifted_insns": b["stats"]["lifted"],
                 "abstained": b["stats"]["abstained"],
                 "statements": b["stats"]["statements"],
                 "text_sha256": hashlib.sha256("\n".join(texts).encode()).hexdigest()},
    }
    _cache[rel] = (res, snap)
    return _cache[rel]


def _binrep(rel):
    """候选层整二进制报告（同一进程内只算一次）。"""
    key = ("bin", rel)
    if key not in _cache:
        res, _snap = _state(rel)
        _cache[key] = switchcand.analyze_binary(os.path.join(WORK, rel), res=res)
    return _cache[key]


# ── 1. 默认关闭 ──────────────────────────────────────────────────────
def test_cli_default_has_no_candidate_field(capsys):
    assert expr.main([CLI, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert "switch_candidates" not in out


def test_cli_default_text_has_no_candidate_section(capsys):
    assert expr.main([CLI]) == 0
    out = capsys.readouterr().out
    assert "── 跳转表候选（非确定" not in out     # 候选段只由显式开关打印
    assert "证据 high" not in out
    assert "候选目标:" not in out


def test_lift_binary_default_unchanged():
    res, _snap = _state(REL["cli-64.exe"])
    b = expr.lift_binary(CLI, res=res)
    assert set(b) == {"path", "section", "recdesc_stats", "functions_total",
                      "functions_lifted", "functions_skipped", "skipped",
                      "verdict", "stats", "abstain_reasons", "functions",
                      "caveats"}


# ── 2. 0x401870 候选形态（显式开启） ─────────────────────────────────
def test_candidate_401870_shape():
    res, _snap = _state(REL["dyn_static"])
    rep = switchcand.analyze_function(res, 0x401870)
    assert len(rep["candidates"]) == 1
    c = rep["candidates"][0]
    assert c["kind"] == "rel32"
    assert c["jmp"] == 0x40192B
    assert c["table"] == 0x476020
    assert c["count"] == 8 and c["guard"] == 0x401914
    assert c["evidence"] == "high"
    assert c["targets"] == [0x40198E, 0x40195A, 0x401A5E, 0x401A46,
                            0x401953, 0x4019B0, 0x401A2E, 0x401A79]
    assert c["rejected_entries"] == []
    assert c["blocks_before"] == 23
    assert len(c["new_block_starts"]) == 20
    assert c["blocks_candidate"] == 43


def test_candidate_does_not_mutate_res():
    path = DYN
    res = recdesc.descend(path)
    stats = dict(res["stats"])
    nblk, nins = len(res["blocks"]), len(res["instructions"])
    blk_ids = [b["start"] for b in res["blocks"]]
    cfg_keys = sorted(res["cfg"]["counts"])
    rep = switchcand.analyze_function(res, 0x401870)
    assert rep["candidates"], "预设前提：该函数应有候选"
    assert res["stats"] == stats
    assert len(res["blocks"]) == nblk and len(res["instructions"]) == nins
    assert [b["start"] for b in res["blocks"]] == blk_ids
    assert sorted(res["cfg"]["counts"]) == cfg_keys


# ── 3. 负向基线：候选关闭/开启，确定数字逐项不变 ────────────────────
@pytest.mark.parametrize("name", sorted(REL))
def test_definite_numbers_unchanged(name):
    res, snap = _state(REL[name])
    want = json.load(open(BASELINE, encoding="utf-8"))[REL[name]]
    for group in ("recdesc", "expr"):
        for k, v in want[group].items():
            assert snap[group][k] == v, "%s.%s.%s 变了" % (name, group, k)
    # 开启候选层（跑在同一个 res 上）后再次对照：证明候选不写回
    _binrep(REL[name])
    for group in ("recdesc", "expr"):
        for k, v in want[group].items():
            if group == "recdesc":
                assert res["stats"][k] == v, "候选层改写了 recdesc.%s" % k


def test_definite_baseline_has_f401870():
    want = json.load(open(BASELINE, encoding="utf-8"))[REL["dyn_static"]]
    res, _snap = _state(REL["dyn_static"])
    r = expr.lift_function(res, 0x401870)
    assert len(r["blocks"]) == want["f_401870"]["blocks"] == 23
    assert r["stats"]["insns"] == want["f_401870"]["insns"]
    assert r["stats"]["statements"] == want["f_401870"]["statements"]
    sha = hashlib.sha256(r["text"].encode()).hexdigest()
    assert sha == want["f_401870"]["text_sha256"]


# ── 4. 被拒理由可见 ─────────────────────────────────────────────────
class _FakeReader:
    def __init__(self, table, entries, es=4):
        self.table, self.es = table, es
        self.blob = {}
        for i, v in enumerate(entries):
            self.blob[table + i * es] = int(v).to_bytes(es, "little", signed=True)

    def read(self, va, n):
        b = self.blob.get(va)
        return b[:n] if b is not None else None


class _OkDec:
    def decode(self, addr):
        return {"addr": addr}, None


class _BadDec:
    def decode(self, addr):
        return None, "测试用不可解"


def test_reject_cross_function_has_reason():
    table = 0x5000
    rd = _FakeReader(table, [0x40])          # 目标 0x5040，落在域外
    valid, rejected, trunc = switchcand._scan_entries(
        rd, table, None, "rel32", 0x1000, 0x2000, _OkDec(), ([], []))
    assert valid == [] and trunc is True
    assert "超出声明函数域" in rejected[0]["reason"]
    assert "跨函数/数据" in rejected[0]["reason"]


def test_reject_inside_decoded_instruction_has_reason():
    table = 0x5000
    rd = _FakeReader(table, [0x1002 - table])   # 目标 0x1002 落在指令 0x1000..0x1005 内
    valid, rejected, trunc = switchcand._scan_entries(
        rd, table, None, "rel32", 0x1000, 0x2000, _OkDec(),
        ([0x1000], [0x1005]))
    assert valid == [] and trunc is True
    assert "落在已解出指令" in rejected[0]["reason"]


def test_reject_undecodable_has_reason():
    table = 0x5000
    rd = _FakeReader(table, [0x1000 - table])
    valid, rejected, _trunc = switchcand._scan_entries(
        rd, table, None, "rel32", 0x1000, 0x2000, _BadDec(), ([], []))
    assert valid == [] and "无法解出指令" in rejected[0]["reason"]


def test_no_guard_never_high():
    """无 cmp/ja 上界：表长未证明，证据不得为 high。"""
    rep = _binrep(REL["dyn_static"])
    lows = [c for f in rep["functions"] for c in f["candidates"]
            if c["count"] is None]
    if not lows:
        pytest.skip("该样本没有无 guard 的候选")
    for c in lows:
        assert c["evidence"] in ("medium", "low")
        assert any("表长未证明" in x for x in c["basis"])


def test_unmatched_indirect_jumps_have_reason():
    rep = _binrep(REL["cli-64.exe"])
    # cli-64 的间接 jmp 都是 IAT 尾跳转：不应被误判成跳转表
    assert rep["stats"]["candidates"] == 0
    assert rep["stats"]["unmatched"] > 0
    for f in rep["functions"]:
        for u in f["unmatched"]:
            assert u["reason"].startswith("形态未识别")


def test_render_marks_candidates_non_definite():
    res, _snap = _state(REL["dyn_static"])
    rep = switchcand.analyze_function(res, 0x401870)
    text = switchcand.render_candidates(rep, single=True)
    assert "非确定" in text
    assert "不进确定边" in text
    assert "候选口径" in text


# ── 5. M9 升格：外部 objdump 边界，不许拿被测实现自证 ───────────────
_BOUNDARY = {}


def _boundary(path, drop=()):
    """边界集合来自外部 objdump（coverage 只负责调用工具与解析文本）。"""
    key = (path, tuple(sorted(drop)))
    if key in _BOUNDARY:
        return _BOUNDARY[key]
    sec = disasm.find_section(path, ".text")
    obj = coverage.objdump_instructions(path, sec)
    assert obj["status"] == "ok"
    starts = {i["addr"] for i in obj["instructions"]} - set(drop)
    _BOUNDARY[key] = {"starts": starts,
                      "source": "test-objdump-boundary（外部）"}
    return _BOUNDARY[key]


def test_promotion_with_external_boundary():
    res, _snap = _state(REL["dyn_static"])
    nblk, nins = len(res["blocks"]), len(res["instructions"])
    b = _boundary(DYN)
    rep = switchcand.analyze_function(res, 0x401870, boundary=b)
    c = rep["candidates"][0]
    assert c["promotion"]["status"] == "promoted"
    assert c["promotion"]["checks"] == {
        "guard_proven": True, "table_complete": True, "min_targets": True,
        "function_domain": True, "external_boundary": True}
    assert len(rep["promoted"]) == 1
    assert rep["promoted"][0]["jmp"] == c["jmp"]
    assert set(c["targets"]) <= b["starts"]
    # 升格不改变候选口径，更不进入确定集
    assert c["blocks_candidate"] == 43
    assert (len(res["blocks"]), len(res["instructions"])) == (nblk, nins)


def test_promotion_blocked_when_target_is_not_external_boundary():
    res, _snap = _state(REL["dyn_static"])
    drop = [0x40198E]                       # 0x401870 的第一个目标
    rep = switchcand.analyze_function(res, 0x401870,
                                      boundary=_boundary(DYN, drop))
    c = rep["candidates"][0]
    assert c["promotion"]["status"] == "blocked"
    assert c["promotion"]["checks"]["external_boundary"] is False
    assert any("objdump" in r for r in c["promotion"]["reasons"])
    assert rep["promoted"] == []


def test_promotion_default_not_checked():
    res, _snap = _state(REL["dyn_static"])
    rep = switchcand.analyze_function(res, 0x401870)
    c = rep["candidates"][0]
    assert c["promotion"]["status"] == "not_checked"
    assert c["promotion"]["checks"] == {}
    assert rep["promoted"] == []


# ── 6. M10 预算与降级：跳过必须单列，不得混进任何比率的分母 ─────────
def test_budget_skip_is_separate_from_candidates():
    rel = REL["bin_ls.elf"]
    res, _snap = _state(rel)
    full = switchcand.analyze_binary(os.path.join(WORK, rel), res=res)
    n = full["functions_with_indirect_jmp"]
    assert n >= 2
    cut = switchcand.analyze_binary(os.path.join(WORK, rel), res=res,
                                    max_functions=1)
    assert cut["budget"]["functions_analyzed"] == 1
    assert cut["budget"]["functions_skipped_budget"] == n - 1
    assert cut["budget"]["analysis_coverage"] == pytest.approx(1 / n)
    # 跳过的函数不产出候选，也不被当成“无候选”：候选只可能来自已分析的那一个
    assert cut["stats"]["candidates"] <= full["stats"]["candidates"]
    assert len(cut["budget"]["skipped_detail"]) == min(n - 1, 50)
    assert all(s["reason"] == "function_batch_limit"
               for s in cut["budget"]["skipped_detail"])


def test_budget_zero_analyzes_nothing_and_reports_it():
    """step_budget=0：分析覆盖率为 0，候选为 0，但必须显式报 skipped。"""
    rel = REL["bin_ls.elf"]
    res, _snap = _state(rel)
    rep = switchcand.analyze_binary(os.path.join(WORK, rel), res=res, step_budget=0)
    n = rep["functions_with_indirect_jmp"]
    assert rep["budget"]["functions_analyzed"] == 0
    assert rep["budget"]["functions_skipped_budget"] == n
    assert rep["budget"]["analysis_coverage"] == 0.0
    assert rep["stats"]["candidates"] == 0
    assert rep["functions"] == []
    text = switchcand.render_candidates(rep)
    assert "预算跳过 %d" % n in text
    assert "分母只含已分析函数" in text


def test_status_names_distinguish_no_run_from_budget_skip():
    """C2 反证：预算报告不得再用裸 "skipped"；整层未运行必须是 no_run。"""
    rel = REL["bin_ls.elf"]
    res, _snap = _state(rel)
    rep = switchcand.analyze_binary(os.path.join(WORK, rel), res=res)
    b = rep["budget"]
    assert b["run_status"] == switchcand.RUN_STATUS_OK
    assert b["run_status"] != switchcand.RUN_STATUS_NO_RUN
    assert b["functions_no_run"] == 0
    assert "skipped" not in b                      # 裸名禁用
    assert "functions_skipped_budget" in b
    assert set(b["status_semantics"]) >= {"run_status", "functions_analyzed",
                                          "functions_skipped_budget",
                                          "functions_no_run"}
    cut = switchcand.analyze_binary(os.path.join(WORK, rel), res=res,
                                    max_functions=1)
    assert all(s["skip_type"] == switchcand.SKIP_TYPE_BUDGET
               for s in cut["budget"]["skipped_detail"])
    assert cut["budget"]["run_status"] == switchcand.RUN_STATUS_OK
    text = switchcand.render_candidates(cut)
    assert "运行状态: ok" in text
    assert "预算跳过" in text


def test_budget_is_deterministic():
    """同一预算重复两次，预算计数/跳过名单/候选必须逐字节一致（不按墙钟）。"""
    rel = REL["bin_ls.elf"]
    res, _snap = _state(rel)
    kw = {"step_budget": 500}
    a = switchcand.analyze_binary(os.path.join(WORK, rel), res=res, **kw)
    b = switchcand.analyze_binary(os.path.join(WORK, rel), res=res, **kw)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["budget"]["functions_skipped_budget"] > 0
    assert a["budget"]["steps_used"] <= 500
