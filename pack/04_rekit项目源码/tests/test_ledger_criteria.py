#!/usr/bin/env python3
# test_ledger_criteria.py — C1–C5 的机器可检约束（M13-patch）
#
# 这些测试直接读 evidence_m13_ledger.json 与 evidence_m14_c4_alignment.json。
# 目的不是复算数字，而是保证“结论的类别与措辞”不会在下次更新时退回去：
#   C1  VEX 分类名 = 非 objdump 指令起点，且同报域内比例
#   C3  strxref 5,039 的类别是补集度量，不是下界
#   C4  Go 域内未达指令声明“含对齐”，且对齐占比有实测支撑
#   C5  analysis_coverage（skipped/no_run）不得出现在 lower_bounds
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
LEDGER = os.path.join(WORK, "evidence_m13_ledger.json")
C4_EVIDENCE = os.path.join(WORK, "evidence_m14_c4_alignment.json")


@pytest.fixture(scope="module")
def led():
    with open(LEDGER, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def c4():
    with open(C4_EVIDENCE, encoding="utf-8") as f:
        return json.load(f)


def _by_id(rows, ident):
    return next(r for r in rows if r["id"] == ident)


def _all_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_keys(v)


def test_bound_table_policy_is_declared(led):
    pol = led["bound_table_policy"]
    assert pol["rule"] == "R107"
    assert "analysis_coverage" in pol["excluded"]
    assert set(pol["required_fields"]) >= {"id", "bound_type", "criterion",
                                           "denominator", "evidence", "verdict"}
    for row in led["lower_bounds"]:
        assert row["bound_type"] in pol["allowed_bound_types"]
        for k in pol["required_fields"]:
            assert k in row and row[k], "%s 缺字段 %s" % (row["id"], k)


def test_strxref_is_complement_measure(led):
    row = _by_id(led["lower_bounds"], "strxref")
    assert row["bound_type"] == "complement_measure"
    assert row["is_lower_bound"] is False
    assert "补集" in row["verdict"] or "补集" in row["criterion"]


def test_vex_category_name_and_domain_ratio(led):
    row = _by_id(led["lower_bounds"], "vex")
    assert row["category_label"].startswith("not_objdump_insn_start")
    assert "data_not_instruction（M9" not in row["category_label"]
    d = row["in_domain_ratio"]
    assert d["elf_synth"].startswith("16,332 / 16,332")
    assert d["pe_synth"].startswith("16,177 / 16,179")


def test_go_domain_declares_alignment_share(led, c4):
    row = _by_id(led["lower_bounds"], "go_domain")
    assert row["includes_alignment_bytes"] is True
    assert "含对齐" in row["name"] or "含对齐" in row["criterion"]
    assert "漏解的指令数" in row["not_equivalent_to"]
    assert row["alignment_share"]["elf_synth"] == pytest.approx(
        c4["go_elf"]["nop_like_share"])
    assert row["alignment_share"]["pe_synth"] == pytest.approx(
        c4["go_pe"]["nop_like_share"])
    # 反证：对齐必须真的存在；若测量变成 0，则“含对齐”这个说法也应被推翻
    assert c4["go_elf"]["nop_like"] > 0
    assert c4["go_pe"]["nop_like"] > 0


def test_no_analysis_coverage_in_lower_bounds(led):
    ids = {r["id"] for r in led["lower_bounds"]}
    assert "switchcand" not in ids
    for r in led["lower_bounds"]:
        assert r["bound_type"] != "analysis_coverage"
        assert "skipped" not in set(_all_keys(r))
    cov = _by_id(led["analysis_coverage"], "switchcand")
    assert cov["run_status"]["lto1"] == "no_run"
    assert cov["run_status"]["cc1"] == "ok"
    assert "不是候选数的下界" in cov["not_a_bound"]
    assert "skipped" not in set(_all_keys(cov))


def test_status_field_inventory_lists_known_collisions(led):
    inv = led["status_field_inventory"]
    assert "skipped" in inv["policy"]
    fields = "\n".join(i["field"] for i in inv["items"])
    for token in ("switchcand.budget", "sitejoin", "expr.lift_binary",
                  "callfacts", "iat"):
        assert token in fields
    fixed = [i for i in inv["items"] if i["status"] == "fixed"]
    assert {i["field"].split(".")[0] for i in fixed} >= {"switchcand", "sitejoin"}


def test_all_criterion_issues_are_fixed_with_test_refs(led):
    for c in led["criterion_issues"]:
        assert c["status"] == "fixed", c["id"]
        assert c["fix"] and c["test"] and c["not_a_relaxation"], c["id"]
        assert "tests/" in c["test"], c["id"]
