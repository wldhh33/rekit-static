# tests/test_coverage.py — M9 收敛线 C：覆盖率报告口径
#
# 断言只钉三件事：
#   1) 恒等式成立：ours_total = 匹配+分歧+仅我方；denominator = 匹配+分歧+仅外部；
#      ratio 必须等于 分子/分母，不能另算一套；
#   2) “没量到”不写 0：objdump 不可用时 numerator/denominator/ratio 全是 None；
#   3) 分歧不进分子：同址不同长计入 len_conflict，分子只认同址同长；
#      批量汇总的 sampled 口径必须带子集名单。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import coverage  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(WORK))
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
UPX = os.path.join(HERE, "samples", "fingerprint", "upx", "upx_dyn_pie")

needs_objdump = pytest.mark.skipif(coverage.objdump_exe() is None,
                                   reason="PATH 中没有 objdump")

_cache = {}


def _rep():
    if "cli" not in _cache:
        _cache["cli"] = coverage.build(CLI)
    return _cache["cli"]


@needs_objdump
def test_identity_and_ratio():
    r = _rep()
    assert r["status"] == "ok"
    assert r["identity_ok"] is True
    assert r["ours_total"] == r["matched"] + r["len_conflict"] + r["ours_only"]
    assert r["denominator"] == r["matched"] + r["len_conflict"] + r["objdump_only"]
    assert r["numerator"] == r["matched"]
    assert r["denominator"] > 0
    assert abs(r["ratio"] - r["numerator"] / r["denominator"]) < 1e-12
    assert r["denominator_scope"] and r["numerator_scope"]


@needs_objdump
def test_len_conflict_not_counted_in_numerator():
    r = _rep()
    obj = coverage.objdump_instructions(CLI, {"va": 0x1000, "size": r["section_bytes"]})
    if obj["status"] != "ok" or not obj["instructions"]:
        pytest.skip("objdump 对该样本不可用")
    first = obj["instructions"][0]
    res = {"instructions": [{"addr": first["addr"],
                             "length": first["length"] + 1,
                             "status": "ok"}],
           "stats": {}}
    bad = coverage.build(CLI, res=res, objdump=obj)
    # 同址不同长 → 必须归 len_conflict，分子不动
    assert bad["len_conflict"] == 1
    assert bad["numerator"] == 0


def test_unavailable_is_none_not_zero():
    res = {"instructions": [], "stats": {}}
    obj = {"status": "unavailable", "instructions": [], "bad": 0,
           "error": "PATH 中找不到 objdump", "command": None}
    r = coverage.build(CLI, res=res, objdump=obj)
    assert r["status"] == "unavailable"
    assert r["numerator"] is None and r["denominator"] is None
    assert r["ratio"] is None


@needs_objdump
def test_aggregate_scope_rules():
    r = _rep()
    with pytest.raises(ValueError):
        coverage.aggregate([r], scope="sampled")
    with pytest.raises(ValueError):
        coverage.aggregate([r], scope="whatever")
    a = coverage.aggregate([r], scope="full")
    assert a["numerator"] == r["numerator"]
    assert a["denominator"] == r["denominator"]


def test_no_section_is_structural_not_zero():
    r = coverage.build(UPX)
    assert r["status"] == "no_section"
    assert r["ratio"] is None and r["denominator"] is None
