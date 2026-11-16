# tests/test_vexaudit.py — M9 收敛线 B：伪 VEX/EVEX 弃权归因
#
# 断言：
#   1) 分类器四个分支都可达（伪造 starts 即可触发，不依赖样本里恰好出现）；
#   2) 真实样本上账目对平：lead_bytes = abstain_sites + decoded + len_diff + other；
#   3) 归因结论：现有 4 个样本上 decoder_defect == 0（若哪天不为 0，本测试失败，
#      逼着把缺陷当缺陷修，而不是继续叫 abstain）。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import coverage, vexaudit  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = [
    os.path.join(HERE, "fixtures", "cli-64.exe"),
    os.path.join(HERE, "fixtures", "bin_ls.elf"),
    os.path.join(HERE, "fixtures", "dyn_static"),
    os.path.join(HERE, "samples", "avx", "avx_dense.exe"),
]

needs_objdump = pytest.mark.skipif(coverage.objdump_exe() is None,
                                   reason="PATH 中没有 objdump")
_cache = {}


def _audit(path):
    if path not in _cache:
        _cache[path] = vexaudit.audit(path)
    return _cache[path]


# ── 1) 分类器分支 ────────────────────────────────────────────────────
def test_classifier_four_branches():
    starts = {0x10: {"addr": 0x10, "length": 4, "text": "vaddpd ymm0,ymm1,ymm2"},
              0x20: {"addr": 0x20, "length": 1, "text": "(bad)"},
              0x30: {"addr": 0x30, "length": 2, "text": "mov eax,ebx"}}
    k, _ = vexaudit.classify_one(starts, 0x10, 0xC5)
    assert k == vexaudit.CAT_DECODER_DEFECT
    k, _ = vexaudit.classify_one(starts, 0x20, 0x62)
    assert k == vexaudit.CAT_ILLEGAL
    k, _ = vexaudit.classify_one(starts, 0x99, 0xC4)
    assert k == vexaudit.CAT_NOT_START
    k, _ = vexaudit.classify_one(starts, 0x30, 0xC5)
    assert k == vexaudit.CAT_NONVEX


# ── 1b) C1：分类名必须等于判据，不得暗示“数据/不在代码里” ────────────
def test_category_name_is_criterion_not_data_semantics():
    assert vexaudit.CAT_NOT_START == "not_objdump_insn_start"
    assert "data" not in vexaudit.CAT_NOT_START
    assert "不等于" in vexaudit.CRITERION["not_objdump_insn_start"]


def test_classification_ignores_declared_domain():
    """反证：若有人把判据改成“域内=代码、域外=数据”，本测试必须失败。"""
    starts = {0x10: {"addr": 0x10, "length": 4, "text": "nop"}}
    k, _ = vexaudit.classify_one(starts, 0x12, 0xC5)   # 0x12 在 [0x10,0x14) 内
    assert k == vexaudit.CAT_NOT_START


def test_domain_accounting_reports_inside_and_outside():
    d = vexaudit.domain_accounting([0x11, 0x22, 0x33],
                                   [(0x10, 0x20), (0x22, 0x24)])
    assert d["provided"] is True and d["ranges"] == 2
    assert d["abstain_in_domain"] == 2 and d["abstain_out_domain"] == 1
    assert d["in_domain_ratio"] == pytest.approx(2 / 3)
    off = vexaudit.domain_accounting([0x11], None)
    assert off["provided"] is False and off["in_domain_ratio"] is None


def test_vex_categories_are_exactly_the_classified_ones():
    assert vexaudit.VEX_CATEGORIES == {"vex_legacy_prefix", "vex_map_undefined",
                                       "evex_reserved", "evex_map0"}


# ── 2) 账目对平 ──────────────────────────────────────────────────────
@needs_objdump
@pytest.mark.parametrize("path", SAMPLES)
def test_audit_reconciles(path):
    r = _audit(path)
    assert r["status"] == "ok"
    assert r["lead_bytes"] == (r["abstain_sites"] + r["other_abstains"]
                               + r["counts"].get(vexaudit.CAT_DECODED, 0)
                               + r["counts"].get(vexaudit.CAT_LEN_DIFF, 0))
    assert r["classified"] == sum(r["counts"].values())


# ── 3) 归因结论：不得有解码器缺陷 ───────────────────────────────────
@needs_objdump
@pytest.mark.parametrize("path", SAMPLES)
def test_no_decoder_defect_on_samples(path):
    r = _audit(path)
    assert r["decoder_defect"] == 0, (
        "objdump 在 0x%x 解出合法 VEX，我方却弃权：这是解码器缺陷，不是 abstain"
        % (r["samples"].get(vexaudit.CAT_DECODER_DEFECT, [{}])[0].get("addr", 0)))
    # 每条“确实非法”的证据必须真的是 (bad)
    for it in r["samples"].get(vexaudit.CAT_ILLEGAL, []):
        assert it["objdump"].startswith("(bad)")
