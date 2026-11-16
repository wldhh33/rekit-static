# tests/test_strxref.py — M8-U3：字符串/数据引用交叉
#
# 断言按验收五条组织：
#   1) 口径可钉住：编码/最短长度/终止/重叠/白名单 各有一条合成字节单测；
#      二进制段、高字节段、短段、节尾无 NUL 必须**不报**（宁可少报）；
#   2) 分母先行：unique/multi/no_site 三态可加和，no_site 四类归因可加和；
#   3) 引用点：target 必须恰是字符串起点；unique ⇔ 恰 1 个站点；imm 有下限；
#   4) 与既有层一致：引用点若同时是 callfacts 站点，函数归属/字节不得矛盾；
#   5) 零值可解释：没有白名单节 / 白名单节里没有可打印段 必须分开说。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import strxref as SX  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(WORK))
BASE = os.path.join(HERE, "fixtures")
SAMPLES = os.path.join(ROOT, "m2-task-card", "work", "samples")
BINLS = os.path.join(BASE, "bin_ls.elf")
CLI = os.path.join(BASE, "cli-64.exe")
DYN_STATIC = os.path.join(BASE, "dyn_static")
DYN_NOPIE = os.path.join(BASE, "dyn_nopie")
MINIDLL = os.path.join(BASE, "minidll.dll")
GO_LINUX = os.path.join(SAMPLES, "hello_go_linux")

_cache = {}


def _rep(path):
    if path not in _cache:
        _cache[path] = SX.build(path)
    return _cache[path]


# ── 1) 口径单测（合成字节）──────────────────────────────────────────
def test_caliber_two_nul_terminated_strings():
    got, st = SX.scan_blob(b"hello\x00world\x00", 0x1000)
    assert [(g["addr"], g["length"], g["text"]) for g in got] == \
        [(0x1000, 5, "hello"), (0x1006, 5, "world")]
    assert st["accepted"] == 2 and st["rejected_binary"] == 0


def test_caliber_min_len_is_four():
    got, st = SX.scan_blob(b"abc\x00abcd\x00", 0)
    assert [g["text"] for g in got] == ["abcd"]
    assert st["rejected_short"] == 1 and st["rejected_short_bytes"] == 3


def test_caliber_rejects_binary_segment():
    got, st = SX.scan_blob(b"hel\x01lo\x00", 0)
    assert got == [] and st["rejected_binary"] == 1
    # 段内混入控制字符：整段不报（不做「可打印子串」二次切分）
    got2, _ = SX.scan_blob(b"hello\x07world\x00", 0)
    assert got2 == []


def test_caliber_rejects_high_bytes_no_utf8_guess():
    got, st = SX.scan_blob(b"caf\xc3\xa9\x00", 0)
    assert got == [] and st["rejected_high"] == 1


def test_caliber_no_nul_tail_not_reported():
    got, st = SX.scan_blob(b"hello", 0)
    assert got == [] and st["no_nul_tail"] == 1 and st["no_nul_tail_bytes"] == 5


def test_caliber_no_overlapping_strings():
    """按 NUL 切分 → 互不相交；父串里的子串不会被单独报出。"""
    got, _ = SX.scan_blob(b"foobar\x00quux\x00", 0)
    addrs = [g["addr"] for g in got]
    assert addrs == [0, 7]
    assert 3 not in addrs                     # "bar"（父串内部）不报


def test_caliber_allowed_whitelist():
    assert SX._allowed(".rodata")
    assert SX._allowed(".rodata.str1.1")
    assert SX._allowed(".rdata")
    assert not SX._allowed(".rodata.cst8")    # 常量池明确排除
    assert not SX._allowed(".data")
    assert not SX._allowed(".data.rel.ro")
    assert not SX._allowed(".text")
    assert not SX._allowed(".edata")


# ── 2) 真实样本：分母与可加和 ───────────────────────────────────────
@pytest.mark.skipif(not os.path.isfile(BINLS), reason="缺 bin_ls.elf")
def test_denominator_adds_up():
    r = _rep(BINLS)
    c = r["counts"]
    assert c["strings_total"] > 0
    assert c["strings_total"] == (c["strings_unique"] + c["strings_multi"]
                                  + c["strings_no_site"])
    assert c["strings_no_site"] == sum(c["no_site_reason"].values())
    assert c["sites_total"] == (c["sites_rip_mem"] + c["sites_lea_rip"]
                                + c["sites_imm"])
    assert c["sites_total"] == (c["sites_with_function"]
                                + c["sites_without_function"])
    assert c["sections_scanned"] == 1


@pytest.mark.skipif(not os.path.isfile(BINLS), reason="缺 bin_ls.elf")
def test_every_site_target_is_a_string_start():
    r = _rep(BINLS)
    starts = {d["addr"] for d in r["strings_detail"]}
    for s in r["sites"]:
        assert s["target"] in starts
        assert s["string"] == s["target"]
        assert s["kind"] in ("rip_mem", "lea_rip", "imm")
        assert isinstance(s["arith"], str) and "0x" in s["arith"]


@pytest.mark.skipif(not os.path.isfile(BINLS), reason="缺 bin_ls.elf")
def test_unique_iff_exactly_one_site():
    r = _rep(BINLS)
    by = {}
    for s in r["sites"]:
        by.setdefault(s["string"], []).append(s["addr"])
    for d in r["strings_detail"]:
        n = len(by.get(d["addr"], []))
        assert d["status"] == ("unique" if n == 1 else
                              "multi" if n > 1 else "no_site")
        assert len(d["sites"]) == n


# ── 3) 引用点：立即数下限 / 数据指针不算引用点 ──────────────────────
def test_immediate_below_threshold_is_not_a_site():
    """imm 值 < 0x100000 时一律不算引用点（PIE 低地址与小整数不可区分）。"""
    ins = {"addr": 0x1000, "length": 10,
           "bytes": "48 bf 00 00 30 00 00 00 00 00", "opcode_map": 1}
    res = {"instructions": [ins]}
    low, _ = SX._sites(res, {0x3000: {"addr": 0x3000}})
    assert low == []
    high, _ = SX._sites(res, {0x300000: {"addr": 0x300000}})
    assert len(high) == 1 and high[0]["kind"] == "imm" and \
        high[0]["target"] == 0x300000


@pytest.mark.skipif(not os.path.isfile(CLI), reason="缺 cli-64.exe")
def test_pointer_table_is_evidence_not_a_site():
    """数据节里的指针值只作归因证据，不产生引用点。"""
    r = _rep(CLI)
    d = next(x for x in r["strings_detail"] if x["text"] == "-script.py")
    assert d["status"] == "no_site" and d["reason"] == "indirect"
    assert d["sites"] == []
    assert d["evidence"]["indirect"]
    targets = {s["target"] for s in r["sites"]}
    assert d["addr"] not in targets


@pytest.mark.skipif(not os.path.isfile(CLI), reason="缺 cli-64.exe")
def test_pointers_into_string_interior_are_suffix_not_sites():
    r = _rep(CLI)
    adds = {h["addr"] for h in r["suffix_refs"]}
    assert all(h["string"] < h["target"] <
               h["string"] + next(x["length"] for x in r["strings_detail"]
                                  if x["addr"] == h["string"])
               for h in r["suffix_refs"])
    assert all(a not in {s["addr"] for s in r["sites"]} for a in adds)


# ── 4) 与既有层对账 ─────────────────────────────────────────────────
@pytest.mark.skipif(not os.path.isfile(BINLS), reason="缺 bin_ls.elf")
def test_crosscheck_with_callfacts_has_no_conflict():
    from rekit import callfacts as CF, callgraph as CG, recdesc
    res = recdesc.descend(BINLS)
    facts = CF.build(BINLS, res=res)
    graph = CG.build(BINLS, res=res)
    r = SX.build(BINLS, res=res, facts=facts, graph=graph)
    cc = r["crosscheck"]
    assert cc is not None
    assert cc["ok"], cc["conflicts"][:3]
    assert cc["checked"] >= 0


# ── 5) 零值可解释 ───────────────────────────────────────────────────
@pytest.mark.skipif(not os.path.isfile(MINIDLL), reason="缺 minidll.dll")
def test_zero_strings_names_the_missing_section():
    r = _rep(MINIDLL)
    c = r["counts"]
    assert c["strings_total"] == 0
    assert c["sections_scanned"] == 0
    assert "白名单只读数据节缺失" in c["strings_zero_reason"]


@pytest.mark.skipif(not os.path.isfile(DYN_NOPIE), reason="缺 dyn_nopie")
def test_zero_strings_with_section_present_is_told_apart():
    r = _rep(DYN_NOPIE)
    c = r["counts"]
    assert c["strings_total"] == 0
    assert c["sections_scanned"] == 1          # .rodata 存在但只有 4 字节
    assert "没有 NUL 终止的可打印 ASCII 段" in c["strings_zero_reason"]


# ── Go/Rust 结构性少报必须写明 ──────────────────────────────────────
def test_go_length_delimited_underreport_is_documented():
    text = " ".join(SX.CAVEATS)
    assert "Go/Rust" in text and "少报" in text


@pytest.mark.skipif(not os.path.isfile(GO_LINUX), reason="缺 Go 样本")
def test_go_sample_reports_rejection_bytes_not_silent_zero():
    r = _rep(GO_LINUX)
    rej = r["counts"]["rejected"]
    # Go 的 .rodata 是长度分界的打包数据：大量长段被拒，必须留下字节数
    assert rej["rejected_binary"] > 0
    assert rej["rejected_binary_bytes"] > 0
