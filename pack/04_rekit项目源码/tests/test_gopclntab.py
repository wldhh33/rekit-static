# tests/test_gopclntab.py — M11：gopclntab 作为 declared 级种子源
#
# 断言分五层：
#   1) 解析：ELF/PE 版本、函数数、标记识别、入口严格递增且在 .text 内；
#   2) 版本边界：不支持的 magic 与篡改整表 → unknown 且 funcs 为空（不猜）；
#   3) 种子分级：gopclntab 与 entry/pdata 并列进 sources，不混成启发式、不合并计数；
#   4) PE RVA：表内 VA 必须减去 image_base 才能与 .pdata 同址合并；
#   5) A/B 增量：默认开启相对关闭时多出的种子与指令，仅来自可达域扩大。
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import elf, gopclntab, pe, recdesc  # noqa: E402

GO_ELF = "samples/m9/elf_medium_synth_go_stripped"
GO_PE = "samples/m9/pe_medium_synth_go_stripped.exe"
NON_GO = "tests/fixtures/cli-64.exe"


def _p(rel):
    return os.path.join(WORK, rel)


# ── 1. 解析 ─────────────────────────────────────────────────────────
def test_elf_parse_ok():
    r = gopclntab.parse(_p(GO_ELF))
    assert r["status"] == "ok"
    assert r["version"] == "go1.20+"
    assert r["magic"] == 0xFFFFFFF1
    assert r["nfunc"] == 8908 and len(r["funcs"]) == 8908
    fs = r["funcs"]
    assert fs[0]["entry"] == 0x401000
    assert all(b["entry"] > a["entry"] for a, b in zip(fs, fs[1:]))
    assert all(f["end"] > f["entry"] for f in fs)
    assert fs[-1]["end"] == r["text_end"]
    assert r["n_markers"] == 2
    assert {f["name"] for f in fs if f["is_marker"]} == {
        "go:textfipsstart", "go:textfipsend"}
    assert all(f["name"] for f in fs)


def test_pe_parse_ok_and_va_space():
    r = gopclntab.parse(_p(GO_PE))
    assert r["status"] == "ok" and r["nfunc"] == 8895
    base = pe.parse(_p(GO_PE))["image_base"]
    assert r["text_start"] == base + 0x1000
    assert all(f["entry"] >= r["text_start"] for f in r["funcs"])
    assert next(f for f in r["funcs"] if f["is_marker"])["name"] == "go:buildid"
    assert r["n_markers"] == 3


def test_elf_locates_by_section_name():
    shs = elf.section_headers(open(_p(GO_ELF), "rb").read())
    tab = next(s for s in shs if s["name"] == ".gopclntab")
    assert tab["size"] > 1_000_000
    assert gopclntab.parse(_p(GO_ELF))["where"] == "elf_section:.gopclntab"


# ── 2. 版本边界与负控 ───────────────────────────────────────────────
def _mutated(tmp_path, what):
    raw = bytearray(open(_p(GO_ELF), "rb").read())
    tab = next(s for s in elf.section_headers(bytes(raw))
               if s["name"] == ".gopclntab")
    off = tab["offset"]
    pcln_off = struct.unpack_from("<Q", raw, off + 64)[0]
    if what == "magic":
        struct.pack_into("<I", raw, off, 0xFFFFFFFB)
    elif what == "nfunc":
        struct.pack_into("<Q", raw, off + 8, 0)
    elif what == "entry_nonmono":
        struct.pack_into("<I", raw, off + pcln_off + 8, 0)
    elif what == "funcoff":
        struct.pack_into("<I", raw, off + pcln_off + 4, 0)
    elif what == "textstart":
        struct.pack_into("<Q", raw, off + 24, 0xDEADBEEF)
    else:
        raise ValueError(what)
    dst = tmp_path / ("bad_%s.bin" % what)
    dst.write_bytes(raw)
    return str(dst)


@pytest.mark.parametrize("what", ["magic", "nfunc", "entry_nonmono",
                                  "funcoff", "textstart"])
def test_tampered_table_is_unknown_not_guessed(tmp_path, what):
    r = gopclntab.parse(_mutated(tmp_path, what))
    assert r["status"] == "unknown"
    assert r["funcs"] == []
    assert r["nfunc"] == 0
    assert r["reason"]


def test_unsupported_magic_says_go12_to_15(tmp_path):
    r = gopclntab.parse(_mutated(tmp_path, "magic"))
    assert "go1.2-1.15" in r["reason"] and "未实现" in r["reason"]


def test_non_go_binary_is_not_ok():
    r = gopclntab.parse(_p(NON_GO))
    assert r["status"] != "ok" and r["funcs"] == []


# ── 3. 种子分级（按来源单列，不合并） ───────────────────────────────
def test_collect_seeds_keeps_gopclntab_separate():
    sec, seeds, rejected, notes, fmt = recdesc.collect_seeds(_p(GO_ELF))
    srcs = {s for e in seeds.values() for s in e["sources"]}
    assert "gopclntab" in srcs and "entry" in srcs
    assert "heuristic" not in srcs
    n_go = sum(1 for e in seeds.values() if "gopclntab" in e["sources"])
    assert n_go == 8908 - 2                     # 排除 2 条链接器标记
    entry = seeds[0x491BC0]
    assert set(entry["sources"]) == {"entry", "gopclntab"}
    assert entry["authority"] == recdesc.AUTH
    assert any("gopclntab go1.20+" in n for n in notes)
    assert rejected == []


def test_collect_seeds_off_restores_old_behaviour():
    _sec, seeds, _rej, notes, _fmt = recdesc.collect_seeds(
        _p(GO_ELF), gopclntab=False)
    assert {s for e in seeds.values() for s in e["sources"]} == {"entry"}
    assert all(e["end"] is None for e in seeds.values())
    assert any("gopclntab" not in n for n in notes)


def test_no_marker_enters_seeds():
    _sec, seeds, _rej, _notes, _fmt = recdesc.collect_seeds(_p(GO_PE))
    text = " ".join(d for e in seeds.values() for d in e["details"])
    assert "go:buildid" not in text
    assert "go:textfips" not in text


# ── 4. PE：VA→RVA 才能与 .pdata 同址 ────────────────────────────────
def test_pe_gopclntab_uses_rva_and_merges_with_pdata():
    _sec, off, _r, _n, _f = recdesc.collect_seeds(_p(GO_PE), gopclntab=False)
    _sec, on, _r, _n, _f = recdesc.collect_seeds(_p(GO_PE), gopclntab=True)
    base = pe.parse(_p(GO_PE))["image_base"]
    assert len(off) == 7153                     # entry 1 + pdata 7152
    assert len(on) == 8892                      # 1 + gopclntab 8892（-3 标记）
    assert max(on) < base                       # 全是 RVA，不是 VA
    only_go = [a for a in on if "gopclntab" in on[a]["sources"]
               and len(set(on[a]["sources"])) == 1]
    assert len(only_go) == 1739
    both = sum(1 for e in on.values()
               if {"pdata", "gopclntab"} <= set(e["sources"]))
    assert both == 7152


# ── 5. descend 集成与 A/B 增量 ──────────────────────────────────────
def test_descend_reports_sources_separately_and_default_is_on():
    r = recdesc.descend(_p(GO_ELF))
    ss = r["seed_stats"]
    assert ss["declared_by_source"] == {"entry": 1, "gopclntab": 8906}
    assert ss["declared_only_by_source"] == {"gopclntab": 8905}
    assert ss["end_conflicts"]["seeds"] == 0
    assert r["gopclntab"]["status"] == "ok"
    assert ss[recdesc.AUTH]["hit"] == ss[recdesc.AUTH]["total"]

    off = recdesc.descend(_p(GO_ELF), gopclntab=False)
    assert off["seed_stats"]["declared_by_source"] == {"entry": 1}
    assert off["gopclntab"] is None
    assert off["stats"]["instructions"] < r["stats"]["instructions"]


def test_pe_ab_increment_is_reachable_domain_only():
    off = recdesc.descend(_p(GO_PE), gopclntab=False)
    on = recdesc.descend(_p(GO_PE), gopclntab=True)
    assert off["seed_stats"]["declared_by_source"] == {"entry": 1, "pdata": 7152}
    assert on["seed_stats"]["declared_only_by_source"] == {"gopclntab": 1739}
    assert on["seed_stats"]["authoritative"]["total"] == 8892
    assert on["stats"]["instructions"] > off["stats"]["instructions"]
    # .pdata 与 gopclntab 的结束地址不一致必须单列归因，不许静默
    conf = on["seed_stats"]["end_conflicts"]
    assert conf["seeds"] > 0 and conf["by_pair"]
    assert all("<" in k for k in conf["by_pair"])
