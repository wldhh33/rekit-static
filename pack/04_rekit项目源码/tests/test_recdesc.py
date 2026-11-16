#!/usr/bin/env python3
"""M4 第二单元断言：递归下降 + 基本块划分。

钉死的四件事（对应本轮硬要求）：
  1. 种子分权威/启发式/派生三类；权威与启发式的成功率字段永不合并；
  2. 下降规则（jmp/jcc/call/ret/间接）与基本块 leader/后继语义；
  3. 边界真指令性的本地可证部分：每条指令 bytes 长度自洽、块内连续、
     FDE/symtab/.pdata 声明的函数起点全部解出（外部 objdump/capstone 对拍
     在 tests/verify_recdesc.py）；
  4. VEX abstain 必须量化：唯一弃权点、受影响 seed 数，而不是“未量化”。

依赖外部二进制的逐行矩阵在 verify_recdesc.py；本文件不要求 objdump 在 PATH。
"""
import json
import os
import sys

import pytest

from rekit import cli, disasm, elf, recdesc

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
CLI64 = os.path.join(FIX, "cli-64.exe")
MINIDLL = os.path.join(FIX, "minidll.dll")
PIE = os.path.join(FIX, "dyn_pie")
NOPIE = os.path.join(FIX, "dyn_nopie")
LS = os.path.join(FIX, "bin_ls.elf")
DYN_STATIC = os.path.join(FIX, "dyn_static")
AVX = os.path.join(ROOT, "tests", "samples", "avx", "avx_dense.exe")


# ── 种子来源与分级 ───────────────────────────────────────────────
def test_pe_seeds_are_authoritative_and_include_pdata_exports_entry():
    sec, seeds, rejected, notes, fmt = recdesc.collect_seeds(CLI64)
    assert fmt == "pe"
    src = set(s for e in seeds.values() for s in e["sources"])
    assert "pdata" in src and "entry" in src
    # cli-64.exe 的 .pdata 有 41 条 RUNTIME_FUNCTION
    assert sum(1 for e in seeds.values() if "pdata" in e["sources"]) == 41
    assert all(e["authority"] == recdesc.AUTH for e in seeds.values())
    assert any("RUNTIME_FUNCTION 41" in n for n in notes)
    # .pdata 给了函数结束地址（用于阻止顺序流外溢）
    pd = [e for e in seeds.values() if "pdata" in e["sources"]]
    assert all(e["end"] and e["end"] > e["addr"] for e in pd)


def test_pe_export_and_ordinal_seeds():
    sec, seeds, _rej, notes, fmt = recdesc.collect_seeds(MINIDLL)
    exported = [e for e in seeds.values() if "export" in e["sources"]]
    assert fmt == "pe" and len(exported) >= 4
    # 纯序号导出（name=None）也要有种子
    assert any("(ordinal)" in e["details"] for e in exported)
    assert all(e["authority"] == recdesc.AUTH for e in exported)


def test_elf_seeds_include_entry_symtab_and_fde():
    sec, seeds, _rej, notes, fmt = recdesc.collect_seeds(NOPIE)
    src = set(s for e in seeds.values() for s in e["sources"])
    assert fmt == "elf"
    assert "entry" in src
    assert "symtab_func" in src or "dynsym_func" in src
    assert "eh_frame_fde" in src
    assert all(e["authority"] == recdesc.AUTH for e in seeds.values())


def test_eh_frame_parse_gives_fde_starts_inside_text():
    data = open(PIE, "rb").read()
    sec = disasm.find_section(PIE)
    eh = next(s for s in elf.section_headers(data) if s["name"] == ".eh_frame")
    fdes, err = recdesc._parse_eh_frame(data, eh)
    assert err is None and len(fdes) >= 3
    inside = [f for f in fdes if sec["va"] <= f[0] < sec["va"] + sec["size"]]
    # 这个探针样本的 .text 只有 0xf4 字节（0x1040..0x1134），实际落入节内的
    # FDE 起点是 2 个（0x1040/0x1129）；其余 FDE 指向 runtime stub 等外部区段。
    assert len(inside) >= 2
    assert inside[0][0] == sec["va"], "首个 FDE 应覆盖 .text 首地址"
    assert all(rng >= 0 for (_loc, rng, _d) in fdes)


def test_heuristic_seeds_are_separate_and_do_not_change_authoritative_rate():
    base = recdesc.descend(NOPIE)
    with_h = recdesc.descend(NOPIE, include_heuristic=True)
    assert base["seed_stats"][recdesc.HEUR]["total"] == 0
    assert with_h["seed_stats"][recdesc.HEUR]["total"] >= 1
    # 权威种子的总数/命中数不能因为加了启发式而改变
    for k in ("total", "hit"):
        assert with_h["seed_stats"][recdesc.AUTH][k] == base["seed_stats"][recdesc.AUTH][k]
    assert with_h["seed_stats"][recdesc.DERIVED]["total"] >= 0


# ── 控制流分类 ───────────────────────────────────────────────────
def _one(hexbytes, addr=0x1000):
    """用 _decode_any 的直接返回构造 ins：sweep_bytes 的结果不带 `opcode` 键。"""
    data = bytes.fromhex(hexbytes.replace(" ", ""))
    ln, meta = disasm._decode_any(data, 0, len(data))
    return {"addr": addr, "off": 0, "length": ln,
            "bytes": data[:ln].hex(" "),
            "opcode": meta.get("opcode"), "opcode_map": meta.get("opcode_map")}


@pytest.mark.parametrize("hexbytes,kind,target", [
    ("e8 05 00 00 00", "call_rel", 0x100A),
    ("e9 fb ff ff ff", "jmp_rel", 0x1000),
    ("eb fe", "jmp_rel", 0x1000),
    ("75 10", "jcc_rel", 0x1012),
    ("e2 10", "loop_rel", 0x1012),
    ("0f 87 98 00 00 00", "jcc_rel32", 0x109E),
    ("ff 25 00 00 00 00", "jmp_ind", None),
    ("ff 15 00 00 00 00", "call_ind", None),
    ("c3", "ret", None),
    ("c2 08 00", "ret", None),
    ("f4", "hlt", None),
    ("cc", "trap", None),
    ("0f 0b", "ud2", None),
    ("90", "next", None),
    ("0f 05", "next", None),
])
def test_classify_flow(hexbytes, kind, target):
    ins = _one(hexbytes)
    got_kind, got_tgt = recdesc.classify(ins)
    assert got_kind == kind
    if target is not None:
        assert got_tgt == target


def test_classify_ff_reg_forms():
    assert recdesc.classify(_one("ff d0"))[0] == "call_ind"      # call rax
    assert recdesc.classify(_one("ff e0"))[0] == "jmp_ind"       # jmp rax
    assert recdesc.classify(_one("ff d7"))[0] == "call_ind"      # call rdi


# ── 递归下降结果（真实样本） ─────────────────────────────────────
def test_cli64_descend_covers_authoritative_seeds_without_abstain():
    r = recdesc.descend(CLI64)
    ss = r["seed_stats"]
    assert r["stats"]["abstains"] == 0
    assert ss[recdesc.AUTH]["total"] == 41 and ss[recdesc.AUTH]["hit"] == 41
    assert r["stats"]["instructions"] > 1000
    assert r["stats"]["coverage"] > 0.9


def test_instruction_bytes_length_selfconsistent():
    r = recdesc.descend(CLI64)
    for ins in r["instructions"][:500]:
        raw = bytes.fromhex(ins["bytes"].replace(" ", ""))
        assert len(raw) == ins["length"]
        assert ins["length"] > 0


def test_blocks_partition_every_instruction_exactly_once():
    r = recdesc.descend(CLI64)
    all_addrs = [i["addr"] for i in r["instructions"]]
    seen = []
    for b in r["blocks"]:
        assert b["insns"], "空基本块"
        assert b["end"] == b["insns"][-1] + next(
            i["length"] for i in r["instructions"] if i["addr"] == b["insns"][-1])
        # 块内连续
        for a, nxt in zip(b["insns"], b["insns"][1:]):
            ln = next(i["length"] for i in r["instructions"] if i["addr"] == a)
            assert a + ln == nxt
        seen.extend(b["insns"])
    assert seen == all_addrs          # 无重复、无遗漏、顺序一致
    decoded = set(all_addrs)
    for b in r["blocks"]:
        assert set(b["successors"]) <= decoded
        assert b["terminator"] in {
            "next", "jmp_rel", "jmp_ind", "jcc_rel", "jcc_rel32", "loop_rel",
            "call_rel", "call_ind", "ret", "hlt", "trap", "ud2"}


def test_function_end_limits_stop_fallthrough_into_padding():
    # cli-64.exe 每个 .pdata 范围都有 end；顺序流不得越过 end 仍在同一根路径里
    r = recdesc.descend(CLI64)
    seeds = {s["addr"]: s for s in r["seeds"]}
    for ins in r["instructions"]:
        org = ins.get("origin")
        s = seeds.get(org)
        if s and s.get("end"):
            assert ins["addr"] + ins["length"] <= s["end"], (
                "指令 0x%x 越出函数 0x%x..0x%x" %
                (ins["addr"], s["addr"], s["end"]))


def test_elf_partial_coverage_and_no_abstain():
    r = recdesc.descend(LS)
    assert r["stats"]["abstains"] == 0
    # stripped PIE 只有 FDE 种子；全部命中
    assert r["seed_stats"][recdesc.AUTH]["hit"] == r["seed_stats"][recdesc.AUTH]["total"]
    assert 0.5 < r["stats"]["coverage"] < 0.95


def test_avx_sample_no_longer_abstains_after_vex_table():
    """M5 补 VEX/EVEX 长度表后：AVX 密集样本必须 5/5 解出，弃权点归零。

    M4 基线（补表前）：权威 2/5、abstain 3 点、覆盖 <35%（见
    evidence_m4_closeout_2026-11-15.log §标准④）。补表后若又退回弃权，
    这里必须直接失败，不允许用"AVX 难"掩盖。
    """
    if not os.path.exists(AVX):
        pytest.skip("AVX 样本未构建")
    r = recdesc.descend(AVX)
    ss = r["seed_stats"]
    assert ss[recdesc.AUTH]["total"] == 5
    assert ss[recdesc.AUTH]["hit"] == 5
    assert r["stats"]["abstains"] == 0
    assert r["stats"]["coverage"] > 0.9
    assert r["stats"]["bytes_covered"] == sum(
        i["length"] for i in r["instructions"])


def test_avx_linear_vs_recursive_are_both_complete_now():
    """补表后线性扫描不再死在第一条 VEX 上：两个通道都能扫到节尾。"""
    if not os.path.exists(AVX):
        pytest.skip("AVX 样本未构建")
    lin = disasm.sweep_file(AVX)
    rec = recdesc.descend(AVX)
    assert lin["stopped"] is None
    # 线性会跨进对齐填充/数据；只要求递归解出的指令全被线性覆盖
    lin_addrs = set(i["addr"] for i in lin["instructions"] if i["status"] == "ok")
    rec_addrs = set(i["addr"] for i in rec["instructions"])
    assert rec_addrs <= lin_addrs


# ── CLI 通道 ────────────────────────────────────────────────────
def test_cli_recdesc_text_and_json(capsys):
    assert cli.main(["recdesc", CLI64]) == 0
    out = capsys.readouterr().out
    assert "RECDESC" in out and "基本块" in out and "权威" in out
    assert "启发式" in out

    assert cli.main(["recdesc", CLI64, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["instructions"] > 1000
    assert "seed_stats" in payload
    assert payload["caveats"]


def test_cli_recdesc_missing_file_returns_2(capsys):
    assert recdesc.main([os.path.join(FIX, "no-such-file.bin")]) == 2


def test_cli_recdesc_heuristic_flag(capsys):
    assert cli.main(["recdesc", NOPIE, "--heuristic", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["seed_stats"][recdesc.HEUR]["total"] >= 1


# ── 基本块 / CFG 边分级（M4 第三单元） ──────────────────────────
def _runs():
    paths = [CLI64, LS, DYN_STATIC, PIE, NOPIE]
    if os.path.exists(AVX):
        paths.append(AVX)
    return [recdesc.descend(p) for p in paths]


def test_blocks_are_function_scoped():
    """块只属于一个函数：块内每条指令的 origin 必须等于块的 function。"""
    for r in _runs():
        by_addr = {i["addr"]: i for i in r["instructions"]}
        for b in r["blocks"]:
            assert b["function"] in by_addr
            assert b["boundary"] in ("declared", "unknown")
            assert b["range"][0] == b["function"]
            assert all(by_addr[a]["origin"] == b["function"] for a in b["insns"])
            if b["boundary"] == "declared":
                assert b["range"][1] and b["end"] <= b["range"][1]
            else:
                assert b["range"][1] is None


def test_cfg_definite_edges_are_decoded_intra_function():
    """确定边：目标已解出、同函数、源函数有权威声明边界，且连线落在目标块内。"""
    for r in _runs():
        by_addr = {i["addr"]: i for i in r["instructions"]}
        blocks = {b["start"]: b for b in r["blocks"]}
        for e in r["cfg"]["edges"]["definite"]:
            assert e["to"] is not None and e["to"] in by_addr
            src = blocks[e["from"]]
            assert src["boundary"] == "declared"
            assert by_addr[e["to"]]["origin"] == src["function"]
            tb = blocks[e["to_block"]]
            assert e["to"] in tb["insns"]


def test_cfg_speculative_never_mixed_into_definite():
    """疑似边与确定边互斥；疑似边只来自无声明边界或启发式根。"""
    for r in _runs():
        key = lambda e: (e["from"], e["to"], e["kind"])
        d = set(key(e) for e in r["cfg"]["edges"]["definite"])
        s = set(key(e) for e in r["cfg"]["edges"]["speculative"])
        assert not (d & s)
        by_start = {b["start"]: b for b in r["blocks"]}
        for e in r["cfg"]["edges"]["speculative"]:
            b = by_start[e["from"]]
            assert b["boundary"] == "unknown" or b["authority"] == recdesc.HEUR


def test_cfg_indirect_edges_are_unresolved_without_guessed_target():
    """间接 jmp/call 必须 target=None；调用边单列，不混进函数内边。"""
    r = recdesc.descend(CLI64)
    un = r["cfg"]["edges"]["unresolved"]
    assert un and all(e["to"] is None and e["kind"] == "jmp_ind" for e in un)
    cu = r["cfg"]["calls"]["unresolved"]
    assert cu and all(e["to"] is None for e in cu)
    assert all(e["to"] is not None for e in r["cfg"]["edges"]["definite"])
    assert all(e["to"] is not None for e in r["cfg"]["calls"]["definite"])


def test_cfg_cross_function_edges_are_separate():
    """跨函数边单列：目标属于另一个 origin，且不出现在函数内确定边里。"""
    r = recdesc.descend(CLI64)
    cross = r["cfg"]["edges"]["cross_function"]
    assert cross, "cli-64 应有跨函数边"
    by_addr = {i["addr"]: i for i in r["instructions"]}
    by_start = {b["start"]: b for b in r["blocks"]}
    intra = set((e["from"], e["to"], e["kind"])
                for e in r["cfg"]["edges"]["definite"])
    for e in cross:
        assert e["to"] is not None and e["to"] in by_addr
        src = by_start[e["from"]]
        assert by_addr[e["to"]]["origin"] != src["function"]
        assert e["to_boundary"] in ("declared", "unknown")
        assert (e["from"], e["to"], e["kind"]) not in intra


def test_avx_without_declared_boundary_has_no_definite_edges():
    """没有 .pdata/符号/FDE 结束界时，边只能记疑似，不得冒充确定边。"""
    if not os.path.exists(AVX):
        pytest.skip("AVX 样本未构建")
    r = recdesc.descend(AVX)
    assert r["stats"]["edges_definite"] == 0
    assert r["stats"]["edges_speculative"] > 0


def test_cfg_counts_match_edge_lists_and_text(capsys):
    r = recdesc.descend(CLI64)
    st = r["stats"]
    for cls in recdesc._EDGE_CLASSES:
        assert st["edges_" + cls] == len(r["cfg"]["edges"][cls])
    for cls in recdesc._CALL_CLASSES:
        assert st["calls_" + cls] == len(r["cfg"]["calls"][cls])
    assert st["blocks"] == len(r["blocks"]) == len(set(b["start"] for b in r["blocks"]))
    assert cli.main(["recdesc", CLI64]) == 0
    out = capsys.readouterr().out
    assert "CFG" in out and "确定" in out and "疑似" in out and "未解析" in out


def test_zero_definite_edges_are_explained_in_cli(capsys):
    """确定边为 0 时必须在输出里说明原因，不许让人误读成“没有控制流”。"""
    assert cli.main(["recdesc", PIE]) == 0
    out = capsys.readouterr().out
    assert "确定边为 0" in out and "不代表没有控制流" in out


def test_true_zero_edges_told_apart_from_label_zero(capsys):
    """真零（全是 ret 桩，确实无控制流）与标签性零（有边但无声明边界）不得同一句话。"""
    assert cli.main(["recdesc", MINIDLL]) == 0
    out = capsys.readouterr().out
    assert "确定边为 0" in out and "确实没有函数内控制流" in out
    assert "不代表没有控制流" not in out
