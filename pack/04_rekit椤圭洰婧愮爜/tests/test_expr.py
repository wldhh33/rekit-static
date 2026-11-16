#!/usr/bin/env python3
# tests/test_expr.py — M5 第一单元：函数内表达式恢复
#
# 断言分三层：
#   1) 操作数结构（不是文本！）：SIB 与 disp 的读取顺序曾经反过——总长度仍然
#      对得上，只有结构断言能抓住。所以这里钉死 base/index/scale/disp/size；
#   2) 语义映射：cmp/test/算术 → 条件文本；表外指令 → abstain 且必须带 missing；
#   3) 真实样本上的定量不变量：lifted+abstained==insns、abstain 记录都能回指指令、
#      文本里不出现占位符。
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import expr, recdesc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
BINLS = os.path.join(HERE, "fixtures", "bin_ls.elf")


def mk(addr, hexbytes, length=None, opcode_map=None):
    b = bytes.fromhex(hexbytes.replace(" ", ""))
    if opcode_map is None:
        head = b[0]
        for x in b[:4]:
            if x in (0xC4, 0xC5):
                opcode_map = "vex:0f"
                break
            if x == 0x62:
                opcode_map = "vex:0f"
                break
            if x not in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67,
                         0xF0, 0xF2, 0xF3) and not (0x40 <= x <= 0x4F):
                break
        if opcode_map is None:
            opcode_map = 1
    return {"addr": addr, "off": 0, "length": length or len(b),
            "bytes": hexbytes, "status": "ok",
            "opcode_map": opcode_map, "opcode": b[0]}


# ── 1. 操作数结构 ────────────────────────────────────────────────────
@pytest.mark.parametrize("hexbytes,family,checks", [
    ("48 89 9c 24 80 07 00 00", "assign",
     {"dst": {"t": "mem", "base": 4, "index": None, "disp": 0x780, "size": 64},
      "src": {"t": "reg", "idx": 3, "size": 64}}),
    ("89 75 fc", "assign",
     {"dst": {"t": "mem", "base": 5, "index": None, "disp": -4, "size": 32},
      "src": {"t": "reg", "idx": 6, "size": 32}}),
    ("48 8d 94 8d 10 00 00 00", "lea",
     {"dst": {"t": "reg", "idx": 2, "size": 64},
      "src": {"t": "mem", "base": 5, "index": 1, "scale": 4, "disp": 0x10}}),
    ("48 83 ec 28", "binop",
     {"mnem": "sub", "dst": {"t": "reg", "idx": 4, "size": 64},
      "src": {"t": "imm", "value": 0x28}}),
    ("41 80 f8 5c", "cmp",
     {"a": {"t": "reg", "idx": 8, "size": 8},
      "b": {"t": "imm", "value": 0x5c}}),
    ("48 0f af c1", "binop",
     {"mnem": "imul", "dst": {"t": "reg", "idx": 0, "size": 64},
      "src": {"t": "reg", "idx": 1, "size": 64}}),
    ("c1 e0 04", "shift",
     {"mnem": "shl", "dst": {"t": "reg", "idx": 0, "size": 32},
      "count": {"t": "imm", "value": 4}}),
    ("f7 d8", "unop", {"mnem": "neg", "dst": {"t": "reg", "idx": 0, "size": 32}}),
    ("0f 45 c1", "cmov", {"cc": 5, "dst": {"t": "reg", "idx": 0},
                          "src": {"t": "reg", "idx": 1}}),
    # fs/gs 段覆盖：mod=0 rm=4 + SIB base=5 是绝对 disp32，不能当普通绝对地址
    ("64 48 8b 04 25 28 00 00 00", "assign",
     {"dst": {"t": "reg", "idx": 0, "size": 64},
      "src": {"t": "mem", "base": None, "disp": 0x28, "size": 64, "seg": "fs"}}),
])
def test_operand_structure(hexbytes, family, checks):
    """SIB/disp 顺序错了总长度也可能对，必须在结构层钉死。"""
    ins = mk(0x1000, hexbytes)
    rec = expr.decode(ins)
    assert rec["family"] == family
    for key, want in checks.items():
        got = rec[key]
        if isinstance(want, dict):
            for k, v in want.items():
                assert got[k] == v, "%s.%s 期望 %r，实际 %r" % (key, k, v, got[k])
        else:
            assert got == want, "%s 期望 %r，实际 %r" % (key, want, got)


def test_rip_relative_target_uses_next_insn():
    ins = mk(0x2000, "ff 15 20 00 00 00")        # call qword [rip+0x20]
    rec = expr.decode(ins)
    assert rec["family"] == "call" and rec["target"] is None
    assert rec["indirect"]["t"] == "mem" and rec["indirect"]["rip"]
    assert rec["indirect"]["rip_target"] == 0x2000 + 6 + 0x20
    assert rec["indirect"]["size"] == 64


def test_decoded_insn_never_overruns_its_boundary():
    """decode 内部自检：操作数消费必须正好等于已解边界。"""
    for hexbytes in ("48 89 9c 24 80 07 00 00", "8b 44 24 20", "48 8d 05 10 00 00 00"):
        expr.decode(mk(0x3000, hexbytes))        # 不抛异常即通过


def test_fs_segment_is_not_rendered_as_absolute_address():
    """fs:[0x28] 是段相对（TLS/stack guard），渲染成绝对 0x28 会误导。"""
    rec = expr.decode(mk(0x3000, "64 48 8b 04 25 28 00 00 00"))
    text = expr.render_operand(rec["src"])
    assert "fs:[" in text and "0x28" in text
    assert text != "*(u64 *)(0x28)"


# ── 2. abstain 必须是显式的、带 missing 的 ───────────────────────────
@pytest.mark.parametrize("hexbytes,needle", [
    ("c5 f8 77", "VEX/EVEX"),
    ("62 f1 7c 48 58 c0", "VEX/EVEX"),
    ("66 0f 6f 04 24", "0F 6f"),
    ("f0 48 0f b1 0d 00 00 00 00", "lock"),
    ("0f 77", "0F 77"),
])
def test_unsupported_raises_with_missing(hexbytes, needle):
    with pytest.raises(expr.LiftError) as ei:
        expr.decode(mk(0x4000, hexbytes))
    assert needle in ei.value.reason
    assert ei.value.missing, "abstain 必须说明缺什么信息"


def test_indirect_jmp_keeps_target_none():
    """已知不可判的间接目标不许补：target 必须留 None。"""
    for b in ("ff e0", "ff 24 24", "ff 25 00 00 40 00"):
        rec = expr.decode(mk(0x5000, b))
        assert rec["family"] == "jmp" and rec["target"] is None
        assert rec["indirect"] is not None


# ── 3. 条件翻译 ──────────────────────────────────────────────────────
def _cond(cmp_bytes, jcc_bytes, addr=0x6000):
    """把 cmp/test 与 jcc 串起来，返回条件文本。"""
    ins1 = mk(addr, cmp_bytes)
    n = ins1["length"]
    ins2 = mk(addr + n, jcc_bytes)
    rec1 = expr.decode(ins1)
    rec2 = expr.decode(ins2)
    flags = expr._next_flags(rec1, None)
    return expr._cond_text(flags, rec2["cc"])


def test_condition_translation():
    assert _cond("83 f8 20", "77 10") == "eax >u 0x20"      # cmp + ja
    assert _cond("83 f8 20", "74 10") == "eax == 0x20"      # cmp + je
    assert _cond("48 3b c8", "7c 10") == "rcx < rax"        # cmp rcx,rax + jl（有符号）
    assert _cond("85 c0", "74 10") == "(eax & eax) == 0"     # test + je
    assert _cond("85 c0", "7e 10") == "(eax & eax) <= 0"     # test + jle（OF=0）
    assert _cond("48 85 c0", "79 10") == "(rax & rax) >=0"   # test + jns


def test_je_after_add_compares_result_with_zero():
    """add 之后的 je 是"结果==0"，不是"操作数相等"。"""
    assert _cond("48 01 d8", "74 10") == "(rax + rbx) == 0"


@pytest.mark.parametrize("cmp_bytes,jcc", [
    ("83 f8 01", "70 10"),      # jo：依赖 OF
    ("85 c0", "7a 10"),         # jp：依赖 PF
    ("85 c0", "72 10"),         # jb after test：需要 CF（test 固定 0 但未建模）
])
def test_condition_abstains_when_flags_not_modeled(cmp_bytes, jcc):
    with pytest.raises(expr.LiftError) as ei:
        _cond(cmp_bytes, jcc)
    assert ei.value.missing


def test_condition_without_flag_source_abstains():
    with pytest.raises(expr.LiftError) as ei:
        expr._cond_text(None, 0x04)
    assert "跨块" in ei.value.missing


# ── 4. 端到端：合成函数 ──────────────────────────────────────────────
def _fake_res(insns, blocks, seed_addr=0x1000, end=0x1020,
              authority="authoritative"):
    return {
        "instructions": [dict(i, origin=seed_addr) for i in insns],
        "blocks": blocks,
        "seeds": [{"addr": seed_addr, "end": end, "authority": authority,
                   "sources": ["eh_frame_fde"], "details": ["demo"]}],
    }


def test_lift_function_end_to_end_text_and_abstain():
    ins = [mk(0x1000, "55"),                      # push rbp
           mk(0x1001, "48 89 e5"),                # mov rbp, rsp
           mk(0x1004, "83 f8 02"),                # cmp eax, 2
           mk(0x1007, "75 05"),                   # jne L_0x100e
           mk(0x1009, "b8 01 00 00 00"),          # mov eax, 1
           mk(0x100e, "c5 f8 77"),                # vzeroupper → abstain
           mk(0x1011, "c3")]                      # ret
    blocks = [{"start": 0x1000, "end": 0x1009, "function": 0x1000,
               "terminator": "jcc_rel", "insns": [0x1000, 0x1001, 0x1004, 0x1007]},
              {"start": 0x1009, "end": 0x100e, "function": 0x1000,
               "terminator": "fallthrough", "insns": [0x1009]},
              {"start": 0x100e, "end": 0x1012, "function": 0x1000,
               "terminator": "ret", "insns": [0x100e, 0x1011]}]
    r = expr.lift_function(_fake_res(ins, blocks), 0x1000)
    assert r["boundary"] == "declared"
    assert r["stats"]["insns"] == 7 and r["stats"]["abstained"] == 1
    assert len(r["abstains"]) == 1
    assert "VEX/EVEX" in r["abstains"][0]["reason"]
    assert r["abstains"][0]["missing"]
    text = r["text"]
    assert "if (eax != 0x2) goto L_0x100e;" in text
    assert "goto L_0x1009;" in text              # 未取分支显式补 goto
    assert "return;" in text
    assert "?" not in text, "伪 C 里不允许出现占位符"
    assert r["verdict"] == "partial"


def test_unknown_boundary_is_not_mixed_into_declared_results():
    ins = [mk(0x1000, "c3")]
    blocks = [{"start": 0x1000, "end": 0x1001, "function": 0x1000,
               "terminator": "ret", "insns": [0x1000]}]
    res = _fake_res(ins, blocks)
    res["seeds"][0]["end"] = None
    r = expr.lift_function(res, 0x1000)
    assert r["boundary"] == "unknown"


# ── 5. 真实样本上的定量不变量 ────────────────────────────────────────
@pytest.mark.skipif(not os.path.exists(CLI), reason="缺 cli-64.exe")
def test_cli64_quantitative_invariants():
    b = expr.lift_binary(CLI)
    st = b["stats"]
    assert b["functions_total"] > 50
    assert st["lifted"] + st["abstained"] == st["insns"]
    assert st["abstain_ratio"] < 0.10, "标量白名单覆盖率不应低于 90%"
    # 每个 abstain 都必须带 missing，且地址必须是真实指令地址
    allfn = expr.lift_binary  # noqa: F841
    res = recdesc.descend(CLI)
    addrs = set(i["addr"] for i in res["instructions"])
    for f in b["functions"]:
        if f["boundary"] != "declared":
            continue
        r = expr.lift_function(res, f["function"])
        for a in r["abstains"]:
            assert a["addr"] in addrs
            assert a["missing"] and a["reason"]
            assert a["bytes"]
    # 跳过的函数必须给出理由，不能静默消失
    assert all(s["reason"] for s in b["skipped"])


@pytest.mark.skipif(not os.path.exists(BINLS), reason="缺 bin_ls.elf")
def test_elf_fde_boundaries_all_declared():
    b = expr.lift_binary(BINLS)
    assert b["functions_skipped"] == 0, "FDE 应覆盖所有解出的函数域"
    assert b["stats"]["abstain_ratio"] < 0.10
