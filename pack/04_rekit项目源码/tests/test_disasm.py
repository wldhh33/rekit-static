#!/usr/bin/env python3
"""M4 首日断言：x86-64 线性扫描只解【指令边界】（对应 M4 四项要求）。

边界判据全部来自字节规则，不依赖 objdump 是否在 PATH：
  - 长度表的表内/表外、前缀族、立即数族、ModRM/SIB/disp 组合逐条钉死；
  - VEX/EVEX/非法 opcode/越界 → status="unsupported" + 停止，不猜长度；
  - 线性扫描盲区必须出现在输出里（CAVEATS 进 JSON 与文本）；
  - 每条指令复用 M3 mapview.addr_to_off 标注文件落点，且与本节算术 offset 一致。

逐行对拍 objdump 2.47 的矩阵载体是 tests/verify_disasm.py（含 selftest）。
"""
import json
import os
import subprocess
import sys

import pytest

from rekit import disasm, mapview

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
CLI64 = os.path.join(FIX, "cli-64.exe")
LS_ELF = os.path.join(FIX, "bin_ls.elf")


def ln(hexbytes):
    """单条指令长度：丢进 sweep_bytes 只看第一条。"""
    data = bytes.fromhex(hexbytes.replace(" ", ""))
    res = disasm.sweep_bytes(data, 0, 0x1000, len(data))
    return res["instructions"][0]["length"], res["instructions"][0]["status"]


# ── 长度表（字节规则自证，不靠 objdump） ─────────────────────────

@pytest.mark.parametrize("hexbytes,expect", [
    # 无前缀 / 常见单字节
    ("90", 1),                          # nop
    ("c3", 1),                          # ret
    ("cc", 1),                          # int3
    ("55", 1),                          # push rbp
    ("f4", 1),                          # hlt
    # 前缀 + opcode
    ("f3 0f 1e fa", 4),                 # endbr64（F3 前缀 → 0F 1E /r）
    ("66 90", 2),                       # xchg ax,ax
    ("48 89 e5", 3),                    # mov rbp,rsp（REX.W）
    ("48 83 ec 20", 4),                 # sub rsp,0x20（83 /5 ib）
    ("48 8d 3d 00 00 00 00", 7),        # lea rdi,[rip+0]（mod=0 rm=5 → disp32）
    ("e8 00 00 00 00", 5),              # call rel32
    ("eb fe", 2),                       # jmp rel8
    ("75 12", 2),                       # jne rel8
    ("0f 87 98 00 00 00", 6),           # ja rel32（0F 8x）
    ("0f cb", 2),                       # bswap ebx
    ("41 0f cb", 3),                    # bswap r11d —— 回归：0F C8..CF 无 ModRM
    ("0f 05", 2),                       # syscall
    ("0f 0b", 2),                       # ud2
    ("0f 31", 2),                       # rdtsc
    ("f3 0f 1e fb", 4),                 # endbr32
    # SIB / disp 组合
    ("48 8b 04 25 00 00 00 00", 8),     # mov rax,[0x0]（SIB base=5 mod=0 → disp32）
    ("48 8b 04 24", 4),                 # mov rax,[rsp]（SIB，无 disp）
    ("48 8b 44 24 08", 5),              # mov rax,[rsp+8]（SIB + disp8）
    ("48 8b 84 24 00 01 00 00", 8),     # mov rax,[rsp+0x100]（SIB + disp32）
    ("48 8b 45 f8", 4),                 # mov rax,[rbp-8]（mod=1 disp8）
    ("48 8b 05 00 00 00 00", 7),        # mov rax,[rip+0]
    # 立即数族
    ("b8 00 00 00 00", 5),              # mov eax,imm32（无 ModRM）
    ("48 b8 00 00 00 00 00 00 00 00", 10),   # mov rax,imm64（REX.W）
    ("66 b8 00 00", 4),                 # mov ax,imm16（66 前缀）
    ("b0 12", 2),                       # mov al,0x12
    ("04 12", 2),                       # add al,0x12
    ("6a 01", 2),                       # push 1
    ("68 00 00 00 00", 5),              # push imm32
    ("a9 00 00 00 00", 5),              # test eax,imm32
    ("a8 12", 2),                       # test al,0x12
    ("69 c0 00 00 00 00", 6),           # imul eax,eax,imm32
    ("6b c0 05", 3),                    # imul eax,eax,5
    ("c7 45 fc 00 00 00 00", 7),        # mov dword [rbp-4],0
    ("c6 45 fc 00", 4),                 # mov byte [rbp-4],0
    # group3：只有 /0 /1 带立即数
    ("f6 c0 01", 3),                    # test al,1
    ("f6 d0", 2),                       # not al（/2，无立即数）
    ("f7 c0 00 00 00 00", 6),           # test eax,imm32
    ("f7 d0", 2),                       # not eax
    ("48 f7 c0 00 00 00 00", 7),        # test rax,imm32（REX.W 下仍 4 字节）
    # 定长/特殊
    ("c2 00 00", 3),                    # ret imm16
    ("c8 00 00 00", 4),                 # enter imm16,imm8
    ("a1 00 00 00 00 00 00 00 00", 9),  # mov rax,moffs64
    ("67 a1 00 00 00 00", 6),           # 67 → moffs32
    # 三字节映射
    ("0f 38 00 c0", 4),                 # pshufb xmm0,xmm0
    ("66 0f 3a 0f c0 08", 6),           # palignr xmm0,xmm0,8
    ("0f ba e0 05", 4),                 # bt eax,5（0F BA /4 ib）
    ("0f 70 c0 1b", 4),                 # pshufd xmm0,xmm0,0x1b
    # 0F 78/79：有 66 才是 imm8
    ("0f 78 c1", 3),                    # vmread（无 66，无 imm）
    ("66 0f 78 c1 05", 5),              # extrq（有 66 → imm8）
])
def test_instruction_lengths(hexbytes, expect):
    length, status = ln(hexbytes)
    assert status == "ok", "%s 应解出边界，实际 %s" % (hexbytes, status)
    assert length == expect, "%s 长度应为 %d，实际 %d" % (hexbytes, expect, length)


@pytest.mark.parametrize("hexbytes,needle", [
    ("06", "非法"),                # push es（64 位非法）
    ("0e", "非法"),                # push cs
    ("ea 00 00 00 00 00 00", "非法"),  # jmpf（64 位非法）
    ("62 f1 78 48 58 c0", "EVEX"),  # EVEX P1[2]=0：伪 EVEX，必须 abstain
    ("c4 e0 7d 58 c0", "VEX3"),     # VEX3 map=0：未定义 map，必须 abstain
])
def test_unsupported_abstains(hexbytes, needle):
    """表外/非法编码：必须 abstain 并停止，不许猜长度让后续整链错位。"""
    data = bytes.fromhex(hexbytes.replace(" ", ""))
    res = disasm.sweep_bytes(data, 0, 0x1000, len(data))
    first = res["instructions"][0]
    assert first["status"] == "unsupported"
    assert first["length"] == 0
    assert res["stopped"] is not None and needle in res["stopped"]["reason"]
    assert res["bytes_scanned"] == 0, "abstain 时不得消耗字节"


@pytest.mark.parametrize("hexbytes,expect", [
    ("c5 f8 77", 3),                    # vzeroupper（VEX2，唯一无 ModRM）
    ("c5 fa 10 45 f8", 5),              # vmovss xmm0,[rbp-8]（VEX2 + disp8）
    ("c4 e2 7d 18 04 24", 6),           # vbroadcastss（VEX3 map=0F38 + SIB）
    ("c4 e3 7d 0f c0 07", 6),           # vpalignr（VEX3 map=0F3A → imm8）
    ("c5 f9 6f 05 10 00 00 00", 8),     # vmovdqa（map=0F，RIP+disp32，无 imm）
    ("62 f1 7c 48 58 c0", 6),           # vaddps zmm（EVEX map=0F）
    ("62 f1 7d 48 6f 45 f8", 7),        # vmovdqa64 zmm（EVEX + disp8）
    ("62 f3 7d 48 25 c0 07", 7),        # vpternlogd（EVEX map=0F3A → imm8）
])
def test_vex_evex_lengths(hexbytes, expect):
    """M5 补表：VEX2/VEX3/EVEX 长度必须按前缀+map+ModRM/SIB/disp+imm 解出。

    与 objdump/capstone 的逐行对拍在 tests/verify_disasm.py（avx_dense 已入矩阵），
    本用例只钉死字节规则本身，不依赖外部工具在 PATH。
    """
    length, status = ln(hexbytes)
    assert status == "ok", "%s 应解出边界，实际 %s" % (hexbytes, status)
    assert length == expect, "%s 长度应为 %d，实际 %d" % (hexbytes, expect, length)


def test_truncated_instruction_stops_without_guessing():
    # 48 8b 45（缺 disp8）→ 长度越出可用字节，停止且不产出假指令
    data = bytes.fromhex("488b45")
    res = disasm.sweep_bytes(data, 0, 0x1000, len(data))
    assert res["stopped"] is not None
    assert "越" in res["stopped"]["reason"]
    assert all(i["status"] != "ok" for i in res["instructions"])


def test_prefix_over_15_bytes_abstains():
    data = bytes.fromhex("66" * 16 + "90")
    res = disasm.sweep_bytes(data, 0, 0x1000, len(data))
    assert res["stopped"] is not None
    assert "前缀" in res["stopped"]["reason"]


# ── 线性扫描语义 ─────────────────────────────────────────────────

def test_sweep_marks_blind_spots_in_output():
    """要求 3：盲区必须写在输出里，别让人以为扫出来的都是指令。"""
    res = disasm.sweep_file(CLI64, ".text", limit=0x20)
    assert len(res["caveats"]) >= 4
    joined = " ".join(res["caveats"])
    assert "数据" in joined and "跳转" in joined and "VEX" in joined
    txt = disasm.render_text(CLI64, res)
    assert "caveats" in txt and "别把结果都当指令" in txt


def test_every_instruction_carries_file_offset_from_mapview():
    """要求 1 后半：每条指令的文件落点复用 M3 的 addr_to_off，且与节算术一致。"""
    res = disasm.sweep_file(CLI64, ".text", limit=0x200)
    sec = res["section"]
    model = mapview.build(CLI64)
    assert res["map_stats"]["hit"] == len(res["instructions"])
    assert res["map_mismatches"] == []
    for i in res["instructions"]:
        assert i["off"] == sec["off"] + (i["addr"] - sec["va"])
        assert i["map"]["status"] == "hit"
        assert i["map"]["offset"] == i["off"]
        assert i["map"]["unit"] == ".text"
        # 落点处字节必须就是这条指令的字节（自证不是算出来的假偏移）
        with open(CLI64, "rb") as f:
            f.seek(i["off"])
            assert f.read(i["length"]).hex(" ") == i["bytes"]


def test_sweep_covers_section_bytes_contiguously():
    res = disasm.sweep_file(CLI64, ".text", limit=0x200)
    pos = res["section"]["off"]
    for i in res["instructions"]:
        assert i["off"] == pos
        pos += i["length"]
    assert pos - res["section"]["off"] == res["bytes_scanned"]


def test_elf_and_pe_both_supported():
    pe_res = disasm.sweep_file(CLI64, ".text", limit=0x40)
    elf_res = disasm.sweep_file(LS_ELF, ".text", limit=0x40)
    assert pe_res["section"]["arch"] == "pe"
    assert elf_res["section"]["arch"] == "elf"
    assert pe_res["instructions"] and elf_res["instructions"]


# ── CLI / 负路径（E8 同款纪律：无 traceback、退出码可区分） ────────

def _cli(args):
    p = subprocess.run([sys.executable, "-m", "rekit.cli"] + args,
                       cwd=ROOT, capture_output=True)
    return p.returncode, p.stdout.decode("utf-8", "replace"), \
        p.stderr.decode("utf-8", "replace")


def test_cli_disasm_json_contract():
    rc, out, err = _cli(["disasm", CLI64, "--limit", "0x20", "--json"])
    assert rc == 0, err
    obj = json.loads(out)
    for k in ("instructions", "caveats", "bytes_scanned", "stopped",
              "map_stats", "map_mismatches", "section"):
        assert k in obj
    assert obj["instructions"][0]["map"]["status"] == "hit"


def test_cli_disasm_text_output_mentions_caveats():
    rc, out, err = _cli(["disasm", CLI64, "--limit", "0x20"])
    assert rc == 0, err
    assert "caveats" in out and "文件落点" in out


def test_disasm_negative_paths():
    rc, out, err = _cli(["disasm", os.path.join(ROOT, "no_such_file.bin")])
    assert rc == 2 and "Traceback" not in err
    rc, out, err = _cli(["disasm", CLI64, "--section", ".nosuch"])
    assert rc == 2 and "找不到可扫描节" in err and "Traceback" not in err
    # 非 PE/ELF（本测试文件自身）→ 2，且必须说清是格式不认识，不许报成"找不到节"
    rc, out, err = _cli(["disasm", os.path.abspath(__file__)])
    assert rc == 2 and "无法识别的格式" in err and "Traceback" not in err


def test_disasm_truncated_pe_exit_3(tmp_path):
    # MZ + e_lfanew 指向 PE\0\0，但后面没有 COFF 头 → 解析失败走 3
    buf = bytearray(0x50)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = (0x40).to_bytes(4, "little")
    buf[0x40:0x44] = b"PE\x00\x00"
    p = tmp_path / "trunc.bin"
    p.write_bytes(bytes(buf))
    rc, out, err = _cli(["disasm", str(p)])
    assert rc == 3 and "Traceback" not in err
