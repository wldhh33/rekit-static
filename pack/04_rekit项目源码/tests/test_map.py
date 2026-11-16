#!/usr/bin/env python3
"""M3 断言：内存映射视图与双向换算（对应任务卡 E1–E5、E8；U1 范围）。

矩阵载体是 tests/verify_map.py（真值快照 + 591 格）；本文件锁定实现契约，
防止矩阵通过但接口语义悄悄漂移。真值不从被测实现推，来自 ELF/PE 头原始字段。

2026-11-15 裁决口径：
  - E3：NOBITS 无文件表示，节类型优先级高于算术 → 一律 not_in_file，
        算术落点与宿主节用独立字段 host_section 记录（不合并、不模糊化）。
  - E4：PE RawSize == 0 的节整节 not_in_file（比原"节首 hit"探针更严）。
  - TLS 覆盖：.tbss 的 sh_addr 与 .init_array 等节地址重叠（dyn_static 实测
    同为 0x49ee40），裸地址查询保守判 not_in_file，节级查询按节身份判定。
"""
import json
import os
import struct
import subprocess
import sys

import pytest

from rekit import elf, mapview

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
UPX = os.path.join(ROOT, "tests", "samples", "fingerprint", "upx")
HIT, NIF, UNMAP, MULTI = "hit", "not_in_file", "unmapped", "multi"


def fix(name):
    return os.path.join(FIX, name)


def build(name):
    return mapview.build(fix(name))


# ── E1：模型顶层结构与 JSON 通道 ──────────────────────────────────

def test_top_level_structure():
    for name in ("dyn_pie", "minipe.exe"):
        m = build(name)
        for k in ("format", "units", "entry", "gaps", "evidence", "stats"):
            assert k in m, (name, k)
        assert m["format"] in ("ELF", "PE")
        assert isinstance(m["units"], list) and m["units"]
        assert set(m["gaps"]) >= {"mem", "file"}
        assert m["evidence"], "强结论必须带证据说明"


def test_cli_json_and_queries():
    out = subprocess.run(
        [sys.executable, "-m", "rekit.cli", "map", fix("minipe.exe"),
         "--json", "--addr", "0x1000", "--off", "0x400"],
        cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    doc = json.loads(out.stdout)
    assert doc["queries"]["addr"]["status"] == HIT
    assert doc["queries"]["addr"]["offset"] == 0x400
    assert doc["queries"]["off"]["status"] == HIT
    assert doc["queries"]["off"]["addrs"] == [0x1000]


# ── E2：ELF = PT_LOAD，字段与探针双向 ────────────────────────────

def _elf_loads(name):
    with open(fix(name), "rb") as f:
        data = f.read()
    return [p for p in elf.program_headers(data) if p["type_id"] == elf.PT_LOAD]


@pytest.mark.parametrize("name", ["dyn_pie", "dyn_nopie", "dyn_static"])
def test_elf_units_are_pt_load(name):
    m = build(name)
    loads = _elf_loads(name)
    assert len(m["units"]) == len(loads)
    for u, p in zip(m["units"], loads):
        assert u["file"] == [p["offset"], p["filesz"]]
        assert u["mem"] == [p["vaddr"], p["memsz"]]
        assert u["mapped"] == ("file" if p["filesz"] else "zero")


@pytest.mark.parametrize("name", ["dyn_pie", "dyn_nopie", "dyn_static"])
def test_elf_segment_probes(name):
    m = build(name)
    for u, p in zip(m["units"], _elf_loads(name)):
        r = mapview.addr_to_off(m, p["vaddr"])
        assert r["status"] == HIT and r["offset"] == p["offset"] and r["unit"] == u["name"]
        if p["filesz"]:
            last = p["vaddr"] + p["filesz"] - 1
            r = mapview.addr_to_off(m, last)
            assert r["status"] == HIT and r["offset"] == p["offset"] + p["filesz"] - 1
            r = mapview.off_to_addr(m, p["offset"])
            assert p["vaddr"] in r["addrs"]
        if p["memsz"] > p["filesz"]:
            r = mapview.addr_to_off(m, p["vaddr"] + p["filesz"])
            assert r["status"] == NIF and r["unit"] == u["name"]
        # 左闭右开：末地址+1 不属于本单元
        r = mapview.addr_to_off(m, p["vaddr"] + p["memsz"])
        assert r["unit"] != u["name"]


# ── E3：节级一致性与 NOBITS ──────────────────────────────────────

def test_elf_sections_hit_their_own_offset():
    for name in ("dyn_pie", "dyn_nopie", "dyn_static", "dyn_execstack",
                 "dyn_norelro", "bin_ls.elf"):
        m = build(name)
        with open(fix(name), "rb") as f:
            secs = elf.section_headers(f.read())
        assert secs, name
        for s in secs:
            if not (s["alloc"] and s["size"] and s["addr"]):
                continue
            if s["type"] == "NOBITS":
                continue
            r = mapview.addr_to_off(m, s["addr"], section=s["name"])
            assert r["status"] == HIT, (name, s["name"], r)
            assert r["offset"] == s["offset"], (name, s["name"], r)


def test_elf_nobits_is_not_in_file():
    for name in ("dyn_pie", "dyn_static", "bin_ls.elf"):
        m = build(name)
        with open(fix(name), "rb") as f:
            secs = elf.section_headers(f.read())
        for s in secs:
            if s["type"] != "NOBITS" or not s["size"] or not s["alloc"]:
                continue
            r = mapview.addr_to_off(m, s["addr"], section=s["name"])
            assert r["status"] == NIF, (name, s["name"], r)
            assert r["offset"] is None, "不得向 map & patch 宣称 NOBITS 地址可改"


def test_tbss_host_section_is_independent_field():
    """反例取证：.tbss 的算术落点有真实字节，但那属于宿主节。"""
    m = build("dyn_static")
    r = mapview.addr_to_off(m, 0x49ee40, section=".tbss")
    assert r["status"] == NIF and r["offset"] is None
    assert r["section"] == ".tbss"
    assert r["arithmetic_offset"] == 0x9de40
    host = r["host_section"]
    assert host is not None and host["name"] != ".tbss"
    assert host["offset"] <= 0x9de40 < host["offset"] + host["size"]
    # 裸地址（不给节身份）保守按 NOBITS 判，语义一致
    bare = mapview.addr_to_off(m, 0x49ee40)
    assert bare["status"] == NIF and bare["host_section"]["name"] == host["name"]


def test_tls_overlap_identity():
    """同一地址两个节身份：节级查询各自命中自己的落点。"""
    m = build("dyn_static")
    r = mapview.addr_to_off(m, 0x49ee40, section=".init_array")
    assert r["status"] == HIT and r["offset"] == 0x9de40
    r = mapview.addr_to_off(m, 0x49ee40, section=".tbss")
    assert r["status"] == NIF


def test_upx_elf_sections_abstain():
    m = mapview.build(os.path.join(UPX, "upx_dyn_pie"))
    assert m["sections"] == []
    assert any("e_shnum=0" in c for c in m["caveats"])


# ── E4：PE = 头区 + 节；RawSize==0 整节 NIF ──────────────────────

def test_pe_header_region():
    for name in ("minipe.exe", "cli-64.exe"):
        m = build(name)
        soh = next(u for u in m["units"] if u["kind"] == "headers")["file"][1]
        assert mapview.addr_to_off(m, 0)["offset"] == 0
        last = mapview.addr_to_off(m, soh - 1)
        assert last["status"] == HIT and last["offset"] == soh - 1


def test_pe_sections_probes():
    from rekit import pe
    for name in ("minipe.exe", "cli-64.exe"):
        m = build(name)
        r0 = pe.parse(fix(name))
        for (va, vsize, rawptr, rawsize, sname) in r0["sections"]:
            ms = max(vsize, rawsize)
            if ms == 0:
                continue
            u = next(u for u in m["units"] if u["name"] == sname)
            assert u["file"] == [rawptr, rawsize]
            assert u["mem"] == [va, ms]
            if rawsize == 0:
                for a in (va, va + ms - 1):
                    r = mapview.addr_to_off(m, a)
                    assert r["status"] == NIF and r["offset"] is None, (name, sname, a)
                continue
            r = mapview.addr_to_off(m, va)
            assert r["status"] == HIT and r["offset"] == rawptr
            r = mapview.addr_to_off(m, va + rawsize - 1)
            assert r["status"] == HIT and r["offset"] == rawptr + rawsize - 1
            if vsize > rawsize:
                r = mapview.addr_to_off(m, va + rawsize)
                assert r["status"] == NIF and r["unit"] == sname
            assert mapview.addr_to_off(m, va + ms)["unit"] != sname


def test_pe_rawsize_zero_section_is_not_in_file():
    m = mapview.build(os.path.join(UPX, "upx_cli-64.exe"))
    upx0 = next(u for u in m["units"] if u["name"] == "UPX0")
    assert upx0["file"] == [0x400, 0] and upx0["mem"] == [0x1000, 0x8000]
    for a in (0x1000, 0x8fff):
        r = mapview.addr_to_off(m, a)
        assert r["status"] == NIF and r["offset"] is None, a


# ── E5：四条边界 ────────────────────────────────────────────────

def test_boundaries_unmapped():
    m = build("dyn_pie")
    assert mapview.addr_to_off(m, -1)["status"] == UNMAP
    assert mapview.addr_to_off(m, m["image"]["limit"])["status"] == UNMAP
    assert mapview.off_to_addr(m, os.path.getsize(fix("dyn_pie")))["status"] == UNMAP
    assert mapview.off_to_addr(m, -1)["status"] == UNMAP
    # 内存空洞：取第一个真实空洞，必须 unmapped（不取最近段）
    hole = m["gaps"]["mem"][0]
    assert mapview.addr_to_off(m, hole[0])["status"] == UNMAP
    # 文件空洞
    fh = m["gaps"]["file"][0]
    assert mapview.off_to_addr(m, fh[0])["status"] == UNMAP


def test_upx_elf_reverse_multi():
    """UPX-ELF 两个 PT_LOAD 共用文件偏移 0 → 反向换算必须报 multi，不给单值。"""
    m = mapview.build(os.path.join(UPX, "upx_dyn_pie"))
    r = mapview.off_to_addr(m, 0)
    assert r["status"] == MULTI
    assert len(r["addrs"]) == len(set(r["addrs"])) == 2


# ── U2：节身份在 CLI / MCP 两侧暴露，两种查询可区分 ─────────────

def test_cli_section_vs_bare_are_distinguishable():
    def run(extra):
        out = subprocess.run(
            [sys.executable, "-m", "rekit.cli", "map", fix("dyn_static"),
             "--json", "--addr", "0x49ee40"] + extra,
            cwd=ROOT, capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        return json.loads(out.stdout)["queries"]["addr"]

    bare = run([])
    assert bare["query_mode"] == "addr"
    assert bare["status"] == NIF and "section_matched" not in bare
    assert bare["host_section"]["name"] == ".init_array"

    scoped = run(["--section", ".init_array"])
    assert scoped["query_mode"] == "section"
    assert scoped["section"] == ".init_array" and scoped["section_matched"] is True
    assert scoped["status"] == HIT and scoped["offset"] == 0x9de40


def test_cli_section_requires_addr():
    out = subprocess.run(
        [sys.executable, "-m", "rekit.cli", "map", fix("minipe.exe"),
         "--off", "0x400", "--section", ".text"],
        cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 2
    assert "--section" in out.stderr


def test_mcp_exposes_section_semantics():
    from rekit import mcp

    def call(args):
        r = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "rekit_map", "arguments": args}})
        return json.loads(r["result"]["content"][0]["text"])

    scoped = call({"path": fix("dyn_static"), "addr": "0x49ee40",
                   "section": ".init_array"})["query"]["addr"]
    bare = call({"path": fix("dyn_static"), "addr": 0x49ee40})["query"]["addr"]
    assert scoped["query_mode"] == "section" and scoped["status"] == HIT
    assert bare["query_mode"] == "addr" and bare["status"] == NIF
    # section 缺 addr 必须报错，不得静默忽略
    r = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "rekit_map",
                               "arguments": {"path": fix("dyn_static"),
                                             "off": "0x400", "section": ".text"}}})
    assert r["result"].get("isError") is True


def test_pe_section_identity():
    m = build("minipe.exe")
    r = mapview.addr_to_off(m, 0x1000, section=".text")
    assert r["status"] == HIT and r["offset"] == 0x400
    assert r["query_mode"] == "section" and r["section_matched"] is True
    r = mapview.addr_to_off(m, 0x1000, section=".idata")
    assert r["status"] == UNMAP and r["section_matched"] is False
    r = mapview.addr_to_off(m, 0x1000, section=".no_such_section")
    assert r["status"] == UNMAP and r["section_matched"] is False


def test_pe_sample_without_sections():
    m = build("minipe_fakerich.exe")
    assert [u["name"] for u in m["units"]] == ["<headers>"]
    assert mapview.addr_to_off(m, 0)["status"] == HIT
    assert mapview.addr_to_off(m, m["image"]["limit"])["status"] == UNMAP


# ── E8：负路径零 traceback ───────────────────────────────────────

def test_negative_paths(tmp_path):
    assert mapview.main([str(tmp_path / "nope.bin")]) == 2
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an executable at all")
    assert mapview.main([str(junk)]) == 2
    trunc = tmp_path / "trunc.exe"
    trunc.write_bytes(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 8)
    assert mapview.main([str(trunc)]) == 3


def test_build_rejects_unknown_format():
    with pytest.raises(ValueError):
        mapview.build(os.path.join(ROOT, "rekit", "__init__.py"))
