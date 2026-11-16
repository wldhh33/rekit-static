#!/usr/bin/env python3
"""M3 断言：IAT 定位/解码/修复雏形（对应任务卡 E6/E7/E8；U3 范围）。

矩阵载体是 tests/verify_iat.py（真值快照 + 反例 + selftest）；本文件锁定实现契约。
写回纪律：
  - 写回只产出新文件，repair_file 拒绝 dst == src（字符串相同与真实路径相同都拒）；
  - 同一输入两次写同一输出路径，产物 sha256 必须相等（幂等可证）；
  - 原样本 sha256 不得变化；
  - 拿"从未被 loader 填充过"的原文件去修复 → 全部 unresolved，不得伪造成功；
  - 加壳（OriginalFirstThunk=0）→ 名称源不可回解，全部 unresolved 且零写入。
"""
import hashlib
import json
import os
import struct
import subprocess
import sys

import pytest

from rekit import iat

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
SAMP = os.path.join(ROOT, "tests", "samples", "fingerprint")
UPX = os.path.join(SAMP, "upx")


def fix(name):
    return os.path.join(FIX, name)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fake_loaded(data):
    """把每个 IAT slot 写成伪加载态地址（>= ImageBase），INT 不动。"""
    h = iat.headers(data)
    loc = iat.locate_bytes(data)
    buf = bytearray(data)
    base = 0x7FF800000000 if h["ptrsize"] == 8 else 0x7FF80000
    for i, s in enumerate(loc["slots"]):
        if s["file_off"] is not None:
            struct.pack_into("<Q" if h["ptrsize"] == 8 else "<I",
                             buf, s["file_off"], base + i)
    return bytes(buf)


# ── E6：定位/解码与真值逐项对拍 ─────────────────────────────────

@pytest.mark.parametrize("name,ndesc,nslots", [
    ("cli-64.exe", 10, 64),
    ("minipe.exe", 1, 1),
    ("minidll.dll", 0, 0),
])
def test_locate_matches_ground_truth(name, ndesc, nslots):
    gt = json.load(open(os.path.join(ROOT, "map_ground_truth.json"),
                       encoding="utf-8"))["samples"]
    rec = next(s for s in gt if s["rel"].endswith("/" + name))
    loc = iat.locate(fix(name))
    assert len(loc["descriptors"]) == ndesc
    assert len(loc["slots"]) == nslots
    if ndesc == 0:
        assert loc["status"] == "no_imports"
        return
    assert loc["status"] == "ok"
    for ad, gd in zip(loc["descriptors"], rec["imports"]):
        assert ad["dll"] == gd["dll"]
        assert len(ad["slots"]) == len(gd["slots"])
        for a, g in zip(ad["slots"], gd["slots"]):
            assert a["name"] == g["name"]
            assert a["rva"] == g["rva"]
            assert a["hint"] == g["hint"]


def test_slot_offsets_are_inside_i_at_ranges():
    """每个 slot 的文件偏移必须落在其 RVA 对应节内（逐项可核，不靠印象）。"""
    data = open(fix("cli-64.exe"), "rb").read()
    h = iat.headers(data)
    loc = iat.locate_bytes(data)
    for d in loc["descriptors"]:
        for s in d["slots"]:
            if s["file_off"] is None:
                continue
            assert iat.rva_to_off(h, s["rva"]) == s["file_off"]
            raw = data[s["file_off"]:s["file_off"] + h["ptrsize"]]
            assert int.from_bytes(raw, "little") == s["int_value"], s["name"]


def test_non_pe_raises():
    with pytest.raises(ValueError):
        iat.headers(open(os.path.join(ROOT, "rekit", "__init__.py"), "rb").read())


# ── E7：修复往返 / 逐 slot 字节 / 幂等 / 原样本不动 ─────────────

def test_repair_roundtrip_region_bytes_equal():
    path = fix("cli-64.exe")
    data = open(path, "rb").read()
    fake = fake_loaded(data)
    repaired, rep = iat.repair_bytes(fake)
    assert rep["stats"]["slots"] == 64
    assert rep["stats"]["repaired"] == 64
    assert rep["stats"]["unresolved"] == 0
    # 区间 sha256 与原始文件逐字节全等（不是"看起来对"）
    for r in rep["regions"]:
        assert sha(repaired[r["start"]:r["start"] + r["size"]]) == r["sha256_after"]
        assert sha(data[r["start"]:r["start"] + r["size"]]) == r["sha256_after"]
    # 逐 slot 字节可核
    for s in rep["slots"]:
        n = rep["ptrsize"]
        assert (repaired[s["file_off"]:s["file_off"] + n]
                == data[s["file_off"]:s["file_off"] + n]), s["rva"]
    # 入参不被修改
    assert fake == fake_loaded(data)


def test_repair_never_touches_original_and_is_idempotent(tmp_path):
    src = fix("minipe.exe")
    before = sha(open(src, "rb").read())
    fake = fake_loaded(open(src, "rb").read())
    fake_path = tmp_path / "fake.exe"
    fake_path.write_bytes(fake)
    dst = tmp_path / "out.exe"
    r1 = iat.repair_file(str(fake_path), str(dst))
    first = dst.read_bytes()
    r2 = iat.repair_file(str(fake_path), str(dst))
    assert r1["dst_sha256"] == r2["dst_sha256"] == sha(dst.read_bytes()) == sha(first)
    assert r1["src_sha256"] == sha(fake)
    assert r1["stats"]["unresolved"] == 0
    assert sha(open(src, "rb").read()) == before, "原样本被改动"


def test_repair_file_refuses_same_target(tmp_path):
    src = tmp_path / "in.exe"
    src.write_bytes(open(fix("minipe.exe"), "rb").read())
    with pytest.raises(ValueError):
        iat.repair_file(str(src), str(src))
    # 同一真实路径的另一种写法也必须拒
    with pytest.raises(ValueError):
        iat.repair_file(str(src), str(tmp_path / "." / "in.exe"))
    assert src.exists()


def test_repair_on_unloaded_file_refuses_to_fake_success():
    """原文件槽值是 RVA（< ImageBase）→ 必须全部 unresolved，一个字节都不写。"""
    path = fix("cli-64.exe")
    data = open(path, "rb").read()
    repaired, rep = iat.repair_bytes(data)
    assert rep["stats"]["repaired"] == 0
    assert rep["stats"]["unresolved"] == 64
    assert repaired == data
    assert all(s["status"] == "unresolved" for s in rep["slots"])


def test_repair_anti_example_keeps_bytes():
    """篡改 slot 为 0x41414141 → unresolved 且该 slot 字节不动（不许猜）。"""
    data = open(fix("minipe.exe"), "rb").read()
    h = iat.headers(data)
    loc = iat.locate_bytes(data)
    slot = next(s for s in loc["slots"] if s["file_off"] is not None)
    buf = bytearray(fake_loaded(data))
    struct.pack_into("<Q" if h["ptrsize"] == 8 else "<I", buf,
                     slot["file_off"], 0x41414141)
    before = bytes(buf[slot["file_off"]:slot["file_off"] + h["ptrsize"]])
    repaired, rep = iat.repair_bytes(bytes(buf))
    rec = next(s for s in rep["slots"] if s["file_off"] == slot["file_off"])
    assert rec["status"] == "unresolved"
    assert repaired[slot["file_off"]:slot["file_off"] + h["ptrsize"]] == before


# ── 加壳单列：INT 缺失 → 不猜、零写入 ──────────────────────────

@pytest.mark.parametrize("name,nslots", [
    ("upx_cli-64.exe", 13),
    ("upx_putty-64bit.exe", 11),
])
def test_packed_has_no_int_and_never_guesses(name, nslots):
    path = os.path.join(UPX, name)
    data = open(path, "rb").read()
    loc = iat.locate_bytes(data)
    assert loc["slots"] and len(loc["slots"]) == nslots
    assert all(d["int_rva"] == 0 for d in loc["descriptors"])
    fake = fake_loaded(data)
    repaired, rep = iat.repair_bytes(fake)
    assert rep["stats"]["repaired"] == 0
    assert rep["stats"]["unresolved"] == nslots
    assert repaired == fake, "无名称来源时仍写入了字节"


# ── 可解释弃权：加壳样本查 IAT 时不能只看到一堆 unresolved ─────────

def test_packed_repairability_explained_in_cli_and_json():
    packed = os.path.join(UPX, "upx_cli-64.exe")
    loc = iat.locate(packed)
    assert loc["repairable"] is False
    assert len(loc["caveats"]) >= 2
    assert any("OriginalFirstThunk=0" in c for c in loc["caveats"])
    assert any("脱壳" in c for c in loc["caveats"])
    assert all(d["repairable"] is False for d in loc["descriptors"])
    txt = iat.render_text(packed, loc)
    assert "不可完整修复" in txt and "[不可修复]" in txt
    # 未加壳样本必须给出相反结论
    assert iat.locate(fix("cli-64.exe"))["repairable"] is True

    out = subprocess.run([sys.executable, "-m", "rekit.cli", "iat", packed],
                         cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert "不可完整修复" in out.stdout and "脱壳" in out.stdout
    doc = json.loads(subprocess.run(
        [sys.executable, "-m", "rekit.cli", "iat", packed, "--json"],
        cwd=ROOT, capture_output=True, text=True).stdout)
    assert doc["repairable"] is False and doc["caveats"]


def test_mcp_iat_reports_repairability():
    from rekit import mcp
    res = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "rekit_iat",
                                 "arguments": {"path": os.path.join(
                                     UPX, "upx_putty-64bit.exe")}}})
    doc = json.loads(res["result"]["content"][0]["text"])
    assert doc["repairable"] is False and doc["caveats"]
    assert doc["status"] == "ok"
    # 非 PE → 工具级错误（连接存活），不是崩溃
    bad = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "rekit_iat",
                                 "arguments": {"path": os.path.join(
                                     ROOT, "rekit", "__init__.py")}}})
    assert bad["result"]["isError"] is True


# ── CLI 通道 ────────────────────────────────────────────────────

def test_cli_json_and_repair_out(tmp_path):
    out = subprocess.run(
        [sys.executable, "-m", "rekit.cli", "iat", fix("minipe.exe"), "--json"],
        cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    doc = json.loads(out.stdout)
    assert doc["status"] == "ok" and doc["slots"][0]["name"] == "ExitProcess"

    fake_path = tmp_path / "fake.exe"
    fake_path.write_bytes(fake_loaded(open(fix("minipe.exe"), "rb").read()))
    dst = tmp_path / "fixed.exe"
    out = subprocess.run(
        [sys.executable, "-m", "rekit.cli", "iat", str(fake_path),
         "--json", "--repair-out", str(dst)],
        cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    rep = json.loads(out.stdout)
    assert rep["stats"]["unresolved"] == 0
    assert dst.read_bytes() == open(fix("minipe.exe"), "rb").read()
    # 同名产物二次执行：同一个 --repair-out 再跑一次，sha256 必须相等（幂等）
    first = sha(dst.read_bytes())
    out = subprocess.run(
        [sys.executable, "-m", "rekit.cli", "iat", str(fake_path),
         "--json", "--repair-out", str(dst)],
        cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout)["dst_sha256"] == first == sha(dst.read_bytes())


def test_cli_refuses_to_repair_non_loaded_file(tmp_path):
    """未加载的原文件：退出码 4（unresolved>0），不得报成功。"""
    dst = tmp_path / "x.exe"
    out = subprocess.run(
        [sys.executable, "-m", "rekit.cli", "iat", fix("minipe.exe"),
         "--repair-out", str(dst)],
        cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 4, out.stdout
    assert "unresolved 1" in out.stdout


# ── E8：负路径零 traceback ───────────────────────────────────────

def test_negative_paths(tmp_path, capsys):
    assert iat.main([str(tmp_path / "nope.bin")]) == 2
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an executable at all")
    assert iat.main([str(junk)]) == 2
    trunc = tmp_path / "trunc.exe"
    trunc.write_bytes(b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
                      + b"PE\x00\x00" + b"\x00" * 8)
    assert iat.main([str(trunc)]) == 3
    err = capsys.readouterr().err
    assert "Traceback" not in err
