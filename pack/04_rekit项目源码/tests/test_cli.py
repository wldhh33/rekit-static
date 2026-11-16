#!/usr/bin/env python3
# rekit 统一 CLI 回归测试 — 2026-11-14 M1 收口日（断言入库纪律）
# 期望值来源：verify_cli.py 首跑 PASS 的真实输出（Entry/Machine 等锚点值
# 与 test_elf.py/test_pe.py 中 readelf/pefile/objdump 交叉验证过的快照一致）
import os
import struct
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = REPO + "/tests/fixtures"


def cli(*args):
    return subprocess.run([sys.executable, "-m", "rekit.cli", *args],
                          capture_output=True, text=True, cwd=REPO)


def mod_direct(module, path):
    return subprocess.run([sys.executable, "-m", "rekit." + module, path],
                          capture_output=True, text=True, cwd=REPO)


# ── 自动识别（D1 核心：路由正确性）──────────────────────────────

def test_auto_detect_elf():
    """ELF 样本走 elf 通道：checksec/entry 均为 ELF 报告字段（0x6760=readelf 定标）"""
    r = cli(f"{FIX}/bin_ls.elf")
    assert r.returncode == 0
    assert "Checksec: NX enabled" in r.stdout
    assert "Entry: 0x6760" in r.stdout


def test_auto_detect_pe():
    """PE 样本走 pe 通道（而非 ELF 崩溃）——路由错误的证伪点"""
    r = cli(f"{FIX}/minipe.exe")
    assert r.returncode == 0
    assert "Machine:    AMD64" in r.stdout
    assert "Checksec:" not in r.stdout  # 不得串台到 ELF 渲染


def test_cli_output_matches_module_elf():
    """cli ≡ 模块直调（ELF 侧）：渲染通道复用，输出逐字节一致"""
    f = f"{FIX}/dyn_execstack"
    assert cli(f).stdout == mod_direct("elf", f).stdout


def test_cli_output_matches_module_pe():
    """cli ≡ 模块直调（PE 侧）"""
    f = f"{FIX}/minidll.dll"
    assert cli(f).stdout == mod_direct("pe", f).stdout


def test_all_ten_fixtures_auto_pass():
    """D1 常绿化：fixtures 目录恰 10 样本，全部自动识别成功"""
    fixtures = sorted(os.listdir(FIX))
    assert len(fixtures) == 10
    for f in fixtures:
        assert cli(f"{FIX}/{f}").returncode == 0, f


# ── 负样本友好降级（D2）───────────────────────────────────────

def test_negative_text_file_friendly():
    """纯文本：exit 2 + 一行 stderr，无 traceback"""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("not a binary\n" * 8)
        p = fh.name
    try:
        r = cli(p)
        assert r.returncode == 2
        assert "rekit:" in r.stderr and "Traceback" not in r.stderr
        assert len(r.stderr.strip().splitlines()) == 1
    finally:
        os.unlink(p)


def test_negative_mz_without_pe_signature():
    """MZ 双重校验：MZ 头但 e_lfanew 处无 PE\\0\\0 → 友好拒绝而非误入 pe 通道"""
    with tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False) as fh:
        fh.write(b"MZ" + b"\x00" * 0x3e + struct.pack("<I", 0x50) + b"JUNK")
        p = fh.name
    try:
        r = cli(p)
        assert r.returncode == 2 and "Traceback" not in r.stderr
        assert "无法识别" in r.stderr
    finally:
        os.unlink(p)


def test_truncated_elf_exit_code_3():
    """魔数对但截断：分诊通过、解析失败走 exit 3（与 exit 2 语义分离）"""
    with tempfile.NamedTemporaryFile("wb", suffix=".elf", delete=False) as fh:
        fh.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
        p = fh.name
    try:
        r = cli(p)
        assert r.returncode == 3
        assert "解析失败" in r.stderr and "Traceback" not in r.stderr
    finally:
        os.unlink(p)


# ── format 覆写 ───────────────────────────────────────────────

def test_format_override():
    """--format 显式指定仍走对应通道（分诊自动化的逃生门）"""
    r = cli("--format", "pe", f"{FIX}/minidll.dll")
    assert r.returncode == 0
    assert "Exports:" in r.stdout and "minidll.dll" in r.stdout
