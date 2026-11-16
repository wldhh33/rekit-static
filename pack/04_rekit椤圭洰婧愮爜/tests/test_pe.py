#!/usr/bin/env python3
# rekit PE 回归测试套件 — 2026-11-07 落地（防退化锚点：minipe.exe）
# 期望值 = make_minipe.py 构造参数（2026-11-07 基线 B 三方验证 PASS）
# 2026-11-12 白银#1：+Rich 头断言（期望值 = pefile 源码级+手动 dump 双重定标）
# 2026-11-13 白银#2：+导出表断言（期望值 = make_minidll.py 构造参数，objdump 三方全等 PASS）
import re
import subprocess
import sys

import pytest

sys.path.insert(0, "<旧仓库根>")
from rekit.pe import parse  # noqa: E402

MINIPE = "<旧仓库根>/tests/fixtures/minipe.exe"
FAKERICH = "<旧仓库根>/tests/fixtures/minipe_fakerich.exe"
CLI64 = "<旧仓库根>/tests/fixtures/cli-64.exe"
MINIDLL = "<旧仓库根>/tests/fixtures/minidll.dll"


@pytest.fixture(scope="module")
def pe():
    return parse(MINIPE)


def test_coff_and_opt_header(pe):
    assert pe["machine"] == "AMD64"
    assert pe["magic"] == 0x20B
    assert pe["entry"] == 0x1000
    assert pe["image_base"] == 0x140000000
    assert pe["subsystem"] == "Console"
    assert pe["size_image"] == 0x3000
    assert pe["size_headers"] == 0x200


def test_section_table(pe):
    secs = {nm: (va, vs, rp, rs) for (va, vs, rp, rs, nm) in pe["sections"]}
    assert set(secs) == {".text", ".idata"}
    assert secs[".text"] == (0x1000, 0x100, 0x400, 0x200)
    assert secs[".idata"] == (0x2000, 0x140, 0x600, 0x200)


def test_import_directory_and_table(pe):
    assert pe["import_dir"] == (0x2000, 0x50)
    assert pe["imports"] == [("KERNEL32.dll", ["ExitProcess"])]


# ---- Rich 头（2026-11-12 白银#1）----

@pytest.fixture(scope="module")
def rich64():
    return parse(CLI64)["rich"]


def test_rich_key_and_offsets(rich64):
    """key 与两锚偏移（pefile 源码级+手动 dump 定标，2026-11-12）"""
    assert rich64["key"] == 0x31A563A3
    assert rich64["dans_off"] == 0x80
    assert rich64["rich_off"] == 0xE8


def test_rich_pair_count_and_first_last(rich64):
    """11 对（修正 11-11 日志'9 对'误读），首对/尾对锚定"""
    assert len(rich64["pairs"]) == 11
    assert rich64["pairs"][0] == (0x00937809, 16)
    assert rich64["pairs"][-1] == (0x01027F14, 1)   # 真实第 11 对，非 Rich^key 尾


def test_rich_all_pairs_full_list(rich64):
    """全 11 对逐项（与 pefile values 配对全等的固化快照）"""
    assert rich64["pairs"] == [
        (0x00937809, 16), (0x01017EA4, 2), (0x00FD7EA4, 4), (0x01057EA4, 19),
        (0x01047EA4, 10), (0x01037EA4, 3), (0x0101784B, 3), (0x00010000, 69),
        (0x01047F14, 1), (0x00FF7F14, 1), (0x01027F14, 1)]


def test_rich_none_for_minipe(pe):
    """负样本：自构造最小 PE 无 Rich → None"""
    assert pe["rich"] is None


def test_rich_fakerich_traps():
    """负样本：stub 区 Rich+key（无 DanS 锚）与 .text 深处 Rich 双陷阱 → None（双向锚定+限界）"""
    assert parse(FAKERICH)["rich"] is None


def test_rich_crosscheck_pefile(rich64):
    """交叉验证：与 pefile values 两两配对逐项全等（pefile 缺失则跳过）"""
    pefile = pytest.importorskip("pefile")
    pv = pefile.PE(CLI64, fast_load=True).parse_rich_header()["values"]
    ppairs = [(pv[i], pv[i + 1]) for i in range(0, len(pv), 2)]
    assert rich64["pairs"] == ppairs


# ============ 2026-11-13 白银#2：导出表 ============

@pytest.fixture(scope="module")
def minidll():
    return parse(MINIDLL)


def test_minidll_dll_chars(minidll):
    """DLL 特征位 IMAGE_FILE_DLL(0x2000) 生效 + 2 节布局"""
    assert minidll["chars"] == "0x2022"
    assert [s[4] for s in minidll["sections"]] == [".text", ".edata"]


def test_minidll_export_dir(minidll):
    """数据目录[0] 指向 .edata 导出表（RVA 0x2000，size 覆盖到名字串末尾 0x7C）"""
    assert minidll["export_dir"] == (0x2000, 0x7C)


def test_minidll_export_summary(minidll):
    """DLL 名 / 序号基址 / 函数总数"""
    ex = minidll["exports"]
    assert (ex["dll"], ex["base"], ex["nfuncs"]) == ("minidll.dll", 1, 4)


def test_minidll_export_full_table(minidll):
    """EAT 全表逐项（含纯序号项 (None, 4, 0x1040)）——期望值 = 构造参数"""
    assert minidll["exports"]["exports"] == [
        ("Add", 1, 0x1010), ("Sub", 2, 0x1020),
        ("Mul", 3, 0x1030), (None, 4, 0x1040)]


def test_minidll_ordinal_mapping_trap(minidll):
    """反陷阱：名字表字母序 [Add,Mul,Sub] ≠ EAT 序 [Add,Sub,Mul]——
    Mul 须映射 ord3@0x1030、Sub 须映射 ord2@0x1020（经 AddressOfNameOrdinals 换算）"""
    nm = {e[0]: (e[1], e[2]) for e in minidll["exports"]["exports"] if e[0]}
    assert nm == {"Add": (1, 0x1010), "Sub": (2, 0x1020), "Mul": (3, 0x1030)}


def test_minidll_ordinal_only(minidll):
    """纯序号导出：不在名字表但占据 EAT 槽位，ordinal = Base+idx = 4"""
    assert (None, 4, 0x1040) in minidll["exports"]["exports"]


def test_export_none_for_minipe(pe):
    """负样本：ExportDir RVA=0 → None，不崩溃"""
    assert pe["exports"] is None
    assert pe["export_dir"] == (0, 0)


def test_export_none_for_cli64():
    """负样本：真实 EXE（cli-64.exe）无导出表 → None"""
    r = parse(CLI64)
    assert r["exports"] is None


def test_minidll_crosscheck_objdump(minidll):
    r"""交叉验证：EAT 逐项 + 名字→ordinal 映射 vs objdump -p 全等
    （锚点唯一化+列宽 \s+，2026-11-13 验证脚本三板斧 R25–R27）"""
    out = subprocess.run(["objdump", "-p", MINIDLL], capture_output=True,
                         text=True, check=True).stdout
    eat_part = out.split("Export Address Table -- Ordinal Base")[1] \
                 .split("[Ordinal/Name Pointer] Table")[0]
    name_part = out.split("[Ordinal/Name Pointer] Table")[1]
    obj_eat = {int(m.group(1)): int(m.group(2), 16)
               for m in re.finditer(r"\[\s*\d+\] \+base\[\s*(\d+)\] ([0-9a-f]{8}) Export RVA", eat_part)}
    obj_named = {m.group(2): int(m.group(1))
                 for m in re.finditer(r"\[\s*\d+\] \+base\[\s*(\d+)\]\s+[0-9a-f]{4} (\w+)", name_part)}
    rk_eat = {e[1]: e[2] for e in minidll["exports"]["exports"]}
    rk_named = {e[0]: e[1] for e in minidll["exports"]["exports"] if e[0]}
    assert obj_eat == rk_eat and obj_named == rk_named
