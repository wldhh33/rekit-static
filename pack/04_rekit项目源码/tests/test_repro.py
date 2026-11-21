#!/usr/bin/env python3
# tests/test_repro.py — 入库 fixture 的可复现性检查（2026-11-21）
#
# 背景：M15/M16 两个正样本由 make_*.py 在编译期生成并入库。旧实现用
# tempfile.mkdtemp(prefix=...) 的随机目录现场编译，DWARF 的 comp_dir/源路径
# 会把本机用户名与随机目录名写进产物：换一台机器（或换个用户名）重生成，
# 字节就不同，"证据可复跑"失效，且泄露本机路径。
#
# 本文件锁定三条判据：
#   1. 连续两次生成逐字节相同（同一机器）；
#   2. 生成产物 == 入库 fixture（入库件必须就是生成器的输出）；
#   3. 产物内不含 C:\Users\ / /home/ / AppData / 构建目录名等本机路径片段。
# 并做失败自证：给检查器喂一段含 C:\Users\ 的字节，必须被检出。
#
# gcc 缺失 → skip（不算通过，也不算失败；与生成器 SKIP 语义一致）。
import hashlib
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import make_datarefs_full as M16        # noqa: E402
import make_funcreport_full as M15      # noqa: E402

# 本机路径片段（小写比较）。temp 目录名单独按 BUILD_DIR 检查，避免误伤
# 样本里合法的 "hello-data" 一类字符串。
LOCAL_MARKERS = (b"c:\\users", b"/home/", b"/users/", b"appdata")

GENERATORS = [
    ("m15 funcreport_full", M15, "funcreport_full"),
    ("m16 datarefs_full.exe", M16, "datarefs_full.exe"),
]


def _leaks(data):
    """返回命中的本机路径片段（小写 bytes）。空列表 = 干净。"""
    low = data.lower()
    hits = [m for m in LOCAL_MARKERS if m in low]
    for name in ("rekit_m15_build", "rekit_m16_build"):
        if name.encode() in low:
            hits.append(name.encode())
    return hits


def test_leak_checker_can_fail():
    """失败自证：含用户名/家目录的合成字节必须被检出，干净字节必须不报。"""
    dirty = b"MZ\x90\x00 debug: C:\\Users\\bob\\AppData\\Local\\Temp\\x.c"
    assert _leaks(dirty), "含 C:\\Users\\ 的字节未被检出"
    assert _leaks(b"xx /home/example-user/proj/a.c"), "含 /home/ 的字节未被检出"
    assert _leaks(b"MZ clean payload hello-data") == []


@pytest.mark.parametrize("label,mod,out_name", GENERATORS)
def test_fixture_reproducible_and_clean(label, mod, out_name, tmp_path):
    a = str(tmp_path / ("a-" + out_name))
    b = str(tmp_path / ("b-" + out_name))
    for path in (a, b):
        status, detail = mod.build(path)
        if status == "SKIP":
            pytest.skip("%s: %s" % (label, detail))
        assert status == "OK", "%s: %s" % (label, detail)

    da, db = open(a, "rb").read(), open(b, "rb").read()
    assert hashlib.sha256(da).hexdigest() == hashlib.sha256(db).hexdigest(), \
        "%s 连续两次生成字节不同" % label

    committed = os.path.join(os.path.dirname(mod.OUT), os.path.basename(mod.OUT))
    dc = open(committed, "rb").read()
    assert dc == da, ("%s 入库 fixture 与生成器输出不同（先重跑生成器；"
                      "换 gcc 版本也会走到这里——字节只保证同工具链内一致）" % label)

    hits = _leaks(dc)
    assert not hits, "%s 产物含本机路径片段：%r" % (label, hits)
