#!/usr/bin/env python3
# verify_cli.py — 2026-11-14 M1 收口日验证脚本（D1/D2/D4）
#
# R25 加固（11-13 降档条款的针对性训练）：
#   * 所有"从文本提字段"必须先经 anchor_line() 断言锚点在全文本中恰好出现 1 次；
#   * --selftest 负测试：构造重复/缺失锚点输入，证明自检真的会拦（可证伪）。
# 用法：
#   python3 verify_cli.py             # D1(10 fixtures cli≡模块) + D2(负样本) + D4(锚点自检)
#   python3 verify_cli.py --selftest  # 仅 D4 锚点自检（重复/缺失两负例 + 一正例）
import struct
import subprocess
import sys
import tempfile
import os

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPO = os.path.join(_ROOT, "pack", "04_rekit项目源码")
FIX = REPO + "/tests/fixtures"
PY = sys.executable

ELF_FIXTURES = ["bin_ls.elf", "dyn_pie", "dyn_nopie", "dyn_static",
                "dyn_norelro", "dyn_execstack"]
PE_FIXTURES = ["minipe.exe", "cli-64.exe", "minidll.dll", "minipe_fakerich.exe"]
ALL_FIXTURES = [(f, "elf") for f in ELF_FIXTURES] + [(f, "pe") for f in PE_FIXTURES]


class AnchorError(AssertionError):
    """R25：锚点出现次数 != 1（0 次或 >=2 次），提取结果不可信，拒绝继续。"""


def anchor_line(text, anchor):
    """返回含锚点的整行。前置断言：锚点在全文本中恰好出现 1 次。"""
    n = text.count(anchor)
    if n != 1:
        raise AnchorError("锚点 %r 出现 %d 次（期望 1）——拒绝提取" % (anchor, n))
    return next(ln for ln in text.splitlines() if anchor in ln)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)


def cli(path, *extra):
    return run([PY, "-m", "rekit.cli", path, *extra])


def mod_direct(module, path):
    return run([PY, "-m", "rekit." + module, path])


# ── D1：10 fixtures 自动识别 + cli 输出与模块直调逐字节一致 ──────────

def check_d1():
    print("== D1: 自动识别 + cli ≡ 模块直调（10 fixtures）==")
    ok = True
    for fname, fmt in ALL_FIXTURES:
        path = "%s/%s" % (FIX, fname)
        c, r = cli(path), mod_direct(fmt, path)
        same = (c.returncode == 0 and c.stdout == r.stdout)
        ok &= same
        print("  %-22s -> %-3s  exit=%d  identical=%s" %
              (fname, fmt, c.returncode, same))
        # 审计字段提取（每个锚点先验唯一——anchor_line 内部断言）
        try:
            if fmt == "elf":
                key = anchor_line(c.stdout, "Entry:")
                sec = anchor_line(c.stdout, "Checksec:")
            else:
                key = anchor_line(c.stdout, "EntryPoint:")
                sec = anchor_line(c.stdout, "Machine:")
            print("      audit: %s | %s" % (key.strip(), sec.strip()))
        except AnchorError as e:
            ok = False
            print("      audit: FAIL %s" % e)
    print("D1 %s\n" % ("PASS" if ok else "FAIL"))
    return ok


# ── D2：负样本友好降级（无 traceback、一行 stderr、非零退出码）────────

def make_negative(dirpath):
    txt = os.path.join(dirpath, "not_a_binary.txt")
    with open(txt, "w") as f:
        f.write("hello rekit, i am not a binary\n" * 8)
    mz = os.path.join(dirpath, "mz_no_pe.bin")
    with open(mz, "wb") as f:
        # MZ 头 + e_lfanew=0x50 指向垃圾（无 PE\0\0 签名）
        f.write(b"MZ" + b"\x00" * 0x3e + struct.pack("<I", 0x50) + b"JUNK")
    trunc = os.path.join(dirpath, "truncated.elf")
    with open(trunc, "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)  # 魔数对但截断
    return [("text 文件（非二进制）", txt, 2),
            ("MZ 无 PE 签名", mz, 2),
            ("截断 ELF（解析失败路径）", trunc, 3)]


def check_d2():
    print("== D2: 负样本友好降级 ==")
    ok = True
    with tempfile.TemporaryDirectory() as td:
        for label, path, want_rc in make_negative(td):
            r = cli(path)
            good = (r.returncode == want_rc and r.stderr.strip()
                    and "Traceback" not in r.stderr
                    and len(r.stderr.strip().splitlines()) == 1)
            ok &= good
            print("  %-24s exit=%d(期望%d) stderr=%r traceback=%s -> %s" %
                  (label, r.returncode, want_rc, r.stderr.strip(),
                   "Traceback" in r.stderr, "PASS" if good else "FAIL"))
    print("D2 %s\n" % ("PASS" if ok else "FAIL"))
    return ok


# ── D4：锚点唯一性自检（--selftest 单独可跑）─────────────────────────

def check_d4():
    print("== D4: 锚点唯一性自检（R25 加固可证伪性）==")
    ok = True
    # 正例：唯一锚点 → 正常提取
    try:
        line = anchor_line("prefix line\nChecksec: NX enabled\nsuffix",
                           "Checksec:")
        print("  正例（唯一锚点）: 提取成功 %r" % line.strip())
    except AnchorError as e:
        ok = False
        print("  正例 FAIL：唯一锚点竟被拒 %s" % e)
    # 负例 1：重复锚点 → 必须抛 AnchorError
    try:
        anchor_line("Checksec: A\nChecksec: B\n", "Checksec:")
        ok = False
        print("  负例1 FAIL：重复锚点未被拦截（静默取错段风险）")
    except AnchorError as e:
        print("  负例1（重复锚点）: 已拦截 ✓ %s" % e)
    # 负例 2：缺失锚点（0 次）→ 同样必须抛
    try:
        anchor_line("nothing here\n", "Checksec:")
        ok = False
        print("  负例2 FAIL：缺失锚点未被拦截")
    except AnchorError as e:
        print("  负例2（缺失锚点）: 已拦截 ✓ %s" % e)
    print("D4 %s\n" % ("PASS" if ok else "FAIL"))
    return ok


def main():
    if "--selftest" in sys.argv[1:]:
        sys.exit(0 if check_d4() else 1)
    results = {"D1": check_d1(), "D2": check_d2(), "D4": check_d4()}
    print("=" * 60)
    print("总验收: " + "  ".join(
        "%s=%s" % (k, "PASS" if v else "FAIL") for k, v in results.items()))
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
