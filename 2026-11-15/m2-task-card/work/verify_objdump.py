#!/usr/bin/env python3
# verify_objdump.py — test_minidll_crosscheck_objdump 的证据生成器（2026-11-15）
#
# 用途（不参与 rekit 运行路径，只做验收留证）：
#   1) 打印 objdump 版本与绝对路径（证明跑的是 GNU binutils，不是 Go 自带 objdump）
#   2) 打印 objdump -p minidll.dll 的导出表原始片段
#   3) 用与 tests/test_pe.py::test_minidll_crosscheck_objdump **同一套正则**解析，
#      与 rekit.pe.parse 的 EAT / name->ordinal 并列打印，逐项比对
#
# 用法： python verify_objdump.py [minidll.dll 路径]
#   —— 输入路径默认取仓库内测试样本（objdump.exe 对非 ASCII 路径不稳，
#      必要时把仓库克隆到纯 ASCII 路径再跑）
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
REPO = os.path.join(_ROOT, "pack", "04_rekit项目源码")
DEFAULT_DLL = REPO + r"\tests\fixtures\minidll.dll"

sys.path.insert(0, REPO)
from rekit.pe import parse  # noqa: E402


def main(argv):
    dll = argv[1] if len(argv) > 1 else DEFAULT_DLL
    exe = shutil.which("objdump")
    if not exe:
        print("FAIL: PATH 中找不到 objdump")
        return 2
    ver = subprocess.run([exe, "--version"], capture_output=True, text=True,
                         check=True).stdout.splitlines()[0]
    print("objdump path : %s" % exe)
    print("objdump ver  : %s" % ver)
    print("target       : %s" % dll)

    out = subprocess.run([exe, "-p", dll], capture_output=True, text=True,
                         check=True).stdout
    eat_part = out.split("Export Address Table -- Ordinal Base")[1] \
                 .split("[Ordinal/Name Pointer] Table")[0]
    name_part = out.split("[Ordinal/Name Pointer] Table")[1]

    print("\n--- objdump 原始片段（EAT + 名字指针表）---")
    raw = [ln for ln in out.splitlines()
           if "Ordinal Base" in ln or "Export Address Table" in ln
           or "Ordinal/Name Pointer" in ln or "Export RVA" in ln
           or re.search(r"\[ *\d+\] \+base\[\s*\d+\]", ln)]
    for ln in raw:
        print("  " + ln.rstrip())

    obj_eat = {int(m.group(1)): int(m.group(2), 16)
               for m in re.finditer(
                   r"\[\s*\d+\] \+base\[\s*(\d+)\] ([0-9a-f]{8}) Export RVA",
                   eat_part)}
    obj_named = {m.group(2): int(m.group(1))
                 for m in re.finditer(
                     r"\[\s*\d+\] \+base\[\s*(\d+)\]\s+[0-9a-f]{4} (\w+)",
                     name_part)}

    r = parse(dll)
    rk_eat = {e[1]: e[2] for e in r["exports"]["exports"]}
    rk_named = {e[0]: e[1] for e in r["exports"]["exports"] if e[0]}

    print("\n--- EAT: ordinal -> RVA ---")
    print("  objdump : %s" % sorted(obj_eat.items()))
    print("  rekit   : %s" % sorted(rk_eat.items()))
    print("  equal   : %s" % (obj_eat == rk_eat))
    print("\n--- 名字 -> ordinal ---")
    print("  objdump : %s" % sorted(obj_named.items()))
    print("  rekit   : %s" % sorted(rk_named.items()))
    print("  equal   : %s" % (obj_named == rk_named))
    ok = obj_eat == rk_eat and obj_named == rk_named
    print("\nVERDICT: %s" % ("PASS 全等" if ok else "FAIL 不等"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
