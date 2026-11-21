#!/usr/bin/env python3
# tests/make_funcreport_full.py — M15 验收样本：完整声明的小函数
#
# 用内联 C 编出 add3/twice/main，带 -g 以产生 DWARF（形参声明来源）。
# 约束：
#   - 仓库路径含中文，gcc 在 Windows 上对非 ASCII 路径不可靠，故在 ASCII
#     临时目录编译，成功后复制回 tests/fixtures/funcreport_full；
#   - gcc 缺失 → 打印 SKIP、退出 0（verify 侧记账为 SKIP，不算 PASS）；
#   - 编译失败 → 退出 1（这是真问题，不伪装成 SKIP）。
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "m15_fixtures", "funcreport_full")
GCC_CANDIDATES = [os.environ.get("CC", ""),
                  r"C:\msys64\ucrt64\bin\gcc.exe",
                  r"C:\msys64\mingw64\bin\gcc.exe"]
SRC = """\
int add3(int a, int b, int c) { return a + b * c; }
int twice(int x) { return x * 2; }
int main(void) { return add3(1, 2, 3) + twice(4); }
"""
# -O0 防止内联；-fno-pie/-no-pie 防止地址随机化影响 low_pc 对齐。
# MinGW 的部分版本不认 -no-pie，故保留退化命令。
VARIANTS = [["-g", "-O0", "-fno-pie", "-no-pie"],
            ["-g", "-O0"]]


def find_gcc():
    w = shutil.which("gcc")
    if w:
        return w
    for c in GCC_CANDIDATES:
        if os.path.exists(c):
            return c
    return None


def main():
    exe = find_gcc()
    if exe is None:
        print("SKIP: 找不到 gcc（PATH 与 msys64 候选目录均无）")
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="rekit_m15_")
    try:
        cpath = os.path.join(tmp, "funcreport_full.c")
        with open(cpath, "w", encoding="ascii") as f:
            f.write(SRC)
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        last = None
        for flags in VARIANTS:
            obj = os.path.join(tmp, "funcreport_full.exe")
            if os.path.exists(obj):
                os.remove(obj)
            cmd = [exe] + flags + ["-o", obj, cpath]
            r = subprocess.run(cmd, capture_output=True, env=env, timeout=180)
            if r.returncode == 0 and os.path.exists(obj):
                shutil.copyfile(obj, OUT)
                print("OK: %s (%d bytes, flags=%s)"
                      % (OUT, os.path.getsize(OUT), " ".join(flags)))
                return 0
            last = (r.returncode, r.stderr.decode("utf-8", "replace")[:400])
        print("ERROR: gcc 编译失败（%s）：%s" % (last[0], last[1]),
              file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
