#!/usr/bin/env python3
# tests/make_datarefs_full.py — M16 验收样本：带全局/静态数据对象的 PE
#
# 目的：给 datarefs 一个可控正样本，覆盖：
#   - DWARF DW_TAG_variable（DW_OP_addr + 类型链尺寸）
#   - .data / .rdata / .bss 三种落点（.bss 无文件字节）
#   - object_start / inside_object 两档归因（g_table[1]、g_zero[2]）
#   - 数据节指针槽（g_ptrs 初始化为 &g_counter / &g_zero[1]）
# 约束同 M15：ASCII 临时目录编译、gcc 缺失 SKIP(0)、编译失败 1。
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "m16_fixtures", "datarefs_full.exe")
GCC_CANDIDATES = [r"C:\Users\<user>\Tools\toolchains\mingw64\bin\gcc.exe",
                  r"D:\msys64\ucrt64\bin\gcc.exe",
                  r"D:\msys64\mingw64\bin\gcc.exe"]
SRC = """\
int g_counter = 7;
static int g_table[4] = {11, 22, 33, 44};
const char g_msg[] = "hello-data";
int g_zero[8];
int *g_ptrs[2] = { &g_counter, &g_zero[1] };

int read_counter(void) { return g_counter; }
int table_sum(void) { return g_table[1] + g_table[3]; }
const char *msg_addr(void) { return g_msg; }
int *zero_two(void) { return &g_zero[2]; }
int *ptr_zero(void) { return g_ptrs[0]; }
int main(void) { return read_counter() + table_sum(); }
"""
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
        print("SKIP: 找不到 gcc（PATH 与候选路径均无）")
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="rekit_m16_")
    try:
        cpath = os.path.join(tmp, "datarefs_full.c")
        with open(cpath, "w", encoding="ascii") as f:
            f.write(SRC)
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        last = None
        for flags in VARIANTS:
            obj = os.path.join(tmp, "datarefs_full.exe")
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
