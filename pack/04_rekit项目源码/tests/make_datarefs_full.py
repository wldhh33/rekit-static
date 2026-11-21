#!/usr/bin/env python3
# tests/make_datarefs_full.py — M16 验收样本：带全局/静态数据对象的 PE
#
# 目的：给 datarefs 一个可控正样本，覆盖：
#   - DWARF DW_TAG_variable（DW_OP_addr + 类型链尺寸）
#   - .data / .rdata / .bss 三种落点（.bss 无文件字节）
#   - object_start / inside_object 两档归因（g_table[1]、g_zero[2]）
#   - 数据节指针槽（g_ptrs 初始化为 &g_counter / &g_zero[1]）
# 可复现性约束（与 make_funcreport_full.py 同一套，2026-11-21 修复）：
#   - 仓库路径含中文，gcc 在 Windows 上对非 ASCII 路径不可靠，故在 ASCII 的
#     **固定**构建目录（tempfile.gettempdir()/rekit_m16_build，每次清空）里编译，
#     不再用 tempfile.mkdtemp 的随机目录；
#   - 用 -fdebug-prefix-map 把构建目录映射为 "."，使 DWARF 的 comp_dir/源路径与
#     机器、用户名无关；
#   - PE 时间戳归零（-Wl,--no-insert-timestamp，且脚本再兜底清零 4 字节），
#     保证同一机器两次、及换用户名的机器生成，产物逐字节相同；
#   - gcc 缺失 → 打印 SKIP、退出 0（verify 侧记账为 SKIP，不算 PASS）；
#   - 编译失败 → 退出 1（这是真问题，不伪装成 SKIP）。
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "m16_fixtures", "datarefs_full.exe")
GCC_CANDIDATES = [os.environ.get("CC", ""),
                  r"C:\msys64\ucrt64\bin\gcc.exe",
                  r"C:\msys64\mingw64\bin\gcc.exe",
                  r"D:\msys64\ucrt64\bin\gcc.exe",
                  r"D:\msys64\mingw64\bin\gcc.exe"]
# 固定的 ASCII 构建目录（含用户名也无妨：debug-prefix-map 会把它映射掉）。
BUILD_DIR = os.path.join(tempfile.gettempdir(), "rekit_m16_build")
SRC_NAME = "datarefs_full.c"
OUT_NAME = "datarefs_full.exe"
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
# -O0 防止内联；-fno-pie/-no-pie 防止地址随机化影响 low_pc 对齐。
# MinGW 的部分版本不认 -no-pie，故保留退化命令。
VARIANTS = [["-g", "-O0", "-fno-pie", "-no-pie"],
            ["-g", "-O0"]]
NO_TIMESTAMP = ["-Wl,--no-insert-timestamp"]


def find_gcc():
    w = shutil.which("gcc")
    if w:
        return w
    for c in GCC_CANDIDATES:
        if c and os.path.exists(c):
            return c
    return None


def _zero_pe_timestamp(data):
    """把 PE COFF 头 TimeDateStamp 置 0（等长 4 字节，不改任何偏移）。

    -Wl,--no-insert-timestamp 已能归零；这里再兜底一次，保证老 ld 也确定。
    非 PE（如 ELF）原样返回。
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return data
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if e + 0x18 > len(data) or data[e:e + 4] != b"PE\0\0":
        return data
    buf = bytearray(data)
    struct.pack_into("<I", buf, e + 8, 0)
    return bytes(buf)


def build(out_path):
    """确定性编译到 out_path。返回 (status, detail)，status ∈ OK/SKIP/FAIL。"""
    exe = find_gcc()
    if exe is None:
        return ("SKIP", "找不到 gcc（PATH 与候选目录均无）")
    shutil.rmtree(BUILD_DIR, ignore_errors=True)
    os.makedirs(BUILD_DIR, exist_ok=True)
    with open(os.path.join(BUILD_DIR, SRC_NAME), "w", encoding="ascii") as f:
        f.write(SRC)
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    # gcc 调 as/ld 依赖 PATH；把工具链 bin 前置，避免“静默 rc=1”。
    env["PATH"] = os.path.dirname(exe) + os.pathsep + env.get("PATH", "")
    prefix_map = "-fdebug-prefix-map=%s=." % BUILD_DIR
    obj = os.path.join(BUILD_DIR, OUT_NAME)
    last = None
    # 先试带 --no-insert-timestamp，失败再退回不带该链接选项（时间戳由 Python 清零）。
    for linker in (NO_TIMESTAMP, []):
        for flags in VARIANTS:
            if os.path.exists(obj):
                os.remove(obj)
            cmd = ([exe] + flags + [prefix_map] + linker +
                   ["-o", OUT_NAME, SRC_NAME])
            r = subprocess.run(cmd, capture_output=True, env=env,
                               cwd=BUILD_DIR, timeout=180)
            if r.returncode == 0 and os.path.exists(obj):
                data = _zero_pe_timestamp(open(obj, "rb").read())
                os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
                with open(out_path, "wb") as f:
                    f.write(data)
                detail = ("%d bytes, flags=%s %s"
                          % (len(data), " ".join(flags), " ".join(linker)))
                return ("OK", detail.strip())
            last = (r.returncode, r.stderr.decode("utf-8", "replace")[:400])
    return ("FAIL", str(last))


def main():
    status, detail = build(OUT)
    if status == "SKIP":
        print("SKIP: %s" % detail)
        return 0
    if status == "OK":
        print("OK: %s (%s)" % (OUT, detail))
        return 0
    print("ERROR: gcc 编译失败（%s）" % detail, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
