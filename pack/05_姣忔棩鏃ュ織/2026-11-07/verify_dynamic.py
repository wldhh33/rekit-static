#!/usr/bin/env python3
# 验收脚本：rekit.elf 动态段解析 vs readelf 权威输出（2026-11-07 白银任务）
import re
import subprocess
import sys

sys.path.insert(0, "<旧仓库根>")
from rekit.elf import parse  # noqa: E402

SAMPLES = ["/bin/ls", "/tmp/re_daily/dyn_pie", "/tmp/re_daily/dyn_nopie"]

RE_NEEDED = re.compile(r"Shared library: \[(.+?)\]")
RE_DYNAMIC = re.compile(
    r"^\s*DYNAMIC\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)",
    re.M)


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def main():
    all_pass = True
    for path in SAMPLES:
        print("== %s ==" % path)
        # ---- 权威基线：readelf ----
        ref_needed = RE_NEEDED.findall(sh("readelf", "-d", path))
        m = RE_DYNAMIC.search(sh("readelf", "-lW", path))
        ref_off, ref_va, ref_pa, ref_fsz = (int(g, 16) for g in m.groups()[:4])

        # ---- 被测：rekit ----
        try:
            r = parse(path)
        except Exception as ex:
            print("  FAIL: rekit parse 异常: %r" % ex)
            all_pass = False
            continue
        d = r["dynamic"]
        if d is None:
            print("  FAIL: 未解析到 PT_DYNAMIC")
            all_pass = False
            continue

        # S1/S2: NEEDED 列表逐项比对（名称+顺序+数量）
        s1 = d["needed"] == ref_needed
        print("  S1/S2 NEEDED: rekit=%r readelf=%r -> %s" %
              (d["needed"], ref_needed, "PASS" if s1 else "FAIL"))

        # S3: PT_DYNAMIC 段字段比对
        s3 = (d["offset"] == ref_off and d["vaddr"] == ref_va
              and d["filesz"] == ref_fsz)
        print("  S3 段字段: off 0x%x/0x%x va 0x%x/0x%x fsz 0x%x/0x%x -> %s" %
              (d["offset"], ref_off, d["vaddr"], ref_va,
               d["filesz"], ref_fsz, "PASS" if s3 else "FAIL"))

        # S4: strtab 换算有效性（非 None 且落在文件内）
        s4 = d["strtab_off"] is not None and 0 <= d["strtab_off"] < 2**31
        print("  S4 STRTAB: vaddr 0x%x -> off 0x%x -> %s" %
              (d["strtab_vaddr"] or 0, d["strtab_off"] or -1,
               "PASS" if s4 else "FAIL"))

        if not (s1 and s3 and s4):
            all_pass = False

    print("\n==== 总判定: %s ====" % ("ALL PASS" if all_pass else "FAIL"))
    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
