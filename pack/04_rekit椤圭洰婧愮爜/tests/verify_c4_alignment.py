#!/usr/bin/env python3
# verify_c4_alignment.py — C4 的独立复核：Go 域内未达指令桶是否真的含对齐。
#
# 判据（与 M13 三分法一致，不新增口径）：
#   1) objdump 全节指令；
#   2) 我方已解出指令集合之外的，按字节全为 cc/90 归 padding，否则看是否落在
#      gopclntab 声明域 [entry,end) 内 → in_range_other；
#   3) 在 in_range_other 里逐条看 objdump 文本/字节，数 nop 族（对齐）。
#
# 断言：
#   · 三分法计数与 evidence_m14_c4_alignment.json / 总账一致；
#   · 对齐数 > 0（否则“含对齐”这句话不成立，应改写结论）；
#   · 对齐占比与存档值一致（容差为 0）。
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import coverage, disasm, recdesc  # noqa: E402

SAMPLES = [
    ("go_elf", "samples/m9/elf_medium_synth_go_stripped"),
    ("go_pe", "samples/m9/pe_medium_synth_go_stripped.exe"),
]
EXPECT = {
    "go_elf": {"in_range_other": 26652, "windows": 0, "nop_like": 1067},
    "go_pe": {"in_range_other": 26702, "windows": 40, "nop_like": 1066},
}


def _ranges(res):
    out = sorted((s["addr"], s["end"]) for s in res["seeds"]
                 if s.get("end") and s["end"] > s["addr"])
    return out


def _in_ranges(ranges, addr):
    import bisect
    i = bisect.bisect_right(ranges, (addr, float("inf"))) - 1
    return i >= 0 and ranges[i][0] <= addr < ranges[i][1]


def _mnem(text):
    t = (text or "").strip().split(None, 1)
    return t[0].lower() if t else ""


def main():
    fails = []
    archive_path = os.path.join(WORK, "evidence_m14_c4_alignment.json")
    archive = {}
    if os.path.exists(archive_path):
        with open(archive_path, encoding="utf-8") as f:
            archive = json.load(f)
    print("=" * 78)
    print("C4：Go 函数域内未达 objdump 指令（含对齐）—— 逐条复算")
    print("=" * 78)
    for name, rel in SAMPLES:
        path = os.path.join(WORK, rel)
        if not os.path.exists(path):
            print("%s: 样本缺失（跳过，不改判定）" % name)
            continue
        res = recdesc.descend(path)
        ranges = _ranges(res)
        sec = disasm.find_section(path, ".text")
        data = open(path, "rb").read()
        obj = coverage.objdump_instructions(path, sec)
        if obj["status"] != "ok":
            fails.append("%s: objdump %s" % (name, obj["status"]))
            continue
        ours = {i["addr"] for i in res["instructions"]
                if i.get("status", "ok") == "ok"}
        pad = other = out = 0
        nop = 0
        for ins in obj["instructions"]:
            a = ins["addr"]
            if a in ours:
                continue
            pos = sec["off"] + (a - sec["va"])
            raw = data[pos:pos + ins["length"]]
            if raw and all(b in (0xCC, 0x90) for b in raw):
                pad += 1
                continue
            if _in_ranges(ranges, a):
                other += 1
                if _mnem(ins["text"]) == "nop" or raw.startswith(b"\x0f\x1f") \
                        or raw == b"\x90":
                    nop += 1
            else:
                out += 1
        exp = EXPECT[name]
        if (other, out, nop) != (exp["in_range_other"], exp["windows"],
                                 exp["nop_like"]):
            fails.append("%s: 复算 (%d,%d,%d) != 期望 (%d,%d,%d)"
                         % (name, other, out, nop, exp["in_range_other"],
                            exp["windows"], exp["nop_like"]))
        if nop <= 0:
            fails.append("%s: 对齐全为 0——「含对齐」结论不成立，必须改写" % name)
        if name in archive:
            a = archive[name]
            if (a.get("classes", {}).get("in_range_other") != other
                    or a.get("nop_like") != nop):
                fails.append("%s: 与 evidence_m14_c4_alignment.json 不一致"
                             % name)
            if abs(a.get("nop_like_share", -1) - nop / other) > 0:
                fails.append("%s: 对齐占比与存档不一致" % name)
        print("%s: padding=%d ｜ in_range_other=%d（nop 族 %d，%.4f%%）"
              " ｜ 域外=%d ｜ 声明域=%d"
              % (name, pad, other, nop, 100.0 * nop / other, out, len(ranges)))
    print("=" * 78)
    if fails:
        for f in fails:
            print("FAIL:", f)
        return 1
    print("OK: 三分法计数与对齐占比均与存档一致；「含对齐」有实测支撑")
    return 0


def selftest():
    """可失败自证：清空 recdesc 已解出指令 → 现有复算必与 EXPECT 不符。"""
    import contextlib
    import io
    orig = recdesc.descend

    def broken(path):
        r = dict(orig(path))
        r["instructions"] = []
        return r

    recdesc.descend = broken
    try:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main()
    finally:
        recdesc.descend = orig
    ok = rc == 1
    print("[selftest] 清空 recdesc.instructions 后复算偏离 EXPECT，"
          "main() 返回 %d（期望 1）→ %s" % (rc, "检出" if ok else "未检出"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv[1:] else main())
