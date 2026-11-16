#!/usr/bin/env python3
# tests/verify_gopclntab.py — M11 验收：gopclntab 作为 declared 级函数边界源
#
# 四件事（对应 M11 要求 1/3，以及"可失败自证"）：
#   A) 性质与版本：ELF 有独立 .gopclntab 节、PE 在 .rdata 内按 magic 定位；
#      报告 magic/版本/nfunc/链接器标记数（标记不是函数，必须单列）。
#   B) 双源对拍（不许自证）：我方 rekit.gopclntab vs Go 官方 debug/gosym
#      （tests/tools/gofunclist.go，只用官方解析器），逐条比对 entry/end/name；
#      不一致按「仅我方 / 仅官方 / end 差 / name 差」分类计数，必须全 0。
#   C) objdump 边界独立校验：每个非标记函数的 entry 与 end 都必须落在
#      GNU objdump 的指令边界上；不一致按 entry/end 分类单列，必须全 0。
#   D) 负控（--selftest 逻辑内联，始终执行）：在 ELF 样本副本上篡改
#      ①magic→go1.2–1.15 ②nfunc=0 ③入口非递增 ④funcoff 越界 ⑤textStart 越界，
#      五次都必须 status=unknown 且 funcs 为空（不接受半个表）；未篡改副本必须 ok。
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# 注意：work/tests 是指向 pack/04_*/tests 的 junction，而 samples/ 只在 work 下。
# 因此这里用 abspath（不解析链接），保证 REPO 落在 work 根而不是 junction 目标。
HERE = Path(os.path.abspath(__file__)).parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))
from rekit import disasm, elf, gopclntab, coverage, pe  # noqa: E402

TOOL = HERE / "tools" / "gofunclist.go"
SAMPLES = [
    ("ELF/go", "samples/m9/elf_medium_synth_go_stripped", "elf"),
    ("PE/go", "samples/m9/pe_medium_synth_go_stripped.exe", "pe"),
]


def run_official(path, dst):
    r = subprocess.run(["go", "run", str(TOOL), path, dst],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode != 0:
        return None, (r.stdout or "") + (r.stderr or "")
    got = {}
    header = {}
    for line in open(dst, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        if not line:
            continue
        if line.startswith("#"):
            m = line.split()
            for tok in m[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    header[k] = int(v, 16) if v.startswith("0x") else int(v)
            continue
        a, b, n = line.split("\t")
        got[int(a, 16)] = (int(b, 16), n)
    return {"funcs": got, "header": header}, None


def compare(ours, official):
    """逐字段对拍，返回分类计数（不合并、不静默）。"""
    o = {f["entry"]: (f["end"], f["name"]) for f in ours}
    g = official["funcs"]
    both = set(o) & set(g)
    end_diff = [a for a in both if o[a][0] != g[a][0]]
    name_diff = [a for a in both if o[a][1] != g[a][1]]
    return {
        "ours_total": len(o),
        "official_total": len(g),
        "only_ours": sorted(set(o) - set(g)),
        "only_official": sorted(set(g) - set(o)),
        "end_diff": end_diff,
        "name_diff": name_diff,
        "entry_same": set(o) == set(g),
    }


def boundary_check(path, fmt, r):
    sec = disasm.find_section(path, ".text")
    obj = coverage.objdump_instructions(path, sec)
    base = 0 if fmt == "elf" else pe.parse(path)["image_base"]
    starts = {t["addr"] for t in obj["instructions"]}
    ends = {t["addr"] + t["length"] for t in obj["instructions"]}
    bad_entry, bad_end = [], []
    marker_ins = 0
    for f in r["funcs"]:
        a, e = f["entry"] - base, f["end"] - base
        if f["is_marker"]:
            marker_ins += sum(1 for t in obj["instructions"]
                              if a <= t["addr"] < e)
            continue
        if a not in starts:
            bad_entry.append((a, f["name"]))
        if e not in starts and e not in ends:
            bad_end.append((e, f["name"]))
    return {"objdump_status": obj["status"], "objdump_n": len(obj["instructions"]),
            "objdump_bad": obj["bad"], "bad_entry": bad_entry,
            "bad_end": bad_end, "marker_instructions": marker_ins}


def corrupt(data, tab_off, pcln_off, what):
    """在 .gopclntab 表内做一处篡改；返回可读描述。"""
    if what == "magic":
        struct.pack_into("<I", data, tab_off, 0xFFFFFFFB)
        return "magic→0xfffffffb（go1.2-1.15）"
    if what == "nfunc":
        struct.pack_into("<Q", data, tab_off + 8, 0)
        return "nfunc=0"
    if what == "entry_nonmono":
        struct.pack_into("<I", data, tab_off + pcln_off + 8, 0)
        return "第 2 个 entryoff=0（非严格递增）"
    if what == "funcoff":
        struct.pack_into("<I", data, tab_off + pcln_off + 4, 0)
        return "首个 funcoff=0（落在 functab 之前）"
    if what == "textstart":
        struct.pack_into("<Q", data, tab_off + 24, 0xDEADBEEF)
        return "textStart=0xdeadbeef（不在 .text）"
    raise ValueError(what)


def negative_controls(src, tmpdir):
    """可失败自证：篡改必须被拒；未篡改副本必须通过。"""
    raw = bytearray(open(src, "rb").read())
    tab = next(s for s in elf.section_headers(bytes(raw))
               if s["name"] == ".gopclntab")
    pcln_off = struct.unpack_from("<Q", raw, tab["offset"] + 64)[0]
    results = []
    p0 = os.path.join(tmpdir, "pristine.bin")
    open(p0, "wb").write(raw)
    r0 = gopclntab.parse(p0)
    results.append(("未篡改副本", r0["status"] == "ok",
                    "status=%s nfunc=%s" % (r0["status"], r0.get("nfunc"))))
    for what in ("magic", "nfunc", "entry_nonmono", "funcoff", "textstart"):
        d = bytearray(raw)
        desc = corrupt(d, tab["offset"], pcln_off, what)
        p = os.path.join(tmpdir, "bad_%s.bin" % what)
        open(p, "wb").write(d)
        r = gopclntab.parse(p)
        ok = (r["status"] == "unknown" and not r["funcs"])
        results.append((desc, ok, "status=%s funcs=%d reason=%s"
                        % (r["status"], len(r["funcs"]), r.get("reason"))))
    return results


def main():
    print("=" * 78)
    print("gopclntab：declared 级函数边界源（双源对拍 + objdump 边界 + 负控）")
    print("=" * 78)
    fails = []
    tmpdir = tempfile.mkdtemp(prefix="m11_gopcln_")
    for tag, rel, fmt in SAMPLES:
        path = str(REPO / rel)
        print("\n[%s] %s" % (rel, tag))
        if not os.path.exists(path):
            fails.append("%s: 样本缺失" % rel)
            continue
        # ── A. 性质与版本 ────────────────────────────────────────────
        r = gopclntab.parse(path)
        print("  A 性质: status=%s version=%s magic=%s where=%s"
              % (r["status"], r.get("version"),
                 hex(r["magic"]) if r.get("magic") else None, r.get("where")))
        print("     nfunc=%s nfiles=%s markers=%s text=[0x%x,0x%x)"
              % (r.get("nfunc"), r.get("nfiles"), r.get("n_markers"),
                 r["text_start"], r["text_end"]))
        for w in r.get("warnings") or []:
            print("     warn: %s" % w)
        if r["status"] != "ok":
            fails.append("%s: 解析失败 %s" % (rel, r.get("reason")))
            continue
        if fmt == "elf":
            names = [s["name"] for s in elf.section_headers(open(path, "rb").read())]
            if ".gopclntab" not in names:
                fails.append("%s: ELF 缺少独立 .gopclntab 节" % rel)
        if r["n_markers"] != sum(1 for f in r["funcs"] if f["is_marker"]):
            fails.append("%s: n_markers 与逐条标记数不一致" % rel)
        mk = sorted({f["name"] for f in r["funcs"] if f["is_marker"]})
        print("     链接器标记（非函数）: %s" % ", ".join(mk))

        # ── B. Go 官方解析器对拍 ────────────────────────────────────
        dst = os.path.join(tmpdir, "%s.tsv" % fmt)
        official, err = run_official(path, dst)
        if official is None:
            fails.append("%s: 官方参照运行失败 %s" % (rel, err[-300:]))
            print("  B 官方参照: 运行失败")
        else:
            c = compare(r["funcs"], official)
            print("  B 官方 debug/gosym: 我方 %d / 官方 %d ｜ entry 集合相同=%s"
                  % (c["ours_total"], c["official_total"], c["entry_same"]))
            print("     仅我方 %d ｜ 仅官方 %d ｜ end 差 %d ｜ name 差 %d"
                  % (len(c["only_ours"]), len(c["only_official"]),
                     len(c["end_diff"]), len(c["name_diff"])))
            for k in ("entry_same",):
                if not c[k]:
                    fails.append("%s: entry 集合与官方不一致" % rel)
            for key, lab in (("end_diff", "end"), ("name_diff", "name")):
                if c[key]:
                    fails.append("%s: %s 不一致 %d 条（样例 %s）"
                                 % (rel, lab, len(c[key]),
                                    [hex(x) for x in c[key][:3]]))
            if c["only_ours"] or c["only_official"]:
                fails.append("%s: 函数集合差异 我方多 %d / 官方多 %d"
                             % (rel, len(c["only_ours"]),
                                len(c["only_official"])))

        # ── C. objdump 边界 ─────────────────────────────────────────
        b = boundary_check(path, fmt, r)
        print("  C objdump: status=%s 指令 %d bad %d ｜ 标记占用 %d 条（不计入）"
              % (b["objdump_status"], b["objdump_n"], b["objdump_bad"],
                 b["marker_instructions"]))
        print("     entry 非边界 %d ｜ end 非边界 %d"
              % (len(b["bad_entry"]), len(b["bad_end"])))
        if b["objdump_status"] != "ok":
            fails.append("%s: objdump 不可用" % rel)
        if b["bad_entry"]:
            fails.append("%s: %d 个入口不在 objdump 指令边界（%s）"
                         % (rel, len(b["bad_entry"]),
                            [hex(x) for x, _n in b["bad_entry"][:3]]))
        if b["bad_end"]:
            fails.append("%s: %d 个结束不在 objdump 指令边界（%s）"
                         % (rel, len(b["bad_end"]),
                            [hex(x) for x, _n in b["bad_end"][:3]]))

    # ── D. 负控 ─────────────────────────────────────────────────────
    src = str(REPO / SAMPLES[0][1])
    print("\n[D] 负控（篡改 .gopclntab 后必须 unknown 且 funcs 为空）")
    if os.path.exists(src):
        for desc, ok, detail in negative_controls(src, tmpdir):
            print("  %s %-42s %s" % ("✓" if ok else "✗", desc, detail))
            if not ok:
                fails.append("负控失败：%s（%s）" % (desc, detail))
    else:
        fails.append("负控样本缺失")
        print("  样本缺失")

    print("\n判定：失败 %d 项" % len(fails))
    for f in fails:
        print("  ✗ %s" % f)
    print("\nVERDICT: %s" % ("PASS" if not fails else "FAIL"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
