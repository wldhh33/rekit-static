#!/usr/bin/env python3
"""2026-11-09 白银任务验收脚本：重定位解析交叉验证
权威源 readelf -rW；三方复核 objdump -R；A3 内部一致性用自家节表。
输出逐项 PASS/FAIL + 证据存档。"""
import os
import re
import subprocess
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPO = os.path.join(_ROOT, "pack", "04_rekit项目源码")
sys.path.insert(0, REPO)
from rekit.elf import parse  # noqa: E402

FIX = REPO + "/tests/fixtures"
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         (" — " + detail) if detail else ""))


def readelf_relocs(path):
    """解析 readelf -rW → [(offset, type, name[剥@VER], addend), ...]"""
    out = subprocess.run(["readelf", "-rW", path],
                         capture_output=True, text=True).stdout
    rows = []
    for ln in out.splitlines():
        m = re.match(r"([0-9a-f]{16})\s+([0-9a-f]{16})\s+(R_X86_64_\S+)\s*(.*)", ln)
        if not m:
            continue
        tail = m.group(4).strip()
        if " + " in tail:  # 带符号：值 名字@VER + addend
            head, _, add = tail.rpartition(" + ")
            name = head.split()[-1].split("@")[0] if head.split() else ""
            rows.append((int(m.group(1), 16), m.group(3), name, int(add)))
        else:              # 无符号：裸十六进制 addend
            rows.append((int(m.group(1), 16), m.group(3), "", int(tail, 16)))
    return rows


def objdump_relocs(path):
    """objdump -R → [(offset, type, name[剥@VER], addend), ...]"""
    out = subprocess.run(["objdump", "-R", path],
                         capture_output=True, text=True).stdout
    rows = []
    for ln in out.splitlines():
        m = re.match(r"([0-9a-f]{16})\s+(R_X86_64_\S+)\s+(.*)", ln)
        if not m:
            continue
        tail = m.group(3).strip()
        if " + " in tail:
            head, _, add = tail.rpartition(" + ")
            name = head.split()[-1].split("@")[0] if head.split() else ""
            rows.append((int(m.group(1), 16), m.group(2), name, int(add)))
        elif re.fullmatch(r"[0-9a-f]+", tail):
            rows.append((int(m.group(1), 16), m.group(2), "", int(tail, 16)))
        else:  # 形如 '0000000000000000 puts@GLIBC_2.2.5'（无 addend 列）
            parts = tail.split()
            name = parts[-1].split("@")[0] if parts else ""
            rows.append((int(m.group(1), 16), m.group(2), name, 0))
    return rows


def mine_relocs(path):
    r = parse(path)
    rows = []
    for (nm, _off, ents) in r["relocations"]:
        for (o, _info, _tn, tname, _si, sn, _sv, ad) in ents:
            rows.append((o, tname, sn, ad))
    return r, rows


def sec_range(r, name):
    s = next((s for s in r["sections"] if s[0] == name), None)
    return (s[2], s[2] + s[4]) if s else None


# ── A1：数量一致（4 样本 × 各 RELA 节）──
EXPECT = {
    "bin_ls.elf": {".rela.dyn": 215, ".rela.plt": 110},
    "dyn_pie": {".rela.dyn": 8},
    "dyn_nopie": {".rela.dyn": 2},
    "dyn_static": {".rela.plt": 22},
}
for fname, exp in EXPECT.items():
    r = parse(f"{FIX}/{fname}")
    got = {nm: len(e) for (nm, _o, e) in r["relocations"]}
    check("A1 %s 节数与条数 %s" % (fname, exp), got == exp, "got %s" % got)

# ── A2：bin_ls.elf 全量 325 条逐字段比对 readelf ──
r_ls, mine_ls = mine_relocs(f"{FIX}/bin_ls.elf")
ref_ls = readelf_relocs(f"{FIX}/bin_ls.elf")
check("A2 bin_ls 总条数 = 325 (readelf=%d, mine=%d)" % (len(ref_ls), len(mine_ls)),
      len(ref_ls) == 325 and len(mine_ls) == 325)
diff = [(i, a, b) for i, (a, b) in enumerate(zip(ref_ls, mine_ls)) if a != b]
check("A2 逐条 (offset,type,name,addend) 一致，diff=0", not diff,
      "首个差异: %s" % (diff[0],) if diff else "325/325 全一致")

# 三方复核：objdump -R（带符号行比名字；无符号行比 *ABS*+0x 伪符号的 addend）
obj_ls = objdump_relocs(f"{FIX}/bin_ls.elf")
obj_map = {(o, t): n for (o, t, n, _a) in obj_ls}
mism = []
for (o, t, n, a) in mine_ls:
    if (o, t) not in obj_map:
        continue
    oname = obj_map[(o, t)]
    if n:  # 带符号：直接比名（剥 @VER 后）
        if oname != n:
            mism.append((o, t, n, oname))
    else:  # 无符号：objdump 显示 *ABS*+0x%016x，比对 addend
        if not oname.startswith("*ABS*+0x") or int(oname[len("*ABS*+0x"):], 16) != a:
            mism.append((o, t, a, oname))
check("A2' objdump -R 三方复核（名字 + *ABS* addend）", not mism,
      "objdump %d 条；带符号名与无符号 addend 全一致" % len(obj_ls) if not mism else str(mism[:3]))

# ── A3：联动语义 ──
dynsym = r_ls["symbols"]["dynsym"]
rela_all = [e for (_nm, _o, ents) in r_ls["relocations"] for e in ents]
# A3-1 符号索引落界 + 查表名与 readelf 一致（全量，比抽 5 条更强）
bad_idx = [e for e in rela_all if e[6] is not None and e[4] >= len(dynsym) and e[4] != 0]
check("A3-1 sym_idx ∈ [0, %d) 全量落界" % len(dynsym), not bad_idx)
symful = [e for e in rela_all if e[4] != 0]
name_ok = all(dynsym[e[4]][0] == e[5] for e in symful)
check("A3-1' JUMP_SLOT/GLOB_DAT/COPY 查表名 == r_info 序号对应名（全量 %d 条）" % len(symful),
      name_ok)
# A3-2 JUMP_SLOT+GLOB_DAT 落 .got 区间（e[2]=类型号：7=JUMP_SLOT 6=GLOB_DAT）
got_lo, got_hi = sec_range(r_ls, ".got")
oob = [e for e in rela_all if e[2] in (6, 7) and not (got_lo <= e[0] < got_hi)]
n_js = sum(1 for e in rela_all if e[2] == 7)
n_gd = sum(1 for e in rela_all if e[2] == 6)
check("A3-2 %d JUMP_SLOT + %d GLOB_DAT 的 r_offset 落 .got [0x%x, 0x%x)" % (n_js, n_gd, got_lo, got_hi),
      not oob and n_js == 110 and n_gd == 12, "越界 %d 条" % len(oob) if oob else "122/122 全落")
# A3-3 COPY 落 .bss 且 st_value==r_offset（e[2]==5）
bss_lo, bss_hi = sec_range(r_ls, ".bss")
copies = [e for e in rela_all if e[2] == 5]
oob2 = [e for e in copies if not (bss_lo <= e[0] < bss_hi)]
val_eq = all(e[6] == e[0] for e in copies)
check("A3-3 6 条 COPY 落 .bss [0x%x,0x%x) 且 st_value==r_offset" % (bss_lo, bss_hi),
      not oob2 and val_eq and len(copies) == 6)
# A3-4 抽样人工比对（getenv 等 5 条）
sample = {e[5]: (e[0], e[3]) for e in rela_all if e[5]}
ref_map = {n: (o, t) for (o, t, n, _a) in ref_ls}
picked = [n for n in ("getenv", "puts", "printf", "cap_to_text",
                      "__ctype_toupper_loc", "__progname", "stdout") if n in sample]
ok5 = all(sample[n] == ref_map.get(n) for n in picked)
check("A3-4 抽样 %d 条 (%s...) offset+type 与 readelf 一致" % (len(picked), ",".join(picked[:3])),
      ok5 and len(picked) >= 5)

# ── A1 补充：dyn_static 全 IRELATIVE、sym_idx=0 ──
r_st = parse(f"{FIX}/dyn_static")
st_ents = [e for (_n, _o, ents) in r_st["relocations"] for e in ents]
check("A1' dyn_static 22 条全 R_X86_64_IRELATIVE(0x25) 且 sym_idx=0",
      len(st_ents) == 22 and all(e[2] == 0x25 and e[4] == 0 for e in st_ents))

print("\n%d/%d PASS" % (sum(1 for _r in RESULTS if _r[1]), len(RESULTS)))
sys.exit(0 if all(_r[1] for _r in RESULTS) else 1)
