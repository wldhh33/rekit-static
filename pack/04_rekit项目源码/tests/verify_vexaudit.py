#!/usr/bin/env python3
# tests/verify_vexaudit.py — M9 收敛线 B 验收
#
# A) 独立复算分母：自带 struct 级节头解析 + 逐字节数 C4/C5/62，
#    与 vexaudit 的 lead_bytes 逐样本相等。
# B) 逐条归因复核：不用 vexaudit 的 objdump 结果，脚本自己 parse objdump 文本，
#    对每类样例逐条重判（defect=objdump 有 v* 指令；illegal=(bad)；
#    not_start=外部 objdump 未在该地址列指令）。
# C) 可失败自证：伪造 starts，四个分类分支必须各自触发；若分类器空转，直接 FAIL。
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(os.path.realpath(__file__)).parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))
from rekit import coverage, recdesc, vexaudit  # noqa: E402

SAMPLES = [
    ("tests/fixtures/cli-64.exe", "PE/MSVC"),
    ("tests/fixtures/bin_ls.elf", "ELF/PIE"),
    ("tests/fixtures/dyn_static", "ELF/static"),
    ("tests/samples/avx/avx_dense.exe", "PE/AVX"),
]
# C1：至少一个样本要带声明函数域，证明“域内比例”确实被报出来（不是只写在文档里）
DOMAIN_SAMPLE = "tests/fixtures/cli-64.exe"
LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")


def section_window(path, name=".text"):
    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        shnum = struct.unpack_from("<H", data, 0x3C)[0]
        shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        if not shoff or not shnum or shstrndx >= shnum:
            return None
        def sh(i):
            o = shoff + i * shentsize
            nm, _t, _f, addr, off, size = struct.unpack_from("<IIQQQQ", data, o)
            return nm, addr, off, size
        _n, st_addr, st_off, st_size = sh(shstrndx)
        for i in range(shnum):
            nm, addr, off, size = sh(i)
            p = st_off + nm
            if data[p:data.index(b"\x00", p)].decode("latin-1") == name and size:
                return {"va": addr, "off": off, "size": size, "base": 0, "data": data}
        return None
    if data[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
    optsize = struct.unpack_from("<H", data, lfanew + 20)[0]
    opt = lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    base = (struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B
            else struct.unpack_from("<I", data, opt + 28)[0])
    secs = opt + optsize
    for i in range(nsec):
        b = secs + i * 40
        nm = data[b:b + 8].split(b"\x00", 1)[0].decode("latin-1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        if nm == name and rawsize:
            return {"va": va, "off": rawptr, "size": min(rawsize, vsize or rawsize),
                    "base": base, "data": data}
    return None


def independent_objdump(path, win):
    exe = coverage.objdump_exe()
    if exe is None or win is None:
        return None
    env = dict(os.environ, LC_ALL="C")
    start = win["base"] + win["va"]
    out = subprocess.run([exe, "-d", "-M", "intel", "--insn-width=16",
                          "--start-address=0x%x" % start,
                          "--stop-address=0x%x" % (start + win["size"]), path],
                         capture_output=True, env=env)
    if out.returncode != 0:
        return None
    m = {}
    for ln in out.stdout.decode("utf-8", "replace").splitlines():
        x = LINE.match(ln)
        if x and x.group(2).split():
            m[int(x.group(1), 16) - win["base"]] = x.group(3).strip()
    return m


def count_leads(win):
    lo, hi = win["off"], win["off"] + win["size"]
    return sum(1 for b in win["data"][lo:hi] if b in (0xC4, 0xC5, 0x62))


def selftest():
    starts = {0x10: {"addr": 0x10, "length": 4, "text": "vaddpd ymm0,ymm1,ymm2"},
              0x20: {"addr": 0x20, "length": 1, "text": "(bad)"},
              0x30: {"addr": 0x30, "length": 2, "text": "mov eax,ebx"}}
    cases = [(0x10, vexaudit.CAT_DECODER_DEFECT), (0x20, vexaudit.CAT_ILLEGAL),
             (0x99, vexaudit.CAT_NOT_START), (0x30, vexaudit.CAT_NONVEX)]
    ok = True
    for addr, want in cases:
        got, _ = vexaudit.classify_one(starts, addr, 0xC5)
        print("  [selftest] 0x%x → %s（期望 %s）%s"
              % (addr, got, want, "" if got == want else "  <-- 未触发"))
        ok = ok and got == want
    # 负控（可失败自证）：把期望故意写成错值，判据必须报「不一致」；否则说明分类器空转
    got, _ = vexaudit.classify_one(starts, 0x10, 0xC5)
    wrong = vexaudit.CAT_ILLEGAL
    detected = got != wrong
    print("  [selftest] 负控 0x10 → %s（故意期望 %s）%s"
          % (got, wrong, "  <-- 不一致（已检出）" if detected else "  <-- 未检出"))
    ok = ok and detected
    print("  [selftest] %s" % ("通过（四个分支都可达）" if ok else "失败（分类器空转）"))
    return 0 if ok else 1


def declared_ranges(path):
    """声明函数域：取自 recdesc 的种子 end（只用于解释域内比例，不参与分类）。"""
    res = recdesc.descend(path)
    return [(s["addr"], s["end"]) for s in res["seeds"] if s.get("end")]


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    fails = []
    print("=" * 78)
    print("伪 VEX/EVEX 弃权归因：分母独立复算 + 逐条外部复核")
    print("=" * 78)
    for rel, tag in SAMPLES:
        path = str(REPO / rel)
        if not os.path.exists(path):
            fails.append("%s: 样本缺失" % rel)
            continue
        win = section_window(path)
        if win is None:
            fails.append("%s: 独立解析找不到 .text" % rel)
            continue
        n_lead = count_leads(win)
        dom = declared_ranges(path) if rel == DOMAIN_SAMPLE else None
        r = vexaudit.audit(path, declared_ranges=dom)
        print("\n[%s] %s" % (rel, tag))
        print("  lead_bytes: 模块 %d ｜ 独立复算 %d" % (r["lead_bytes"], n_lead))
        if r["lead_bytes"] != n_lead:
            fails.append("%s: lead_bytes 不一致" % rel)
        if r["lead_bytes"] != (r["abstain_sites"] + r["other_abstains"]
                               + r["counts"].get(vexaudit.CAT_DECODED, 0)
                               + r["counts"].get(vexaudit.CAT_LEN_DIFF, 0)):
            fails.append("%s: 账目不平（lead != 分类之和）" % rel)
        ind = independent_objdump(path, win)
        if ind is None:
            fails.append("%s: 独立 objdump 失败" % rel)
            continue
        for it in r["samples"].get(vexaudit.CAT_DECODER_DEFECT, []):
            txt = ind.get(it["addr"])
            ok = txt is not None and txt.startswith("v")
            print("  defect 0x%x: 独立 objdump=%r %s"
                  % (it["addr"], txt, "OK" if ok else "<-- 复核失败"))
            if not ok:
                fails.append("%s: defect@0x%x 独立复核不符" % (rel, it["addr"]))
        for it in r["samples"].get(vexaudit.CAT_ILLEGAL, []):
            txt = ind.get(it["addr"])
            ok = txt is not None and txt.startswith("(bad)")
            if not ok:
                fails.append("%s: illegal@0x%x 独立 objdump=%r 不是 (bad)"
                             % (rel, it["addr"], txt))
        for it in r["samples"].get(vexaudit.CAT_NOT_START, []):
            if it["addr"] in ind:
                fails.append("%s: not_start@0x%x 在独立 objdump 里却是指令起点"
                             % (rel, it["addr"]))
        # C1：域内比例必须被报出，且账目对平；未提供域时必须显式 None
        d = r["domain"]
        if d["provided"]:
            if d["abstain_in_domain"] + d["abstain_out_domain"] != r["abstain_sites"]:
                fails.append("%s: 域内/域外之和不等于 abstain_sites" % rel)
            print("  域内比例: 声明域 %d ｜ 域内 %s / 域外 %s ｜ 占比 %.4f"
                  % (d["ranges"], d["abstain_in_domain"],
                     d["abstain_out_domain"], d["in_domain_ratio"]))
        else:
            if d["in_domain_ratio"] is not None:
                fails.append("%s: 未提供域却报出了域内比例" % rel)
            print("  域内比例: 未提供 declared_ranges（None）")
        print("  分类: %s" % ", ".join("%s=%d" % (k, v)
                                      for k, v in sorted(r["counts"].items())))
        print("  结论: decoder_defect=%d ｜ illegal=%d ｜ not_objdump_insn_start=%d"
              " ｜ decoded=%d"
              % (r["decoder_defect"], r["illegal_encoding"],
                 r["not_objdump_insn_start"],
                 r["counts"].get(vexaudit.CAT_DECODED, 0)))
    print("\n判定：失败 %d 项" % len(fails))
    for f in fails:
        print("  ✗ %s" % f)
    print("\nVERDICT: %s" % ("PASS" if not fails else "FAIL"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
