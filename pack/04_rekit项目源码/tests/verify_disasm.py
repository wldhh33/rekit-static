#!/usr/bin/env python3
# verify_disasm.py — M4 首日验收载体：x86-64 线性扫描 vs GNU objdump 2.47 逐行对齐
#
# 口径：
#   比的是【指令边界】：每条的起始地址 + 长度。助记符/操作数不参与判定
#   （本实现不解语义，拿文本比会把"边界错"掩盖成"文本差异"）。
#   首个分歧处停表并定位到：地址、我方长度/字节、objdump 长度/文本、
#   16 字节上下文；并用 capstone（与 objdump 独立实现）做第三方仲裁：
#     capstone 与我方一致 → 判 objdump 可疑（记 evidence，不算我方错）
#     capstone 与 objdump 一致 → 判我方错
#     三方各异 → 记 three_way_split，停下来人工看字节规则
#
# 用法：
#   python tests/verify_disasm.py --all [--json]
#   python tests/verify_disasm.py --all --selftest   # 故意把我方长度 +1，必须被检出
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(os.path.realpath(__file__)).parents[1]
sys.path.insert(0, str(REPO))
from rekit import disasm, pe  # noqa: E402

SAMPLES = [
    ("tests/fixtures/cli-64.exe", ".text", "PE/MSVC x64"),
    ("tests/samples/fingerprint/hello_rust.exe", ".text", "PE/rustc"),
    ("tests/fixtures/bin_ls.elf", ".text", "ELF/glibc PIE"),
    ("tests/fixtures/dyn_pie", ".text", "ELF GCC PIE"),
    # M5 补表后新增：VEX/EVEX 长度必须与 objdump 逐条对齐（含 vzeroupper 无 ModRM 特例）
    ("tests/samples/avx/avx_dense.exe", ".text", "PE/自建 AVX 密集（VEX2/VEX3）"),
]

LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")


def objdump_path():
    p = shutil.which("objdump")
    return p


def image_base(path, data):
    if data[:4] == b"\x7fELF":
        return 0
    return pe.parse(path)["image_base"]


def run_objdump(path, va, size, base):
    exe = objdump_path()
    start, stop = base + va, base + va + size
    cmd = [exe, "-d", "-M", "intel", "--insn-width=16",
           "--start-address=0x%x" % start, "--stop-address=0x%x" % stop, path]
    # Windows 上 objdump 会把文件名按本地代码页回显，UTF-8 解码会炸；
    # 按字节收，再以 replace 解码——只有 `  addr: bytes  text` 行参与判定。
    out = subprocess.run(cmd, capture_output=True)
    if out.returncode != 0:
        return None, "objdump 失败: %s" % out.stderr.decode("utf-8", "replace").strip()[:200]
    ins = []
    for ln in out.stdout.decode("utf-8", "replace").splitlines():
        m = LINE.match(ln)
        if not m:
            continue
        addr = int(m.group(1), 16) - base
        raw = m.group(2).split()
        ins.append({"addr": addr, "length": len(raw), "text": m.group(3)})
    return ins, None


def capstone_len(data, off):
    try:
        import capstone
    except Exception:
        return None
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for ins in md.disasm(data[off:off + 16], 0):
        return {"length": ins.size, "text": "%s %s" % (ins.mnemonic, ins.op_str)}
    return None


def compare(ours, theirs, data, sec_off):
    """逐条对齐，返回 (对齐数, 分歧|None)。"""
    n = min(len(ours), len(theirs))
    for i in range(n):
        a, b = ours[i], theirs[i]
        if a["addr"] != b["addr"] or a["length"] != b["length"]:
            off = sec_off + (a["addr"] - ours[0]["addr"])
            cs = capstone_len(data, off)
            verdict = "unknown"
            if cs:
                if cs["length"] == a["length"]:
                    verdict = "ours_and_capstone_agree"
                elif cs["length"] == b["length"]:
                    verdict = "ours_wrong"
                else:
                    verdict = "three_way_split"
            return i, {
                "index": i, "addr": a["addr"],
                "ours_len": a["length"], "ours_bytes": a["bytes"],
                "obj_len": b["length"],
                "objdump_text": b["text"],
                "context": data[off:off + 16].hex(" "),
                "capstone": cs, "verdict": verdict,
                "extra_ours": len(ours) - len(theirs),
            }
    return n, None


def run(samples, selftest=False):
    if objdump_path() is None:
        print("[env] 找不到 objdump：请把 binutils 2.47 的 bin 目录加进 PATH")
        return 2
    rows, fails = [], []
    for rel, secname, tag in samples:
        path = str(REPO / rel)
        if not os.path.exists(path):
            fails.append("%s 样本缺失" % rel)
            continue
        data = open(path, "rb").read()
        sec = disasm.find_section(path, secname)
        if sec is None:
            fails.append("%s 找不到节 %s" % (rel, secname))
            continue
        # sweep_file 内部复用 mapview.addr_to_off 逐条算文件落点，
        # 并与本节算术 offset 对账（map_mismatches 必须为空）
        ours = disasm.sweep_file(path, secname)
        if selftest and len(ours["instructions"]) > 3:
            # 自证可失败：把第 4 条的长度 +1，制造一次真实可定位的边界错
            bad = ours["instructions"][3]
            bad["length"] += 1
            if len(bad["bytes"].split()) < bad["length"]:
                bad["bytes"] = (bad["bytes"] + " 00")
        ins = [i for i in ours["instructions"] if i["status"] == "ok"]
        theirs, err = run_objdump(path, sec["va"], sec["size"],
                                  image_base(path, data))
        if err:
            fails.append("%s %s" % (rel, err))
            continue
        aligned, div = compare(ins, theirs, data, sec["off"])
        row = {"rel": rel, "tag": tag, "section": sec,
               "ours": len(ins), "objdump": len(theirs),
               "aligned": aligned, "stopped": ours["stopped"],
               "map_stats": ours["map_stats"],
               "map_mismatches": ours["map_mismatches"],
               "divergence": div}
        rows.append(row)
        if ours["map_mismatches"]:
            m = ours["map_mismatches"][0]
            fails.append("%s 文件落点不一致 @0x%x（本节算术 0x%x vs addr_to_off=%s/0x%s）"
                         % (rel, m["addr"], m["section_offset"], m["status"],
                            m["map_offset"]))
        if div and div["verdict"] == "ours_wrong":
            fails.append("%s 边界错 @0x%x（capstone 与 objdump 一致）"
                         % (rel, div["addr"]))
        elif div:
            fails.append("%s 边界分歧 @0x%x（verdict=%s）"
                         % (rel, div["addr"], div["verdict"]))

    print("=" * 78)
    print("x86-64 线性扫描 vs objdump 2.47：指令边界逐行对齐")
    print("=" * 78)
    for r in rows:
        print("\n[%s] %s  .text VA=0x%x off=0x%x size=0x%x"
              % (r["rel"], r["tag"], r["section"]["va"], r["section"]["off"],
                 r["section"]["size"]))
        print("  我方边界 %d 条 / objdump %d 条 / 已对齐 %d 条"
              % (r["ours"], r["objdump"], r["aligned"]))
        st = r["stopped"]
        print("  停止: %s" % ("无（扫到节尾）" if not st else
                            "addr=0x%x reason=%s" % (st["addr"], st["reason"])))
        ms = r["map_stats"]
        print("  文件落点: hit=%d not_in_file=%d unmapped=%d multi=%d / 不一致 %d 条"
              % (ms["hit"], ms["not_in_file"], ms["unmapped"], ms["multi"],
                 len(r["map_mismatches"])))
        d = r["divergence"]
        if d:
            print("  ✗ 首个分歧 #%d @0x%x" % (d["index"], d["addr"]))
            print("     我方 len=%d bytes=%s" % (d["ours_len"], d["ours_bytes"]))
            print("     objdump len=%d text=%s" % (d["obj_len"], d["objdump_text"]))
            print("     上下文: %s" % d["context"])
            cs = d["capstone"]
            print("     capstone: %s" % ("不可用" if not cs else
                                         "len=%d %s" % (cs["length"], cs["text"])))
            print("     仲裁: %s" % d["verdict"])
    print("\ncaveats（线性扫描盲区，扫出来的不都是指令）:")
    for c in disasm.CAVEATS:
        print("  ! %s" % c)
    print("\n判定：分歧 %d 项 / 环境错误 %d 项" % (len(fails), 0))
    for f in fails:
        print("  ✗ %s" % f)
    print("\nVERDICT: %s" % ("PASS" if not fails else "FAIL"))
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        # 自证：注入错误后必须 FAIL；若仍 PASS，说明检查器是空转的
        samples = [SAMPLES[0]]
        print("[selftest] 把我方第 4 条指令长度 +1，检查器必须检出\n")
        rc = run(samples, selftest=True)
        if rc == 0:
            print("\n[selftest] 未检出：验证器是空转的 → 失败")
            return 1
        print("\n[selftest] 已检出（能失败）→ 通过")
        return 0
    return run(SAMPLES)


if __name__ == "__main__":
    sys.exit(main())
