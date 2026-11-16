#!/usr/bin/env python3
# tests/verify_coverage.py — M9 收敛线 C 验收：覆盖率报告的分子/分母/口径
#
# 三件事：
#   A) 分母独立复算：脚本自带 struct 级 ELF/PE 节头解析取 .text 窗口，
#      再自己调 objdump 数指令条数——不 import rekit.coverage，也不信它给的窗口。
#      与 coverage.build 的 denominator 必须逐样本相等。
#   B) 恒等式与分子定义：matched ⊆ objdump 起始地址、同址长度全等、
#      numerator == matched、len_conflict == 0、ratio == matched/denominator。
#   C) 可失败自证（--selftest）：
#      ① 把一条已匹配指令的长度 +1 → len_conflict 必须 ≥1（检查器能看见分歧）；
#      ② 伪造 objdump 列表少 10 条 → 独立复算与报告分母不一致，必须被检出。
#
# 样本口径：默认跑 4 个分层样本（PE / ELF PIE / ELF static / AVX-PE）；
# 另加 1 个无节表 UPX-ELF 验证“无 .text”的结构性结果不算 PASS 也不算 FAIL。
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(os.path.realpath(__file__)).parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))
from rekit import coverage, disasm, recdesc  # noqa: E402

SAMPLES = [
    ("tests/fixtures/cli-64.exe", "PE/MSVC"),
    ("tests/fixtures/bin_ls.elf", "ELF/PIE"),
    ("tests/fixtures/dyn_static", "ELF/static"),
    ("tests/samples/avx/avx_dense.exe", "PE/AVX"),
]
NO_SECTION = [("tests/samples/fingerprint/upx/upx_dyn_pie", "UPX-ELF 无节表")]
LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")


# ── 独立节头读取（不用 rekit.elf / rekit.pe） ────────────────────────
def section_window(path, name=".text"):
    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        shnum = struct.unpack_from("<H", data, 0x3C)[0]
        shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
        if shoff == 0 or shnum == 0 or shstrndx >= shnum:
            return None
        def sh(i):
            o = shoff + i * shentsize
            nm, _typ, _flags, addr, off, size = struct.unpack_from(
                "<IIQQQQ", data, o)
            return nm, addr, off, size
        _n, st_addr, st_off, st_size = sh(shstrndx)
        for i in range(shnum):
            nm, addr, off, size = sh(i)
            p = st_off + nm
            end = data.index(b"\x00", p)
            if data[p:end].decode("latin-1") == name and size:
                return {"arch": "elf", "va": addr, "off": off, "size": size}
        return None
    if data[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[lfanew:lfanew + 4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
    optsize = struct.unpack_from("<H", data, lfanew + 20)[0]
    opt = lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    secs = opt + optsize
    for i in range(nsec):
        b = secs + i * 40
        nm = data[b:b + 8].split(b"\x00", 1)[0].decode("latin-1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        if nm == name and rawsize:
            return {"arch": "pe", "va": va, "off": rawptr,
                    "size": min(rawsize, vsize or rawsize),
                    "image_base": image_base}
    return None


def count_objdump(path, win):
    if win is None:
        return None
    exe = coverage.objdump_exe()
    if exe is None:
        return None
    base = win.get("image_base", 0)
    start, stop = base + win["va"], base + win["va"] + win["size"]
    env = dict(os.environ, LC_ALL="C")
    out = subprocess.run([exe, "-d", "-M", "intel", "--insn-width=16",
                          "--start-address=0x%x" % start,
                          "--stop-address=0x%x" % stop, path],
                         capture_output=True, env=env)
    if out.returncode != 0:
        return None
    n = 0
    for ln in out.stdout.decode("utf-8", "replace").splitlines():
        m = LINE.match(ln)
        if m and m.group(2).split():
            n += 1
    return n


# ── 检查 ─────────────────────────────────────────────────────────────
def check_one(rel, tag, path):
    fails = []
    rep = coverage.build(path)
    win = section_window(path)
    if rep["status"] == "no_section":
        if win is not None:
            fails.append("%s: 模块说无节，独立解析却找到了" % rel)
        return rep, fails, None
    if win is None:
        fails.append("%s: 独立解析找不到 .text，模块却报 status=%s"
                     % (rel, rep["status"]))
        return rep, fails, None
    n_ind = count_objdump(path, win)
    if n_ind is None:
        fails.append("%s: 独立 objdump 计数失败" % rel)
        return rep, fails, None
    if rep["denominator"] != n_ind:
        fails.append("%s: 分母不一致（模块 %s vs 独立复算 %d）"
                     % (rel, rep["denominator"], n_ind))
    if not rep["identity_ok"]:
        fails.append("%s: 恒等式不成立" % rel)
    if rep["len_conflict"]:
        fails.append("%s: 同址不同长 %d 条（首条 %s）"
                     % (rel, rep["len_conflict"],
                        rep["len_conflict_sample"][:1]))
    if rep["numerator"] != rep["matched"]:
        fails.append("%s: 分子 != matched" % rel)
    if rep["denominator"] and abs(rep["ratio"] - rep["numerator"] / rep["denominator"]) > 1e-12:
        fails.append("%s: ratio 与 分子/分母 不一致" % rel)
    return rep, fails, n_ind


def selftest():
    """注入两类错误，检查器必须看见。"""
    rel = SAMPLES[0][0]
    path = str(REPO / rel)
    win = section_window(path)
    obj = coverage.objdump_instructions(path, win)
    res = recdesc.descend(path, ".text")
    bad_res = dict(res)
    bad_res["instructions"] = [dict(i) for i in res["instructions"]]
    by_addr = {i["addr"]: i for i in bad_res["instructions"]}
    target = None
    for t in obj["instructions"]:
        i = by_addr.get(t["addr"])
        if i and i["length"] == t["length"]:
            target = i
            break
    if target is None:
        print("  [selftest] 找不到可篡改的匹配指令 → 无法自证")
        return 1
    target["length"] += 1
    rep = coverage.build(path, res=bad_res, objdump=obj)
    seen = rep["len_conflict"] >= 1
    print("  [selftest-①] 篡改 0x%x 长度 +1 → len_conflict=%d（%s）"
          % (target["addr"], rep["len_conflict"],
             "已检出" if seen else "未检出"))

    fake = {"status": "ok", "bad": 0, "error": None,
            "command": obj["command"],
            "instructions": obj["instructions"][:-10]}
    rep2 = coverage.build(path, res=res, objdump=fake)
    n_ind = count_objdump(path, win)
    seen2 = rep2["denominator"] != n_ind
    print("  [selftest-②] 伪造 objdump 少 10 条 → 模块分母=%d，独立复算=%d（%s）"
          % (rep2["denominator"], n_ind, "已检出" if seen2 else "未检出"))

    agg = None
    try:
        coverage.aggregate([rep2], scope="sampled")
    except ValueError:
        agg = "拒绝无子集名单的 sampled 汇总"
    print("  [selftest-③] sampled 汇总缺名单 → %s" % (agg or "未拒绝"))
    ok = seen and seen2 and agg is not None
    print("  [selftest] %s" % ("通过（检查器能失败）" if ok else "失败（空转）"))
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        return selftest()
    print("=" * 78)
    print("覆盖率：分子 / 分母 / 分母口径（分母由外部 objdump 独立复算）")
    print("=" * 78)
    fails, reports = [], []
    for rel, tag in SAMPLES:
        path = str(REPO / rel)
        if not os.path.exists(path):
            fails.append("%s: 样本缺失" % rel)
            continue
        rep, f, n_ind = check_one(rel, tag, path)
        reports.append(rep)
        fails += f
        print("\n[%s] %s" % (rel, tag))
        if rep["status"] == "no_section":
            print("  结构性：无 .text（%s），分母不适用" % rep.get("error"))
            continue
        print("  分子 %d / 分母 %d = %.4f ｜ 独立复算分母 %s"
              % (rep["numerator"], rep["denominator"], rep["ratio"], n_ind))
        print("  我方=匹配+分歧+仅我方: %d = %d + %d + %d"
              % (rep["ours_total"], rep["matched"], rep["len_conflict"],
                 rep["ours_only"]))
        print("  分母=匹配+分歧+仅外部: %d = %d + %d + %d"
              % (rep["denominator"], rep["matched"], rep["len_conflict"],
                 rep["objdump_only"]))
        print("  字节口径: %d/%d=%.4f ｜ objdump bad %d"
              % (rep["ours_bytes"], rep["section_bytes"],
                 rep["byte_coverage_ours"], rep["objdump_bad"]))
        print("  恒等式: %s" % ("成立" if rep["identity_ok"] else "不成立"))

    for rel, tag in NO_SECTION:
        path = str(REPO / rel)
        if not os.path.exists(path):
            fails.append("%s: 样本缺失" % rel)
            continue
        rep = coverage.build(path)
        reports.append(rep)
        print("\n[%s] %s → status=%s（结构性，不写 0）" % (rel, tag, rep["status"]))
        if rep["status"] != "no_section":
            fails.append("%s: 应为 no_section，实为 %s" % (rel, rep["status"]))

    measured = [r for r in reports if r.get("denominator")]
    agg = coverage.aggregate(measured, scope="sampled",
                             sample_set=[os.path.basename(r["path"])
                                         for r in measured],
                             note="verify_coverage 分层子集（非全样本）")
    print("\n抽样汇总（sampled，子集 %d 个）: 分子 %d / 分母 %d = %.4f"
          % (agg["samples_measured"], agg["numerator"], agg["denominator"],
             agg["ratio"]))
    print("汇总声明: scope=%s ｜ 分母口径=%s" % (agg["scope"], agg["denominator_scope"]))
    if not agg["identity_ok"]:
        fails.append("汇总恒等式不成立")

    print("\n判定：失败 %d 项" % len(fails))
    for f in fails:
        print("  ✗ %s" % f)
    print("\nVERDICT: %s" % ("PASS" if not fails else "FAIL"))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
