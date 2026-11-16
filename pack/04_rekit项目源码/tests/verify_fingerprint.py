#!/usr/bin/env python3
# verify_fingerprint.py — E9 一次性验收载体（2026-11-15）
#
# 设计纪律（对应任务卡 E9 + 净室纪律）：
#   1. ground truth 只从 manifest 的 e9_ground_truth 读入（执行前冻结），脚本内不写死期望值
#   2. unknown 只在 ground truth 为 undeterminable 时算命中；对可判定格答 unknown 记为 miss
#   3. 对 undeterminable 格给出确定结论（非 unknown）记为误报（FP），不允许"猜对也算对"
#   4. 强结论（packer 非 none、compiler 非 unknown）必须 >=2 条独立 evidence，
#      否则记 violation（这是本项目自己的判据门槛，不是外部标准）
#   5. 四个维度分别出混淆矩阵：分母为该维度可判定格数，弃权格单列，不并入命中率
#
# 用法：
#   python tests/verify_fingerprint.py --all --matrix
#   python tests/verify_fingerprint.py --all --matrix --out <log 路径>
#   python tests/verify_fingerprint.py --all --matrix --selftest
# 退出码：0=全格命中且零误报零违规；1=存在 miss/FP/violation；2=环境或清单错误
import argparse
import collections
import contextlib
import io
import json
import os
import sys
from pathlib import Path

REPO = Path(os.path.realpath(__file__)).parents[1]
sys.path.insert(0, str(REPO))

from rekit import fingerprint  # noqa: E402


def _find_manifest():
    """从仓库根逐级上溯找 2026-11-15/m2-task-card/work/sample_manifest.json。
    逐级上溯而非写死相对层级：本工作区在工具层可能经 ASCII 目录联接访问。"""
    p = REPO
    for _ in range(6):
        cand = p / "2026-11-15" / "m2-task-card" / "work" / "sample_manifest.json"
        if cand.exists():
            return cand
        p = p.parent
    return (REPO.parent.parent.parent / "2026-11-15" / "m2-task-card"
            / "work" / "sample_manifest.json")


MANIFEST_DEFAULT = _find_manifest()
UNKNOWN = ("unknown", "undeterminable")


def is_unknown(v):
    return v is None or (isinstance(v, str) and v.strip().lower() in UNKNOWN)


def resolve(path_str, work_root):
    if path_str.startswith("tests/"):
        return REPO / path_str
    if path_str.startswith("work/"):
        return work_root / path_str[len("work/"):]
    return Path(path_str)


class Cell:
    __slots__ = ("sample", "dim", "key", "expected", "actual", "status",
                 "note", "authority")

    def __init__(self, sample, dim, key, expected, actual, status, note="",
                 authority=""):
        self.sample, self.dim, self.key = sample, dim, key
        self.expected, self.actual, self.status = expected, actual, status
        self.note, self.authority = note, authority


def judge(gid, dim, key, expected, actual, authority, note_if_miss=""):
    """单格裁决：返回 Cell。expected 为 undeterminable 时，actual 必须也是 unknown。"""
    if is_unknown(expected):
        if is_unknown(actual):
            return Cell(gid, dim, key, expected, actual, "abstain_hit")
        return Cell(gid, dim, key, expected, actual, "fp",
                    "GT 不可判定，工具给出确定结论 → 误报", authority)
    if is_unknown(actual):
        return Cell(gid, dim, key, expected, actual, "miss",
                    note_if_miss or "GT 可判定，工具弃权 → 未命中", authority)
    if str(expected).lower() == str(actual).lower():
        return Cell(gid, dim, key, expected, actual, "hit")
    return Cell(gid, dim, key, expected, actual, "miss",
                note_if_miss or "与 GT 不一致", authority)


def evidence_count(ev):
    return len(ev or [])


def check_sample(s, fp):
    """把一个样本的四维结论展开成 Cell 列表。"""
    gid = s["id"]
    cells = []
    auth = s.get("authority", "")

    # ── 维度 1：packer ──
    pk = fp["packer"]
    c = judge(gid, "packer", "-", s["packer"], pk["name"], auth)
    if c.status == "hit" and pk["name"] not in ("none", "unknown"):
        if evidence_count(pk.get("evidence")) < 2:
            c.status = "violation"
            c.note = "强结论但独立证据 <2 条（本项目自定门槛）"
    if pk.get("hint"):
        # hint 级（conf<=0.3）不得当作强判；GT 为 none 时应记为误报
        if s["packer"] == "none":
            c.status = "fp"
            c.note = "仅 hint 级命中（conf<=0.3），却被当作壳结论"
    cells.append(c)

    # ── 维度 2：compiler ──
    gtc = s["compiler"]
    cp = fp["compiler"]
    c = judge(gid, "compiler", "family", gtc["family"], cp["family"], auth)
    if c.status == "hit" and cp["family"] != "unknown":
        if evidence_count(cp.get("evidence")) < 2:
            c.status = "violation"
            c.note = "强结论但独立证据 <2 条（本项目自定门槛）"
    cells.append(c)
    if gtc.get("version"):
        cells.append(judge(gid, "compiler", "version", gtc["version"],
                           cp.get("version"), auth,
                           "GT 有明确版本，工具版本不一致或缺失"))
    elif not is_unknown(gtc["family"]):
        # GT 只约束 family（版本本身不可得）→ 版本不参与命中率，仅记录
        cells.append(Cell(gid, "compiler", "version", "(不约束)",
                          cp.get("version"), "record_only"))

    # ── 维度 3：stripped / COFF ──
    if s["format"] == "PE":
        cells.append(judge(gid, "stripped", "stripped", "n/a",
                           fp["stripped"], auth))
        cells.append(judge(gid, "stripped", "coff_symbols", s["coff"],
                           fp.get("coff_symbols"), auth))
    else:
        cells.append(judge(gid, "stripped", "stripped", s["stripped"],
                           fp["stripped"], auth))

    # ── 维度 4：mitigations ──
    gm = s["mitigations"]
    am = fp["mitigations"]
    for key in gm:
        cells.append(judge(gid, "mitigations", key, gm[key], am.get(key), auth))
    return cells


def print_sample_matrix(rows):
    print("\n[1] 逐样本矩阵（✓ 命中 / ○ 正确弃权 / ✗ 未命中 / ‼ 违规）")
    mark = {"hit": "✓", "abstain_hit": "○", "miss": "✗", "fp": "✗",
            "violation": "‼", "record_only": "-"}
    hdr = "%-30s %-4s %-8s %-6s %-18s %-14s %s" % (
        "sample", "fmt", "role", "pack", "compiler", "stripped/coff", "mitigations")
    print(hdr)
    print("-" * len(hdr))
    for gid, fmt, role, cells in rows:
        by = {(c.dim, c.key): c for c in cells}
        pk = by[("packer", "-")]
        cf = by[("compiler", "family")]
        cv = by.get(("compiler", "version"))
        comp_s = "%s%s" % (cf.actual,
                           (" " + str(cv.actual)) if (cv and cv.actual) else "")
        if by.get(("stripped", "coff_symbols")):
            st_s = "n/a / %s" % by[("stripped", "coff_symbols")].actual
            st_c = by[("stripped", "coff_symbols")]
        else:
            st_s = str(by[("stripped", "stripped")].actual)
            st_c = by[("stripped", "stripped")]
        if isinstance(st_c.actual, bool):
            st_s = "true" if st_c.actual else "false"
        mit_s = ",".join("%s=%s" % (c.key, c.actual) for (d, k), c in by.items()
                         if d == "mitigations" and k != "dll_characteristics")
        mstat = {c.status for (d, k), c in by.items() if d == "mitigations"}
        if mstat <= {"hit"}:
            mit_mark = "✓"
        elif mstat <= {"hit", "abstain_hit"}:
            mit_mark = "○"
        else:
            mit_mark = "✗"
        print("%-30s %-4s %-8s %s%-4s %s%-24s %s%-12s %s%s" % (
            gid, fmt, role, mark[pk.status], pk.actual,
            mark[cf.status], comp_s, mark[st_c.status], st_s,
            mit_mark, mit_s))


def confusion(cells, dim=None, key=None):
    """GT × 实际 计数（只统计可判定格，弃权格另计）。"""
    tab = collections.Counter()
    for c in cells:
        if dim and c.dim != dim:
            continue
        if key and c.key != key:
            continue
        if c.status == "record_only" or is_unknown(c.expected):
            continue
        tab[(str(c.expected), str(c.actual))] += 1
    return tab


def print_confusion(title, tab):
    print("\n%s" % title)
    if not tab:
        print("  （无可判定格）")
        return
    gts = sorted({k[0] for k in tab})
    acts = sorted({k[1] for k in tab})
    print("  %-22s %s" % ("GT \\ 实际", " ".join("%-10s" % a for a in acts)))
    for g in gts:
        print("  %-22s %s" % (g, " ".join("%-10d" % tab[(g, a)] for a in acts)))


def print_mitigations(cells):
    """加固位按子键分别出矩阵：ELF 的 nx/relro/pie 是枚举，PE 的位是布尔 + DllChar 十六进制。"""
    print("\n[2] mitigations 分项（only 可判定格；弃权格单独计数）")
    keys = [k for k in ("nx", "relro", "pie", "dynamicbase", "high_entropy_va",
                        "cfg", "dll_characteristics")
            if any(c.dim == "mitigations" and c.key == k for c in cells)]
    for k in keys:
        sub = [c for c in cells if c.dim == "mitigations" and c.key == k]
        det = [c for c in sub if not is_unknown(c.expected)]
        und = [c for c in sub if is_unknown(c.expected)]
        ok = sum(1 for c in det if c.status == "hit")
        ab = sum(1 for c in und if c.status == "abstain_hit")
        print("\n  %s：可判定 %d 格，命中 %d；弃权格 %d，正确弃权 %d"
              % (k, len(det), ok, len(und), ab))
        tab = confusion(sub, "mitigations", k)
        for (g, a), n in sorted(tab.items()):
            print("    GT=%-14s 实际=%-14s ×%d%s"
                  % (g, a, n, "" if g.lower() == a.lower() else "  ← 不一致"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="verify_fingerprint.py",
        description="E9 一次性验收载体：读取冻结的 ground truth，产出四维混淆矩阵")
    ap.add_argument("--all", action="store_true", help="纳入 manifest 全部样本")
    ap.add_argument("--matrix", action="store_true", help="输出四维混淆矩阵")
    ap.add_argument("--manifest", default=str(MANIFEST_DEFAULT))
    ap.add_argument("--out", default=None, help="同时把完整输出写入该文件")
    ap.add_argument("--selftest", action="store_true",
                    help="自证可失败：翻转一个负样本的 packer 真值，要求退出码非 0")
    args = ap.parse_args(argv)
    if not (args.all and args.matrix):
        print("E9 载体：必须同时给 --all --matrix（见任务卡 E9）", file=sys.stderr)
        return 2
    if not args.out:
        return run(args)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = run(args)
    out = buf.getvalue()
    sys.stdout.write(out)
    sys.stdout.flush()
    Path(args.out).write_text(out, encoding="utf-8")
    return rc


def run(args):
    mp = Path(args.manifest)
    if not mp.exists():
        print("清单不存在: %s" % mp, file=sys.stderr)
        return 2
    gt = json.loads(mp.read_text(encoding="utf-8"))
    if "e9_ground_truth" not in gt:
        print("清单缺少 e9_ground_truth 块（E9 需先冻结真值）", file=sys.stderr)
        return 2
    spec = gt["e9_ground_truth"]
    samples = spec["samples"]
    work_root = mp.parent

    if args.selftest:
        samples = [dict(s) for s in samples]
        target = next(s for s in samples if s["packer"] == "none")
        target["packer"] = "upx"   # 人为翻转，矩阵必须因此变红
        print("[selftest] 已把 %s 的 packer 真值翻成 upx，期望退出码非 0"
              % target["id"])

    print("E9 fingerprint 混淆矩阵 · 真值冻结于 %s" % spec["frozen_at"])
    print("清单: %s" % mp)
    print("样本数: %d（正样本 upx=%d，负样本=%d）" % (
        len(samples),
        sum(1 for s in samples if s["role"] == "positive"),
        sum(1 for s in samples if s["role"] == "negative")))

    all_cells, rows, errors = [], [], []
    for s in samples:
        p = resolve(s["path"], work_root)
        if not p.exists():
            errors.append("样本缺失: %s (%s)" % (s["id"], p))
            continue
        try:
            fp = fingerprint.analyze(str(p))
        except Exception as exc:  # 解析崩溃即环境/实现问题，单独记，不混入命中率
            errors.append("分析异常: %s (%s: %s)" % (s["id"], type(exc).__name__, exc))
            continue
        cells = check_sample(s, fp)
        all_cells.extend(cells)
        rows.append((s["id"], s["format"], s["role"], cells))

    print_sample_matrix(rows)
    print_confusion("[2] packer 混淆矩阵（only 可判定格）",
                    confusion(all_cells, "packer", "-"))
    print_confusion("[2] compiler.family 混淆矩阵（only 可判定格）",
                    confusion(all_cells, "compiler", "family"))
    print_confusion("[2] compiler.version 混淆矩阵（only GT 有明确版本的格）",
                    confusion(all_cells, "compiler", "version"))
    print_confusion("[2] stripped 混淆矩阵（ELF true/false；PE 固定 n/a）",
                    confusion(all_cells, "stripped", "stripped"))
    print_confusion("[2] COFF 符号表混淆矩阵（PE）",
                    confusion(all_cells, "stripped", "coff_symbols"))
    print_mitigations(all_cells)

    bad = [c for c in all_cells if c.status in ("miss", "fp", "violation")]
    hits = [c for c in all_cells if c.status == "hit"]
    abst = [c for c in all_cells if c.status == "abstain_hit"]
    det = [c for c in all_cells
           if c.status != "record_only" and not is_unknown(c.expected)]
    undet = [c for c in all_cells
             if c.status != "record_only" and is_unknown(c.expected)]
    fp_cells = [c for c in all_cells if c.status == "fp"]
    vio = [c for c in all_cells if c.status == "violation"]

    print("\n[3] 汇总")
    print("  样本分母           : %d（异常 %d）" % (len(rows), len(errors)))
    print("  可判定格           : %d，命中 %d，命中率 %.2f%%"
          % (len(det), len(hits), 100.0 * len(hits) / len(det) if det else 0.0))
    print("  不可判定格（弃权） : %d，正确弃权 %d（%.0f%%），误报 %d"
          % (len(undet), len(abst),
             100.0 * len(abst) / len(undet) if undet else 0.0, len(fp_cells)))
    print("  未命中 / 误报 / 违规: %d / %d / %d"
          % (len([c for c in all_cells if c.status == "miss"]),
             len(fp_cells), len(vio)))

    if bad or errors:
        print("\n[4] 逐条归因（未命中/误报/违规/异常）")
        for c in bad:
            print("  - [%s] %s / %s: 期望 %r，实际 %r — %s | 权威: %s"
                  % (c.status, c.sample, "%s.%s" % (c.dim, c.key),
                     c.expected, c.actual, c.note, c.authority))
        for e in errors:
            print("  - [error] %s" % e)

    ok = not bad and not errors
    print("\nE9 VERDICT: %s（可判定格 %d/%d，误报 %d，违规 %d，异常 %d）"
          % ("PASS" if ok else "FAIL", len(hits), len(det),
             len(fp_cells), len(vio), len(errors)))
    if args.selftest:
        print("[selftest] 期望 FAIL，实际 %s → %s"
              % ("FAIL" if not ok else "PASS", "OK" if not ok else "SELFTEST 失效"))
        return 0 if not ok else 1

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
