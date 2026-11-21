#!/usr/bin/env python3
# tests/verify_switchcand.py — M5-U2 验收：候选层与确定集的隔离 + 0x401870 收益量化
#
# 三件事，缺一不可：
#   A) 负向基线：关闭候选层与开启候选层，逐项对照 tests/fixtures/definite_baseline.json
#      （确定边、块数、表达式覆盖、语句数、伪 C 文本 sha256）——任何一项变化即判污染。
#   B) 0x401870 收益：我方既有块 vs Ghidra 块，报「补回多少 / 补错多少」两个数，
#      并把补错的按「在 Ghidra 体内但不是块起点 / 不在体内」细分。
#   C) 拒绝理由可见：候选里被判错的目标必须带 reason（本脚本抽验非空）。
#
# Ghidra 是弱参照：块切分口径不同不算我们错，但必须分类列出，不静默合并。
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import disasm, expr, pe, recdesc, switchcand  # noqa: E402

REL = "tests/fixtures/dyn_static"
FUNC = 0x401870
BASELINE = os.path.join(HERE, "baselines", "definite_baseline.json")


def _snapshot(res, b):
    texts = [expr.lift_function(res, f["function"])["text"] for f in b["functions"]]
    return {
        "recdesc": dict(res["stats"]),
        "expr": {
            "functions_total": b["functions_total"],
            "lifted": b["functions_lifted"],
            # C2：expr 的“跳过”= 边界未声明，不用裸 "skipped"，
            # 以免与 switchcand 的预算跳过同名不同义。
            "skipped_undeclared_boundary": b["functions_skipped"],
            "insns": b["stats"]["insns"],
            "lifted_insns": b["stats"]["lifted"],
            "abstained": b["stats"]["abstained"],
            "statements": b["stats"]["statements"],
            "text_sha256": hashlib.sha256("\n".join(texts).encode()).hexdigest(),
        },
    }


def negative_baseline():
    path = os.path.join(WORK, REL)
    res = recdesc.descend(path)
    b = expr.lift_binary(path, res=res)
    before = _snapshot(res, b)
    nblk = len(res["blocks"])
    nins = len(res["instructions"])

    # 候选层在同一个 res 上跑：只读，不改写
    rep = switchcand.analyze_function(res, FUNC)
    after = _snapshot(res, b)

    base = json.load(open(BASELINE, encoding="utf-8"))[REL]
    rows = []
    for sec in ("recdesc", "expr"):
        for k in sorted(base[sec]):
            want, got = base[sec][k], before[sec][k]
            rows.append({"group": sec, "key": k, "baseline": want, "now": got,
                         "same": want == got})
    rows.append({"group": "switchcand", "key": "res.blocks",
                 "baseline": nblk, "now": len(res["blocks"]),
                 "same": nblk == len(res["blocks"])})
    rows.append({"group": "switchcand", "key": "res.instructions",
                 "baseline": nins, "now": len(res["instructions"]),
                 "same": nins == len(res["instructions"])})
    rows.append({"group": "switchcand", "key": "snapshot(before/after)",
                 "baseline": "identical", "now":
                 "identical" if before == after else "DIFF",
                 "same": before == after})
    return {"ok": all(r["same"] for r in rows), "rows": rows, "report": rep}


def ghidra_starts(path, func_addr, sec_va):
    if not os.environ.get("GHIDRA_INSTALL_DIR"):
        raise ImportError("GHIDRA_INSTALL_DIR 未设置（Ghidra 弱参照可选，跳过）")
    import pyghidra
    pyghidra.start()
    from ghidra.program.model.block import BasicBlockModel

    with pyghidra.open_program(
            path, analyze=True,
            project_location=tempfile.mkdtemp(prefix="rksw_")) as flat:
        prog = flat.getCurrentProgram()
        monitor = flat.getMonitor()
        delta = prog.getMemory().getBlock(".text").getStart().getOffset() - sec_va
        space = prog.getAddressFactory().getDefaultAddressSpace()
        f = prog.getFunctionManager().getFunctionAt(space.getAddress(func_addr + delta))
        if f is None:
            return {"found": False}
        body = f.getBody()
        bbm = BasicBlockModel(prog)
        starts, it = [], bbm.getCodeBlocksContaining(body, monitor)
        while it.hasNext():
            b = it.next()
            starts.append(b.getFirstStartAddress().getOffset() - delta)
        body_lo = body.getMinAddress().getOffset() - delta
        body_hi = body.getMaxAddress().getOffset() - delta + 1
        return {"found": True, "name": f.getName(), "starts": sorted(starts),
                "body": [body_lo, body_hi], "delta": delta}


def quantify(rep, gh):
    cands = rep["candidates"]
    new_starts = sorted(set(a for c in cands for a in c["new_block_starts"]))
    base = rep["blocks_before"]
    cand_blocks = rep["blocks_candidate"]
    out = {"ours_base": base, "ours_new_starts": new_starts,
           "ours_candidate_blocks": cand_blocks,
           "ghidra_found": gh.get("found")}
    if not gh.get("found"):
        return out
    gs = set(gh["starts"])
    lo, hi = gh["body"]
    out["ghidra_blocks"] = len(gs)
    out["gap"] = len(gs) - base
    out["recovered"] = sorted(a for a in new_starts if a in gs)
    wrong = [a for a in new_starts if a not in gs]
    out["wrong_in_body"] = sorted(a for a in wrong if lo <= a < hi)
    out["wrong_out_body"] = sorted(a for a in wrong if not (lo <= a < hi))
    # 精确对账：既有块起点单独算，避免把「既有切分差异」算到候选头上
    before = set(rep.get("block_starts_before") or [])
    ours_all = before | set(new_starts)
    out["base_hit"] = sorted(a for a in before if a in gs)
    out["base_extra"] = sorted(a for a in before if a not in gs)
    out["missing_after"] = sorted(gs - ours_all)
    out["extra_after"] = sorted(ours_all - gs)
    out["remaining"] = len(out["missing_after"])
    out["remaining_gap"] = out["remaining"]
    return out


_OBJ_LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")


def objdump_starts(path, sec):
    """外部 objdump 的指令起点集合（脚本自己解析文本，不用被测实现）。"""
    exe = shutil.which("objdump")
    if exe is None:
        return None
    base = 0
    if open(path, "rb").read(2) == b"MZ":
        base = pe.parse(path)["image_base"]
    start = base + sec["va"]
    env = dict(os.environ, LC_ALL="C")
    out = subprocess.run([exe, "-d", "-M", "intel", "--insn-width=16",
                          "--start-address=0x%x" % start,
                          "--stop-address=0x%x" % (start + sec["size"]), path],
                         capture_output=True, env=env)
    if out.returncode != 0:
        return None
    starts = set()
    for ln in out.stdout.decode("utf-8", "replace").splitlines():
        m = _OBJ_LINE.match(ln)
        if m and m.group(2).split():
            starts.add(int(m.group(1), 16) - base)
    return starts


def promotion_audit(rel):
    """M9 升格验收：逐候选比对“独立算出的应升格” vs 模块给的结果。"""
    path = os.path.join(WORK, rel)
    res = recdesc.descend(path)
    sec = disasm.find_section(path, ".text")
    ind = objdump_starts(path, sec)
    if ind is None:
        return {"rel": rel, "error": "objdump 不可用"}
    before = (len(res["blocks"]), len(res["instructions"]), dict(res["stats"]))
    b = {"starts": ind, "source": "verify 独立解析 GNU objdump 的指令起点"}
    rep = switchcand.analyze_binary(path, res=res, boundary=b)
    rows = []
    for f in rep["functions"]:
        lo, hi = f["range"]
        for c in f["candidates"]:
            eligible = (c["count"] is not None
                        and not c["rejected_entries"] and not c["truncated"]
                        and len(c["targets"]) >= 4
                        and all(lo <= t < hi for t in c["targets"])
                        and all(t in ind for t in c["targets"]))
            got = c["promotion"]["status"] == "promoted"
            rows.append({"fn": f["function"], "jmp": c["jmp"],
                         "count": c["count"], "n_targets": len(c["targets"]),
                         "eligible": eligible, "promoted": got,
                         "rejected": len(c["rejected_entries"]),
                         "truncated": c["truncated"]})
    # 负向：空边界集合 → 一个都不许升格
    rep2 = switchcand.analyze_binary(path, res=res,
                                     boundary={"starts": set(), "source": "空边界"})
    n_empty = sum(1 for f in rep2["functions"] for c in f["candidates"]
                  if c["promotion"]["status"] == "promoted")
    after = (len(res["blocks"]), len(res["instructions"]), dict(res["stats"]))
    return {"rel": rel, "rows": rows, "n_empty": n_empty,
            "unchanged": before == after,
            "n_candidates": rep["stats"]["candidates"],
            "n_promoted": rep["stats"]["promoted"],
            "n_blocked": rep["stats"]["blocked"]}


def selftest():
    """可失败自证：让候选层改写 res.stats → 前后快照必须不再相同。"""
    import contextlib
    import io
    orig = switchcand.analyze_function

    def impure(res, func, *a, **kw):
        rep = orig(res, func, *a, **kw)
        res["stats"] = dict(res["stats"])
        res["stats"]["blocks"] = res["stats"].get("blocks", 0) + 1
        return rep

    switchcand.analyze_function = impure
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            neg = negative_baseline()
    finally:
        switchcand.analyze_function = orig
    bad = [r for r in neg["rows"] if not r["same"]]
    hit = bool(bad) and not neg["ok"]
    print("[selftest] 注入候选层污染（改写 res.stats）后负向基线报 %d 项变化，"
          "neg.ok=%s（期望 False）→ %s"
          % (len(bad), neg["ok"], "检出" if hit else "未检出"))
    return 0 if hit else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    path = os.path.join(WORK, REL)
    sec = disasm.find_section(path, ".text")

    print("=" * 78)
    print("A) 负向基线：候选层关闭/开启逐项对照 %s" % os.path.basename(BASELINE))
    neg = negative_baseline()
    bad = [r for r in neg["rows"] if not r["same"]]
    for r in neg["rows"]:
        print("  [%s] %-14s %-22s baseline=%s now=%s %s"
              % ("OK" if r["same"] else "!!", r["group"], r["key"],
                 str(r["baseline"])[:18], str(r["now"])[:18],
                 "" if r["same"] else "<-- 变化"))
    print("  结论: %s" % ("确定数字逐项不变（候选层未污染确定集）"
                          if neg["ok"] else "存在 %d 项变化，候选层不许上" % len(bad)))

    rep = neg["report"]
    print("\nB) 候选（0x%x）：" % FUNC)
    for c in rep["candidates"]:
        print("  %s jmp@0x%x 表 0x%x 证据 %s ｜ 目标 %d 项 ｜ 拒绝表项 %d 项"
              % (c["kind"], c["jmp"], c["table"], c["evidence"],
                 len(c["targets"]), len(c["rejected_entries"])))
        for e in c["rejected_entries"]:
            print("      拒绝[%d]: %s" % (e["index"], e["reason"]))
    for u in rep["unmatched"]:
        print("  未识别 0x%x: %s" % (u["jmp"], u["reason"]))
    for j in rep["rejected"]:
        print("  整条被拒 0x%x: %s" % (j["jmp"], j["reason"]))

    try:
        gh = ghidra_starts(path, FUNC, sec["va"])
    except ImportError as e:
        print("\n[NO-GHIDRA] %s —— 只报我方结果，不假装对过" % e)
        gh = {"found": False}

    q = quantify(rep, gh)
    print("\nC) 收益量化（弱参照 Ghidra）:")
    if not gh.get("found"):
        print("  Ghidra 侧无该函数，无法量化 recovered/wrong")
    else:
        print("  我方既有块 %d ｜ 候选口径 %d（新增起点 %d）｜ Ghidra %d ｜ 差距 %d"
              % (q["ours_base"], q["ours_candidate_blocks"],
                 len(q["ours_new_starts"]), q["ghidra_blocks"], q["gap"]))
        print("  补回 recovered = %d" % len(q["recovered"]))
        print("  补错 wrong     = %d（在体内但非块起点 %d；不在体内 %d）"
              % (len(q["wrong_in_body"]) + len(q["wrong_out_body"]),
                 len(q["wrong_in_body"]), len(q["wrong_out_body"])))
        print("  我方既有块起点命中 Ghidra: %d/%d（多出 %d）"
              % (len(q["base_hit"]), q["ours_base"], len(q["base_extra"])))
        print("  剩余差距 = %d 个 Ghidra 块起点仍缺（= %d - %d - 既有命中 %d）"
              % (q["remaining"], q["ghidra_blocks"],
                 len(q["ours_new_starts"]), len(q["base_hit"])))
        print("  剩余明细（候选层未覆盖，属既有块切分口径差异）: %s"
              % (", ".join("0x%x" % a for a in q["missing_after"]) or "无"))
        print("  我方多出 Ghidra 之外的块起点 = %d" % len(q["extra_after"]))
        if q["extra_after"]:
            print("  多出明细: %s"
                  % ", ".join("0x%x" % a for a in q["extra_after"][:12]))
        if q["wrong_in_body"]:
            print("  wrong(体内非块起点): %s"
                  % ", ".join("0x%x" % a for a in q["wrong_in_body"][:12]))
        if q["wrong_out_body"]:
            print("  wrong(不在体内): %s"
                  % ", ".join("0x%x" % a for a in q["wrong_out_body"][:12]))
        print("  补回明细: %s" % ", ".join("0x%x" % a for a in q["recovered"]))

    reasons_ok = all(e.get("reason") for c in rep["candidates"]
                     for e in c["rejected_entries"])
    print("\nD) 拒绝理由可见: %s" % ("是" if reasons_ok else "否（有拒绝项缺理由）"))

    print("\nE) 升格判据：外部 objdump 边界（不用被测实现自证）")
    audits, promo_fails = [], []
    for rel in ("tests/fixtures/cli-64.exe", "tests/fixtures/bin_ls.elf",
                REL):
        a = promotion_audit(rel)
        audits.append(a)
        if a.get("error"):
            promo_fails.append("%s: %s" % (rel, a["error"]))
            continue
        bad = [r for r in a["rows"] if r["eligible"] != r["promoted"]]
        print("  %-28s 候选 %d ｜ 应升格 %d ｜ 实际升格 %d ｜ 空边界升格 %d ｜ res 不变 %s"
              % (os.path.basename(rel), a["n_candidates"],
                 sum(1 for r in a["rows"] if r["eligible"]),
                 a["n_promoted"], a["n_empty"],
                 "是" if a["unchanged"] else "否"))
        for r in a["rows"]:
            if r["eligible"]:
                print("    fn 0x%x jmp 0x%x：目标 %d 项、guard 表长 %s → 升格 %s"
                      % (r["fn"], r["jmp"], r["n_targets"],
                         r["count"], "是" if r["promoted"] else "否"))
        if bad:
            promo_fails.append("%s: %d 个候选的应/实升格不一致（首个 jmp 0x%x）"
                               % (rel, len(bad), bad[0]["jmp"]))
        if a["n_empty"] != 0:
            promo_fails.append("%s: 空边界集合仍升格 %d 个（判据没起作用）"
                               % (rel, a["n_empty"]))
        if not a["unchanged"]:
            promo_fails.append("%s: 升格改写了 res（违反 R45 隔离）" % rel)
    print("  结论: %s" % ("全部候选的应/实升格一致，空边界不升格，res 未变"
                          if not promo_fails else "；".join(promo_fails)))

    out = {"negative": neg, "quantify": q,
           "ghidra": {k: v for k, v in gh.items() if k != "starts"},
           "promotion": audits}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("\nJSON 已写入 %s" % args.json)

    bad_all = (not neg["ok"]) or (not reasons_ok) or bool(promo_fails)
    print("\n%s（负向基线 %s；收益数字见上，不静默取舍）"
          % ("PASS" if not bad_all else "FAIL",
             "通过" if neg["ok"] else "失败"))
    return 0 if not bad_all else 1


if __name__ == "__main__":
    sys.exit(main())
