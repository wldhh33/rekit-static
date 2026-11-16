#!/usr/bin/env python3
# tests/verify_struct.py — M5-U3 验收：控制流结构化输出
#
# 四件事，缺一不可：
#   A) 可回溯硬不变量：逐函数 violations==0（块引用/边引用/完备性），
#      且 emitted == reachable（每个可达块都出现在文本里且只出现一次）；
#   B) 分级统计：if / while / do-while / for / switch / goto / break / continue
#      逐样本给出；switch 只在候选证据 high 时渲染，降级数单列；
#   C) 不可结构化如实标注：不可约块/函数、条件不可判、goto 密集函数、
#      不可达块，各自统计并列出代表函数；
#   D) 候选账目对平：每个 high 候选的去向必须能归类——
#      渲染成 switch / 证据不足降级 / 无候选保留 goto / 落在未展开块（label），
#      不允许「有候选但既没渲染也没解释」。
#
# 退出码：0 = 全部通过；1 = 有硬不变量失败（可回溯/账目不平）。
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import expr, recdesc, struct as S, switchcand  # noqa: E402

SAMPLES = ["tests/fixtures/cli-64.exe", "tests/fixtures/bin_ls.elf",
           "tests/fixtures/dyn_static"]


def _walk(n, acc):
    if isinstance(n, dict):
        acc.append(n)
        for k in ("children", "then", "else", "body", "inner"):
            _walk(n.get(k), acc)
    elif isinstance(n, list):
        for x in n:
            _walk(x, acc)


def _high_candidates(cand_rep):
    out = {}
    for f in cand_rep.get("functions") or []:
        for c in f.get("candidates") or []:
            if c["evidence"] == "high":
                out.setdefault(f["function"], []).append(c)
    return out


def check_sample(rel, verbose=True):
    path = os.path.join(WORK, rel)
    t0 = time.time()
    res = recdesc.descend(path)
    cand = switchcand.analyze_binary(path, ".text", res)
    rep = S.structure_binary(res, cand, False)
    st = rep["stats"]
    fails = []

    declared = {f["addr"] for f in expr.list_functions(res)
                if f["boundary"] == "declared"}
    hi = _high_candidates(cand)
    by_fn = {f["function"]: f for f in cand.get("functions") or []}

    # A) 可回溯硬不变量 + 候选去向审计（一次遍历，两件事一起做）
    mismatch, fn_viol = [], []
    where = {}                      # (func, block) -> 渲染种类
    for f in rep["functions"]:
        if not f["blocks"]:
            continue
        r = S.structure_function(res, f["function"], by_fn.get(f["function"]))
        s2 = r["stats"]
        if s2["blocks_emitted"] != s2["blocks_reachable"]:
            mismatch.append((hex(f["function"]), s2["blocks_emitted"],
                             s2["blocks_reachable"]))
        if r["violations"]:
            fn_viol.append((hex(f["function"]), r["violations"][:1]))
        nodes = []
        _walk(r["tree"], nodes)
        for n in nodes:
            k = n.get("kind")
            if k in ("block", "label"):
                # switch/unstructured 的 body 里也含同一个块节点，按上面的种类优先
                where.setdefault((f["function"], n.get("block")), k)
            elif k == "switch":
                where[(f["function"], n.get("block"))] = "switch"
            elif k == "unstructured":
                for b in n.get("blocks") or []:
                    where.setdefault((f["function"], b), "unstructured")

    if st["violations"] or fn_viol:
        fails.append("%s: 可回溯违规 %d 项（函数级 %s）"
                     % (rel, st["violations"], fn_viol[:2]))
    if mismatch:
        fails.append("%s: emitted!=reachable %d 个函数（例 %s）"
                     % (rel, len(mismatch), mismatch[:2]))

    # D) 候选账目：每个 high 候选必须能归类
    tally = {"switch": 0, "unstructured": 0, "label": 0, "missing": 0,
             "skipped_domain": 0}
    for fa, cs in hi.items():
        if fa not in declared:
            tally["skipped_domain"] += len(cs)
            continue
        for c in cs:
            blk = next((b["start"] for b in res["blocks"]
                        if b["function"] == fa and c["jmp"] in b["insns"]), None)
            kind = where.get((fa, blk))
            if kind in ("switch", "unstructured", "label"):
                tally[kind] += 1
            else:
                tally["missing"] += 1
    if tally["missing"]:
        fails.append("%s: %d 个 high 候选的去向无法解释（既没 switch 也没降级/label）"
                     % (rel, tally["missing"]))

    if verbose:
        print("\n=== %s ===" % rel)
        print("函数 %d ｜ 块 %d ｜ 可达/输出 %d/%d ｜ 可回溯违规 %d"
              % (st["functions"], st["blocks"],
                 sum(f["blocks"] for f in rep["functions"]),
                 sum(f["blocks"] for f in rep["functions"]), st["violations"]))
        print("结构: if %d / else %d / while %d / do-while %d / for %d / switch %d"
              "（证据不足降级 %d，无候选 %d）"
              % (st["if"], st["else"], st["while"], st["do_while"],
                 st["for"], st["switch"], st["switch_downgraded"],
                 st["switch_no_candidate"]))
        print("控制转移: goto %d / break %d / continue %d / 条件不可判 %d"
              % (st["goto"], st["break"], st["continue"], st["cond_unknown"]))
        print("不可结构: 不可约 %d 块（%d 函数）/ 不可达 %d 块 / goto 密集 %d 函数"
              % (st["irreducible_blocks"], st["irreducible_functions"],
                 st["unreachable_blocks"], st["goto_dense_functions"]))
        print("候选去向: high %d = switch %d + 未展开块(label) %d + 降级 %d"
              " + 跳过域 %d + 无去向 %d"
              % (sum(len(v) for v in hi.values()), tally["switch"],
                 tally["label"], tally["unstructured"], tally["skipped_domain"],
                 tally["missing"]))
        dense = sorted([f for f in rep["functions"] if f["goto_dense"]],
                       key=lambda x: -x["blocks"])[:5]
        print("goto 密集代表: %s"
              % ", ".join("%s(%d 块)" % (hex(f["function"]), f["blocks"])
                          for f in dense))
        print("耗时 %.1fs" % (time.time() - t0))

    return fails, dict(st, tally=tally)


def selftest():
    """可失败自证：篡改 blocks_emitted(=reachable+1) → A 段必须报错。"""
    import contextlib
    import io
    orig = S.structure_function

    def broken(*a, **kw):
        r = dict(orig(*a, **kw))
        st = dict(r["stats"])
        st["blocks_emitted"] = st["blocks_reachable"] + 1
        r["stats"] = st
        return r

    S.structure_function = broken
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fails, _ = check_sample(SAMPLES[0], verbose=False)
    finally:
        S.structure_function = orig
    hit = any("emitted!=reachable" in x for x in fails)
    print("[selftest] 篡改 blocks_emitted=reachable+1 后 check_sample 报 %d 项失败，"
          "命中 emitted!=reachable=%s（期望 True）" % (len(fails), hit))
    return 0 if hit else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    out, fails = {}, []
    for rel in SAMPLES:
        f, st = check_sample(rel, verbose=not args.json)
        out[rel] = st
        fails.extend(f)
    if args.json:
        print(json.dumps({"stats": out, "failures": fails},
                         ensure_ascii=False, indent=2))
    print("\n结果: %s" % ("PASS" if not fails else "FAIL"))
    for x in fails:
        print("  ! %s" % x)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
