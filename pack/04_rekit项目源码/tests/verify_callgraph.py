#!/usr/bin/env python3
# tests/verify_callgraph.py — M6-U1 验收：调用图 + 保守跨过程观察
#
# 硬不变量（任一不成立 → FAIL/退出码 1）：
#   A) 账目对平：call_sites = direct + indirect；direct = decoded + plt_or_import
#      + unresolved；edges 条数 = direct；三态占比之和 = 1。
#   B) 三态独立复核（不复用 callgraph 内部判定）：
#        decoded       目标必须在 recdesc 已解出指令集合里；
#        unresolved    目标必须不在已解出集合里，且不落在任何 .plt* 节；
#        plt_or_import 必须满足三者之一：目标节名 .plt* / 证据含「导入跳板」/
#                      目标符号 @plt 后缀；
#        直接调用点集合必须与 E8（call rel32）指令集合逐点一致；E8 判定须跳
#        legacy 前缀 + REX（M7-U2：按 raw 首字节会与被测模块犯同一个错，
#        校验器自身也属 R71 管辖）。
#   C) 隔离：间接调用候选层默认关闭（candidates 为空）；开启后条数 = indirect、
#      证据等级只取 high/medium/low、high 必须带回指到的导入名、medium 必须带槽。
#   D) 环：cycles 成员都在 nodes 里且 recursion == self/mutual；渲染有节点上限、
#      两次渲染逐字节一致、体积有上界（防环递归爆掉）。
#   E) 观察：窗口必须严格限定在调用点所在基本块内（before.at < call < after.at）；
#      不做 ABI 推断的声明必须出现在报告里。
#   F) 只读 + 负向基线：build 前后 res 快照不变；三样本 recdesc 17 项、
#      cli-64.exe 表达式文本 sha256、dyn_static 0x401870 文本 sha256 与
#      tests/baselines/definite_baseline.json 逐项相等。
import argparse
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import callgraph as CG, elf, expr, pe, recdesc  # noqa: E402

SAMPLES = ["tests/fixtures/cli-64.exe", "tests/fixtures/bin_ls.elf",
           "tests/fixtures/dyn_static"]
BASELINE = os.path.join(HERE, "baselines", "definite_baseline.json")


def _sections(path):
    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        return [(s["name"], s["addr"], s["addr"] + s["size"])
                for s in elf.section_headers(data)
                if s["size"] > 0 and s["addr"]]
    r = pe.parse(path)
    return [(nm, va, va + max(vsz, rsz))
            for (va, vsz, _rp, rsz, nm) in r["sections"]]


def _sec_of(secs, addr):
    for nm, lo, hi in secs:
        if lo <= addr < hi:
            return nm
    return None


# 独立的前缀解析（不复用 callgraph / sitejoin 的实现；R71 同样适用于校验器）
_LEGACY = frozenset((0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67,
                     0xF0, 0xF2, 0xF3))


def _opcode(b):
    """bytes → 跳过 legacy 前缀与 REX 后的 opcode（越界返回 None）。"""
    raw = bytes.fromhex(b.replace(" ", ""))
    i, n = 0, len(raw)
    while i < n and raw[i] in _LEGACY:
        i += 1
    if i < n and 0x40 <= raw[i] <= 0x4F:
        i += 1
    return raw[i] if i < n else None


def _snapshot(res):
    return (len(res["instructions"]), len(res["blocks"]),
            dict(res["stats"]), json.dumps(res["cfg"]["counts"], sort_keys=True))


def _sha(texts):
    return hashlib.sha256("\n".join(texts).encode()).hexdigest()


def check_sample(rel, baseline, verbose=True):
    path = os.path.join(WORK, rel)
    t0 = time.time()
    res = recdesc.descend(path)
    secs = _sections(path)
    ins = {i["addr"] for i in res["instructions"]}
    e8 = {i["addr"] for i in res["instructions"] if _opcode(i["bytes"]) == 0xE8}
    snap0 = _snapshot(res)

    base = CG.build(path, res=res)
    ind = CG.build(path, res=res, indirect=True)
    obs = CG.build(path, res=res, observe=True)
    snap1 = _snapshot(res)

    fails = []

    # A) 账目
    c = base["counts"]
    if c["call_sites"] != c["direct"] + c["indirect"]:
        fails.append("%s: call_sites != direct + indirect" % rel)
    if c["decoded"] + c["plt_or_import"] + c["unresolved"] != c["direct"]:
        fails.append("%s: 三态之和 != direct" % rel)
    if len(base["edges"]) != c["direct"]:
        fails.append("%s: edges 条数 != direct" % rel)
    if c["direct"] and abs(sum(base["ratios"].values()) - 1.0) > 1e-9:
        fails.append("%s: 三态占比之和 != 1" % rel)

    # B) 独立复核三态
    for e in base["edges"]:
        if _opcode(e["bytes"]) != 0xE8:
            fails.append("%s: 直接边 0x%x 不是 E8 指令" % (rel, e["from"]))
            break
        if e["state"] == "decoded":
            if e["to"] not in ins:
                fails.append("%s: decoded 目标 0x%x 未解出" % (rel, e["to"]))
                break
        elif e["state"] == "unresolved":
            if e["to"] in ins:
                fails.append("%s: unresolved 目标 0x%x 其实已解出" % (rel, e["to"]))
                break
            if (_sec_of(secs, e["to"]) or "").startswith(".plt"):
                fails.append("%s: unresolved 目标 0x%x 落在 PLT 节" % (rel, e["to"]))
                break
        elif e["state"] == "plt_or_import":
            sec = _sec_of(secs, e["to"]) or ""
            ok = (sec.startswith(".plt") or "导入跳板" in e["evidence"]
                  or (e["target_symbol"] or "").endswith("@plt"))
            if not ok:
                fails.append("%s: plt_or_import 目标 0x%x 无 PLT/导入证据"
                             % (rel, e["to"]))
                break
        else:
            fails.append("%s: 未知状态 %r" % (rel, e["state"]))
            break
    if {e["from"] for e in base["edges"]} != e8:
        fails.append("%s: 直接调用点集合与 E8 指令集合不一致（%d vs %d）"
                     % (rel, len({e["from"] for e in base["edges"]}), len(e8)))

    # C) 候选层隔离
    if base["indirect"]["enabled"] or base["indirect"]["candidates"]:
        fails.append("%s: 默认状态下候选层未关闭" % rel)
    ic = ind["indirect"]
    if not ic["enabled"] or len(ic["candidates"]) != c["indirect"]:
        fails.append("%s: 开启后候选条数 != indirect" % rel)
    for cand in ic["candidates"]:
        if cand["evidence"] not in ("high", "medium", "low"):
            fails.append("%s: 候选证据等级非法 %r" % (rel, cand["evidence"]))
            break
        if cand["evidence"] == "high" and not cand["target_label"]:
            fails.append("%s: high 候选无回指导入名（0x%x）"
                         % (rel, cand["from"]))
            break
        if cand["evidence"] == "medium" and cand["target_slot"] is None:
            fails.append("%s: medium 候选无静态槽（0x%x）" % (rel, cand["from"]))
            break

    # D) 环 + 渲染安全
    nodes = {n["addr"]: n for n in base["nodes"]}
    for cy in base["cycles"]:
        for m in cy["members"]:
            n = nodes.get(m)
            if n is None or n["recursion"] not in ("self", "mutual"):
                fails.append("%s: 环成员 0x%x 未标注 recursion" % (rel, m))
                break
    t1, t2 = CG.render(base), CG.render(base)
    if t1 != t2:
        fails.append("%s: 渲染不确定" % rel)
    if len(t1) > 60000:
        fails.append("%s: 渲染体积 %d 字节（疑似环未截断）" % (rel, len(t1)))
    if "节点上限" not in t1:
        fails.append("%s: 渲染缺少节点上限声明" % rel)

    # E) 观察窗口
    if "不做 ABI 推断" not in (obs["observe_note"] or ""):
        fails.append("%s: 观察报告缺少不做 ABI 推断的声明" % rel)
    blk_of = {}
    for b in res["blocks"]:
        for a in b["insns"]:
            blk_of[a] = b
    before_n = after_n = barrier_n = rsp_n = 0
    for o in obs["observations"]:
        w = o["window"]
        if not w:
            fails.append("%s: 调用点 0x%x 不在任何基本块" % (rel, o["from"]))
            break
        b = blk_of.get(o["from"])
        if b is None or w["block_start"] != b["start"] or w["block_end"] != b["end"]:
            fails.append("%s: 观察窗口不是调用点所在块" % rel)
            break
        for d in o["before_defs"]:
            before_n += 1
            if not (b["start"] <= d["at"] < o["from"]):
                fails.append("%s: before 定义地址越界 0x%x" % (rel, d["at"]))
                break
        for u in o["after_uses"]:
            after_n += 1
            if not (o["from"] < u["at"] <= b["end"]):
                fails.append("%s: after 使用地址越界 0x%x" % (rel, u["at"]))
                break
        barrier_n += bool(w.get("before_barrier")) + bool(w.get("after_barrier"))
        rsp_n += bool(w.get("rsp_modified_before"))

    # F) 只读 + 负向基线
    if snap0 != snap1:
        fails.append("%s: build 改写了 res（快照不一致）" % rel)
    rows = []
    for k, want in baseline["recdesc"].items():
        got = res["stats"].get(k)
        rows.append((k, want, got, want == got))
    for (k, want, got, same) in rows:
        if not same:
            fails.append("%s: recdesc.%s 基线 %r != 现 %r" % (rel, k, want, got))

    expr_sha = None
    if rel == "tests/fixtures/cli-64.exe":
        b = expr.lift_binary(path, res=res)
        expr_sha = _sha([expr.lift_function(res, f["function"])["text"]
                         for f in b["functions"]])
        if expr_sha != baseline["expr"]["text_sha256"]:
            fails.append("%s: 表达式文本 sha256 变化" % rel)
    if rel == "tests/fixtures/dyn_static":
        r = expr.lift_function(res, 0x401870)
        got = _sha([r["text"]])
        want = baseline["f_401870"]["text_sha256"]
        if got != want:
            fails.append("%s: 0x401870 文本 sha256 变化" % rel)
        if r["stats"]["insns"] != baseline["f_401870"]["insns"]:
            fails.append("%s: 0x401870 指令数变化" % rel)

    stats = dict(c, ratios=base["ratios"],
                 cycles_self=sum(1 for x in base["cycles"] if x["kind"] == "self"),
                 cycles_mutual=sum(1 for x in base["cycles"]
                                   if x["kind"] == "mutual"),
                 indirect_counts=ic["counts"],
                 nodes=len(base["nodes"]),
                 cycles=len(base["cycles"]),
                 before_defs=before_n, after_uses=after_n,
                 barriers=barrier_n, rsp_modified=rsp_n,
                 render_bytes=len(t1), expr_sha=expr_sha,
                 baseline_rows=len(rows))

    if verbose:
        print("\n=== %s ===" % rel)
        print("调用点 %d（直接 %d ｜ 间接 %d；不合并）"
              % (c["call_sites"], c["direct"], c["indirect"]))
        print("三态（分母=直接 %d）: decoded %d (%.2f%%) ｜ plt_or_import %d (%.2f%%)"
              " ｜ unresolved %d (%.2f%%)"
              % (c["direct"], c["decoded"], 100 * base["ratios"]["decoded"],
                 c["plt_or_import"], 100 * base["ratios"]["plt_or_import"],
                 c["unresolved"], 100 * base["ratios"]["unresolved"]))
        print("间接候选层: 默认关闭 ｜ 开启后 high %d / medium %d / low %d"
              % (ic["counts"]["high"], ic["counts"]["medium"],
                 ic["counts"]["low"]))
        print("函数节点 %d ｜ 环 %d 组（自递归 %d / 互递归 %d）"
              % (len(base["nodes"]), len(base["cycles"]),
                 stats["cycles_self"], stats["cycles_mutual"]))
        for cy in base["cycles"][:5]:
            print("  · %s: %s" % (cy["kind"],
                                  ", ".join("0x%x" % m for m in cy["members"][:6])
                                  + (" …" if cy["size"] > 6 else "")))
        print("观察: 调用点 %d ｜ before 定义 %d ｜ after 使用 %d ｜ 窗口截断 %d ｜ "
              "rsp 改写 %d"
              % (len(obs["observations"]), before_n, after_n, barrier_n, rsp_n))
        print("渲染 %d 字节 ｜ 负向基线 %d 项 ｜ 耗时 %.1fs"
              % (len(t1), len(rows), time.time() - t0))

    return fails, stats


def selftest():
    """可失败自证：把一条 decoded 直接边改成 unresolved → B 段必须报错。"""
    import contextlib
    import copy
    import io
    baseline = json.load(open(BASELINE, encoding="utf-8"))
    orig = CG.build

    def tampered(path, **kw):
        r = orig(path, **kw)
        if not kw.get("indirect") and not kw.get("observe"):
            r = copy.deepcopy(r)
            for e in r["edges"]:
                if e["state"] == "decoded":
                    e["state"] = "unresolved"
                    break
        return r

    CG.build = tampered
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            fails, _ = check_sample(SAMPLES[0], baseline[SAMPLES[0]],
                                    verbose=False)
    finally:
        CG.build = orig
    hit = any("其实已解出" in x for x in fails)
    print("[selftest] 把一条 decoded 边改成 unresolved 后 check_sample 报 %d 项失败，"
          "命中「已解出却标 unresolved」=%s（期望 True）" % (len(fails), hit))
    return 0 if hit else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    baseline = json.load(open(BASELINE, encoding="utf-8"))
    out, fails = {}, []
    for rel in SAMPLES:
        f, st = check_sample(rel, baseline[rel], verbose=not args.json)
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
