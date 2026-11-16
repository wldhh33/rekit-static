#!/usr/bin/env python3
# verify_sitejoin.py — M7-U1 验收：三层拼接（调用图 / 参数事实层 / 结构化文本）
#
# 硬不变量（任一不成立 → FAIL/退出码 1）：
#   A) 对齐键账目：keys = |facts ∪ graph|、键唯一、duplicate 0；
#      已解出 call 全集（独立重算，另走一条代码路径）== keys + 两层都漏 + 0 多出。
#      M7-U2 修掉带前缀 call 漏检后，三样本的「两层都漏」应恒为 0（见 KNOWN_HARD 注释）。
#   B) 三层完整：每个键都能在 graph/facts/struct 里找到；aligned 的行号能在块内
#      回指到同一行文本，且直接调用行含目标地址、间接调用行含 `(*`。
#   C) 冲突归因合规：kind ∈ 白名单、attribution 与映射一致、detail 非空；
#      硬冲突必须带 key 或 (function, block)；M7-U2 后已知根因清零，任何硬冲突
#      都是 FAIL（口径差异 struct_function_absent 仍单列、不算硬冲突）。
#   D) 只读：注入既有 graph/facts/sidx/res 跑 build() 前后逐字段深相等。
#   E) 能失败（自证）：四种注入（改 state / 删图边 / 破坏文本 / 两层同时删站点）
#      必须各自被检出——真实缺口已修掉，键覆盖账改由注入证明不是空转。
#   F) 负向基线：三样本 recdesc 17 项 + cli-64 表达式文本 sha256 与基线相等。
import argparse
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import callfacts as CF, callgraph as CG, expr, recdesc  # noqa: E402
from rekit import sitejoin  # noqa: E402

SAMPLES = ["tests/fixtures/cli-64.exe", "tests/fixtures/bin_ls.elf",
           "tests/fixtures/dyn_static"]
BASELINE = os.path.join(HERE, "baselines", "definite_baseline.json")
# M7-U2 已修 callgraph._call_insns 的首字节过滤：三样本「两层都漏」= 0，
# 因此这里不再放行任何硬冲突种类——出现即 FAIL（口径更严，不是放宽）。
KNOWN_HARD = set()

# R74：本文件用到的三处「判据」不再 import sitejoin 的私有实现，改为在这里
# 独立复述契约。若 sitejoin 侧新增冲突种类而契约未更新，C 段会直接报未知种类。
#   · _text_lines → _JOIN_LINES：块文本 = body 行 + term 行，body 计数用于切片换算；
#   · _slice      → _JOIN_SLICE：行号 < body 行数即 body，否则 term；
#   · _KIND_ATTR  → _KIND_ATTR_EXPECT：种类 → 归因层的契约表（期望值来源）。
def _JOIN_LINES(node):
    body = list(node.get("lines") or [])
    term = list(node.get("term") or [])
    return body + term, len(body)


def _JOIN_SLICE(idx, nbody):
    return "body" if idx < nbody else "term"


_KIND_ATTR_EXPECT = {
    "duplicate_key": "data_anomaly",
    "function_mismatch": "layer_bug",
    "state_mismatch": "layer_bug",
    "target_mismatch": "layer_bug",
    "graph_edge_missing": "layer_bug",
    "facts_site_missing": "layer_bug",
    "operand_declared": "layer_bug",
    "struct_block_missing": "layer_bug",
    "struct_line_unmatched": "layer_bug",
    "struct_line_target": "layer_bug",
    "struct_line_count_mismatch": "layer_bug",
    "struct_function_absent": "caliber_difference",
    "struct_block_unreachable": "caliber_difference",
    "struct_abstain_line": "caliber_difference",
    "call_site_missing": "layer_bug",
    "facts_site_not_call": "layer_bug",
    "graph_edge_not_call": "layer_bug",
}


def _calls_alternate(res):
    """独立重算已解出 call（与 sitejoin._opcode_of 不同路径，避免自证循环）。"""
    out = set()
    for ins in res.get("instructions") or []:
        raw = (ins.get("bytes") or "").replace(" ", "")
        if "e8" not in raw and "ff" not in raw:
            continue
        try:
            rec = expr.decode(ins)
        except expr.LiftError:
            continue
        if rec.get("family") == "call":
            out.add(ins["addr"])
    return out


def _json(x):
    return json.dumps(x, sort_keys=True, default=str)


def check_sample(rel, baseline):
    path = os.path.join(WORK, rel)
    res = recdesc.descend(path)
    graph = CG.build(path, res=res)
    facts = CF.build(path, res=res, graph=graph)
    funcs = sorted({s["function"] for s in facts["sites"]},
                   key=lambda x: (x is None, x or 0))
    sidx = sitejoin.struct_index(res, funcs)
    fails = []

    # D 前置快照
    res0, g0, f0, s0 = _json(res), _json(graph), _json(facts), _json(sidx)
    rep = sitejoin.build(path, res=res, graph=graph, facts=facts, sidx=sidx)
    c = rep["counts"]

    # A) 键账目与覆盖
    keys = [s["key"] for s in rep["sites"]]
    union = {s["from"] for s in facts["sites"]} | {e["from"] for e in graph["edges"]}
    if len(keys) != len(set(keys)):
        fails.append("%s: 对齐键有重复" % rel)
    if set(keys) != union:
        fails.append("%s: 键集合 != facts ∪ graph 的 from 集合" % rel)
    if c["keys"] != c["key_unique"] or c["duplicate_keys"]:
        fails.append("%s: 键唯一性账目不平（unique=%d keys=%d dup=%d）"
                     % (rel, c["key_unique"], c["keys"], c["duplicate_keys"]))
    alt = _calls_alternate(res)
    mine = sitejoin._decoded_calls(res)
    if alt != set(mine):
        fails.append("%s: 独立重算的 call 全集不一致（alt=%d mine=%d）"
                     % (rel, len(alt), len(mine)))
    if c["decoded_calls"] != len(alt):
        fails.append("%s: decoded_calls 与独立重算不一致" % rel)
    if c["decoded_calls"] != c["keys"] + c["call_site_missing"]:
        fails.append("%s: decoded_calls != keys + 两层都漏" % rel)
    if c["facts_site_not_call"] or c["graph_edge_not_call"]:
        fails.append("%s: 出现不属于 call 的站点/边" % rel)
    if (c["call_site_missing"] == 0) != c["key_coverage_ok"]:
        fails.append("%s: key_coverage_ok 与缺口数矛盾" % rel)
    if c["call_site_missing"]:
        fails.append("%s: 出现 %d 条两层都漏的 call（M7-U2 修正后应为 0）"
                     % (rel, c["call_site_missing"]))
    inst_by = {i["addr"]: i for i in res["instructions"]}
    for x in rep["conflicts"]:
        if x["kind"] != "call_site_missing":
            continue
        ins = inst_by.get(x["key"])
        if ins is None:
            fails.append("%s: call_site_missing 0x%x 不在已解出指令里"
                         % (rel, x["key"]))
            continue
        raw = ins["bytes"].replace(" ", "")
        if raw[:2] in ("e8", "ff"):
            fails.append("%s: 0x%x 首字节是 e8/ff，不应漏" % (rel, x["key"]))
        try:
            if expr.decode(ins).get("family") != "call":
                fails.append("%s: 0x%x 不是 call" % (rel, x["key"]))
        except expr.LiftError:
            fails.append("%s: 0x%x 无法解码为 call" % (rel, x["key"]))

    # B) 三层完整 + 行号回指
    status = {}
    for s in rep["sites"]:
        for k in ("key", "graph", "facts", "struct"):
            if k not in s:
                fails.append("%s: 站点缺字段 %s" % (rel, k))
                break
        st = s["struct"]["status"]
        status[st] = status.get(st, 0) + 1
        if st != "aligned":
            continue
        node = (sidx.get(s["function"]) or {}).get("blocks", {}).get(s["block"])
        if node is None:
            fails.append("%s: aligned 站点 0x%x 的块不在结构化索引里"
                         % (rel, s["key"]))
            continue
        lines, nbody = _JOIN_LINES(node)
        i = s["struct"]["line_index"]
        if not (0 <= i < len(lines)):
            fails.append("%s: 0x%x 行号越界" % (rel, s["key"]))
            continue
        if lines[i] != s["struct"]["line_text"]:
            fails.append("%s: 0x%x 行文本与块内第 %d 行不一致"
                         % (rel, s["key"], i))
        if s["struct"]["slice"] != _JOIN_SLICE(i, nbody):
            fails.append("%s: 0x%x 切片标注错" % (rel, s["key"]))
        text = s["struct"]["line_text"]
        if s["facts"]["call_kind"] == "direct":
            if ("0x%x" % (s["facts"]["target"] or 0)) not in text:
                fails.append("%s: 0x%x 文本行不含目标地址" % (rel, s["key"]))
        elif "(*" not in text:
            fails.append("%s: 0x%x 间接调用行不含 (*" % (rel, s["key"]))
    if sum(status.values()) != len(rep["sites"]):
        fails.append("%s: 结构化状态计数 != 站点数" % rel)

    # C) 冲突归因合规
    re_kinds = {}
    for x in rep["conflicts"]:
        re_kinds[x["kind"]] = re_kinds.get(x["kind"], 0) + 1
        if x["kind"] not in _KIND_ATTR_EXPECT:
            fails.append("%s: 未知冲突种类 %s" % (rel, x["kind"]))
            continue
        if x["attribution"] != _KIND_ATTR_EXPECT[x["kind"]]:
            fails.append("%s: 冲突 %s 归因与映射不一致" % (rel, x["kind"]))
        if x["attribution"] not in sitejoin.ATTRIBUTION:
            fails.append("%s: 冲突 %s 归因不在三类里" % (rel, x["kind"]))
        if not x.get("detail"):
            fails.append("%s: 冲突 %s 没有 detail" % (rel, x["kind"]))
        if x["attribution"] in ("layer_bug", "data_anomaly"):
            if x["key"] is None and not (x.get("function") or x.get("block")):
                fails.append("%s: 硬冲突 %s 既无 key 也无函数/块" % (rel, x["kind"]))
            if x["kind"] not in KNOWN_HARD:
                fails.append("%s: 出现未归因的硬冲突种类 %s（需人工复核）"
                             % (rel, x["kind"]))
    if re_kinds != c["conflict_kinds"]:
        fails.append("%s: 冲突种类计数与逐条重算不一致" % rel)
    if c["conflicts"] != len(rep["conflicts"]):
        fails.append("%s: 冲突总数不平" % rel)

    # D) 只读
    if _json(res) != res0:
        fails.append("%s: build() 改写了 recdesc 结果" % rel)
    if _json(graph) != g0:
        fails.append("%s: build() 改写了调用图报告" % rel)
    if _json(facts) != f0:
        fails.append("%s: build() 改写了事实层报告" % rel)
    if _json(sidx) != s0:
        fails.append("%s: build() 改写了结构化索引" % rel)

    # E) 注入自证（复用已建好的对象，不重算）
    inj = []
    f2 = copy.deepcopy(facts)
    ds = next(x for x in f2["sites"] if x["call_kind"] == "direct")
    ds["state"] = "unresolved" if ds["state"] != "unresolved" else "decoded"
    r2 = sitejoin.check(graph, f2, sidx)
    inj.append(("state", any(x["kind"] == "state_mismatch" for x in r2["conflicts"])))
    g2 = copy.deepcopy(graph)
    g2["edges"] = [e for e in g2["edges"] if e["from"] != ds["from"]]
    r3 = sitejoin.check(g2, facts, sidx)
    inj.append(("edge", any(x["kind"] == "graph_edge_missing"
                            and x["key"] == ds["from"] for x in r3["conflicts"])))
    s2 = copy.deepcopy(sidx)
    node = s2[ds["function"]]["blocks"][ds["block"]]
    body = node.get("lines") or []
    term = node.get("term") or []
    for i, ln in enumerate(body + term):
        if sitejoin._is_call_line(ln):
            if i < len(body):
                body[i] = "/* 注入破坏 */"
            else:
                term[i - len(body)] = "/* 注入破坏 */"
            break
    r4 = sitejoin.check(graph, facts, s2)
    inj.append(("struct", any(x["kind"].startswith("struct_")
                              and x["attribution"] == "layer_bug"
                              for x in r4["conflicts"])))
    # 注入 4：两层同时删掉同一直接调用点 → 键覆盖账必须报 call_site_missing。
    # 真实缺口在 M7-U2 已清零，这一项保证覆盖检查不是「因为没东西可查」才通过。
    f3 = copy.deepcopy(facts)
    g3 = copy.deepcopy(graph)
    f3["sites"] = [x for x in f3["sites"] if x["from"] != ds["from"]]
    g3["edges"] = [e for e in g3["edges"] if e["from"] != ds["from"]]
    r5 = sitejoin.check(g3, f3, sidx, res=res)
    inj.append(("coverage", any(x["kind"] == "call_site_missing"
                                and x["key"] == ds["from"]
                                for x in r5["conflicts"])))
    for name, ok in inj:
        if not ok:
            fails.append("%s: 注入 %s 未被检出（检查器空转）" % (rel, name))

    # F) 负向基线
    for k, want in baseline["recdesc"].items():
        if res["stats"].get(k) != want:
            fails.append("%s: recdesc.%s 基线 %r != 现 %r"
                         % (rel, k, want, res["stats"].get(k)))
    if rel == "tests/fixtures/cli-64.exe":
        b = expr.lift_binary(path, res=res)
        sha = hashlib.sha256("\n".join(
            expr.lift_function(res, f["function"])["text"]
            for f in b["functions"]).encode()).hexdigest()
        if sha != baseline["expr"]["text_sha256"]:
            fails.append("%s: 表达式文本 sha256 变化" % rel)

    st = {"sites": c["facts_sites"], "keys": c["keys"],
          "decoded_calls": c["decoded_calls"],
          "missing": c["call_site_missing"], "aligned": c["aligned"],
          "struct_status": status, "conflicts": c["conflicts"],
          "hard": c["hard_conflicts"], "caliber": c["caliber_differences"],
          "kinds": re_kinds, "injections": dict(inj)}

    print("\n=== %s ===" % rel)
    print("键: %d（唯一 %d ｜ 重复 %d）｜ 已解出 call %d ｜ 两层都漏 %d ｜ 覆盖 %s"
          % (c["keys"], c["key_unique"], c["duplicate_keys"],
             c["decoded_calls"], c["call_site_missing"],
             "完整" if c["key_coverage_ok"] else "有缺口"))
    print("结构化: %s"
          % " ｜ ".join("%s=%d" % (k, v) for k, v in sorted(status.items())))
    print("冲突: %d（硬 %d ｜ 口径差异 %d）: %s"
          % (c["conflicts"], c["hard_conflicts"], c["caliber_differences"],
             ", ".join("%s=%d" % (k, v) for k, v in sorted(re_kinds.items()))
             or "无"))
    print("注入自证: %s ｜ 只读: %s"
          % (", ".join("%s=%s" % (k, "检出" if v else "漏检") for k, v in inj),
             "OK" if not any("改写" in x for x in fails) else "FAIL"))
    return fails, st


def selftest():
    """自证检查器不是空转：把「块内调用行」定位规则打断，必须报出硬冲突。"""
    rel = SAMPLES[0]
    path = os.path.join(WORK, rel)
    res = recdesc.descend(path)
    graph = CG.build(path, res=res)
    facts = CF.build(path, res=res, graph=graph)
    funcs = sorted({s["function"] for s in facts["sites"]},
                   key=lambda x: (x is None, x or 0))
    sidx = sitejoin.struct_index(res, funcs)
    real = sitejoin._slots
    try:
        sitejoin._slots = lambda node, addr_set: ([], list(node.get("lines") or []),
                                                  len(node.get("lines") or []))
        rep = sitejoin.check(graph, facts, sidx, res=res)
    finally:
        sitejoin._slots = real
    hit = [x for x in rep["conflicts"]
           if x["kind"] == "struct_line_count_mismatch"
           and x["attribution"] == "layer_bug"]
    print("[selftest] 打断文本行定位后：struct_line_count_mismatch=%d" % len(hit))
    if not hit:
        print("[selftest] 未检出：定位检查器是空转的 → 失败")
        return 1
    print("[selftest] 已检出（能失败）→ 通过")
    return 0


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
        f, st = check_sample(rel, baseline[rel])
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
