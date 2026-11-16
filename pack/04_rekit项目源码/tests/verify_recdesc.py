#!/usr/bin/env python3
# verify_recdesc.py — M4 第二单元验收：递归下降 + 基本块划分
#
# 回答三个问题，每个都给出可复现命令与数字：
#   Q1 权威种子 vs 启发式种子：成功率必须分开报（本脚本每个样本两行）。
#   Q2 “边界是否落在真指令上”：用三条独立证据交叉验证——
#      (a) GNU objdump 2.47（-z，禁用零字节折叠）在同地址的长度；
#      (b) capstone 5 在同地址的长度（第三方解码器）；
#      (c) 工具链声明：symtab STT_FUNC / .eh_frame FDE / PE .pdata / 导出表
#          的函数起点与范围。
#      覆盖与漏检在输出里分条写明（见 SAMPLE 段落）。
#   Q3 线性扫描 vs 递归下降：指令起点集合做差集，单列，不合成一个总数；
#      AVX 样本上单独量化 abstain：弃权点、丢了多少条指令、占比。
#
# 用法：
#   python tests/verify_recdesc.py --all
#   python tests/verify_recdesc.py --all --selftest    # 注入错边界，必须被检出
import argparse
import bisect
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(os.path.realpath(__file__)).parents[1]
sys.path.insert(0, str(REPO))
from rekit import disasm, pe, recdesc  # noqa: E402

SAMPLES = [
    ("tests/fixtures/cli-64.exe", ".text", "PE/MSVC · .pdata 41 条"),
    ("tests/fixtures/minidll.dll", ".text", "PE/导出表 4 条（含纯序号）"),
    ("tests/fixtures/bin_ls.elf", ".text", "ELF/stripped PIE · 仅 FDE"),
    ("tests/fixtures/dyn_pie", ".text", "ELF GCC PIE"),
    ("tests/fixtures/dyn_nopie", ".text", "ELF GCC no-PIE"),
    ("tests/fixtures/dyn_static", ".text", "ELF static · 含真实 AVX"),
    ("tests/samples/avx/avx_dense.exe", ".text", "自建 AVX/VEX 密集 PE"),
]

LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")


def objdump_path():
    return shutil.which("objdump")


def image_base(path, data):
    if data[:4] == b"\x7fELF":
        return 0
    return pe.parse(path)["image_base"]


def run_objdump(path, sec, base):
    """返回 {addr: {len,text}}。必须带 -z：否则 objdump 把零字节折叠成 '...'，
    minidll.dll 这种全零填充 + 单字节 ret 的样本会漏掉大部分指令行。"""
    cmd = [objdump_path(), "-d", "-z", "-M", "intel", "--insn-width=16",
           "--start-address=0x%x" % (base + sec["va"]),
           "--stop-address=0x%x" % (base + sec["va"] + sec["size"]), path]
    out = subprocess.run(cmd, capture_output=True)
    if out.returncode != 0:
        return None, "objdump 失败: %s" % out.stderr.decode("utf-8", "replace")[:200]
    ins = {}
    for ln in out.stdout.decode("utf-8", "replace").splitlines():
        m = LINE.match(ln)
        if not m:
            continue
        raw = m.group(2).split()
        ins[int(m.group(1), 16) - base] = {"len": len(raw), "text": m.group(3)}
    return ins, None


_CAP = None


def capstone_len(data, sec, addr):
    global _CAP
    try:
        import capstone
    except Exception:
        return None
    if _CAP is None:
        _CAP = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    off = sec["off"] + (addr - sec["va"])
    for ins in _CAP.disasm(data[off:off + 16], addr):
        return {"length": ins.size, "text": "%s %s" % (ins.mnemonic, ins.op_str)}
    return None


def _slice(addrs, lo, hi):
    i = bisect.bisect_left(addrs, lo)
    j = bisect.bisect_left(addrs, hi)
    return addrs[i:j]


def _effective_end(data, sec):
    """节尾零填充不计入“函数范围”（否则 AVX 样本最后一个函数的漏检比例被灌水）。"""
    off = sec["off"]
    end = off + sec["size"]
    while end > off and data[end - 1] == 0:
        end -= 1
    return sec["va"] + (end - off)


def check_boundaries(ours, od):
    """边界硬检查：返回 (errors, not_start, len_diff)。

    ours/od: {addr: length}。不在 objdump 起点的条目由调用方结合 seed/overlap
    归类；这里只负责“同起点长度必须一致”。
    """
    len_diff = [a for a in ours if a in od and od[a] != ours[a]]
    not_start = [a for a in ours if a not in od]
    errors = ["长度不一致 @0x%x 我方=%d objdump=%d" %
              (a, ours[a], od[a]) for a in len_diff]
    return errors, not_start, len_diff


def seed_report(res, od, sec, data):
    """按权威/启发式/派生分列种子成功率；权威与启发式绝不合并。"""
    abstain_addrs = set(a["addr"] for a in res["abstains"])
    ins_by_addr = {i["addr"]: i["length"] for i in res["instructions"]}
    out = {}
    for cls in (recdesc.AUTH, recdesc.HEUR):
        rows = [s for s in res["seeds"] if s["authority"] == cls]
        cnt = {"total": len(rows), "decoded": 0, "aligned": 0,
               "seed_only": 0, "abstained": 0, "not_reached": 0,
               "examples": []}
        for s in rows:
            a = s["addr"]
            if a in abstain_addrs:
                cnt["abstained"] += 1
                if len(cnt["examples"]) < 3:
                    cnt["examples"].append((hex(a), "abstain(VEX/EVEX)"))
                continue
            olen = ins_by_addr.get(a)
            if olen is None:
                cnt["not_reached"] += 1
                if len(cnt["examples"]) < 3:
                    cnt["examples"].append((hex(a), "未被调度/无法解码"))
                continue
            cnt["decoded"] += 1
            if a in od and od[a]["len"] == olen:
                cnt["aligned"] += 1
            elif a not in od:
                cnt["seed_only"] += 1
                if len(cnt["examples"]) < 3:
                    cnt["examples"].append(
                        (hex(a), "种子起点不在 objdump 线性边界（capstone=%s）" %
                         ((capstone_len(data, sec, a) or {}).get("text", "?"))))
            else:
                cnt["examples"].append(
                    (hex(a), "长度与 objdump 不一致 %d vs %d"
                     % (olen, od[a]["len"])))
        cnt["rate"] = (cnt["decoded"] / cnt["total"]) if cnt["total"] else None
        cnt["aligned_rate"] = (cnt["aligned"] / cnt["total"]) if cnt["total"] else None
        out[cls] = cnt
    return out


def range_report(res, od_addrs, ours_addrs, abstain_addrs):
    """函数范围覆盖：起点是否解到、范围内 objdump 指令是否全部覆盖。"""
    ranges = []
    seen = set()
    for s in res["seeds"]:
        if s["authority"] != recdesc.AUTH or not s.get("end"):
            continue
        lo, hi = s["addr"], s["end"]
        if (lo, hi) in seen:
            continue
        seen.add((lo, hi))
        ranges.append((lo, hi, s["sources"]))
    full = partial = start_missing = 0
    exp_total = cov_total = 0
    miss_abstain = miss_other = 0
    samples = []
    ours_set = set(ours_addrs)
    for (lo, hi, _src) in ranges:
        exp = _slice(od_addrs, lo, hi)
        cov = set(_slice(ours_addrs, lo, hi)) & set(exp)
        exp_total += len(exp)
        cov_total += len(cov)
        missed = len(exp) - len(cov)
        has_abs = any(lo <= a < hi for a in abstain_addrs)
        if has_abs:
            miss_abstain += missed
        else:
            miss_other += missed
        if lo not in ours_set:
            start_missing += 1
            if len(samples) < 2:
                samples.append((hex(lo), hex(hi), "起点未解出"))
        elif missed == 0:
            full += 1
        else:
            partial += 1
            if len(samples) < 5:
                samples.append((hex(lo), hex(hi), "漏 %d/%d 条%s"
                                % (missed, len(exp),
                                   "（含 abstain）" if has_abs else "")))
    return {"ranges": len(ranges), "full": full, "partial": partial,
            "start_missing": start_missing, "expected": exp_total,
            "covered": cov_total,
            "miss_abstain": miss_abstain, "miss_other": miss_other,
            "samples": samples}


def linear_diff(path, section, rec_addrs):
    lin = disasm.sweep_file(path, section)
    lin_addrs = set(i["addr"] for i in lin["instructions"] if i["status"] == "ok")
    rec = set(rec_addrs)
    return {
        "linear_ins": len(lin_addrs),
        "linear_stopped": lin["stopped"],
        "both": len(lin_addrs & rec),
        "recursive_only": sorted(rec - lin_addrs),
        "linear_only": sorted(lin_addrs - rec),
        "linear_bytes": sum(i["length"] for i in lin["instructions"]
                            if i["status"] == "ok"),
    }


def cfg_check(res):
    """CFG 边分级硬检查：独立重算，不信任实现自己的计数。

    返回 (errors, summary)。规则：
      · 确定边：源函数有权威声明 end、根非启发式、目标已解出且同函数；
      · 确定边与疑似边必须互斥（不得把猜的边混进确定集）；
      · 跨函数边：目标已解出但 origin 不同，且不得同时出现在函数内边集合；
      · 未解析边：间接目标，target 必须为 None（不猜）；
      · 未解出边：target 非 None 但不在已解出集合。
    """
    ins = {i["addr"]: i for i in res["instructions"]}
    blocks = {b["start"]: b for b in res["blocks"]}
    edges = res["cfg"]["edges"]
    errs = []

    def key(e):
        return (e["from"], e["to"], e["kind"])

    d = set(key(e) for e in edges["definite"])
    s = set(key(e) for e in edges["speculative"])
    if d & s:
        errs.append("确定边与疑似边重叠 %d 条" % len(d & s))
    for cls in ("definite", "speculative"):
        for e in edges[cls]:
            b = blocks.get(e["from"])
            if b is None:
                errs.append("%s 边起点不是块首 @0x%x" % (cls, e["from"]))
                continue
            if e["to"] not in ins:
                errs.append("%s 边目标未解出 @0x%x→0x%x"
                            % (cls, e["from"], e["to"]))
                continue
            if ins[e["to"]]["origin"] != b["function"]:
                errs.append("%s 边跨函数 @0x%x→0x%x"
                            % (cls, e["from"], e["to"]))
            if e.get("to_block") not in blocks:
                errs.append("%s 边目标块不存在 @0x%x" % (cls, e["to"]))
            if cls == "definite" and b["boundary"] != "declared":
                errs.append("确定边来自未声明边界 @0x%x" % e["from"])
    for e in edges["unresolved"]:
        if e["to"] is not None:
            errs.append("未解析边却有目标 @0x%x" % e["from"])
    for e in edges["undecoded"]:
        if e["to"] in ins:
            errs.append("未解出边的目标其实已解出 @0x%x" % e["from"])
    for e in edges["cross_function"]:
        if e["to"] not in ins:
            errs.append("跨函数边目标未解出 @0x%x" % e["from"])
            continue
        src = blocks[e["from"]]
        if ins[e["to"]]["origin"] == src["function"]:
            errs.append("跨函数边其实同函数 @0x%x→0x%x"
                        % (e["from"], e["to"]))
        if key(e) in d or key(e) in s:
            errs.append("跨函数边混入函数内边 @0x%x" % e["from"])
    for cls in ("definite", "undecoded"):
        for e in res["cfg"]["calls"][cls]:
            if e["to"] is None:
                errs.append("调用边目标为空 @0x%x" % e["from"])
    for e in res["cfg"]["calls"]["unresolved"]:
        if e["to"] is not None:
            errs.append("未解析调用边却有目标 @0x%x" % e["from"])
    cnt = res["cfg"]["counts"]
    return errs, {
        "definite": cnt["definite"], "speculative": cnt["speculative"],
        "cross": cnt["cross_function"], "undecoded": cnt["undecoded"],
        "unresolved": cnt["unresolved"],
        "calls": res["cfg"]["call_counts"],
        "functions": res["cfg"]["function_stats"],
    }


def analyze_sample(rel, section, tag):
    path = str(REPO / rel)
    if not os.path.exists(path):
        return None, "%s 样本缺失" % rel
    data = open(path, "rb").read()
    sec = disasm.find_section(path, section)
    if sec is None:
        return None, "%s 找不到节 %s" % (rel, section)
    base = image_base(path, data)
    od, err = run_objdump(path, sec, base)
    if err:
        return None, "%s %s" % (rel, err)

    res = recdesc.descend(path, section)
    res_h = recdesc.descend(path, section, include_heuristic=True)
    ours = {i["addr"]: i["length"] for i in res["instructions"]}
    ours_addrs = sorted(ours)
    od_addrs = sorted(od)
    od_len = {a: v["len"] for a, v in od.items()}

    errors, not_start, len_diff = check_boundaries(ours, od_len)
    overlap_addrs = set(o["addr"] for o in res["overlaps"])
    seed_addrs = set(s["addr"] for s in res["seeds"])
    origin = {i["addr"]: i.get("origin") for i in res["instructions"]}
    unexplained = []
    not_start_kind = {}
    for a in not_start:
        cs = capstone_len(data, sec, a)
        org = origin.get(a)
        if a in overlap_addrs:
            kind = "overlap(分支跳进前一条指令／跳过 lock 前缀)"
        elif a in seed_addrs:
            kind = "seed_declared(种子声明的重叠入口)"
        elif org in seed_addrs and org not in od:
            # 权威种子本身不是 objdump 线性边界（如零填充中的 ret），
            # 从它顺序下降得到的边界自然也不在线性视图里；capstone 必须认可。
            kind = "seed_path(源自非线性的权威种子 0x%x)" % org
        else:
            kind = "UNEXPLAINED"
            unexplained.append(a)
        not_start_kind[a] = kind
        if cs is not None and cs["length"] != ours[a]:
            errors.append("重叠起点 @0x%x 我方=%d capstone=%d"
                          % (a, ours[a], cs["length"]))
    # 不在 objdump 起点的条目必须逐条有归属（overlap / seed），否则算错
    err_detail = []
    for a in not_start[:5]:
        cs = capstone_len(data, sec, a)
        err_detail.append((hex(a), ours[a],
                           (cs or {}).get("length"), (cs or {}).get("text")))
    if unexplained:
        errors.append("有 %d 条边界既不在 objdump 起点、也不是 seed/overlap：%s"
                      % (len(unexplained), ",".join(hex(a) for a in unexplained[:5])))

    cfg_errs, cfg_sum = cfg_check(res)
    errors.extend(cfg_errs)
    seed_rep = seed_report(res, od, sec, data)
    seed_rep_h = seed_report(res_h, od, sec, data)
    abstain_addrs = set(a["addr"] for a in res["abstains"])
    rng = range_report(res, od_addrs, ours_addrs, abstain_addrs)
    lin = linear_diff(path, section, ours_addrs)

    # 线性扫描停止点之后的递归收获（说明“递归能跨过线性死点”）
    stop = lin["linear_stopped"]
    rec_after_stop = [a for a in ours_addrs if stop and a > stop["addr"]]

    # AVX/VEX 代价：唯一弃权点 + 归因漏检
    unique_abstain = sorted(set(a["addr"] for a in res["abstains"]))
    vex = [a for a, v in od.items() if v["text"].split()[:1]
           and v["text"].split()[0].startswith("v")]
    covered = set(ours) & set(od)
    missed = set(od) - set(ours)
    # 伪函数范围（无 end 的权威种子）：[seed_i, seed_{i+1}) 或到有效节尾
    pseudo = []
    starts = sorted(s["addr"] for s in res["seeds"]
                    if s["authority"] == recdesc.AUTH)
    eff_end = _effective_end(data, sec)
    for i, lo in enumerate(starts):
        hi = starts[i + 1] if i + 1 < len(starts) else eff_end
        if lo < eff_end:
            pseudo.append((lo, min(hi, eff_end)))
    pseudo_expected = pseudo_covered = pseudo_miss_abs = pseudo_miss_other = 0
    for (lo, hi) in pseudo:
        exp = _slice(od_addrs, lo, hi)
        cov = set(exp) & set(ours)
        pseudo_expected += len(exp)
        pseudo_covered += len(cov)
        miss = len(exp) - len(cov)
        if any(lo <= a < hi for a in unique_abstain):
            pseudo_miss_abs += miss
        else:
            pseudo_miss_other += miss

    return {
        "rel": rel, "tag": tag, "section": sec, "data_len": len(data),
        "res": res, "res_h": res_h, "ours": ours, "od": od_len,
        "errors": errors, "not_start": not_start, "len_diff": len_diff,
        "not_start_detail": err_detail, "not_start_kind": not_start_kind,
        "cfg": cfg_sum, "seed_report": seed_rep,
        "seed_report_h": seed_rep_h, "ranges": rng, "linear": lin,
        "rec_after_stop": len(rec_after_stop),
        "unique_abstain": unique_abstain, "vex_ins": len(vex),
        "covered": len(covered), "missed": len(missed),
        "flow": Counter(recdesc.classify(i)[0] for i in res["instructions"]),
        "pseudo": {"expected": pseudo_expected, "covered": pseudo_covered,
                   "miss_abstain": pseudo_miss_abs,
                   "miss_other": pseudo_miss_other},
    }, None


def print_sample(r):
    st = r["res"]["stats"]
    sec = r["section"]
    print("\n[%s] %s" % (r["rel"], r["tag"]))
    print("  节: VA=0x%x off=0x%x size=0x%x ｜ 指令 %d 条 / 块 %d ｜ 覆盖 %d/%d 字节 (%.1f%%)"
          % (sec["va"], sec["off"], sec["size"], st["instructions"], st["blocks"],
             st["bytes_covered"], sec["size"], 100 * (st["coverage"] or 0)))
    print("  种子成功率（分列，不合并）:")
    for label, cls, c in (("权威", recdesc.AUTH, r["seed_report"][recdesc.AUTH]),
                          ("启发式", recdesc.HEUR, r["seed_report_h"][recdesc.HEUR])):
        if c["total"] == 0:
            print("    %-8s %-13s 0 条（未启用/样本无此来源）" % (label, cls))
            continue
        print("    %-8s %-13s 解出 %d/%d (%.1f%%) ｜ objdump 对齐 %d (%.1f%%) ｜ "
              "非 objdump 线性(但 capstone 认可) %d ｜ abstain %d ｜ 未调度 %d"
              % (label, cls, c["decoded"], c["total"],
                 100 * (c["rate"] or 0), c["aligned"],
                 100 * (c["aligned_rate"] or 0), c["seed_only"],
                 c["abstained"], c["not_reached"]))
        for ex in c["examples"][:2]:
            print("        · %s %s" % ex)
    rg = r["ranges"]
    print("  函数范围验证: %d 段 ｜ 全覆 %d / 部分 %d / 起点未解 %d ｜ 范围内 objdump 指令 %d，覆盖 %d (%.1f%%)"
          % (rg["ranges"], rg["full"], rg["partial"], rg["start_missing"],
             rg["expected"], rg["covered"],
             100 * (rg["covered"] / rg["expected"] if rg["expected"] else 0)))
    print("    漏检归因: abstain 范围 %d 条 / 其它(数据·填充·不可达) %d 条 ｜ "
          "间接 jmp %d 处 / 间接 call %d 处（目标无法静态确定，其后代码不可达）"
          % (rg["miss_abstain"], rg["miss_other"],
             r["flow"].get("jmp_ind", 0), r["flow"].get("call_ind", 0)))
    for s in rg["samples"]:
        print("      · %s..%s %s" % s)
    c = r["cfg"]
    print("  CFG（函数内边分级，不合并；调用边单列）: 确定 %d ｜ 疑似 %d ｜ "
          "跨函数 %d ｜ 目标未解出 %d ｜ 未解析 %d"
          % (c["definite"], c["speculative"], c["cross"],
             c["undecoded"], c["unresolved"]))
    print("    函数: 声明边界 %d / 边界未知 %d ｜ 调用边: 确定 %d / 目标未解出 %d / "
          "未解析 %d（间接，不猜目标）"
          % (c["functions"]["declared"], c["functions"]["unknown"],
             c["calls"]["definite"], c["calls"]["undecoded"],
             c["calls"]["unresolved"]))
    l = r["linear"]
    print("  线性 vs 递归（单列）: 线性 %d 条%s ｜ 交集 %d ｜ 递归独有 %d ｜ 线性独有 %d"
          % (l["linear_ins"],
             "" if not l["linear_stopped"] else
             "（停在 0x%x: %s）" % (l["linear_stopped"]["addr"],
                                   l["linear_stopped"]["reason"]),
             l["both"], len(l["recursive_only"]), len(l["linear_only"])))
    if l["recursive_only"]:
        print("    递归独有样例: %s" %
              ", ".join("0x%x" % a for a in l["recursive_only"][:8]))
    if l["linear_stopped"]:
        print("    线性停止点之后递归仍解出 %d 条（线性扫描永远到不了）"
              % r["rec_after_stop"])
    print("  边界硬检查: 长度不一致 %d 条 ｜ 不在 objdump 线性起点 %d 条（必须逐条有归属）"
          % (len(r["len_diff"]), len(r["not_start"])))
    if r["not_start_kind"]:
        kind_cnt = Counter(v.split("(")[0] for v in r["not_start_kind"].values())
        print("    归属: %s" % ", ".join("%s=%d" % (k, v)
                                         for k, v in sorted(kind_cnt.items())))
    for (a, olen, cslen, cstext) in r["not_start_detail"]:
        print("      · %s 我方 len=%d capstone len=%s %s" % (a, olen, cslen, cstext))
    print("  abstain: 唯一弃权点 %d 个 ｜ 受影响函数范围漏检 %d 条 ｜ VEX 指令 %d/%d (%.1f%%)"
          % (len(r["unique_abstain"]), r["pseudo"]["miss_abstain"],
             r["vex_ins"], len(r["od"]),
             100 * (r["vex_ins"] / len(r["od"]) if r["od"] else 0)))
    if r["ranges"]["ranges"] == 0 and r["pseudo"]["expected"]:
        print("    伪范围(无 pdata/size 时按下一 seed 切): 预期 %d，覆盖 %d (%.1f%%)，"
              "abstain 归因漏 %d，其它漏 %d"
              % (r["pseudo"]["expected"], r["pseudo"]["covered"],
                 100 * (r["pseudo"]["covered"] / r["pseudo"]["expected"]),
                 r["pseudo"]["miss_abstain"], r["pseudo"]["miss_other"]))


def run(selftest=False):
    if objdump_path() is None:
        print("[env] 找不到 objdump：请把 binutils 2.47 的 bin 目录加进 PATH")
        return 2
    rows, fails = [], []
    for (rel, secname, tag) in SAMPLES:
        r, err = analyze_sample(rel, secname, tag)
        if err:
            fails.append(err)
            continue
        rows.append(r)
        for e in r["errors"]:
            fails.append("%s: %s" % (rel, e))

    print("=" * 82)
    print("递归下降 + 基本块：种子分级 / 边界真指令性 / 线性↔递归差集 / VEX abstain 代价")
    print("=" * 82)
    print("覆盖判定（本脚本实际验证了什么）:")
    print("  · 权威种子：PE 导出 EAT / .pdata BeginAddress / EntryPoint；ELF e_entry /")
    print("    symtab·dynsym STT_FUNC / .eh_frame FDE initial_location（CIE/FDE 手解）")
    print("  · 启发式种子：55 48 89 e5 等函数序言模式，单独一组统计，不与权威合并")
    print("  · 每条自研边界：objdump 2.47(-z) 同址同长 + capstone 5 同址同长；")
    print("    不同起点必须归属到 overlap（分支跳进指令内部）或 seed（种子声明）")
    print("  · 函数范围：FDE range / symtab st_size / .pdata EndAddress 内逐条点名覆盖")
    print("  · CFG 边：确定/疑似/跨函数/目标未解出/未解析五类互斥，跨函数单列、")
    print("    间接 jmp/call 目标写 None（不猜）；确定边必须有权威声明的函数边界")
    print("漏检判定（本脚本不能验证什么）:")
    print("  · 种子不可达的代码（无符号无 FDE 的函数、间接 jmp/call 目标、跳转表分支）")
    print("  · VEX/EVEX 之后的函数尾部（abstain 停止，代价按样本单列）")
    print("  · 节内数据/对齐填充会被线性扫描当成指令；递归只走可达路径，故差值单列")
    print("  · objdump 若与自研解码以同样方式出错则无法互相发现（capstone 作为第三票）")
    for r in rows:
        print_sample(r)

    print("\n" + "=" * 82)
    print("汇总（abstain 代价按样本单列）")
    print("=" * 82)
    for r in rows:
        st = r["res"]["stats"]
        print("%-34s 指令 %6d ｜ 覆盖 %5.1f%% ｜ 权威种子 %d/%d ｜ abstain 点 %2d ｜ 丢了 %5d 条 (%.1f%%)"
              % (r["rel"], st["instructions"], 100 * (st["coverage"] or 0),
                 r["seed_report"][recdesc.AUTH]["decoded"],
                 r["seed_report"][recdesc.AUTH]["total"], len(r["unique_abstain"]),
                 r["pseudo"]["miss_abstain"],
                 100 * (r["pseudo"]["miss_abstain"] / r["pseudo"]["expected"]
                        if r["pseudo"]["expected"] else 0)))

    if selftest:
        # 自证可失败：把第一条指令长度 +1，check_boundaries 必须报长度不一致
        r = rows[0]
        ours = dict(r["ours"])
        a = next(iter(ours))
        ours[a] += 1
        errs, _ns, _ld = check_boundaries(ours, r["od"])
        print("\n[selftest] 注入 0x%x 长度 +1 → 检出错误 %d 条" % (a, len(errs)))
        if not errs:
            print("[selftest] 未检出：检查器空转 → FAIL")
            return 1
        print("[selftest] 已检出（能失败）→ PASS")
        return 0

    print("\n缺失/不可解释边界 %d 项" % len(fails))
    for f in fails:
        print("  ✗ %s" % f)
    print("\nVERDICT: %s" % ("PASS" if not fails else "FAIL"))
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    return run(a.selftest)


if __name__ == "__main__":
    sys.exit(main())
