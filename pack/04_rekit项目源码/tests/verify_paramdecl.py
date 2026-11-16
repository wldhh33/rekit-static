#!/usr/bin/env python3
# tests/verify_paramdecl.py — M8-U2 验收：参数绑定只认 declared 来源
#
# 硬不变量（任一不成立 → FAIL/退出码 1）：
#   A) 分母先行：先报 18 样本 × 9 类声明来源的 present/readable/声明计数，
#      再报结果。某类来源 present=0 → 必须写「本轮无法验证」，不得用 0 当结论；
#      present>0 但 readable=0（PDB 未解码、gnu_debuglink 外部文件缺失）同样
#      写「本轮无法验证」，不得报成「该类不含形参」。
#   B) 声明可定位：DWARF 的 locator 必须给出节头索引/sh_offset/sh_size（ELF）
#      或 rawptr(raw_name→规范名)/RVA（PE）+ 压缩头标记；每条绑定证据必须给出
#      CU@偏移、DIE@偏移、位置表达式字节。读不到的位置不绑定。
#   C) 绑定纪律（逐站点独立重算）：形参级 bound/partial/abstained 与站点明细
#      重算一致；站点状态 = bound/partial/zero_params/abstained 与形参结论一致
#      （有绑定又有未绑定 → partial，不得报 bound）；绑定寄存器必须属于声明位置；
#      定义地址必须在调用点之前；操作数证据不得出现 declared 级。
#   D) 分母守恒：sites == sum(site_status)；available=false 且 sites>0 时
#      每站恰好一条 abstain、params_bound=0；sites==0（如 minidll 无调用）
#      单列「无可绑定对象」，不得并入「0 个参数」结论。
#   E) 独立复核（外部工具）：
#      · readelf（ELF）/ objdump --dwarf=info（PE）的 DIE 普查——CU 数、subprogram
#        数、subprogram 的 low_pc 数、subprogram 下的 formal_parameter 数——
#        与模块 meta 逐项相等（不经被测解析器）；
#      · objdump -d 文本核对：被绑定寄存器的 def_at 指令确实写该寄存器
#        （独立判据只能证伪，未建模指令单列计数）；未建模 > 已核对 → 判据失效。
#   F) --selftest：注入错例必须被检出（换掉声明外的寄存器、删掉 declared 证据、
#      给无声明样本伪造 params_bound>0）。
import copy
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)
sys.path.insert(0, HERE)

from rekit import callfacts as CF, disasm, paramdecl as PD, recdesc  # noqa: E402
from verify_callfacts import _objdump_writes, _written  # noqa: E402

CLASSES = ["dwarf", "pdb", "export_table", "coff_symbols", "elf_symtab",
           "elf_dynsym", "gnu_debuglink", "eh_frame", "pdata"]
# 无 DWARF 的对照样本：仍然构建一次，证明分母没有被吞掉。
# minidll.dll 无调用点（sites=0）：单列「无可绑定对象」，不得读成「0 个参数」。
CONTROL = {"cli-64.exe", "bin_ls.elf", "dyn_static", "hello_rust.exe",
           "minidll.dll"}


def _find_manifest():
    p = WORK
    while True:
        for cand in (os.path.join(p, "2026-11-15", "m2-task-card", "work",
                                  "sample_manifest.json"),
                     os.path.join(p, "m2-task-card", "work",
                                  "sample_manifest.json")):
            if os.path.isfile(cand):
                return cand
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


MANIFEST = _find_manifest()
M2WORK = os.path.dirname(MANIFEST or "")
M2ROOT = os.path.dirname(M2WORK)


def _resolve(rel):
    for base in (M2WORK, M2ROOT):
        p = os.path.join(base, rel)
        if os.path.isfile(p):
            return p
    return None


def _tool(name):
    exe = shutil.which(name)
    if exe:
        return exe
    cand = os.path.join(M2WORK, "tools", "binutils-2.47", "mingw64", "bin",
                        name + ".exe")
    return cand if os.path.isfile(cand) else None


# ── E) DWARF DIE 普查（外部工具，独立于被测解析器） ──────────────────
_DIE_RE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>:\s+Abbrev Number:\s+\d+\s+"
                     r"\((DW_TAG_\w+)\)")
_ATTR_RE = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)")
_CU_RE = re.compile(r"Compilation Unit @ offset")


def _census(text):
    stack, cur = {}, None
    out = {"cus": 0, "subprograms": 0, "params_under_subprogram": 0,
           "subprogram_with_low_pc": 0}
    for line in text.splitlines():
        if _CU_RE.search(line):
            out["cus"] += 1
        m = _DIE_RE.match(line)
        if m:
            depth, tag = int(m.group(1)), m.group(3)
            stack[depth] = tag
            cur = (depth, tag)
            if tag == "DW_TAG_subprogram":
                out["subprograms"] += 1
            elif (tag == "DW_TAG_formal_parameter"
                  and stack.get(depth - 1) == "DW_TAG_subprogram"):
                out["params_under_subprogram"] += 1
            continue
        a = _ATTR_RE.match(line)
        if (a and cur and cur[1] == "DW_TAG_subprogram"
                and a.group(1) == "DW_AT_low_pc"):
            out["subprogram_with_low_pc"] += 1
    return out


def _dwarf_dump(path, fmt):
    if fmt == "PE":
        exe = _tool("objdump")
        args = [exe, "--dwarf=info", path] if exe else None
    else:
        exe = _tool("readelf")
        args = [exe, "--debug-dump=info", path] if exe else None
    if args is None:
        raise RuntimeError("缺 binutils 工具：%s" % ("objdump" if fmt == "PE"
                                                   else "readelf"))
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout.decode("utf-8", "replace")


# ── C/D) 绑定纪律与账目 ─────────────────────────────────────────────
def _check_binding(rel, report, wmap=None):
    fails, st = [], {"bound_sites": 0, "partial_sites": 0, "zero_sites": 0,
                     "abstained_sites": 0, "declared_pieces": 0,
                     "defs_checked": 0, "defs_unmodeled": 0, "bad_defs": 0,
                     "sites": 0}
    c, sites = report["counts"], report["sites"]
    pb = report.get("param_binding") or {}
    pc = pb.get("counts") or {}
    if c["sites"] != len(sites):
        fails.append("%s: sites 与站点明细数不一致" % rel)
    if pc.get("sites") != c["sites"]:
        fails.append("%s: 参数绑定分母 %r != 站点数 %r"
                     % (rel, pc.get("sites"), c["sites"]))
    if sum((pc.get("site_status") or {}).values()) != pc.get("sites"):
        fails.append("%s: site_status 之和 != 分母" % rel)
    stored = [s for s in sites if s.get("param_binding")]
    implied = c["sites"] - len(stored)
    nd = pc.get("no_declaration_sites", 0)
    nt = pc.get("no_target_sites", 0)
    if nd + nt != implied:
        fails.append("%s: 未落盘的站点 %d 与 no_decl(%d)+no_target(%d) 不符"
                     % (rel, implied, nd, nt))
    n_bound = n_part = n_abst = n_piece = n_zero = 0
    for s in stored:
        b = s["param_binding"]
        if b.get("target") != s.get("target"):
            fails.append("%s: 0x%x 绑定目标 %r != 站点目标 %r"
                         % (rel, s["from"], b.get("target"), s.get("target")))
        if b["status"] == "zero_params":
            n_zero += 1
            if len(b.get("bound") or []) != 1 or b["bound"][0].get("param") is not None:
                fails.append("%s: 0x%x 零形参声明结构非法" % (rel, s["from"]))
            continue
        want = ("partial" if (b.get("partial") or
                              (b.get("bound") and b.get("abstains")))
                else ("bound" if b.get("bound") else "abstained"))
        if b["status"] != want:
            fails.append("%s: 0x%x 站点状态 %r，按形参结论应为 %r"
                         % (rel, s["from"], b["status"], want))
        for item in (b.get("bound") or []) + (b.get("partial") or []):
            if item.get("param") is None:
                continue
            decl = [e for e in item.get("evidence") or []
                    if e.get("level") == "declared" and e.get("source") == "dwarf"]
            if not decl:
                fails.append("%s: 0x%x 形参 %r 的绑定没有 declared 证据"
                             % (rel, s["from"], item.get("name")))
                continue
            text = decl[0].get("text") or ""
            if not ("CU@0x" in text and "DIE@0x" in text and "寄存器段" in text):
                fails.append("%s: 0x%x 形参 %r 的证据未给出 CU/DIE/位置"
                             % (rel, s["from"], item.get("name")))
            binds = item.get("binds") or []
            if not binds:
                fails.append("%s: 0x%x 形参 %r 的绑定寄存器段为空"
                             % (rel, s["from"], item.get("name")))
            for q in binds:
                if q.get("reg") not in (item.get("regs") or []):
                    fails.append("%s: 0x%x 绑定寄存器 %r 不在声明位置 %r 里"
                                 % (rel, s["from"], q.get("reg"), item.get("regs")))
                if q.get("def_at") is None or q["def_at"] >= s["from"]:
                    fails.append("%s: 0x%x 定义地址 %r 不在调用点之前"
                                 % (rel, s["from"], q.get("def_at")))
                if q.get("from") not in ("same_block", "cross_block"):
                    fails.append("%s: 0x%x 绑定来源 %r 非法"
                                 % (rel, s["from"], q.get("from")))
                for e in q.get("fact_evidence") or []:
                    if e.get("level") not in ("observed", "derived"):
                        fails.append("%s: 0x%x 操作数证据出现 declared 级"
                                     % (rel, s["from"]))
                n_piece += 1
                if wmap is not None and q.get("def_at") is not None:
                    w = _written(wmap, q["def_at"])
                    if w is None:
                        st["defs_unmodeled"] += 1
                    elif q["reg"] not in w:
                        st["bad_defs"] += 1
                        fails.append("%s: 0x%x 声称 %s 定义于 0x%x，但 objdump "
                                     "文本里该指令不写它"
                                     % (rel, s["from"], q["reg"], q["def_at"]))
                    else:
                        st["defs_checked"] += 1
    # 独立重算形参级计数（不信任模块自报）；zero_params 站点的
    # 「0 个形参」占位条目不进入形参计数（与 summarize 的分流一致）。
    real = [s["param_binding"] for s in stored
            if s["param_binding"]["status"] != "zero_params"]
    n_bound = sum(len(b.get("bound") or []) for b in real)
    n_part = sum(len(b.get("partial") or []) for b in real)
    n_abst = sum(len(b.get("abstains") or []) for b in real)
    for key, want in (("params_bound", n_bound), ("params_partial", n_part),
                      ("params_abstained", n_abst + implied),
                      ("bound_pieces", n_piece)):
        if pc.get(key) != want:
            fails.append("%s: %s 自报 %r != 独立重算 %r"
                         % (rel, key, pc.get(key), want))
    if pc.get("zero_params_sites") != n_zero:
        fails.append("%s: zero_params_sites 自报 %r != 重算 %r"
                     % (rel, pc.get("zero_params_sites"), n_zero))
    st["sites"] = c["sites"]
    st["bound_sites"] = sum(1 for s in stored
                            if s["param_binding"]["status"] == "bound")
    st["partial_sites"] = sum(1 for s in stored
                              if s["param_binding"]["status"] == "partial")
    st["zero_sites"] = n_zero
    st["abstained_sites"] = sum(1 for s in stored
                                if s["param_binding"]["status"] == "abstained")
    st["declared_pieces"] = n_piece
    st["sites_without_binding"] = implied
    # D) 无声明样本：分母不消失、不按 ABI 补
    if not pb.get("available"):
        if any(s.get("param_binding") for s in sites):
            fails.append("%s: available=false 却出现逐点绑定" % rel)
        if pc.get("params_bound") or pc.get("params_partial"):
            fails.append("%s: 无声明来源却报出绑定结论" % rel)
        if c["sites"] > 0 and pc.get("params_abstained") != c["sites"]:
            fails.append("%s: 无声明样本弃权 %r != 分母 %d"
                         % (rel, pc.get("params_abstained"), c["sites"]))
        if c["sites"] > 0 and ("不是「0 个参数」" not in (pb.get("note") or "")):
            fails.append("%s: 无声明样本未声明「不是 0 个参数」" % rel)
    return fails, st


# ── 单样本检查 ──────────────────────────────────────────────────────
def check_sample(rel, path):
    fails = []
    read = PD.read(path)
    audit, dwarf = read["audit"], read["dwarf"]
    fmt = audit.get("format")
    stats = {"format": fmt, "dwarf": None, "binding": None}
    # B) 审计结构
    for cls in CLASSES:
        v = (audit.get("classes") or {}).get(cls)
        if v is None:
            fails.append("%s: 审计缺来源类别 %s" % (rel, cls))
            continue
        if not v.get("locator"):
            fails.append("%s: 来源 %s 未给出定位串" % (rel, cls))
        if not v["present"] and v["readable"]:
            fails.append("%s: 来源 %s 不存在却报 readable" % (rel, cls))
        if cls != "dwarf" and v.get("param_decl_count") is not None:
            fails.append("%s: 非 DWARF 来源 %s 声称有形参计数" % (rel, cls))
        if v["present"] and cls == "dwarf" and v["readable"]:
            if v["param_decl_count"] != dwarf["meta"]["formal_parameters"]:
                fails.append("%s: dwarf 声明计数与 meta 不一致" % rel)
            loc = v["locator"]
            need = ("rawptr=0x" if fmt == "PE" else "sh_offset=0x")
            if need not in loc:
                fails.append("%s: DWARF 定位串缺 %s" % (rel, need))
            if "SHF_COMPRESSED" not in loc and "ZLIB" not in loc:
                fails.append("%s: 压缩节未报压缩头（读法不可复核）" % rel)
    if dwarf:
        meta = dwarf["meta"]
        stats["dwarf"] = {k: meta.get(k) for k in
                          ("cus", "versions", "declarations",
                           "subprograms_with_low_pc", "formal_parameters",
                           "params_with_expr", "params_with_loclist",
                           "params_without_location")}
        # E) 独立普查
        census = _census(_dwarf_dump(path, fmt))
        for key, mine in (("cus", "cus"), ("subprograms", "declarations"),
                          ("subprogram_with_low_pc", "subprograms_with_low_pc"),
                          ("params_under_subprogram", "formal_parameters")):
            if census[key] != meta[mine]:
                fails.append("%s: 独立普查 %s=%d != 模块 %s=%d"
                             % (rel, key, census[key], mine, meta[mine]))
    # C/D) 只在有 DWARF 或对照样本上构建
    if dwarf or os.path.basename(rel) in CONTROL:
        report = CF.build(path, res=recdesc.descend(path))
        wmap = None
        try:
            wmap, _delta = _objdump_writes(
                path, disasm.find_section(path, ".text")["va"])
        except Exception as e:                      # 工具缺失 → 判据失效即 FAIL
            fails.append("%s: objdump 独立判据不可用：%s" % (rel, e))
        bfails, bst = _check_binding(rel, report, wmap)
        fails.extend(bfails)
        if bst["defs_unmodeled"] > bst["defs_checked"]:
            fails.append("%s: 独立写判据未建模 %d > 已核对 %d（判据失效）"
                         % (rel, bst["defs_unmodeled"], bst["defs_checked"]))
        stats["binding"] = bst
        stats["sites"] = report["counts"]["sites"]
        stats["pc"] = report["param_binding"]["counts"]
        stats["available"] = report["param_binding"]["available"]
    return fails, stats


# ── F) 自证 ─────────────────────────────────────────────────────────
def selftest():
    entry = next((s for s in _load_samples()
                  if s["id"] == "hello_go_linux"), None)
    path = _resolve(entry["path"]) if entry else None
    if not path:
        print("[selftest] 缺 hello_go_linux 样本 → 失败")
        return 1
    report = CF.build(path, res=recdesc.descend(path))
    base, _st = _check_binding("base", report)
    if base:
        print("[selftest] 基线检查已失败，自证无意义：%s" % base[:2])
        return 1
    site = next(s for s in report["sites"]
                if s.get("param_binding")
                and any(b.get("binds") for b in s["param_binding"]["bound"]))
    item = next(b for b in site["param_binding"]["bound"] if b.get("binds"))

    r1 = copy.deepcopy(report)
    it1 = next(b for s in r1["sites"] if s.get("param_binding")
               for b in s["param_binding"]["bound"] if b.get("binds"))
    it1["binds"][0]["reg"] = "r99"
    f1, _ = _check_binding("inj-reg", r1)
    if not any("不在声明位置" in x for x in f1):
        print("[selftest] 注入声明外寄存器未被检出 → 失败")
        return 1

    r2 = copy.deepcopy(report)
    it2 = next(b for s in r2["sites"] if s.get("param_binding")
               for b in s["param_binding"]["bound"] if b.get("binds"))
    it2["evidence"] = [e for e in it2["evidence"] if e["level"] != "declared"]
    f2, _ = _check_binding("inj-ev", r2)
    if not any("没有 declared 证据" in x for x in f2):
        print("[selftest] 删除 declared 证据未被检出 → 失败")
        return 1

    ctl = next((s for s in _load_samples() if s["id"] == "cli-64.exe"), None)
    cpath = _resolve(ctl["path"]) if ctl else None
    if cpath:
        r3 = CF.build(cpath, res=recdesc.descend(cpath))
        r3["param_binding"]["counts"]["params_bound"] = 5
        f3, _ = _check_binding("inj-nodecl", r3)
        if not any("params_bound" in x for x in f3):
            print("[selftest] 无声明样本伪造 params_bound 未被检出 → 失败")
            return 1
    print("[selftest] 三类注入（声明外寄存器 / 缺 declared 证据 / 无声明伪造绑定）"
          "全部被检出 → 通过")
    print("[selftest] 基线（真实 hello_go_linux）零失败，检查器不是空转的")
    return 0


# ── 主流程 ──────────────────────────────────────────────────────────
def _load_samples():
    with open(MANIFEST, encoding="utf-8") as f:
        return json.load(f)["e9_ground_truth"]["samples"]


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not MANIFEST:
        print("找不到 sample_manifest.json", file=sys.stderr)
        return 1
    samples = _load_samples()
    out, fails = {}, []
    present = {c: 0 for c in CLASSES}
    readable = {c: 0 for c in CLASSES}
    decl_count = {c: 0 for c in CLASSES}
    versions = {}
    rows = []
    for e in samples:
        rel = e["path"]
        path = _resolve(rel)
        if not path:
            fails.append("%s: 样本文件缺失（%s）" % (e["id"], rel))
            continue
        f, st = check_sample(rel, path)
        fails.extend(f)
        out[e["id"]] = st
        audit = PD.read(path)["audit"]
        for c in CLASSES:
            v = audit["classes"][c]
            present[c] += 1 if v["present"] else 0
            readable[c] += 1 if (v["present"] and v["readable"]) else 0
            decl_count[c] += (v.get("param_decl_count") or 0)
        if st["dwarf"]:
            for v, n in (st["dwarf"]["versions"] or {}).items():
                versions[v] = versions.get(v, 0) + n
        rows.append((e["id"], st))

    print("== A) 分母先行：18 样本 × 声明来源 ==")
    print("%-15s %8s %9s %12s  %s" % ("来源类别", "present", "readable",
                                      "形参声明数", "语义（CLASS_DECLARES）"))
    for c in CLASSES:
        sem = PD.CLASS_DECLARES[c]
        print("%-15s %5d/18 %6d/18 %12d  %s"
              % (c, present[c], readable[c], decl_count[c], sem))
    for c in CLASSES:
        if c == "dwarf":
            continue
        if present[c] == 0:
            print("  [无法验证] %s：18 样本中 0 条 → 这类来源本轮无法验证"
                  "（不以 0 作为「该类不含形参」的结论）" % c)
        elif readable[c] == 0:
            print("  [无法验证] %s：present %d/18 但 readable 0/18 → "
                  "定位到了、读不出声明，本轮无法验证" % (c, present[c]))
        else:
            print("  [结构性] %s：present %d/18，语义=%s，不含形参位置 → "
                  "不能用于绑定（不是样本碰巧为 0）"
                  % (c, present[c], PD.CLASS_DECLARES[c]))
    ver_txt = "、".join("v%s×%d" % (k, v) for k, v in sorted(versions.items()))
    print("  DWARF 版本分布（有可读 DWARF 的样本）：%s" % (ver_txt or "无"))
    for v in (2, 3):
        if v not in versions:
            print("  [无法验证] DWARF v%d：18 样本中 0 条 → 真实样本无法验证"
                  "（仅有合成单测；不得写成「v%d 不支持/没有形参」）"
                  % (v, v))

    print("\n== 样本矩阵（先 present，再结果；无声明来源的样本单列分母）==")
    print("%-28s %-4s %-10s %7s %7s %7s %7s %7s %7s %8s"
          % ("样本", "格式", "DWARF(可读/声明)", "站点", "bound", "partial",
             "zero", "无声明", "无目标", "形参弃权"))
    for sid, st in rows:
        d = st["dwarf"]
        dcell = ("%s/%s" % (st["format"], d["formal_parameters"])
                 if d else "%s/-" % st["format"])
        b, pc = st.get("binding"), st.get("pc")
        if b:
            print("%-28s %-4s %-10s %7d %7d %7d %7d %7d %7d %8d"
                  % (sid, st["format"], dcell, b["sites"], b["bound_sites"],
                     b["partial_sites"], b["zero_sites"],
                     pc.get("no_declaration_sites", 0),
                     pc.get("no_target_sites", 0), pc.get("params_abstained", 0)))
        else:
            print("%-28s %-4s %-10s %7s %7s %7s %7s %7s %7s %8s"
                  % (sid, st["format"], dcell, "未构建", "-", "-", "-", "-",
                     "-", "-"))
        if b and b["sites"] == 0:
            print("  [无可绑定对象] %s：0 个调用点 → 本样本不构成参数绑定的分母；"
                  "不能读成「0 个参数」" % sid)

    print("\n== 结果分列（只统计声明来源可读的样本）==")
    for sid, st in rows:
        if not st["dwarf"]:
            continue
        b, pc = st["binding"], st["pc"]
        print("  %s：站点 %d ｜ 因声明绑定：形参 %d、寄存器段 %d（bound 站点 %d）"
              " ｜ 部分绑定形参 %d（partial 站点 %d）"
              " ｜ 因证据不足弃权：形参 %d（abstained 站点 %d）"
              " ｜ 零形参声明站点 %d ｜ objdump 写核对 %d 段（未建模 %d）"
              % (sid, b["sites"], pc["params_bound"], b["declared_pieces"],
                 b["bound_sites"], pc["params_partial"], b["partial_sites"],
                 pc["params_abstained"], b["abstained_sites"], b["zero_sites"],
                 b["defs_checked"], b["defs_unmodeled"]))

    if args.json:
        print(json.dumps({"stats": out, "failures": fails},
                         ensure_ascii=False, indent=2))
    print("\n结果: %s" % ("PASS" if not fails else "FAIL"))
    for x in fails[:60]:
        print("  ! %s" % x)
    if len(fails) > 60:
        print("  … 其余 %d 条失败" % (len(fails) - 60))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
