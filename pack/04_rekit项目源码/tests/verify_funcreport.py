#!/usr/bin/env python3
# tests/verify_funcreport.py — M15 外部抽查（objdump 独立证据）
#
# 三类样本：
#   完整声明  tests/fixtures/funcreport_full（gcc -g，DWARF 形参）的 add3
#   部分证据  samples/m9/elf_medium_synth_go_stripped 的 0x401320
#   严重不足  tests/fixtures/minidll.dll 的首个已解出函数
#
# 抽查项：
#   (a) 块起点与 state=decoded 的直接调用目标都是 objdump 指令起点
#   (b) 报告块内的每条指令地址都落在 [start,end) 且是 objdump 指令起点
#   (c) 完整声明样本：boundary.end - addr == objdump 符号 size（无符号则用 DWARF）
#   (d) 完整声明样本：DWARF 形参数 == objdump --dwarf=info 的 formal_parameter 数
#   (e) Go 样本：报告指令数 ≤ objdump 在 [addr, end) 的指令数
#   (f) 严重不足样本：parameters 状态 ∈ {missing_source, missing_declaration}
#       且人读含“缺：”
# 另核对 spec §6 的三类状态矩阵与 absence_summary 覆盖。
#
# 任何一项 FAIL → 退出 1；样本缺失/工具缺失 → SKIP（不算 PASS）。
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

from rekit import coverage                     # noqa: E402
from rekit import expr                         # noqa: E402
from rekit import funcreport as FR             # noqa: E402
from rekit import recdesc                      # noqa: E402

FULL = os.path.join(HERE, "m15_fixtures", "funcreport_full")
MINIDLL = os.path.join(HERE, "fixtures", "minidll.dll")
GO = os.path.join(WORK, "samples", "m9", "elf_medium_synth_go_stripped")
OUT_JSON = os.path.join(WORK, "evidence_m15_funcreport.json")

CHECKS = []


def _add(cid, name, status, detail):
    CHECKS.append({"id": cid, "name": name, "status": status,
                   "detail": detail})
    print("[%s] %s %s :: %s" % (status, cid, name, detail))


def _run(cmd):
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env,
                          timeout=180)


def _objdump(path):
    sec = recdesc.descend(path)["section"]
    r = coverage.objdump_instructions(path, sec)
    if r.get("status") != "ok":
        return None
    return r.get("instructions") or []


def _first_func(path):
    res = recdesc.descend(path)
    fs = expr.list_functions(res)
    return (fs[0]["addr"] if fs else None), res


def _dwarf_subprograms(path):
    """返回 [{name, low, high, nparams, die}]；解析失败返回 None。"""
    r = _run(["objdump", "--dwarf=info", path])
    if r.returncode != 0:
        return None
    text = r.stdout
    dies = list(re.finditer(
        r"<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((DW_TAG_\w+)\)", text))
    subs = []
    for i, m in enumerate(dies):
        if m.group(3) != "DW_TAG_subprogram":
            continue
        lvl = int(m.group(1))
        end = len(text)
        for nxt in dies[i + 1:]:
            if int(nxt.group(1)) <= lvl:
                end = nxt.start()
                break
        body = text[m.start():end]
        nm = re.search(r"DW_AT_name\s*:\s*(?:\([^)]*\):\s*)?([^\n]+)", body)
        name = nm.group(1).strip() if nm else None
        low = re.search(r"DW_AT_low_pc\s*:\s*(0x[0-9a-fA-F]+)", body)
        high = re.search(r"DW_AT_high_pc\s*:\s*(0x[0-9a-fA-F]+)", body)
        subs.append({
            "name": name,
            "low": int(low.group(1), 16) if low else None,
            "high": int(high.group(1), 16) if high else None,
            "nparams": body.count("DW_TAG_formal_parameter"),
            "die": m.group(2),
        })
    return subs


def _report_states(rep):
    return {n: s["evidence_state"] for n, s in rep["sections"].items()}


MATRIX = {
    "full": {
        "identity": {"present"},
        "boundary": {"present"},
        "blocks_and_edges": {"present"},
        "expressions": {"present", "abstained"},
        "calls": {"absent_measured"},
        "strings_and_data": {"absent_measured"},
        "parameters": {"present"},
    },
    "go": {
        "identity": {"present"},
        "boundary": {"present"},
        "blocks_and_edges": {"present"},
        "expressions": {"present", "abstained"},
        "calls": {"present", "absent_measured"},
        "strings_and_data": {"present", "absent_measured"},
        "parameters": {"missing_source"},
    },
    "scarce": {
        "identity": {"present"},
        "boundary": {"missing_source"},
        "blocks_and_edges": {"present"},
        "expressions": {"present", "abstained"},
        "calls": {"present", "absent_measured"},
        "strings_and_data": {"present", "absent_measured"},
        "parameters": {"missing_source", "missing_declaration"},
    },
}


def _check_matrix(tag, rep):
    st = _report_states(rep)
    bad = []
    for sec, allowed in MATRIX[tag].items():
        if st.get(sec) not in allowed:
            bad.append("%s=%s（允许 %s）" % (sec, st.get(sec),
                                            "/".join(sorted(allowed))))
    _add("%s-matrix" % tag, "状态矩阵", "PASS" if not bad else "FAIL",
         "全部匹配" if not bad else "; ".join(bad))

    rows = {(r["section"], r["field"]) for r in rep["absence_summary"]}
    missing = []
    for sec in FR.SECTION_ORDER:
        if st.get(sec) != "present" and (sec, FR._SECTION_FIELD[sec]) not in rows:
            missing.append(sec)
    dr = rep["sections"]["strings_and_data"]["data_refs"]
    if dr["evidence_state"] != "present" and \
            ("strings_and_data", "data_refs") not in rows:
        missing.append("strings_and_data/data_refs")
    _add("%s-absence" % tag, "absence 覆盖",
         "PASS" if not missing else "FAIL",
         "覆盖全部非 present 字段" if not missing else "缺: %s" % missing)


def _check_objdump_basics(tag, path, rep, insns):
    starts = {i["addr"] for i in insns}
    sec = recdesc.descend(path)["section"]
    lo, hi = sec["va"], sec["va"] + sec["size"]
    bad = []
    for b in rep["sections"]["blocks_and_edges"]["blocks"]:
        if b["start"] not in starts:
            bad.append("块起点 0x%x 不是 objdump 指令起点" % b["start"])
    outside = 0
    for d in rep["sections"]["calls"]["direct"]:
        if d.get("state") != "decoded" or d.get("target") is None:
            continue
        if not (lo <= d["target"] < hi):
            outside += 1
            continue
        if d["target"] not in starts:
            bad.append("调用目标 0x%x 不是 objdump 指令起点" % d["target"])
    _add("%s-a" % tag, "块/调用目标为指令起点",
         "PASS" if not bad else "FAIL",
         "checked; %d 个目标不在本节（未抽查）" % outside if not bad
         else "; ".join(bad[:5]))

    bad2 = []
    for b in rep["sections"]["blocks_and_edges"]["blocks"]:
        for a in b.get("insn_addrs") or []:
            if not (b["start"] <= a < b["end"]):
                bad2.append("0x%x 不在块 [0x%x,0x%x)" % (a, b["start"], b["end"]))
            elif a not in starts:
                bad2.append("0x%x 不是 objdump 指令起点" % a)
    n = sum(len(b.get("insn_addrs") or [])
            for b in rep["sections"]["blocks_and_edges"]["blocks"])
    _add("%s-b" % tag, "块内指令落域且为起点",
         "PASS" if not bad2 else "FAIL",
         "%d 条指令全部通过" % n if not bad2 else "; ".join(bad2[:5]))


def _check_full_size(rep):
    addr = rep["function"]["addr"]
    end = rep["sections"]["boundary"]["end"]
    if not end:
        _add("full-c", "符号 size", "FAIL", "boundary.end 缺失")
        return
    size = None
    src = None
    # PE 的 COFF 符号表值不是 size（aux 记录才有），故先走 DWARF 的
    # DW_AT_low_pc / DW_AT_high_pc；ELF 的 objdump -t 才直接给 size。
    subs = _dwarf_subprograms(FULL) or []
    for s in subs:
        if s["name"] == "add3" and s["low"] and s["high"]:
            size = (s["high"] - s["low"] if s["high"] > s["low"] else s["high"])
            src = "objdump --dwarf=info"
            break
    if size is None:
        t = _run(["objdump", "-t", FULL])
        if t.returncode == 0:
            for line in t.stdout.splitlines():
                parts = line.split()
                if len(parts) == 6 and parts[-1] == "add3":
                    try:
                        size = int(parts[-2], 16)
                        src = "objdump -t"
                    except ValueError:
                        size = None
                    break
    if size is None:
        _add("full-c", "符号 size", "SKIP", "objdump 无 add3 符号/DWARF 范围")
        return
    got = end - addr
    _add("full-c", "符号 size", "PASS" if got == size else "FAIL",
         "报告 end-addr=0x%x，%s size=0x%x" % (got, src, size))


def _check_full_params(rep):
    own = rep["sections"]["parameters"]["own_declaration"]
    subs = _dwarf_subprograms(FULL)
    if subs is None:
        _add("full-d", "DWARF 形参数", "SKIP", "objdump --dwarf=info 失败")
        return
    hit = next((s for s in subs if s["name"] == "add3"), None)
    if hit is None:
        _add("full-d", "DWARF 形参数", "SKIP", "objdump 里找不到 add3 subprogram")
        return
    got = len(own.get("params") or [])
    _add("full-d", "DWARF 形参数", "PASS" if got == hit["nparams"] else "FAIL",
         "报告=%d objdump=%d（DIE@%s）" % (got, hit["nparams"], hit["die"]))


def _check_go_upper(rep, insns):
    addr = rep["function"]["addr"]
    end = rep["sections"]["boundary"]["end"]
    sec = recdesc.descend(GO)["section"]
    hi = end or (sec["va"] + sec["size"])
    n_ext = sum(1 for i in insns if addr <= i["addr"] < hi)
    n_rep = sum(len(b.get("insn_addrs") or [])
                for b in rep["sections"]["blocks_and_edges"]["blocks"])
    _add("go-e", "指令数上界", "PASS" if n_rep <= n_ext else "FAIL",
         "报告=%d objdump[0x%x,0x%x)=%d" % (n_rep, addr, hi, n_ext))


def _check_scarce_f(rep):
    st = rep["sections"]["parameters"]["evidence_state"]
    text = FR.render(rep)
    ok = st in ("missing_source", "missing_declaration") and "缺：" in text
    _add("scarce-f", "缺失语义", "PASS" if ok else "FAIL",
         "parameters=%s，人读含“缺：”=%s" % (st, "缺：" in text))


def selftest():
    """可失败自证：把块起点改成 objdump 起点之外 → (a) 段必须报 FAIL。"""
    if shutil.which("objdump") is None:
        print("[selftest] 环境缺 objdump，无法构造注入 → 未检出")
        return 1
    path = FULL if os.path.exists(FULL) else MINIDLL
    addr, _ = _first_func(path)
    if addr is None:
        print("[selftest] 样本 %s 无已解出函数 → 未检出" % path)
        return 1
    insns = _objdump(path)
    if not insns:
        print("[selftest] objdump 指令表不可用 → 未检出")
        return 1
    rep = FR.build(path, addr)
    blocks = rep["sections"]["blocks_and_edges"]["blocks"]
    if not blocks:
        print("[selftest] 报告无块 → 未检出")
        return 1
    starts = sorted(i["addr"] for i in insns)
    injected = copy.deepcopy(rep)
    injected["sections"]["blocks_and_edges"]["blocks"][0]["start"] = starts[0] - 1

    n0 = len(CHECKS)
    _check_objdump_basics("selftest-clean", path, rep, insns)
    clean_fail = [c for c in CHECKS[n0:] if c["status"] == "FAIL"]
    n1 = len(CHECKS)
    _check_objdump_basics("selftest-injected", path, injected, insns)
    inj_fail = [c for c in CHECKS[n1:] if c["status"] == "FAIL"]

    hit = bool(inj_fail) and not clean_fail
    print("[selftest] 篡改块起点为 objdump 起点之外 → (a) 段 FAIL %d 项"
          "（未篡改时 FAIL %d 项）→ %s"
          % (len(inj_fail), len(clean_fail), "检出" if hit else "未检出"))
    return 0 if hit else 1


def main():
    if shutil.which("objdump") is None:
        print("SKIP: PATH 中没有 objdump（先加入 GNU binutils 的 bin 目录）")
        return 0
    reports = {}
    # 完整声明
    if os.path.exists(FULL):
        dwarf = None
        from rekit import paramdecl
        try:
            dwarf = paramdecl.read(FULL).get("dwarf")
            hit = None
            for s in (_dwarf_subprograms(FULL) or []):
                if s["name"] == "add3":
                    hit = s
                    break
            addr = None
            if hit and dwarf:
                base = dwarf.get("addr_base") or 0
                cand = (hit["low"] - base) if base else hit["low"]
                origins = {f["addr"] for f in expr.list_functions(
                    recdesc.descend(FULL))}
                if cand in origins:
                    addr = cand
                elif hit["low"] in origins:
                    addr = hit["low"]
            if addr is None:
                addr, _ = _first_func(FULL)
            reports["full"] = FR.build(FULL, addr)
        except Exception as e:
            _add("full-build", "报告构建", "FAIL", "%s: %s" % (type(e).__name__, e))
    else:
        _add("full-build", "报告构建", "SKIP", "样本不存在（先跑 make_funcreport_full.py）")

    if os.path.exists(GO):
        reports["go"] = FR.build(GO, 0x401320)
    else:
        _add("go-build", "报告构建", "SKIP", "样本不存在: %s" % GO)

    scarce_addr = None
    if os.path.exists(MINIDLL):
        scarce_addr, _ = _first_func(MINIDLL)
        if scarce_addr is None:
            _add("scarce-build", "报告构建", "SKIP", "minidll 无已解出函数")
        else:
            reports["scarce"] = FR.build(MINIDLL, scarce_addr)
    else:
        _add("scarce-build", "报告构建", "SKIP", "样本不存在: %s" % MINIDLL)

    for tag, path in (("full", FULL), ("go", GO), ("scarce", MINIDLL)):
        rep = reports.get(tag)
        if rep is None:
            continue
        _check_matrix(tag, rep)
        insns = _objdump(path)
        if insns is None:
            _add("%s-objdump" % tag, "objdump 指令表", "SKIP", "objdump 失败")
        else:
            _check_objdump_basics(tag, path, rep, insns)
            if tag == "go":
                _check_go_upper(rep, insns)

    if "full" in reports:
        _check_full_size(reports["full"])
        _check_full_params(reports["full"])
    if "scarce" in reports:
        _check_scarce_f(reports["scarce"])

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    payload = {
        "schema": 1,
        "status": "fail" if failed else "pass",
        "checks": CHECKS,
        "reports": {k: {"status": v["status"],
                        "function": v["function"],
                        "sections": _report_states(v),
                        "layer_errors": v["layer_errors"]}
                    for k, v in reports.items()},
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    n_fail = len(failed)
    n_skip = sum(1 for c in CHECKS if c["status"] == "SKIP")
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=%d  → %s"
          % (len(CHECKS), len(CHECKS) - n_fail - n_skip, n_fail, n_skip,
             "FAIL" if n_fail else "PASS"))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(selftest() if "--selftest" in sys.argv[1:] else main())
