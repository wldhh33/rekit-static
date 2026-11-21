#!/usr/bin/env python3
# tests/verify_datarefs.py — M16 数据引用层外部抽查（readelf / objdump 独立重算）
#
# 期望值全部来自外部工具，不取自被测实现：
#   (a) 对象表：ELF 用 readelf -sW 重算 OBJECT 符号（st_value/st_size/节），
#       逐个与 datarefs.objects 对账；带尺寸的 OBJECT 符号不得凭空消失；
#       PE 用 objdump --dwarf=info 重算 DW_TAG_variable 的 DW_OP_addr 与
#       类型链尺寸（byte_size / array count），与对象表对账。
#   (b) 引用点：objdump -d 的 `# 目标` 注释是 objdump 自己算的算术结果，
#       与 datarefs 的 rip_mem/lea_rip target 逐点比对。
#   (c) 指针槽：objdump -s 的原始字节按指针宽解包，减去 ImageBase 后与
#       pointer_edges / pointer_values_inside 比对。
#   (d) 可失败自证：把期望目标 +4、把一条声明对象从外部集合删掉，检查器
#       必须判 FAIL；干净输入必须判 PASS。
#   (e) 三类样本（full / go / scarce）的 funcreport.sections.strings_and_data
#       .data_refs.evidence_state 与 absence_summary 覆盖。
#
# 任何一项 FAIL → 退出 1；样本/工具缺失 → SKIP（不算 PASS）。
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

from rekit import datarefs as DR             # noqa: E402
from rekit import expr                       # noqa: E402
from rekit import funcreport as FR           # noqa: E402
from rekit import recdesc                    # noqa: E402

FIX = os.path.join(HERE, "m16_fixtures", "datarefs_full.exe")
DYN = os.path.join(HERE, "fixtures", "dyn_static")
MINIDLL = os.path.join(HERE, "fixtures", "minidll.dll")
FULL = os.path.join(HERE, "m15_fixtures", "funcreport_full")
GO = os.path.join(WORK, "samples", "m9", "elf_medium_synth_go_stripped")
OUT_JSON = os.path.join(WORK, "evidence_m16_datarefs.json")

CHECKS = []
_TMP = tempfile.mkdtemp(prefix="rekit_m16_verify_")


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
                          timeout=300)


def _ascii_copy(path):
    """objdump/readelf 对非 ASCII 路径不可靠：复制到 ASCII 临时目录。"""
    dst = os.path.join(_TMP, re.sub(r"[^A-Za-z0-9_.-]", "_",
                                    os.path.basename(path)))
    shutil.copyfile(path, dst)
    return dst


# ── ELF：readelf 独立对象表 ─────────────────────────────────────────
def _elf_sections(path):
    r = _run(["readelf", "-SW", path])
    if r.returncode != 0:
        return None
    secs = {}
    for line in r.stdout.splitlines():
        m = re.match(r"\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+"
                     r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
                     r"([A-Za-z]*)\s+\S+\s+\S+\s+\S+\s*$", line)
        if m:
            secs[int(m.group(1))] = {
                "name": m.group(2), "type": m.group(3),
                "addr": int(m.group(4), 16), "size": int(m.group(6), 16),
                "flags": m.group(8),
            }
    return secs or None


def _elf_object_symbols(path):
    secs = _elf_sections(path)
    if secs is None:
        return None
    r = _run(["readelf", "-sW", path])
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        m = re.match(r"\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(OBJECT|TLS)\s+"
                     r"(\S+)\s+(\S+)\s+(\S+)\s*(.*)$", line)
        if not m:
            continue
        value, size, typ, _bind, _vis, ndx, name = m.groups()
        if typ != "OBJECT" or not ndx.isdigit():
            continue
        sec = secs.get(int(ndx))
        if sec is None or sec["type"] == "TLS":
            continue
        if "A" not in sec["flags"] or "X" in sec["flags"]:
            continue
        if sec["name"].startswith(".debug"):
            continue
        out.append({"name": name.strip(), "value": int(value, 16),
                    "size": int(size), "section": sec["name"],
                    "flags": sec["flags"]})
    return out


def _check_elf_objects(tag, rep, syms):
    """(a) 逐条对账 + 不凭空消失。返回 (ok, detail)。失败时 detail 列证据。"""
    objs = {o["start"]: o for o in rep["objects"]}
    by_tier = {o["tier"] for o in rep["objects"]}
    bad, ok_n, dup_n = [], 0, 0
    for s in syms:
        if s["size"] == 0 or s["size"] < DR.MIN_SIZE:
            continue                       # 已声明的拒收类（size_zero/too_small）
        if "T" in (s.get("flags") or ""):
            continue                       # TLS 节
        start = s["value"]
        o = objs.get(start)
        if o is not None:
            if o["name"] == s["name"] and o["size"] != s["size"]:
                bad.append("%s 尺寸不符：readelf=%d 对象=%d"
                           % (s["name"], s["size"], o["size"]))
                continue
            ok_n += 1
            continue
        inside = next((x for x in rep["objects"]
                       if x["start"] < start < x["end"]), None)
        if inside is not None:
            ok_n += 1                      # overlaps_object / duplicate
            dup_n += 1
            continue
        if (s["size"] >= 8 and start % 8) or (
                DR.MIN_SIZE <= s["size"] < 8 and start % 4):
            continue                       # misaligned_start（已声明拒收）
        bad.append("%s@0x%x size=%d 未出现在对象表且无声明拒收"
                   % (s["name"], start, s["size"]))
    # 反方向：对象表里的 symbol 级对象必须有 readelf 依据
    sym_starts = {s["value"] for s in syms}
    for o in rep["objects"]:
        if o["tier"] == "declared_symbol" and o["start"] not in sym_starts:
            bad.append("对象 %s@0x%x 无 readelf 符号依据" % (o["name"], o["start"]))
    detail = ("对账 %d 条符号对象（其中 %d 条落在更大对象内部）；对象表 tier=%s；%s"
              % (ok_n, dup_n, ",".join(sorted(by_tier)),
                 "无不一致" if not bad else "; ".join(bad[:5])))
    return (not bad), detail


# ── PE：objdump --dwarf=info 独立对象表 ─────────────────────────────
_DIE_RE = re.compile(r"<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ "
                     r"\((DW_TAG_\w+)\)")
_ATTR_RE = {
    "name": re.compile(r"DW_AT_name\s*:\s*(?:\([^)]*\):\s*)?([^\n]+)"),
    "byte_size": re.compile(r"DW_AT_byte_size\s*:\s*(\d+)"),
    "type": re.compile(r"DW_AT_type\s*:\s*<0x([0-9a-f]+)>"),
    "count": re.compile(r"DW_AT_count\s*:\s*(\d+)"),
    "upper": re.compile(r"DW_AT_upper_bound\s*:\s*(\d+)"),
    "lower": re.compile(r"DW_AT_lower_bound\s*:\s*(-?\d+)"),
    "location": re.compile(r"DW_OP_addr:\s*([0-9a-fA-F]+)"),
}


def _dwarf_dies(path):
    r = _run(["objdump", "--dwarf=info", path])
    if r.returncode != 0:
        return None
    text = r.stdout
    hits = list(_DIE_RE.finditer(text))
    dies = {}
    kids = {}
    for i, m in enumerate(hits):
        lvl, off, tag = int(m.group(1)), int(m.group(2), 16), m.group(3)
        end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
        body = text[m.end():end]
        attrs = {}
        for key, rx in _ATTR_RE.items():
            mm = rx.search(body)
            if mm:
                attrs[key] = mm.group(1).strip()
        dies[off] = {"level": lvl, "tag": tag, "attrs": attrs}
    for off, d in dies.items():
        kids.setdefault(d["level"], [])
        d["parent"] = None
    # 父链：同级后出现的 DIE 的父是前面最近的更低 level
    order = sorted(dies, key=lambda o: o)
    stack = []
    for off in order:
        d = dies[off]
        while stack and dies[stack[-1]]["level"] >= d["level"]:
            stack.pop()
        if stack:
            d["parent"] = stack[-1]
            kids.setdefault(stack[-1], []).append(off)
        stack.append(off)
    return dies, kids


def _dwarf_size(off, dies, kids, depth=0):
    if off is None or off not in dies or depth > 16:
        return None
    d = dies[off]
    tag = d["tag"]
    if tag in ("DW_TAG_base_type", "DW_TAG_structure_type",
               "DW_TAG_union_type", "DW_TAG_enumeration_type",
               "DW_TAG_unspecified_type"):
        bs = d["attrs"].get("byte_size")
        return int(bs) if bs else None
    if tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type",
               "DW_TAG_rvalue_reference_type"):
        return 8
    if tag == "DW_TAG_array_type":
        t = d["attrs"].get("type")
        esz = _dwarf_size(int(t, 16) if t else None, dies, kids, depth + 1)
        if esz is None:
            return None
        total = 0
        for kid in kids.get(off) or []:
            if dies[kid]["tag"] != "DW_TAG_subrange_type":
                continue
            a = dies[kid]["attrs"]
            if "count" in a:
                n = int(a["count"])
            elif "upper" in a:
                lo = int(a.get("lower", "0"))
                n = int(a["upper"]) - lo + 1
            else:
                return None
            total += n
        return esz * total if total else None
    t = d["attrs"].get("type")
    if t:
        return _dwarf_size(int(t, 16), dies, kids, depth + 1)
    bs = d["attrs"].get("byte_size")
    return int(bs) if bs else None


def _pe_dwarf_vars(path):
    got = _dwarf_dies(path)
    if got is None:
        return None
    dies, kids = got
    out = []
    for off, d in dies.items():
        if d["tag"] != "DW_TAG_variable":
            continue
        loc = d["attrs"].get("location")
        if loc is None:
            continue
        t = d["attrs"].get("type")
        out.append({
            "name": d["attrs"].get("name"),
            "addr": int(loc, 16),
            "size": _dwarf_size(int(t, 16) if t else None, dies, kids),
        })
    return out


def _image_base(path):
    r = _run(["objdump", "-p", path])
    m = re.search(r"ImageBase\s+([0-9a-fA-F]+)", r.stdout)
    return int(m.group(1), 16) if m else None


def _check_pe_objects(tag, rep, dvs, base):
    if dvs is None or base is None:
        return None, "objdump --dwarf=info / -p 不可用"
    objs = {o["start"]: o for o in rep["objects"]}
    bad, ok_n = [], 0
    for v in dvs:
        start = v["addr"] - base if v["addr"] >= base else v["addr"]
        o = objs.get(start)
        if o is None:
            bad.append("DWARF 变量 %s@0x%x 未出现在对象表" % (v["name"], start))
            continue
        if v["size"] is not None and o["size"] != v["size"]:
            bad.append("%s 尺寸不符：objdump DWARF=%s 对象=%d"
                       % (v["name"], v["size"], o["size"]))
            continue
        ok_n += 1
    # 反方向：声明来源必须能追溯到外部工具
    names = {v["name"] for v in dvs}
    for o in rep["objects"]:
        if o["tier"] == "declared_dwarf" and o["name"] not in names:
            bad.append("对象 %s 无 objdump DWARF 依据" % o["name"])
    return (not bad), ("对账 %d 条 DWARF 变量；%s"
                       % (ok_n, "无不一致" if not bad else "; ".join(bad[:5])))


# ── 引用点：objdump -d 注释 ─────────────────────────────────────────
_DIS_RE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S.*)?$")
_HASH_RE = re.compile(r"#\s*([0-9a-f]+)")


def _objdump_targets(path):
    r = _run(["objdump", "-d", path])
    if r.returncode != 0:
        return None
    out = {}
    for line in r.stdout.splitlines():
        m = _DIS_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        tgt = _HASH_RE.search(line)
        if tgt:
            out[addr] = int(tgt.group(1), 16)
    return out


def _site_rows(rep, base):
    rows = []
    for s in rep["sites"]:
        if s["form"] not in ("rip_mem", "lea_rip") or s["target"] is None:
            continue
        rows.append((s["addr"] + (base or 0), s["target"] + (base or 0),
                     s["form"], s["mnem"]))
    return rows


def _check_site_targets(tag, path, rep, base, shift=0):
    ext = _objdump_targets(path)
    if ext is None:
        return None, "objdump -d 失败"
    rows = _site_rows(rep, base)
    bad, checked = [], 0
    for addr, target, form, mnem in rows:
        if addr not in ext:
            continue
        checked += 1
        if ext[addr] != target + shift:
            bad.append("0x%x %s：本层=0x%x objdump=0x%x"
                       % (addr, mnem, target + shift, ext[addr]))
    return (not bad), ("核对 %d/%d 个 rip 引用点；%s"
                       % (checked, len(rows),
                          "全部一致" if not bad else "; ".join(bad[:5])))


# ── 指针槽：objdump -s 原始字节 ─────────────────────────────────────
def _section_bytes(path, secname):
    r = _run(["objdump", "-s", "-j", secname, path])
    if r.returncode != 0:
        return None
    data = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s+((?:[0-9a-f]{2,8}\s+)+)", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        for i, b in enumerate(raw):
            data[addr + i] = b
    return data or None


def _check_pointer_slots(tag, path, rep, base):
    secs = {s["name"]: s for s in rep["sections"]}
    bad, checked = [], 0
    for e in rep["pointer_edges"] + rep["pointer_values_inside"]:
        o = next((x for x in rep["objects"]
                  if x["start"] <= e["from"] < x["end"]), None)
        if o is None:
            continue
        sec = secs.get(o["section"])
        if sec is None or sec["nobits"]:
            continue
        raw = _section_bytes(path, sec["name"])
        if raw is None:
            continue
        w = e.get("width") or 8
        start = e["from"] + (base or 0)
        blob = bytes(raw.get(start + i, 0) for i in range(w))
        val = int.from_bytes(blob, "little")
        if base and val >= base:
            val -= base
        checked += 1
        if val != e["to"]:
            bad.append("槽 0x%x：本层=0x%x objdump -s=0x%x"
                       % (e["from"], e["to"], val))
    return (not bad), ("核对 %d 个指针槽；%s"
                       % (checked, "全部一致" if not bad else "; ".join(bad[:5]))), checked


# ── 三类样本的 funcreport data_refs 状态 ────────────────────────────
def _first_func_addr(path):
    res = recdesc.descend(path)
    fs = expr.list_functions(res)
    return (fs[0]["addr"] if fs else None)


def _check_sample_state(tag, rep, allowed):
    dr = rep["sections"]["strings_and_data"]["data_refs"]
    st = dr["evidence_state"]
    rows = {(r["section"], r["field"]) for r in rep["absence_summary"]}
    covered = ("strings_and_data", "data_refs") in rows
    ok = st in allowed and (st == "present" or covered)
    detail = ("data_refs=%s（允许 %s）；absence 覆盖=%s；缺证据=%r；层错误=%s"
              % (st, "/".join(sorted(allowed)), covered, dr.get("reason"),
                 rep.get("layer_errors") or "无"))
    return ok, detail


def main():
    for tool in ("objdump", "readelf"):
        if shutil.which(tool) is None:
            print("SKIP: PATH 中没有 %s（先加入 GNU binutils 的 bin 目录）" % tool)
            return 0
    reports = {}
    tmp_dyn = _ascii_copy(DYN)
    tmp_fix = _ascii_copy(FIX)
    tmp_full = _ascii_copy(FULL)
    tmp_go = _ascii_copy(GO)
    tmp_min = _ascii_copy(MINIDLL)

    # (a1) ELF 对象表
    if os.path.exists(DYN):
        rep = reports["dyn"] = DR.build(DYN)
        syms = _elf_object_symbols(tmp_dyn)
        if syms is None:
            _add("dyn-a", "readelf 对象表", "SKIP", "readelf 失败")
        else:
            ok, detail = _check_elf_objects("dyn", rep, syms)
            _add("dyn-a", "readelf 对象表对账",
                 "PASS" if ok else "FAIL", detail)
        _add("dyn-identity", "分母恒等式",
             "PASS" if rep["denominator"]["identity_ok"] else "FAIL",
             "declared=%d accepted=%d rejected=%d dups=%d"
             % (rep["denominator"]["declared_candidates"],
                rep["denominator"]["accepted"],
                rep["denominator"]["rejected_total"],
                rep["denominator"]["duplicates"]))
        fmt = rep["denominator"]["format_rejections"]
        _add("dyn-fmt", "ELF 无格式层拒收",
             "PASS" if fmt == {"coff_symbols": 0, "export_table": 0}
             else "FAIL", json.dumps(fmt))

    # (a2) PE 对象表（DWARF 类型链）
    if os.path.exists(FIX):
        pe = reports["fix"] = DR.build(FIX)
        dvs = _pe_dwarf_vars(tmp_fix)
        base = _image_base(tmp_fix)
        ok, detail = _check_pe_objects("fix", pe, dvs, base)
        if ok is None:
            _add("fix-a", "objdump DWARF 对象表", "SKIP", detail)
        else:
            _add("fix-a", "objdump DWARF 对象表对账",
                 "PASS" if ok else "FAIL", detail)

        # (b) 引用点
        ok, detail = _check_site_targets("fix", tmp_fix, pe, base)
        if ok is None:
            _add("fix-b", "objdump 引用点目标", "SKIP", detail)
        else:
            _add("fix-b", "objdump 引用点目标",
                 "PASS" if ok else "FAIL", detail)
        # (c) 指针槽
        got = _check_pointer_slots("fix", tmp_fix, pe, base)
        ok, detail, n_slots = got
        if ok is None:
            _add("fix-c", "objdump -s 指针槽", "SKIP", detail)
        else:
            _add("fix-c", "objdump -s 指针槽",
                 "PASS" if (ok and n_slots > 0) else "FAIL",
                 detail if n_slots else detail + "（0 个槽=没有真正核对）")

        # (d) 可失败自证
        ok_clean, _ = _check_site_targets("fix", tmp_fix, pe, base)
        ok_shift, _ = _check_site_targets("fix", tmp_fix, pe, base, shift=4)
        _add("selfproof-sites", "引用点检查器能失败",
             "PASS" if (ok_clean and not ok_shift) else "FAIL",
             "干净输入=%s，目标+4=%s（期望 True/False）"
             % (ok_clean, ok_shift))
        if dvs:
            dropped = [v for v in dvs if v["name"] == "g_table"]
            ok_clean2, _ = _check_pe_objects("fix", pe, dvs, base)
            ok_drop, _ = _check_pe_objects("fix", pe,
                                           [v for v in dvs
                                            if v["name"] != "g_table"], base)
            _add("selfproof-objects", "对象表检查器能失败",
                 "PASS" if (ok_clean2 and not ok_drop) else "FAIL",
                 "完整声明=%s，删掉 g_table=%s（期望 True/False）"
                 % (ok_clean2, ok_drop))

    # (b2) ELF 引用点
    if os.path.exists(DYN):
        ok, detail = _check_site_targets("dyn", tmp_dyn, reports["dyn"], None)
        if ok is None:
            _add("dyn-b", "objdump 引用点目标", "SKIP", detail)
        else:
            _add("dyn-b", "objdump 引用点目标",
                 "PASS" if ok else "FAIL", detail)

    # (e) 三类样本状态
    samples = []
    if os.path.exists(FULL):
        addr = _first_func_addr(FULL)
        if addr is not None:
            samples.append(("full", FR.build(FULL, addr),
                            {"absent_measured"}))
    if os.path.exists(GO):
        samples.append(("go", FR.build(GO, 0x401320), {"missing_source"}))
    if os.path.exists(MINIDLL):
        addr = _first_func_addr(MINIDLL)
        if addr is not None:
            samples.append(("scarce", FR.build(MINIDLL, addr),
                            {"missing_source"}))
    if not samples:
        _add("samples", "三类样本", "SKIP", "样本不存在")
    for tag, rep, allowed in samples:
        ok, detail = _check_sample_state(tag, rep, allowed)
        _add("%s-e" % tag, "data_refs 状态", "PASS" if ok else "FAIL", detail)

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    payload = {
        "schema": 1,
        "status": "fail" if failed else "pass",
        "checks": CHECKS,
        "denominators": {k: v["denominator"] for k, v in reports.items()},
        "sample_states": {tag: (rep["sections"]["strings_and_data"]
                                ["data_refs"]["evidence_state"])
                          for tag, rep, _a in samples},
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    n_fail = len(failed)
    n_skip = sum(1 for c in CHECKS if c["status"] == "SKIP")
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=%d → %s"
          % (len(CHECKS), len(CHECKS) - n_fail - n_skip, n_fail, n_skip,
             "FAIL" if n_fail else "PASS"))
    shutil.rmtree(_TMP, ignore_errors=True)
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
