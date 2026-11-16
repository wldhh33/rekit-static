#!/usr/bin/env python3
# tests/verify_dotnet.py — M17 .NET 结构层外部独立重算
#
# 期望值全部来自独立来源，不取自被测实现：
#   (a) dnfile（第三方独立元数据解析器）逐表行数、TypeDef/MethodDef 逐行字段；
#   (b) dnfile.get_offset_from_rva 独立换算 RVA→文件偏移，与方法体头/代码区对账；
#   (c) dncil（独立 opcode 表/解码器）逐方法给出 (offset,size,opcode)，与
#       rekit.dotnet 的 IL 边界逐条比对（偏移基准差 body 头长度，做归一化）；
#   (d) CLR 反射（PowerShell Assembly.LoadFrom）核对受控样本的类型名、每类型
#       方法名与 GetILAsByteArray().Length —— 与 rekit 的解析完全无关；
#   (e) 可失败自证：偏移 +1 / 删指令 / 未知 opcode 的字节改动 / RVA 漂移，
#       检查器必须判 FAIL；干净输入必须判 PASS；
#   (f) funcreport 对 .NET 文件必须 not_applicable 且有 absence 覆盖（不是静默空）。
#
# 样本：受控 csc 编译样本（samples/m17/_gen/RekitSample.dll）、
#       真实 Framework mscorlib.dll、真实 CoreCLR System.Console.dll。
# 工具缺失 → SKIP（不算 PASS）；任何 FAIL → 退出 1。
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import dotnet as DN                     # noqa: E402
from rekit import funcreport as FR                 # noqa: E402

SAMPLE = os.path.join(WORK, "samples", "m17", "_gen", "RekitSample.dll")
CONSOLE = r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\7.0.20\System.Console.dll"
MSCORLIB = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
OUT_JSON = os.path.join(WORK, "evidence_m17_dotnet.json")
IL_LIMIT_REAL = 120          # 真实程序集逐方法 IL 都比对；这里限制数量控制时长

CHECKS = []


def _add(cid, name, status, detail):
    CHECKS.append({"id": cid, "name": name, "status": status,
                   "detail": detail})
    print("[%s] %s %s :: %s" % (status, cid, name, detail))


def _norm_ours(m):
    """本层 IL 偏移相对代码区起点；dncil 相对方法体头。归一化到同一基准。"""
    hdr = (m.get("body") or {}).get("header_size", 0)
    return [(i["offset"] + hdr, i["size"], i["opcode"].lower())
            for i in m["il"]["instructions"]]


def _norm_dncil(body):
    return [(i.offset, i.size, i.opcode.name.lower())
            for i in body.instructions]


def _compare_il(ours, ref):
    """严格逐条比对；返回 (ok, detail)。不截断、不跳过。"""
    if len(ours) != len(ref):
        return False, "指令数不同：本层=%d dncil=%d（首差：%r vs %r）" % (
            len(ours), len(ref),
            next((o for o, r in zip(ours, ref) if o != r), None),
            next((r for o, r in zip(ours, ref) if o != r), None))
    for i, (o, r) in enumerate(zip(ours, ref)):
        if o != r:
            return False, "第 %d 条不同：本层=%r dncil=%r" % (i, o, r)
    return True, "逐条一致（%d 条）" % len(ours)


def _dncil_body(data, pe, rva, slice_bytes=0x40000):
    from dncil.cil.body.reader import read_method_body_from_bytes
    off = pe.get_offset_from_rva(rva)
    return read_method_body_from_bytes(data[off:off + slice_bytes])


DN_ALIAS = {"FieldRVA": "FieldRva"}
DN_UNSUPPORTED = {"FieldRVA", "ENCLog", "ENCMap"}


def _dnfile_counts(md):
    """返回 (counts, unsupported)。dnfile 不实现的表不计入强比对。"""
    out, unsupported = {}, set()
    for name in DN.TABLE_NAMES.values():
        attr = DN_ALIAS.get(name, name)
        t = getattr(md, attr, None)
        if t is None or not hasattr(t, "rows") or t.rows is None:
            unsupported.add(name)
            continue
        out[name] = len(t.rows)
    return out, unsupported


def _check_tables(tag, rep, got):
    counts, unsupported = got
    bad = []
    for name, n in rep["tables"]["row_counts"].items():
        if name in unsupported:
            continue
        if counts.get(name, 0) != n:
            bad.append("%s：本层=%d dnfile=%d" % (name, n, counts.get(name, 0)))
    for name, n in counts.items():
        if n and name not in rep["tables"]["row_counts"]:
            bad.append("%s：dnfile=%d，本层缺失" % (name, n))
    skipped = sorted(unsupported & set(rep["tables"]["row_counts"]))
    return (not bad), ("表行数核对 %d 张%s；%s"
                       % (len(rep["tables"]["row_counts"]) - len(skipped),
                          ("（dnfile 不解析 %s）" % "/".join(skipped))
                          if skipped else "",
                          "全部一致" if not bad else "; ".join(bad[:5])))


def _check_typedefs(rep, md):
    rows = md.TypeDef.rows
    if len(rows) != len(rep["types"]):
        return False, "TypeDef 行数不同：本层=%d dnfile=%d" % (
            len(rep["types"]), len(rows))
    bad = []
    for t, r in zip(rep["types"], rows):
        nm, ns = str(r.TypeName), str(r.TypeNamespace)
        if (t["name"], t["namespace"], t["flags"]) != \
                (nm, ns, r.struct.Flags):
            bad.append("row %d：本层=%r dnfile=%r"
                       % (t["row"], (t["namespace"], t["name"], t["flags"]),
                          (ns, nm, r.struct.Flags)))
            continue
        idxs = []
        for x in (r.MethodList or []):
            idxs.append(getattr(x, "row_index", None)
                        if not isinstance(x, int) else x)
        if None in idxs:
            bad.append("row %d：dnfile MethodList 索引不可读" % t["row"])
            continue
        want = list(range(t["method_range"][0], t["method_range"][1])) \
            if t["method_range"] else []
        if [i for i in idxs] != want:
            bad.append("row %d：方法区间 本层=%r dnfile=%r"
                       % (t["row"], want, idxs))
    return (not bad), ("TypeDef 逐行核对 %d 行；%s"
                       % (len(rows), "全部一致" if not bad
                          else "; ".join(bad[:5])))


def _check_methoddefs(rep, md):
    rows = md.MethodDef.rows
    if len(rows) != len(rep["methods"]):
        return False, "MethodDef 行数不同：本层=%d dnfile=%d" % (
            len(rep["methods"]), len(rows))
    bad = []
    for m, r in zip(rep["methods"], rows):
        if (m["rva"], m["impl_flags"], m["flags"], m["name"]) != \
                (r.struct.Rva, r.struct.ImplFlags, r.struct.Flags,
                 str(r.Name)):
            bad.append("row %d：本层=%r dnfile=%r"
                       % (m["row"], (m["rva"], m["impl_flags"], m["flags"],
                                     m["name"]),
                          (r.struct.Rva, r.struct.ImplFlags, r.struct.Flags,
                           str(r.Name))))
            if len(bad) > 5:
                break
    return (not bad), ("MethodDef 逐行核对 %d 行；%s"
                       % (len(rows), "全部一致" if not bad
                          else "; ".join(bad[:5])))


def _check_offsets(rep, pe):
    bad, checked = [], 0
    for m in rep["methods"]:
        if not m.get("body"):
            continue
        checked += 1
        try:
            off = pe.get_offset_from_rva(m["rva"])
        except Exception as e:
            bad.append("%s：dnfile 换算失败 %s" % (m["token"], e))
            continue
        if off != m["body"]["header_off"]:
            bad.append("%s：本层=0x%x dnfile=0x%x"
                       % (m["token"], m["body"]["header_off"], off))
    return (not bad), ("方法体文件偏移核对 %d 个；%s"
                       % (checked, "全部一致" if not bad
                          else "; ".join(bad[:5]))), checked


def _check_il(rep, data, pe, limit, tag):
    total, bad, skipped = 0, [], 0
    for m in rep["methods"]:
        if not (m.get("body") and m["body_status"] == "ok"):
            continue
        if limit is not None and total >= limit:
            break
        total += 1
        try:
            body = _dncil_body(data, pe, m["rva"])
        except Exception as e:
            skipped += 1
            bad.append("%s：dncil 读取失败 %s: %s"
                       % (m["token"], type(e).__name__, e))
            continue
        if body.code_size != m["body"]["code_size"]:
            bad.append("%s：code_size 本层=%d dncil=%d"
                       % (m["token"], m["body"]["code_size"], body.code_size))
        ok, detail = _compare_il(_norm_ours(m), _norm_dncil(body))
        if not ok:
            bad.append("%s %s：%s" % (m["token"], m["name"], detail))
        if len(bad) > 5:
            break
    return (not bad), ("IL 边界逐条核对 %d 个方法（%s）；%s"
                       % (total, tag, "全部一致" if not bad
                          else "; ".join(bad[:5]))), total


def _reflection(path):
    ps = (
        "$ErrorActionPreference='Stop';"
        "$a=[Reflection.Assembly]::LoadFrom('%s');"
        "$f=[Reflection.BindingFlags]::Public -bor "
        "[Reflection.BindingFlags]::NonPublic -bor "
        "[Reflection.BindingFlags]::Static -bor "
        "[Reflection.BindingFlags]::Instance -bor "
        "[Reflection.BindingFlags]::DeclaredOnly;"
        "$o=@(); foreach($t in $a.GetTypes()){ $ms=@(); "
        "foreach($m in $t.GetMethods($f)){ $b=$m.GetMethodBody(); "
        "$len= -1; if($null -ne $b){ $len=$b.GetILAsByteArray().Length }; "
        "$ms += [pscustomobject]@{name=$m.Name; il=$len} }; "
        "$o += [pscustomobject]@{type=$t.FullName; methods=$ms} }; "
        "ConvertTo-Json -Compress -Depth 6 $o" % path.replace("'", "''"))
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-Command", ps], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=120)
    if r.returncode != 0:
        return None, (r.stderr or r.stdout or "powershell 失败").strip()[:300]
    try:
        obj = json.loads(r.stdout)
    except Exception as e:
        return None, "反射输出不是 JSON：%s" % e
    if isinstance(obj, dict):
        obj = [obj]
    return obj, None


def _check_reflection(rep, reflected):
    ours = {}
    for t in rep["types"]:
        if t["kind"] == "pseudo_module":
            continue
        full = ((t["namespace"] + ".") if t["namespace"] else "") + t["name"]
        ours[full] = t
    ref = {x["type"]: x["methods"] for x in reflected}
    if set(ours) != set(ref):
        return False, "类型名集合不同：本层多 %r；反射多 %r" % (
            sorted(set(ours) - set(ref)), sorted(set(ref) - set(ours)))
    bad, ctors = [], 0
    for full, t in ours.items():
        want = {}
        for m in rep["methods"]:
            if m["owner_row"] != t["row"]:
                continue
            if m["name"] in (".ctor", ".cctor"):
                ctors += 1
                continue
            want.setdefault(m["name"], []).append(
                m["body"]["code_size"] if m["body"] and
                m["body_status"] == "ok" else -1)
        got = {}
        for x in ref[full]:
            got.setdefault(x["name"], []).append(x["il"])
        for k in got:
            got[k].sort()
        for k in want:
            want[k].sort()
        if got != want:
            bad.append("%s：本层=%r 反射=%r" % (full, want, got))
    if ctors == 0:
        bad.append("受控样本应含 4 个构造方法（.ctor/.cctor），本层一个也没排除到")
    return (not bad), ("反射核对 %d 个类型、排除构造方法 %d 个；%s"
                       % (len(ours), ctors, "全部一致" if not bad
                          else "; ".join(bad[:3])))


def _check_us(rep, pe, exact):
    """用 dnfile 的 #US 读取器独立核对每个堆条目与 ldstr token。"""
    items = rep["strings_us"]["items"]
    bad = []
    for it in items:
        u = pe.net.user_strings.get(it["offset"])
        if u is None:
            bad.append("offset 0x%x：dnfile 读不到" % it["offset"])
        elif u.value != it["text"]:
            bad.append("offset 0x%x：本层=%r dnfile=%r"
                       % (it["offset"], it["text"], u.value))
        if len(bad) >= 5:
            break
    toks, texts = set(), set()
    for m in rep["methods"]:
        for ins in (m["il"]["instructions"] or []):
            if ins["opcode"] == "ldstr" and ins["operand_hex"]:
                t = int.from_bytes(bytes.fromhex(ins["operand_hex"])[:4],
                                   "little")
                toks.add(t)
                u = pe.net.user_strings.get(t & 0xFFFFFF)
                if u is not None:
                    texts.add(u.value)
    known_offsets = {it["offset"] for it in items}
    miss = [("0x%08x" % t) for t in toks if (t & 0xFFFFFF) not in known_offsets]
    if miss:
        bad.append("ldstr 指向未知 #US 偏移：%r" % miss[:3])
    if exact:
        non_empty = {it["text"] for it in items if it["text"]}
        if texts != non_empty:
            bad.append("受控样本应每个字面量都被 ldstr 引用；差集=%r"
                       % sorted(texts ^ non_empty)[:3])
    ok = not bad
    return ok, ("#US 条目 %d（dnfile 逐个取值核对）；ldstr token %d 个；%s"
                % (len(items), len(toks),
                   "全部一致" if ok else "; ".join(bad[:3])))


def main():
    try:
        import dnfile
        import dncil  # noqa: F401
    except Exception as e:
        print("SKIP: 缺少 dnfile/dncil（%s）" % e)
        return 0
    import logging
    logging.disable(logging.CRITICAL)

    reports = {}

    def run_sample(tag, path, il_limit):
        if not os.path.exists(path):
            _add("%s-tables" % tag, "dnfile 表行数", "SKIP", "样本不存在")
            return
        rep = reports[tag] = DN.build(path, detail_methods=None,
                                      detail_insns=None)
        _add("%s-status" % tag, "状态与恒等式",
             "PASS" if (rep["status"] == "ok"
                        and rep["denominators"]["identity_ok"]) else "FAIL",
             "status=%s identity=%s MethodDef=%d 有RVA=%d 无RVA=%d 体成功=%d"
             % (rep["status"], rep["denominators"]["identity_ok"],
                rep["denominators"]["methoddef_rows"],
                rep["denominators"]["methods_with_rva"],
                rep["denominators"]["methods_without_rva"],
                rep["denominators"]["body_ok"]))
        pe = dnfile.dnPE(path)
        md = pe.net.mdtables
        ok, detail = _check_tables(tag, rep, _dnfile_counts(md))
        _add("%s-tables" % tag, "dnfile 表行数", "PASS" if ok else "FAIL",
             detail)
        ok, detail = _check_typedefs(rep, md)
        _add("%s-typedef" % tag, "dnfile TypeDef 逐行",
             "PASS" if ok else "FAIL", detail)
        ok, detail = _check_methoddefs(rep, md)
        _add("%s-methoddef" % tag, "dnfile MethodDef 逐行",
             "PASS" if ok else "FAIL", detail)
        ok, detail, n = _check_offsets(rep, pe)
        _add("%s-offsets" % tag, "dnfile RVA→文件偏移",
             "PASS" if (ok and n > 0) else "FAIL", detail)
        with open(path, "rb") as f:
            data = f.read()
        ok, detail, n = _check_il(rep, data, pe, il_limit, "前 %s 个" % il_limit)
        _add("%s-il" % tag, "dncil IL 边界逐条",
             "PASS" if (ok and n > 0) else "FAIL", detail)
        ok, detail = _check_us(rep, pe, exact=(tag == "sample"))
        _add("%s-us" % tag, "#US 字符串字面量（dnfile）",
             "PASS" if ok else "FAIL", detail)

    # (a)(b)(c) 受控样本：全量
    run_sample("sample", SAMPLE, None)

    # (d) CLR 反射：只对受控样本（系统程序集无法在另一运行时里独立加载）
    if os.path.exists(SAMPLE) and "sample" in reports:
        reflected, err = _reflection(SAMPLE)
        if reflected is None:
            _add("sample-reflect", "CLR 反射核对", "SKIP", err or "反射失败")
        else:
            ok, detail = _check_reflection(reports["sample"], reflected)
            _add("sample-reflect", "CLR 反射核对",
                 "PASS" if ok else "FAIL", detail)

    # 真实样本：表/方法体全量，IL 逐条抽样（时长限制）
    run_sample("console", CONSOLE, IL_LIMIT_REAL)
    run_sample("mscorlib", MSCORLIB, IL_LIMIT_REAL)

    # (e) 可失败自证
    if "sample" in reports:
        rep = reports["sample"]
        m = next(x for x in rep["methods"]
                 if x["body"] and x["body_status"] == "ok"
                 and x["name"] == "Add" and x["owner_row"] == 2)
        pe = dnfile.dnPE(SAMPLE)
        data = open(SAMPLE, "rb").read()
        body = _dncil_body(data, pe, m["rva"])
        ours = _norm_ours(m)
        ref = _norm_dncil(body)
        ok_clean, _ = _compare_il(ours, ref)
        mut = list(ours)
        mut[0] = (mut[0][0] + 1, mut[0][1], mut[0][2])
        ok_shift, _ = _compare_il(mut, ref)
        dropped = ours[:-1]
        ok_drop, _ = _compare_il(dropped, ref)
        _add("selfproof-il", "IL 边界检查器能失败",
             "PASS" if (ok_clean and not ok_shift and not ok_drop) else "FAIL",
             "干净=%s，偏移+1=%s，删一条=%s（期望 True/False/False）"
             % (ok_clean, ok_shift, ok_drop))

        code = data[m["body"]["code_off"]:
                    m["body"]["code_off"] + m["body"]["code_size"]]
        clean_ins, clean_err = DN._decode_il(code)
        bad_code = bytearray(code)
        bad_code[-1] = 0xFF
        bad_ins, bad_err = DN._decode_il(bytes(bad_code))
        _add("selfproof-opcode", "未知 opcode 必须报不可解",
             "PASS" if (clean_err is None and bad_err is not None
                        and bad_err["reason"] == "unknown_opcode"
                        and bad_err["offset"] == len(code) - 1) else "FAIL",
             "干净 err=%r；末字节改 0xFF 后 err=%r（期望 unknown_opcode@%d）"
             % (clean_err, bad_err, len(code) - 1))

        off_clean = (m["body"]["header_off"] == pe.get_offset_from_rva(m["rva"]))
        off_bad = ((m["body"]["header_off"] + 1)
                   == pe.get_offset_from_rva(m["rva"]))
        _add("selfproof-offset", "方法体偏移检查器能失败",
             "PASS" if (off_clean and not off_bad) else "FAIL",
             "干净=%s，偏移+1=%s（期望 True/False）" % (off_clean, off_bad))

        counts = _dnfile_counts(dnfile.dnPE(SAMPLE).net.mdtables)
        ok_clean, _ = _check_tables("sample", rep, counts)
        tweaked_counts, tweaked_unsup = counts
        tweaked = dict(tweaked_counts)
        tweaked["MethodDef"] = tweaked["MethodDef"] + 1
        ok_bad, _ = _check_tables("sample", rep, (tweaked, tweaked_unsup))
        _add("selfproof-tables", "表行数检查器能失败",
             "PASS" if (ok_clean and not ok_bad) else "FAIL",
             "干净=%s，MethodDef+1=%s（期望 True/False）"
             % (ok_clean, ok_bad))

    # (f) funcreport 显式 not_applicable
    if os.path.exists(SAMPLE):
        fr = FR.build(SAMPLE, 0x06000002)
        states = {k: v["evidence_state"] for k, v in fr["sections"].items()}
        cover = {(r["section"], r["field"]) for r in fr["absence_summary"]}
        need = {("identity", "function"), ("boundary", "end"),
                ("strings_and_data", "data_refs")}
        ok = (fr["status"] == "not_applicable"
              and all(s != "present" for s in states.values())
              and need.issubset(cover)
              and fr["sections"]["identity"].get("reason"))
        _add("funcreport-na", "funcreport 对 .NET 显式 not_applicable",
             "PASS" if ok else "FAIL",
             "status=%s 全节非present=%s absence 覆盖 %d 行；reason=%r"
             % (fr["status"], all(s != "present" for s in states.values()),
                len(cover),
                (fr["sections"]["identity"].get("reason") or "")[:60]))

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    payload = {"schema": 1, "status": "fail" if failed else "pass",
               "checks": CHECKS,
               "denominators": {k: v["denominators"]
                                for k, v in reports.items()},
               "tables": {k: v["tables"]["row_counts"]
                          for k, v in reports.items()}}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    n_fail = len(failed)
    n_skip = sum(1 for c in CHECKS if c["status"] == "SKIP")
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=%d → %s"
          % (len(CHECKS), len(CHECKS) - n_fail - n_skip, n_fail, n_skip,
             "FAIL" if n_fail else "PASS"))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
