#!/usr/bin/env python3
# tests/verify_layout.py — M20 .NET 类型布局与字段 RVA 外部独立对拍
#
# 期望值全部来自独立来源，不取自被测实现：
#   (a) 源码即真值：受控 IL / C# 源文件里写明的 `.pack`/`.size`/`.field [N]`/
#       `.data`/`[FieldOffset]`/`[StructLayout]`/数组初始化器，按声明解析成
#       期望值；被检实现只提供实际值。
#   (b) dnfile 独立读 FieldLayout / ClassLayout / FieldRva 三张表的原始列值
#       （含 Field 名称），逐行比较；并用 dnfile 的 PE RVA→文件偏移换算
#       独立复算 FieldRVA 的位置与字节。
#   (c) 运行时 oracle：tests/layoutref.ps1（Windows PowerShell 5.1 + CLR）给出
#       Marshal.OffsetOf / Marshal.SizeOf(Type)。只用于受控样本，显式标注为
#       运行期推导；sequential/auto 偏移不得进入静态结论。
#   (d) 受控样本 FieldRVA 数据字节与源码数组初始化器 / `.data` 字面量逐字节
#       对拍（这是 FieldRVA 的主对拍，不是 dnfile）。
#   (e) 真实样本上的独立不变量：字段类型名 __StaticArrayInitTypeSize=N 必须
#       等于该类型 ClassLayout.ClassSize，也必须等于推导出的数据长度。
#   (f) 可失败自证（工件形式，首版即带）：FieldLayout 偏移注入、ClassLayout
#       大小注入、FieldRVA 文件字节篡改、RVA+1 注入、空比对，五类都必须被
#       检出；任何一类检不出即 FAIL。
#
# 空比对一律 FAIL（_guard）；分母为 0 的逐表比较记 SKIP 并由聚合分母兜底。
# 缺 dnfile / powershell / 样本 -> env_missing(exit 2)，不静默跳过。
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import layout as LB                     # noqa: E402

IL = os.path.join(WORK, "samples", "m20", "_gen", "LayoutSample.dll")
CS = os.path.join(WORK, "samples", "m20", "_gen", "LayoutCSharp.dll")
IL_SRC = os.path.join(WORK, "outputs", "m20_layout", "LayoutSample.il")
CS_SRC = os.path.join(WORK, "outputs", "m20_layout", "LayoutCSharp.cs")
MSCORLIB = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
CONSOLE = (r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App"
           r"\7.0.20\System.Console.dll")
ORACLE = os.path.join(HERE, "layoutref.ps1")
OUT_JSON = os.path.join(WORK, "evidence_m20_layout.json")

SAMPLES = (("il", IL), ("csharp", CS), ("mscorlib", MSCORLIB),
           ("console", CONSOLE))
CONTROLLED = ("il", "csharp")
RT_TYPES = {
    "il": ["LayoutSample.ExplicitBlob", "LayoutSample.SeqStruct",
           "LayoutSample.AutoStruct"],
    "csharp": ["LayoutCSharp.ExplicitPair", "LayoutCSharp.SeqPack4",
               "LayoutCSharp.Plain"],
}
TID = {"FieldLayout": 0x10, "ClassLayout": 0x0F, "FieldRVA": 0x1D}

CHECKS = []


def _add(cid, name, status, detail):
    CHECKS.append({"id": cid, "name": name, "status": status,
                   "detail": detail})
    print("[%s] %s %s :: %s" % (status, cid, name, detail))


def _guard(n, what):
    if n <= 0:
        print("  !! 空比对：%s 的分母为 0，不得判 PASS" % what)
        return False
    return True


def _pct(a, b):
    return "None" if not b else "%.4f%%" % (a * 100.0 / b)


# ── (a) 源码真值解析 ────────────────────────────────────────────────
def _parse_il(path):
    """从 IL 源文件解析期望值；解析不到就报明确错误，不猜。

    返回 {fieldlayouts:{name:off}, classlayouts:{name:(pack,size)},
          fieldrvas:{name:{label,type,bytes|None}}, auto_types:set}
    """
    text = open(path, "r", encoding="ascii", errors="replace").read()
    # 续行：`.class ...\n extends ...` / `.field ...\n at I_0003`
    text = re.sub(r"\n\s+extends\b", " extends", text)
    text = re.sub(r"\n\s+at\s+(I_\w+)", r" at \1", text)
    data = {}
    for m in re.finditer(r"\.data\s+cil\s+(\w+)\s*=\s*bytearray\s*\(([^)]*)\)",
                         text):
        data[m.group(1)] = bytes(int(x, 16) for x in m.group(2).split())
    for m in re.finditer(r"\.data\s+cil\s+(\w+)\s*=\s*int32\s*\(0x([0-9A-Fa-f]+)\)",
                         text):
        data[m.group(1)] = int(m.group(2), 16).to_bytes(4, "little")
    out = {"fieldlayouts": {}, "classlayouts": {}, "fieldrvas": {},
           "auto_types": set()}
    cur = None
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"\.class\s+(.*?)\s+([\w.]+)$", line)
        if m and "extends" not in line:
            cur = None
            continue
        m = re.match(r"\.class\s+(.*?)\s+([\w.]+)\s+extends\b", line)
        if m:
            attrs, name = m.group(1).split(), m.group(2)
            cur = {"name": name, "pack": None, "size": None}
            if "auto" in attrs:
                out["auto_types"].add(name)
            continue
        if cur is None:
            continue
        m = re.match(r"\.pack\s+(\d+)", line)
        if m:
            cur["pack"] = int(m.group(1))
            continue
        m = re.match(r"\.size\s+(\d+)", line)
        if m:
            cur["size"] = int(m.group(1))
            continue
        m = re.match(r"\.field\s+(?:\[(\d+)\]\s+)?(.*)$", line)
        if m:
            off, rest = m.group(1), m.group(2)
            fm = re.search(r"(\w+)\s+at\s+(\w+)$", rest)
            if fm:
                fname, label = fm.group(1), fm.group(2)
                ftype = rest[:fm.start()].split()[-1]
                # 外部程序集的类型没有本模块 ClassLayout：数据长度不可静态
                # 判定，期望值只能是「unknown」，不能拿 .data 字面量当长度真值
                external = ftype.startswith("[")
                out["fieldrvas"][fname] = {
                    "label": label, "type": ftype,
                    "bytes": None if external else data.get(label)}
            elif off is not None:
                fname = rest.split()[-1]
                out["fieldlayouts"][fname] = int(off)
            continue
        if line == "}":
            if cur and (cur["pack"] is not None or cur["size"] is not None):
                out["classlayouts"][cur["name"]] = (
                    cur["pack"] or 0, cur["size"] or 0)
            cur = None
    return out


def _parse_cs(path):
    """从 LayoutCSharp.cs 解析 [FieldOffset]/[StructLayout] 与数组初始化器。"""
    text = open(path, "r", encoding="utf-8").read()
    out = {"fieldlayouts": {}, "classlayouts": {}, "fieldrvas": {},
           "array_bytes": None, "explicit_types": set()}
    nm = re.search(r"\bnamespace\s+([\w.]+)", text)
    prefix = (nm.group(1) + ".") if nm else ""
    for m in re.finditer(
            r"\[StructLayout\(LayoutKind\.Explicit,\s*Size\s*=\s*(\d+)\)\]"
            r"\s*public struct (\w+)", text):
        out["classlayouts"][prefix + m.group(2)] = (0, int(m.group(1)))
        out["explicit_types"].add(prefix + m.group(2))
    for m in re.finditer(
            r"\[StructLayout\(LayoutKind\.Sequential,\s*Pack\s*=\s*(\d+)\)\]"
            r"\s*public struct (\w+)", text):
        out["classlayouts"][prefix + m.group(2)] = (int(m.group(1)), 0)
    for m in re.finditer(r"\[FieldOffset\((\d+)\)\]\s*public\s+\w+\s+(\w+);",
                         text):
        out["fieldlayouts"][m.group(2)] = int(m.group(1))
    m = re.search(r"new byte\[\]\s*\{(.*?)\};", text, re.S)
    if m:
        out["array_bytes"] = bytes(
            int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
    return out


# ── 比较器：源码真值 ────────────────────────────────────────────────
def _src_problems(rep, exp, tag):
    probs = []

    def bad(line):
        probs.append({"line": "[FAIL] m20-src %s %s" % (tag, line)})

    got_fl = {}
    for it in rep["fieldlayouts"]:
        if it["status"] != "decoded":
            bad("fieldlayout row=%d 状态=%s（源码有显式偏移）"
                % (it["row"], it["status"]))
        got_fl[it["field_name"]] = it["offset"]
    if set(exp["fieldlayouts"]) != set(got_fl):
        bad("FieldLayout 字段集合不一致 expected=%r actual=%r"
            % (sorted(exp["fieldlayouts"]), sorted(got_fl)))
    for name, off in exp["fieldlayouts"].items():
        if got_fl.get(name) != off:
            bad("FieldLayout %s offset expected=%r actual=%r"
                % (name, off, got_fl.get(name)))

    got_cl = {}
    for it in rep["classlayouts"]:
        got_cl[it["type"]] = (it["packing_size"], it["class_size"])
    for name, ps in exp["classlayouts"].items():
        if got_cl.get(name) != ps:
            bad("ClassLayout %s (pack,size) expected=%r actual=%r"
                % (name, ps, got_cl.get(name)))
    for name in set(got_cl) - set(exp["classlayouts"]):
        # 允许编译器生成的 __StaticArrayInitTypeSize=N（由命名不变量单独校验）
        if "__StaticArrayInitTypeSize=" not in (name or ""):
            bad("ClassLayout 多出未声明类型 %s -> %r" % (name, got_cl[name]))

    got_rva = {it["field_name"]: it for it in rep["fieldrvas"]}
    n_extra = 0
    if exp.get("array_bytes") is not None:
        # C# 样本：字段名由编译器生成，不能从源码得到；以「唯一一条
        # FieldRVA，数据等于数组初始化器字面量」为期望
        want = exp["array_bytes"]
        rows = [it for it in rep["fieldrvas"] if it["status"] == "decoded"]
        n_extra += 2
        if len(rows) != 1:
            bad("C# FieldRVA 行数 expected=1 actual=%d" % len(rows))
        else:
            it = rows[0]
            if it["length"] != len(want):
                bad("C# FieldRVA 长度 expected=%d actual=%r"
                    % (len(want), it["length"]))
            if it["data_hex"] != want.hex():
                bad("C# FieldRVA 数据 expected=%s actual=%r"
                    % (want.hex(), it["data_hex"]))
    for name, want in exp["fieldrvas"].items():
        it = got_rva.get(name)
        if it is None:
            bad("FieldRVA 缺少字段 %s" % name)
            continue
        if want["bytes"] is None:
            if it["status"] != "decoded_with_unknown":
                bad("FieldRVA %s 无源码数据却报了静态长度：status=%s len=%r"
                    % (name, it["status"], it["length"]))
            continue
        if it["length"] != len(want["bytes"]):
            bad("FieldRVA %s 长度 expected=%d actual=%r"
                % (name, len(want["bytes"]), it["length"]))
        if it["data_hex"] != want["bytes"].hex():
            bad("FieldRVA %s 数据 expected=%s actual=%r"
                % (name, want["bytes"].hex(), it["data_hex"]))
    return probs, len(exp["fieldlayouts"]) + len(exp["classlayouts"]) \
        + len(exp["fieldrvas"]) + n_extra


def _cs_extra_classlayouts(rep, exp):
    """C# 样本：编译器生成的 __StaticArrayInitTypeSize=N 的类型名必须等于 size。"""
    probs, n = [], 0
    for it in rep["classlayouts"]:
        name = it["type"] or ""
        if name in exp["classlayouts"] or "__StaticArrayInitTypeSize=" not in name:
            continue
        n += 1
        m = re.search(r"__StaticArrayInitTypeSize=(\d+)$", name)
        if not m or int(m.group(1)) != it["class_size"]:
            probs.append({"line": "[FAIL] m20-cs-extra %s ClassSize=%r"
                                  % (name, it["class_size"])})
    return probs, n


# ── 比较器：dnfile 原始列值 ─────────────────────────────────────────
def _dn_pe(path):
    import dnfile
    return dnfile.dnPE(data=open(path, "rb").read())


def _dn_rows(md, name):
    t = getattr(md, name, None)
    return t.rows if t is not None else []


def _dn_field_name(md, row):
    rows = _dn_rows(md, "Field")
    if row < 1 or row > len(rows):
        return None
    return str(rows[row - 1].Name)


def _dn_cols_problems(path, rep):
    pe = _dn_pe(path)
    md = pe.net.mdtables
    probs = []
    n = 0

    def bad(line):
        probs.append({"line": "[FAIL] m20-dn %s" % line})

    dn = _dn_rows(md, "FieldLayout")
    if len(dn) != len(rep["fieldlayouts"]):
        bad("FieldLayout 行数 dnfile=%d rekit=%d"
            % (len(dn), len(rep["fieldlayouts"])))
    for i, (dr, it) in enumerate(zip(dn, rep["fieldlayouts"]), 1):
        n += 1
        if int(dr.struct.Offset) != it["offset"]:
            bad("FieldLayout row=%d Offset dnfile=%d rekit=%r"
                % (i, int(dr.struct.Offset), it["offset"]))
        if int(dr.struct.Field_CodedIndex) != it["field_row"]:
            bad("FieldLayout row=%d Field dnfile=%d rekit=%r"
                % (i, int(dr.struct.Field_CodedIndex), it["field_row"]))
        nm = _dn_field_name(md, it["field_row"])
        if nm != it["field_name"]:
            bad("FieldLayout row=%d FieldName dnfile=%r rekit=%r"
                % (i, nm, it["field_name"]))

    dn = _dn_rows(md, "ClassLayout")
    if len(dn) != len(rep["classlayouts"]):
        bad("ClassLayout 行数 dnfile=%d rekit=%d"
            % (len(dn), len(rep["classlayouts"])))
    for i, (dr, it) in enumerate(zip(dn, rep["classlayouts"]), 1):
        n += 1
        for attr, key in (("PackingSize", "packing_size"),
                          ("ClassSize", "class_size")):
            if int(getattr(dr.struct, attr)) != it[key]:
                bad("ClassLayout row=%d %s dnfile=%d rekit=%r"
                    % (i, attr, int(getattr(dr.struct, attr)), it[key]))
        if int(dr.struct.Parent_Index) != it["parent_row"]:
            bad("ClassLayout row=%d Parent dnfile=%d rekit=%r"
                % (i, int(dr.struct.Parent_Index), it["parent_row"]))

    dn = _dn_rows(md, "FieldRva")
    if len(dn) != len(rep["fieldrvas"]):
        bad("FieldRVA 行数 dnfile=%d rekit=%d"
            % (len(dn), len(rep["fieldrvas"])))
    for i, (dr, it) in enumerate(zip(dn, rep["fieldrvas"]), 1):
        n += 1
        if int(dr.struct.Rva) != it["rva"]:
            bad("FieldRVA row=%d Rva dnfile=0x%x rekit=%r"
                % (i, int(dr.struct.Rva), it["rva"]))
        if int(dr.struct.Field_Index) != it["field_row"]:
            bad("FieldRVA row=%d Field dnfile=%d rekit=%r"
                % (i, int(dr.struct.Field_Index), it["field_row"]))
    return probs, n


def _dn_rva_problems(path, rep):
    """用 dnfile 的 RVA→offset 换算独立复算位置与字节。"""
    pe = _dn_pe(path)
    raw = open(path, "rb").read()
    probs, n = [], 0
    for it in rep["fieldrvas"]:
        if it["status"] != "decoded":
            continue
        n += 1
        try:
            off = pe.get_offset_from_rva(it["rva"])
        except Exception as e:
            probs.append({"line": "[FAIL] m20-rva %s rva=0x%x dnfile 换算失败：%s"
                                  % (it["field_name"], it["rva"], e)})
            continue
        if off != it["file_off"]:
            probs.append({"line": "[FAIL] m20-rva %s file_off dnfile=%r rekit=%r"
                                  % (it["field_name"], off, it["file_off"])})
            continue
        got = raw[off:off + it["length"]].hex()
        if got != it["data_hex"]:
            probs.append({"line": "[FAIL] m20-rva %s 字节 dnfile=%s rekit=%s"
                                  % (it["field_name"], got[:64],
                                     (it["data_hex"] or "")[:64])})
    return probs, n


# ── 比较器：命名不变量（真实样本）───────────────────────────────────
def _name_invariant(rep):
    probs, n = [], 0
    for it in rep["fieldrvas"]:
        if not (it["length_source"] or "").startswith("valuetype_class_size"):
            continue
        m = re.search(r"__StaticArrayInitTypeSize=(\d+)$",
                      it["field_type"] or "")
        if not m:
            continue
        n += 1
        if int(m.group(1)) != it["length"]:
            probs.append({"line": "[FAIL] m20-name %s 名字=%d 长度=%r"
                                  % (it["field_name"], int(m.group(1)),
                                     it["length"])})
    return probs, n


# ── (c) 运行时 oracle ───────────────────────────────────────────────
def _run_oracle(path, types):
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-File", ORACLE,
           "-Assembly", path, "-Types", ",".join(types)]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=180)
    if p.returncode != 0:
        raise RuntimeError("layoutref.ps1 exit=%d stderr=%s"
                           % (p.returncode,
                              p.stderr.decode("utf-8", "replace")[:300]))
    txt = p.stdout.decode("utf-8", "replace").strip()
    if not txt:
        raise RuntimeError("layoutref.ps1 无输出")
    return json.loads(txt)


def _runtime_checks(tag, path, rep, oracle):
    rt = rep["runtime_derived"]
    probs, n_off, n_size, n_auto = [], 0, 0, 0

    def bad(line):
        probs.append({"line": "[FAIL] m20-rt %s %s" % (tag, line)})

    if rt.get("available") is not True:
        bad("runtime_derived 未接上：%r" % rt.get("reason"))
    if rt.get("static_conclusion") is not False:
        bad("runtime_derived.static_conclusion 必须为 False")
    for t in rt["types"]:
        for f in t["fields"]:
            if t["layout"] == "explicit":
                if f["offset_runtime"] is None:
                    continue
                n_off += 1
                if f["offset_static"] != f["offset_runtime"] \
                        or f["match"] is not True:
                    bad("%s.%s explicit offset static=%r runtime=%r"
                        % (t["type"], f["name"], f["offset_static"],
                           f["offset_runtime"]))
            else:
                if f["offset_static"] is not None:
                    bad("%s.%s layout=%s 不得有静态偏移，却有 %r"
                        % (t["type"], f["name"], t["layout"],
                           f["offset_static"]))
                if f["offset_runtime"] is not None:
                    n_off += 1
        if t["class_size_static"] not in (None, 0) \
                and t["size_runtime"] is not None:
            n_size += 1
            if t["size_match"] is not True:
                bad("%s ClassSize static=%r runtime=%r"
                    % (t["type"], t["class_size_static"], t["size_runtime"]))
        if t["layout"] == "auto":
            n_auto += 1
            if t["size_runtime"] is None and not t["size_error"]:
                bad("%s auto 既无 runtime size 又无错误原因（不可静默）"
                    % t["type"])
    return probs, n_off, n_size, n_auto


# ── 分母恒等式 / 计数一致性 ─────────────────────────────────────────
def _den_problems(rep):
    probs = []
    den = rep["denominators"]
    for name in ("FieldLayout", "ClassLayout", "FieldRVA"):
        d = den[name]
        for k in ("identity_rows_ok", "identity_ref_ok",
                  "identity_unknown_ok", "identity_length_ok",
                  "identity_data_ok"):
            if k in d and not d[k]:
                probs.append({"line": "[FAIL] m20-den %s %s 不成立 rows=%d "
                                      "rows_read=%d"
                                      % (name, k, d["rows"], d["rows_read"])})
    fl, cl, fr = den["FieldLayout"], den["ClassLayout"], den["FieldRVA"]
    if fl["decoded"] != fl["decoded_clean"] + fl["decoded_with_unknown"]:
        probs.append({"line": "[FAIL] m20-den FieldLayout decoded 分解不等"})
    if cl["decoded"] != cl["decoded_clean"] + cl["decoded_with_unknown"]:
        probs.append({"line": "[FAIL] m20-den ClassLayout decoded 分解不等"})
    if fr["undecoded"] != (fr["rva_unmapped"] + fr["data_truncated"]
                           + fr["field_ref_missing"]):
        probs.append({"line": "[FAIL] m20-den FieldRVA undecoded 分解不等"})
    if not den.get("identity_ok"):
        probs.append({"line": "[FAIL] m20-den identity_ok=False"})
    sc = rep.get("static_conclusion") or {}
    if "sequential/auto 字段偏移" not in (sc.get("excludes") or []):
        probs.append({"line": "[FAIL] m20-den static_conclusion 未排除 "
                              "sequential/auto 偏移"})
    return probs


# ── 自证 ────────────────────────────────────────────────────────────
def selfproof(rep0, il_exp):
    base = "fieldlayouts=%d classlayouts=%d fieldrvas=%d" % (
        len(rep0["fieldlayouts"]), len(rep0["classlayouts"]),
        len(rep0["fieldrvas"]))
    hits = {}
    tmpdir = tempfile.mkdtemp(prefix="rekit_m20_")
    try:
        # 1) FieldLayout 偏移注入
        r1 = json.loads(json.dumps(rep0))
        r1["fieldlayouts"][0]["offset"] += 4
        p1, _ = _src_problems(r1, il_exp, "selfproof")
        hits["fieldlayout"] = next((x["line"] for x in p1
                                    if "FieldLayout" in x["line"]), "")
        # 2) ClassLayout 大小注入
        r2 = json.loads(json.dumps(rep0))
        r2["classlayouts"][0]["class_size"] += 1
        p2, _ = _src_problems(r2, il_exp, "selfproof")
        hits["classlayout"] = next((x["line"] for x in p2
                                    if "ClassLayout" in x["line"]), "")
        # 3) FieldRVA 文件字节篡改
        target = next(it for it in rep0["fieldrvas"]
                      if it["status"] == "decoded")
        t3 = os.path.join(tmpdir, "tamper.dll")
        shutil.copyfile(IL, t3)
        buf = bytearray(open(t3, "rb").read())
        buf[target["file_off"]] ^= 0xFF
        open(t3, "wb").write(buf)
        rep3 = LB.build(t3, limit=None)
        p3, _ = _src_problems(rep3, il_exp, "selfproof")
        hits["fieldrva-bytes"] = next((x["line"] for x in p3
                                       if "数据" in x["line"]), "")
        # 4) RVA +1 注入 -> dnfile 换算位置必须对不上
        r4 = json.loads(json.dumps(rep0))
        r4["fieldrvas"][0]["rva"] += 1
        p4, _ = _dn_rva_problems(IL, r4)
        hits["rva+1"] = next((x["line"] for x in p4
                              if "file_off" in x["line"]
                              or "换算" in x["line"]), "")
        # 5) 空比对必须 FAIL
        hits["empty"] = "" if _guard(0, "selfproof-empty") else "空比对已拒绝"
    except Exception as e:
        _add("selfproof", "比对器可失败自证", "FAIL",
             "%s: %s" % (type(e).__name__, e))
        return
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    ok = all(hits.values())
    if ok:
        print("[PASS] selfproof 注入ID=layout-injection 基线=%s 观察=%s"
              % (base, hits["fieldlayout"]))
    _add("selfproof", "比对器可失败自证（5 类注入 + 空比对）",
         "PASS" if ok else "FAIL",
         " / ".join("%s=%s" % (k, v or "未检出") for k, v in hits.items()))


# ── 主流程 ──────────────────────────────────────────────────────────
def main():
    try:
        import dnfile  # noqa: F401
    except Exception as e:
        print("env_missing: 缺少 dnfile（%s）" % e)
        return 2
    if not shutil.which("powershell"):
        print("env_missing: powershell 不在 PATH（运行时 oracle 需要）")
        return 2
    logging.disable(logging.CRITICAL)
    for p in (IL_SRC, CS_SRC, ORACLE):
        if not os.path.exists(p):
            print("env_missing: 缺文件 %s" % p)
            return 2

    il_exp = _parse_il(IL_SRC)
    cs_exp = _parse_cs(CS_SRC)
    exp_by_tag = {"il": il_exp, "csharp": cs_exp}
    evidence = {}
    agg = {"FieldLayout": 0, "ClassLayout": 0, "FieldRVA": 0,
           "dn_cols": 0, "dn_rva": 0, "src": 0, "rt_off": 0, "rt_size": 0,
           "rt_auto": 0, "name": 0}
    rep0 = None

    for tag, path in SAMPLES:
        if not os.path.exists(path):
            _add("sample-" + tag, "样本存在", "FAIL", "缺文件 %s" % path)
            continue
        try:
            rep = LB.build(path, limit=None)
        except Exception as e:
            _add("sample-" + tag, "样本可构建", "FAIL",
                 "%s: %s" % (type(e).__name__, e))
            continue
        if rep.get("status") != "ok":
            _add("sample-" + tag, "样本可构建", "FAIL",
                 "status=%s reason=%s" % (rep.get("status"),
                                          rep.get("reason")))
            continue
        if tag == "il":
            rep0 = rep
        den = rep["denominators"]
        for name in ("FieldLayout", "ClassLayout", "FieldRVA"):
            agg[name] += den[name]["rows"]

        pden = _den_problems(rep)
        _add("den-" + tag, "分母恒等式与 unknown/undecoded 分离",
             "PASS" if not pden else "FAIL",
             "行=%d/%d/%d 问题=%d%s"
             % (den["FieldLayout"]["rows"], den["ClassLayout"]["rows"],
                den["FieldRVA"]["rows"], len(pden),
                "" if not pden else " 首条=" + pden[0]["line"]))

        try:
            pc, nc = _dn_cols_problems(path, rep)
        except Exception as e:
            pc, nc = [{"line": "[FAIL] m20-dn %s: %s"
                               % (type(e).__name__, e)}], 0
        agg["dn_cols"] += nc
        _add("dn-cols-" + tag, "dnfile 三表原始列值逐行相等",
             "PASS" if (nc > 0 and not pc) else "FAIL",
             "行=%d 问题=%d%s" % (nc, len(pc),
                                 "" if not pc else " 首条=" + pc[0]["line"]))

        try:
            pr, nr = _dn_rva_problems(path, rep)
        except Exception as e:
            pr, nr = [{"line": "[FAIL] m20-rva %s: %s"
                               % (type(e).__name__, e)}], 0
        agg["dn_rva"] += nr
        if nr == 0 and den["FieldRVA"]["rows"] == 0:
            _add("dn-rva-" + tag, "dnfile RVA→offset 复算",
                 "SKIP", "该样本 FieldRVA=0，无可复算行（由聚合分母兜底）")
        else:
            _add("dn-rva-" + tag, "dnfile RVA→offset 与数据字节逐行复算",
                 "PASS" if (nr > 0 and not pr) else "FAIL",
                 "行=%d 问题=%d%s" % (nr, len(pr),
                                     "" if not pr else " 首条=" + pr[0]["line"]))

        if tag in CONTROLLED:
            exp = exp_by_tag[tag]
            ps, ns = _src_problems(rep, exp, tag)
            if tag == "csharp":
                pe2, ne2 = _cs_extra_classlayouts(rep, exp)
                ps, ns = ps + pe2, ns + ne2
            agg["src"] += ns
            _add("src-" + tag, "源码声明（.il/.cs）逐行相等",
                 "PASS" if (ns > 0 and not ps) else "FAIL",
                 "比较项=%d 问题=%d%s" % (ns, len(ps),
                                         "" if not ps else " 首条=" + ps[0]["line"]))
            try:
                oracle = _run_oracle(path, RT_TYPES[tag])
                rep_rt = LB.build(path, limit=None, runtime=oracle)
                prt, no, nsz, nau = _runtime_checks(tag, path, rep_rt, oracle)
                agg["rt_off"] += no
                agg["rt_size"] += nsz
                agg["rt_auto"] += nau
                _add("runtime-" + tag,
                     "运行期 oracle（OffsetOf/SizeOf）与静态段边界",
                     "PASS" if (no > 0 and not prt) else "FAIL",
                     "偏移=%d size=%d auto=%d 问题=%d%s"
                     % (no, nsz, nau, len(prt),
                        "" if not prt else " 首条=" + prt[0]["line"]))
            except Exception as e:
                _add("runtime-" + tag, "运行期 oracle 可执行", "FAIL",
                     "%s: %s" % (type(e).__name__, e))
        else:
            _add("runtime-" + tag, "非受控样本不产出运行期结论",
                 "PASS" if rep["runtime_derived"]["available"] is False
                 else "FAIL", "runtime_derived.available=%r"
                 % rep["runtime_derived"]["available"])

        try:
            pn, nn = _name_invariant(rep)
        except Exception as e:
            pn, nn = [{"line": "[FAIL] m20-name %s" % e}], 0
        agg["name"] += nn
        if nn:
            _add("name-" + tag, "__StaticArrayInitTypeSize=N == ClassSize == 长度",
                 "PASS" if not pn else "FAIL",
                 "行=%d 问题=%d%s" % (nn, len(pn),
                                     "" if not pn else " 首条=" + pn[0]["line"]))

        evidence[tag] = {
            "path": path,
            "denominators": {k: den[k] for k in
                             ("FieldLayout", "ClassLayout", "FieldRVA",
                              "identity_ok")},
            "counts": rep["counts"],
            "runtime_derived": {"available": rep["runtime_derived"]["available"],
                                "types": len(rep["runtime_derived"]["types"]),
                                "static_conclusion":
                                    rep["runtime_derived"]["static_conclusion"]},
        }

    # 聚合分母：三张表都必须在全部样本里真的出现过
    for name, minimum in (("FieldLayout", 3), ("ClassLayout", 3),
                          ("FieldRVA", 1)):
        _add("agg-" + name.lower(), "聚合分母（全样本合计）",
             "PASS" if agg[name] >= minimum else "FAIL",
             "rows=%d 下限=%d" % (agg[name], minimum))
    _add("agg-src", "源码真值比较项聚合",
         "PASS" if agg["src"] >= 8 else "FAIL", "比较项=%d 下限=8" % agg["src"])
    _add("agg-runtime", "运行期推导偏移聚合",
         "PASS" if agg["rt_off"] >= 3 else "FAIL",
         "偏移=%d size=%d auto=%d 下限=3"
         % (agg["rt_off"], agg["rt_size"], agg["rt_auto"]))
    _add("agg-dn", "dnfile 逐行比较聚合",
         "PASS" if agg["dn_cols"] >= 3 and agg["dn_rva"] >= 1 else "FAIL",
         "cols=%d rva=%d 下限=3/1" % (agg["dn_cols"], agg["dn_rva"]))
    _add("agg-name-invariant", "ClassSize 命名不变量聚合",
         "PASS" if agg["name"] >= 1 else "FAIL",
         "行=%d 下限=1" % agg["name"])

    if rep0 is not None:
        selfproof(rep0, il_exp)
    else:
        _add("selfproof", "比对器可失败自证", "FAIL", "IL 样本未能构建")

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    n_skip = sum(1 for c in CHECKS if c["status"] == "SKIP")
    payload = {"schema": 1, "status": "fail" if failed else "pass",
               "checks": CHECKS, "samples": evidence, "aggregate": agg}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=%d → %s"
          % (len(CHECKS), len(CHECKS) - len(failed) - n_skip, len(failed),
             n_skip, "FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
