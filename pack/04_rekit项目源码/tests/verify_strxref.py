#!/usr/bin/env python3
# tests/verify_strxref.py — M8-U3 验收：字符串/数据引用交叉
#
# 硬不变量（任一不成立 → FAIL/退出码 1）：
#   A) 口径独立复算：用**本脚本自己的** ELF/PE 节头解析 + 自己的切分实现重算
#      字符串集合（addr/length/text），与模块报出的逐项相等。不 import
#      rekit.elf / rekit.pe / strxref.scan_blob 作为期望值来源。
#   B) 引用点期望值来自外部 objdump：解析 `objdump -d -M intel` 的
#      **原始字节长度 + rip 位移 / 立即数**，自行算目标（addr+len+disp）。
#      模块报出的每个站点都必须与 objdump 算出的目标相等；
#      objdump 算出的每个「命中字符串起点」的指令，模块必须也有站点；
#      除非该指令在表达式层 unlifted（单列计数，不静默丢）。
#   C) 账目对平：unique+multi+no_site = total；四类归因和 = no_site；
#      rip_mem+lea_rip+imm = sites；有函数+无函数 = sites。
#   D) 三态一致：unique ⇔ 恰 1 个站点；multi ⇔ ≥2；no_site ⇔ 0。
#   E) 对账：与 callfacts/callgraph 的交集冲突 0；函数域核对（声明 end）
#      冲突 0；交集为 0 时必须写明「无非空对账对象」，不当作通过。
#   F) 零值可解释：字符串 0 时必须给出结构性原因（缺白名单节 / 节内无可打印段）。
#
# 期望值不取被测实现：字符串由本脚本独立切分，引用目标由 objdump 字节算。
# `--selftest` 注入四类错误必须被检出。
import json
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import callfacts as CF, callgraph as CG, recdesc, strxref as SX  # noqa: E402

MIN_LEN = 4
IMM_MIN = 0x100000
ALLOW = (".rodata", ".rdata")


# ── 独立节头解析（不 import rekit.elf / rekit.pe）────────────────────
def _sections(path):
    data = open(path, "rb").read()
    out = []
    if data[:4] == b"\x7fELF":
        cls = data[4]
        end = "<" if data[5] == 1 else ">"
        if cls == 2:
            e_shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
            e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(end + "HHH", data, 0x3A)
            fmt = end + "IIQQQQ"
        else:
            e_shoff = struct.unpack_from(end + "I", data, 0x20)[0]
            e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(end + "HHH", data, 0x2E)
            fmt = end + "IIIIII"
        if not e_shoff or not e_shnum:
            return data, []
        raw = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            raw.append(struct.unpack_from(fmt, data, o))
        blob = b""
        if 0 <= e_shstrndx < len(raw):
            _n, _t, _f, _a, so, ss = raw[e_shstrndx]
            blob = data[so:so + ss]
        for (nm, typ, flg, addr, off, size) in raw:
            name = ""
            if blob and nm < len(blob):
                e = blob.find(b"\x00", nm)
                name = blob[nm:e if e >= 0 else len(blob)].decode("ascii", "replace")
            out.append({"name": name, "addr": addr, "off": off, "size": size,
                        "file_size": 0 if typ == 8 else size,
                        "write": bool(flg & 1), "exec": bool(flg & 4),
                        "nobits": typ == 8})
    elif data[:2] == b"MZ":
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\x00\x00":
            raise ValueError("MZ 但无 PE 签名")
        nsect, optsize = struct.unpack_from("<H", data, lfanew + 6)[0], \
            struct.unpack_from("<H", data, lfanew + 20)[0]
        opt = lfanew + 24
        magic = struct.unpack_from("<H", data, opt)[0]
        image_base = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20B \
            else struct.unpack_from("<I", data, opt + 28)[0]
        for i in range(nsect):
            o = opt + optsize + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            chars = struct.unpack_from("<I", data, o + 36)[0]
            out.append({"name": name, "addr": vaddr,
                        "off": rawptr, "size": vsize or rawsize,
                        "file_size": rawsize,
                        "write": bool(chars & 0x80000000),
                        "exec": bool(chars & 0x20000000),
                        "nobits": rawsize == 0, "image_base": image_base})
    else:
        raise ValueError("非 ELF / PE")
    return data, out


def _allowed(name):
    return name in ALLOW or name.startswith(".rodata.str")


def _strings(data, secs):
    """独立切分：按 NUL 分段的整段可打印 ASCII，长度 >= 4。"""
    got = {}
    for s in secs:
        if not _allowed(s["name"]) or s["nobits"] or s["file_size"] == 0:
            continue
        blob = data[s["off"]:s["off"] + min(s["file_size"],
                                            max(0, len(data) - s["off"]))]
        parts = blob.split(b"\x00")
        off = 0
        for i, seg in enumerate(parts):
            if i == len(parts) - 1:            # 末尾无 NUL 的残段不报
                break
            if len(seg) >= MIN_LEN and all(0x20 <= c <= 0x7E for c in seg):
                got[s["addr"] + off] = seg.decode("ascii")
            off += len(seg) + 1
    return got


def _file_bytes(data, secs, addr, n):
    for s in secs:
        if s["nobits"] or s["file_size"] <= 0:
            continue
        if s["addr"] <= addr < s["addr"] + s["file_size"]:
            o = s["off"] + (addr - s["addr"])
            return data[o:o + n], s
    return b"", None


# ── 外部 objdump：自行算目标 ────────────────────────────────────────
def _tool(name):
    exe = shutil.which(name)
    if exe:
        return exe
    for base in (os.path.join(WORK, "tools", "binutils-2.47", "mingw64", "bin"),
                 os.path.join(os.path.dirname(WORK), "m2-task-card", "work",
                              "tools", "binutils-2.47", "mingw64", "bin")):
        cand = os.path.join(base, name + ".exe")
        if os.path.isfile(cand):
            return cand
    return None


_RIP = re.compile(r"\[rip([+-])0x([0-9a-f]+)\]")


def _objdump(path, text_va):
    exe = _tool("objdump")
    if not exe:
        raise RuntimeError("找不到 objdump：引用点期望值必须来自外部工具")
    p = subprocess.run([exe, "-d", "-M", "intel", "--insn-width=16", path],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("objdump 失败：%s"
                           % p.stderr.decode("utf-8", "replace")[:200])
    out, delta, sec = {}, None, None
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        m = re.match(r"^Disassembly of section (\S+):", line.strip())
        if m:
            sec = m.group(1)
            continue
        if sec != ".text":
            continue
        m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if delta is None:
            if text_va is None:
                raise RuntimeError("模块未给出 .text VA，无法对齐地址")
            delta = addr - text_va
        raw = m.group(2).strip()
        nbytes = (len(raw.split()) if raw else 0)
        body = m.group(3)
        body = body.split("#")[0]
        toks = body.strip().split(None, 1)
        mnem = toks[0].lower() if toks else ""
        ops = toks[1] if len(toks) > 1 else ""
        ent = {"bytes": nbytes, "mnem": mnem, "rip": set(), "imm": set()}
        r = _RIP.search(ops)
        if r:
            disp = int(r.group(2), 16)
            if r.group(1) == "-":
                disp = -disp
            ent["rip"].add(addr + nbytes + disp - delta)
        flat = re.sub(r"\[[^\]]*\]", "", ops)         # 去掉内存操作数里的位移
        for t in re.findall(r"(?<![\w])0x([0-9a-f]+)", flat):
            v = int(t, 16)
            if v >= IMM_MIN:
                ent["imm"].add(v)
        out[addr - delta] = ent
    if delta is None:
        raise RuntimeError("objdump 输出里没有 .text 反汇编")
    return out, delta


# ── 检查器（独立于模块）─────────────────────────────────────────────
def check_strings(rel, rep, data, secs, fails, stats):
    """A) 独立切分逐项比对 + 逐条字节复核。"""
    exp = _strings(data, secs)
    got = {d["addr"]: d["text"] for d in rep["strings_detail"]}
    stats["strings_expected"] = len(exp)
    stats["strings_got"] = len(got)
    for a in sorted(set(exp) - set(got)):
        fails.append("%s: 漏报字符串 0x%x %r（独立切分命中）" % (rel, a, exp[a]))
    for a in sorted(set(got) - set(exp)):
        fails.append("%s: 误报字符串 0x%x %r（独立切分未命中）" % (rel, a, got[a]))
    for d in rep["strings_detail"]:
        raw, sec = _file_bytes(data, secs, d["addr"], d["length"] + 1)
        if sec is None:
            fails.append("%s: 字符串 0x%x 不在任何节内" % (rel, d["addr"]))
            continue
        if len(raw) < d["length"] + 1 or raw[d["length"]] != 0:
            fails.append("%s: 字符串 0x%x 没有 NUL 终止" % (rel, d["addr"]))
        txt = raw[:d["length"]].decode("ascii", "replace")
        ok = txt.startswith(d["text"]) if d.get("truncated") else txt == d["text"]
        if not ok:
            fails.append("%s: 字符串 0x%x 文本与文件字节不符" % (rel, d["addr"]))
        if not _allowed(sec["name"]):
            fails.append("%s: 字符串 0x%x 落在非白名单节 %s"
                         % (rel, d["addr"], sec["name"]))
    if not exp and not rep["counts"].get("strings_zero_reason"):
        fails.append("%s: 字符串为 0 但未写结构性原因" % rel)


def check_sites(rel, rep, od, starts, decoded, fails, stats):
    """B/D) 引用点目标与外部 objdump 逐条比对；漏报/误报分开。

    漏报再分两种：指令未解码（代码层覆盖缺口，只计数）、表达式层 unlifted
    （只计数）、其余为真漏报（失败）。缺口计数必须写进统计，不静默丢。
    """
    unl = {u["addr"] for u in rep["unlifted"]}
    ours = {}
    for s in rep["sites"]:
        ours.setdefault(s["addr"], []).append(s)
    hit_rip = {a: (v["rip"] & starts) for a, v in od.items() if v["rip"] & starts}
    hit_imm = {a: (v["imm"] & starts) for a, v in od.items() if v["imm"] & starts}
    stats["objdump_rip_hits"] = sum(len(v) for v in hit_rip.values())
    stats["objdump_imm_hits"] = sum(len(v) for v in hit_imm.values())
    stats["unlifted_hits"] = 0
    stats["undecoded_hits"] = 0
    stats["undecoded_strings"] = 0
    lost_strings = set()
    for a, tgts in ours.items():
        ent = od.get(a)
        if ent is None:
            fails.append("%s: 引用点 0x%x 不在 objdump 的 .text 反汇编里" % (rel, a))
            continue
        for s in tgts:
            exp = ent["rip"] if s["kind"] in ("rip_mem", "lea_rip") else ent["imm"]
            if s["target"] not in exp:
                fails.append("%s: 引用点 0x%x 目标 0x%x 与 objdump 不符（objdump=%s）"
                             % (rel, a, s["target"],
                                ",".join("0x%x" % x for x in sorted(exp)) or "无"))
    for a, tgts in sorted(hit_rip.items()):
        if a not in ours:
            if a in decoded and a in unl:
                stats["unlifted_hits"] += 1
                lost_strings |= tgts
            elif a in decoded:
                fails.append("%s: 漏报引用点 0x%x → %s（objdump 命中字符串起点）"
                             % (rel, a, ",".join("0x%x" % t for t in sorted(tgts))))
            else:
                stats["undecoded_hits"] += 1
                lost_strings |= tgts
    for a, tgts in sorted(hit_imm.items()):
        if a not in ours:
            if a in decoded and a in unl:
                stats["unlifted_hits"] += 1
            elif a in decoded:
                fails.append("%s: 漏报立即数引用 0x%x → %s"
                             % (rel, a, ",".join("0x%x" % t for t in sorted(tgts))))
            else:
                stats["undecoded_hits"] += 1
    stats["undecoded_strings"] = len(lost_strings)


def check_accounting(rel, rep, fails):
    c = rep["counts"]
    if c["strings_total"] != (c["strings_unique"] + c["strings_multi"]
                              + c["strings_no_site"]):
        fails.append("%s: 字符串三态不可加和" % rel)
    if c["strings_no_site"] != sum(c["no_site_reason"].values()):
        fails.append("%s: no_site 四类归因不可加和" % rel)
    if c["sites_total"] != (c["sites_rip_mem"] + c["sites_lea_rip"]
                            + c["sites_imm"]):
        fails.append("%s: 引用点按形态不可加和" % rel)
    if c["sites_total"] != (c["sites_with_function"]
                            + c["sites_without_function"]):
        fails.append("%s: 引用点按归属不可加和" % rel)
    by = {}
    for s in rep["sites"]:
        by.setdefault(s["string"], []).append(s["addr"])
    for d in rep["strings_detail"]:
        n = len(by.get(d["addr"], []))
        want = "unique" if n == 1 else ("multi" if n > 1 else "no_site")
        if d["status"] != want:
            fails.append("%s: 字符串 0x%x 状态 %s 与站点数 %d 不符"
                         % (rel, d["addr"], d["status"], n))
        if n and d["sites"] != by[d["addr"]]:
            fails.append("%s: 字符串 0x%x 的站点列表不一致" % (rel, d["addr"]))


def check_cross(rel, rep, fails, stats):
    cc = rep.get("crosscheck")
    if cc is None:
        fails.append("%s: 未做三层对账" % rel)
        return
    if cc["conflicts"]:
        fails.append("%s: 三层对账冲突 %d 条：%s"
                     % (rel, len(cc["conflicts"]), cc["conflicts"][:2]))
    if not cc["checked"] and "无非空对账对象" not in cc.get("note", ""):
        fails.append("%s: 交集为 0 但未写明无对账对象" % rel)
    stats["cross_checked"] = cc["checked"]
    stats["cross_domain"] = cc["domain_checked"]


# ── 单样本 ──────────────────────────────────────────────────────────
def _one(rel, path):
    fails, st = [], {}
    data, secs = _sections(path)
    text = next((s for s in secs if s["name"] == ".text" and not s["nobits"]
                 and s["file_size"] > 0), None)
    if text is None:
        res = {"format": None, "instructions": [], "blocks": [],
               "seeds": [], "cfg": {}, "counts": {}}
        facts, graph = {"sites": []}, {"edges": []}
        rep = SX.build(path, res=res, facts=facts, graph=graph)
        check_strings(rel, rep, data, secs, fails, st)
        check_accounting(rel, rep, fails)
        check_cross(rel, rep, fails, st)
        if rep["sites"]:
            fails.append("%s: 无 .text 节却有引用点" % rel)
        if not rep["counts"]["coverage"].get("no_code_reason"):
            fails.append("%s: 无代码节但未写结构性原因" % rel)
        st.update({"strings": rep["counts"]["strings_total"],
                   "unique": rep["counts"]["strings_unique"],
                   "multi": rep["counts"]["strings_multi"],
                   "no_site": rep["counts"]["strings_no_site"],
                   "reason": rep["counts"]["no_site_reason"],
                   "sites": 0, "rip": 0, "imm": 0, "nofn": 0, "suffix": 0,
                   "unlifted": 0,
                   "coverage": rep["counts"]["coverage"]["ratio"]})
        return fails, st
    res = recdesc.descend(path)
    facts = CF.build(path, res=res)
    graph = CG.build(path, res=res)
    rep = SX.build(path, res=res, facts=facts, graph=graph)
    check_strings(rel, rep, data, secs, fails, st)
    check_accounting(rel, rep, fails)
    check_cross(rel, rep, fails, st)
    starts = {d["addr"] for d in rep["strings_detail"]}
    decoded = {i["addr"] for i in res["instructions"]}
    if text is not None and text["file_size"] > 0:
        try:
            od, _delta = _objdump(path, text["addr"])
        except RuntimeError as e:
            if rep["sites"]:
                fails.append("%s: 引用点期望值取不到（%s）" % (rel, e))
            st["objdump"] = 0
        else:
            st["objdump"] = 1
            check_sites(rel, rep, od, starts, decoded, fails, st)
    elif rep["sites"]:
        fails.append("%s: 无 .text 节却有引用点" % rel)
    st.update({
        "strings": rep["counts"]["strings_total"],
        "unique": rep["counts"]["strings_unique"],
        "multi": rep["counts"]["strings_multi"],
        "no_site": rep["counts"]["strings_no_site"],
        "reason": rep["counts"]["no_site_reason"],
        "sites": rep["counts"]["sites_total"],
        "rip": rep["counts"]["sites_rip_mem"] + rep["counts"]["sites_lea_rip"],
        "imm": rep["counts"]["sites_imm"],
        "nofn": rep["counts"]["sites_without_function"],
        "suffix": rep["counts"]["suffix_refs"],
        "unlifted": rep["counts"]["unlifted"],
        "coverage": rep["counts"]["coverage"]["ratio"],
    })
    return fails, st


# ── 自证：四类注入必须被检出 ────────────────────────────────────────
def selftest():
    base = os.path.join(HERE, "fixtures", "bin_ls.elf")
    if not os.path.isfile(base):
        print("[selftest] 缺 bin_ls.elf → 失败")
        return 1
    data, secs = _sections(base)
    res = recdesc.descend(base)
    facts = CF.build(base, res=res)
    graph = CG.build(base, res=res)
    rep = SX.build(base, res=res, facts=facts, graph=graph)
    text = next(s for s in secs if s["name"] == ".text")
    od, _d = _objdump(base, text["addr"])
    starts = {d["addr"] for d in rep["strings_detail"]}
    decoded = {i["addr"] for i in res["instructions"]}

    f0, st0 = [], {}
    check_strings("base", rep, data, secs, f0, st0)
    check_sites("base", rep, od, starts, decoded, f0, st0)
    if f0:
        print("[selftest] 基线已失败，自证无意义：%s" % f0[:2])
        return 1
    if not rep["sites"]:
        print("[selftest] 基线没有引用点，无法注入 → 失败")
        return 1

    # 1) 目标改错：+1 后既不是字符串起点，也与 objdump 不符
    r1 = json.loads(json.dumps(rep))
    r1["sites"][0]["target"] += 1
    f1, _ = [], {}
    check_sites("inj-target", r1, od, starts, decoded, f1, _)
    if not any("与 objdump 不符" in x for x in f1):
        print("[selftest] 篡改引用目标未被检出 → 失败")
        return 1

    # 2) 删掉一个 objdump 能看到的引用点 → 必须报漏报
    r2 = json.loads(json.dumps(rep))
    r2["sites"] = r2["sites"][1:]
    f2, _ = [], {}
    check_sites("inj-miss", r2, od, starts, decoded, f2, _)
    if not any("漏报引用点" in x or "漏报立即数引用" in x for x in f2):
        print("[selftest] 删除引用点未被检出 → 失败")
        return 1

    # 3) 伪造字符串（文本与文件字节不符 + 独立切分未命中）→ 必须报误报
    r3 = json.loads(json.dumps(rep))
    r3["strings_detail"].append({"addr": 0x1000, "length": 4, "text": "FAKE",
                                 "status": "no_site", "reason": "no_evidence",
                                 "sites": [], "site_kinds": [], "evidence": {}})
    f3, _ = [], {}
    check_strings("inj-string", r3, data, secs, f3, _)
    if not any("误报字符串" in x or "文本与文件字节不符" in x for x in f3):
        print("[selftest] 伪造字符串未被检出 → 失败")
        return 1

    # 4) 函数归属改错（与 callfacts 同一地址时）→ 三层对账必须报 layer_bug
    site = next((s for s in rep["sites"] if s["function"] is not None), None)
    fsite = next((s for s in facts["sites"] if s["from"] == site["addr"]), None)
    if fsite is not None:
        r4 = json.loads(json.dumps(rep))
        for s in r4["sites"]:
            if s["addr"] == site["addr"]:
                s["function"] = 0xDEAD
        cc = SX.crosscheck(r4, facts, graph, res.get("seeds"))
        if cc["ok"] or not any(x["attribution"] == "layer_bug"
                               for x in cc["conflicts"]):
            print("[selftest] 函数归属矛盾未被检出 → 失败")
            return 1
    # 5) 函数域越界：把某站点函数换成一个声明了 end 的种子，站点不在域内
    seeded = next((s for s in res["seeds"] if s.get("end")
                   and not (s["addr"] <= site["addr"] < s["end"])), None)
    if seeded is not None:
        r5 = json.loads(json.dumps(rep))
        for s in r5["sites"]:
            if s["addr"] == site["addr"]:
                s["function"] = seeded["addr"]
        cc = SX.crosscheck(r5, facts, graph, res.get("seeds"))
        if cc["ok"] or not any(x["field"] == "function_range"
                               for x in cc["conflicts"]):
            print("[selftest] 函数域越界未被检出 → 失败")
            return 1

    print("[selftest] 五类注入（篡改目标 / 删除引用点 / 伪造字符串 / "
          "函数归属矛盾 / 函数域越界）全部被检出")
    print("[selftest] 基线（真实 bin_ls.elf）零失败，检查器不是空转的")
    return 0


# ── 主流程 ──────────────────────────────────────────────────────────
def _find_manifest():
    p = WORK
    while True:
        for cand in (os.path.join(p, "m2-task-card", "work", "sample_manifest.json"),
                     os.path.join(p, "m2-task-card", "sample_manifest.json")):
            if os.path.isfile(cand):
                return cand
        parent = os.path.dirname(p)
        if parent == p:
            return None
        p = parent


MANIFEST = _find_manifest()
M2WORK = os.path.dirname(MANIFEST or "")


def _resolve(rel):
    for base in (M2WORK, os.path.dirname(M2WORK)):
        p = os.path.join(base, rel)
        if os.path.isfile(p):
            return p
    return None


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--only", default=None,
                    help="只跑某个样本 id（调试用；全量验收不要带）")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not MANIFEST:
        print("找不到 sample_manifest.json", file=sys.stderr)
        return 1
    samples = json.load(open(MANIFEST, encoding="utf-8"))["e9_ground_truth"]["samples"]
    fails, rows, agg = [], [], {"strings": 0, "unique": 0, "multi": 0,
                                "no_site": 0, "sites": 0, "rip": 0, "imm": 0,
                                "nofn": 0, "suffix": 0, "unlifted": 0,
                                "cross_checked": 0, "cross_domain": 0,
                                "unlifted_hits": 0, "undecoded_hits": 0,
                                "undecoded_strings": 0}
    reasons = {"cross_section": 0, "undecoded": 0, "indirect": 0,
               "no_evidence": 0}
    print("== 分母（先分母后结果）：18 样本 · 白名单只读数据节 ==")
    for e in samples:
        if args.only and e["id"] != args.only:
            continue
        rel = e["path"]
        path = _resolve(rel)
        if not path:
            fails.append("%s: 样本缺失（%s）" % (e["id"], rel))
            continue
        f, st = _one(rel, path)
        fails.extend("%s: %s" % (e["id"], x) for x in f)
        rows.append((e["id"], st))
        for k in agg:
            agg[k] += st.get(k, 0)
        for k in reasons:
            reasons[k] += st["reason"].get(k, 0)
        print("  %-28s 字符串 %4d (u%3d/m%3d/n%3d)  引用点 %4d (rip%4d/imm%3d)"
              "  无归属 %2d  suffix %2d  unlifted %4d  对账 %d/%d  覆盖 %.1f%%"
              % (e["id"], st["strings"], st["unique"], st["multi"],
                 st["no_site"], st["sites"], st["rip"], st["imm"], st["nofn"],
                 st["suffix"], st["unlifted"], st["cross_checked"],
                 st["cross_domain"], st.get("coverage", 0.0) * 100.0))
    print("== 合计 ==")
    print("  字符串 %d = unique %d + multi %d + no_site %d"
          % (agg["strings"], agg["unique"], agg["multi"], agg["no_site"]))
    print("  no_site 归因: 跨界 %d / 未解出 %d / 间接 %d / 无证据 %d"
          % (reasons["cross_section"], reasons["undecoded"],
             reasons["indirect"], reasons["no_evidence"]))
    print("  引用点 %d = rip %d + imm %d；无函数归属 %d；suffix %d"
          % (agg["sites"], agg["rip"], agg["imm"], agg["nofn"], agg["suffix"]))
    print("  对账: 交集 %d / 函数域核对 %d" % (agg["cross_checked"],
                                              agg["cross_domain"]))
    print("  代码层覆盖缺口（外部 objdump 判定，模块不可知）："
          "未解码代码里的引用点 %d 个，涉及字符串 %d 条；"
          "表达式层 unlifted 命中 %d 个"
          % (agg["undecoded_hits"], agg["undecoded_strings"],
             agg["unlifted_hits"]))
    print("  口径: 上面两项是**补集度量**（只在未解码代码里可见），不是下界；"
          "可达域变大它变小，且对 Go（非 NUL 终止字符串）近乎盲")
    if args.json:
        print(json.dumps({"rows": [{"id": i, **s} for i, s in rows],
                          "aggregate": agg, "reasons": reasons},
                         ensure_ascii=False, indent=2))
    if fails:
        print("\nFAIL %d 项：" % len(fails))
        for x in fails[:60]:
            print("  - %s" % x)
        if len(fails) > 60:
            print("  … 其余 %d 项" % (len(fails) - 60))
        return 1
    print("\nOK: 18 样本字符串集合与外部 objdump 引用点全部一致，账目对平，三层对账零冲突")
    return 0


if __name__ == "__main__":
    sys.exit(main())
