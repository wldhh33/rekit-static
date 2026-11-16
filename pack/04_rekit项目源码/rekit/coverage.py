#!/usr/bin/env python3
# rekit.coverage — 覆盖率报告（M9 收敛线 C：分子 / 分母 / 分母口径三件套）
#
# 为什么单独一层：
#   M8 的 `strxref.coverage` 只给「已解出字节 / .text 文件字节」，分母是“字节”，
#   不是“指令条数”；不同节的填充/数据比例会把同一个解码器算成完全不同的分数。
#   本层的分母口径写死为【GNU objdump 2.47 在同一节地址范围内列出的指令条数】，
#   由外部工具独立计数——不用 recdesc 自己的结果当分母，避免“自己判自己”。
#
# 对账恒等式（任何一条不成立即视为报告无效，不是“差一点”）：
#   ours_total = matched + len_conflict + ours_only          （我方条数的去向）
#   denominator = matched + len_conflict + objdump_only      （分母条数的去向）
#   matched  = 同起始地址且同长度；len_conflict 单列，不计入分子
#
# 分子只认「同址同长」：同址不同长说明边界判定有分歧，归 len_conflict，
# 既不粉饰成命中，也不偷偷算进分子。
#
# 抽样 vs 全样本：
#   单样本报告只写 sample_scope="single"；批量汇总必须显式传
#   aggregate(..., scope="full"|"sampled", sample_set=[...])，且不允许两种口径混算。
#   “全样本”= 清单里全部样本都跑了；“抽样”= 只跑了清单的子集，汇总里必须带子集名单。
#
# objdump 不可用/失败时：报告 status="unavailable"，分母为 None，ratio 为 None，
# 绝不把“没量到”写成 0%。
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

CAVEATS = [
    "分子只认 objdump 同址同长；同址不同长单列 len_conflict，不计入分子",
    "分母 = objdump 在该节地址范围内列出的指令条数；objdump 也把数据当指令时，"
    "分母会包含数据，这是“外部工具口径”的已知偏差，不是本层修饰",
    "objdump 失败/不可用时 ratio=None（不写 0），并报 status=unavailable",
    "字节覆盖率另算：我方字节并集 / 节文件字节，与指令条数口径并列，不互相替代",
    "批量汇总必须声明 full / sampled；sampled 必须列出子集名单，禁止混算",
]

DENOMINATOR_SCOPE = (
    "分母 = GNU objdump 2.47 对同一文件、同一节地址范围 [VA, VA+size) "
    "用 `objdump -d -M intel` 列出的指令条数（外部工具独立计数；"
    "不以 recdesc 自身解出的条数为分母）")
NUMERATOR_SCOPE = (
    "分子 = recdesc 已解出且与 objdump 同起始地址、同长度的指令条数")

_LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")


def objdump_exe():
    return shutil.which("objdump")


def _objdump_version(exe):
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, timeout=30)
        first = out.stdout.decode("utf-8", "replace").splitlines()
        return first[0].strip() if first else "unknown"
    except Exception as e:                      # 环境问题不影响报告结构
        return "unknown(%s)" % e


def _image_base(path, data):
    if data[:4] == b"\x7fELF":
        return 0
    from . import pe
    return pe.parse(path)["image_base"]


def objdump_instructions(path, sec, image_base=None, timeout=600):
    """外部 objdump 列出的指令：返回 {"status","instructions","error","command"}。

    instructions[i] = {"addr","length","text"}；addr 已换算成节内 VA
    （PE 减去 ImageBase）。`(bad)` 行仍按其字节数计数——objdump 认为它是指令
    边界，只是语义非法；是否算“解出”由使用方决定，本层只如实计数并给 bad 计数。
    """
    exe = objdump_exe()
    if exe is None:
        return {"status": "unavailable", "instructions": [], "bad": 0,
                "error": "PATH 中找不到 objdump", "command": None}
    if image_base is None:
        data = open(path, "rb").read(0x40)
        image_base = _image_base(path, data)
    start = image_base + sec["va"]
    stop = start + sec["size"]
    cmd = [exe, "-d", "-M", "intel", "--insn-width=16",
           "--start-address=0x%x" % start, "--stop-address=0x%x" % stop, path]
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env)
    except Exception as e:
        return {"status": "error", "instructions": [], "bad": 0,
                "error": "%s: %s" % (type(e).__name__, e),
                "command": " ".join(cmd)}
    if out.returncode != 0:
        return {"status": "error", "instructions": [], "bad": 0,
                "error": "objdump exit %d: %s"
                         % (out.returncode,
                            out.stderr.decode("utf-8", "replace").strip()[:200]),
                "command": " ".join(cmd)}
    ins, bad = [], 0
    # Windows 上 objdump 按本地代码页回显文件名；只有 `addr: bytes text` 行参与计数。
    for ln in out.stdout.decode("utf-8", "replace").splitlines():
        m = _LINE.match(ln)
        if not m:
            continue
        raw = m.group(2).split()
        if not raw:
            continue
        text = m.group(3).strip()
        if text.startswith("(bad)"):
            bad += 1
        ins.append({"addr": int(m.group(1), 16) - image_base,
                    "length": len(raw), "text": text})
    ins.sort(key=lambda x: x["addr"])
    return {"status": "ok", "instructions": ins, "bad": bad, "error": None,
            "command": " ".join(cmd)}


def _merge_len(intervals):
    """区间并集长度（重叠只算一次）。"""
    if not intervals:
        return 0
    iv = sorted(intervals)
    total = 0
    lo, hi = iv[0]
    for a, b in iv[1:]:
        if a > hi:
            total += hi - lo
            lo, hi = a, b
        elif b > hi:
            hi = b
    return total + hi - lo


def build(path, section=".text", res=None, objdump=None, sample_scope="single",
          sample_set=None):
    """单样本覆盖率报告。res/objdump 可注入（测试与批量复用），默认现算。"""
    from . import disasm, recdesc
    sec = disasm.find_section(path, section)
    if sec is None:
        return {"path": str(path), "section": section, "status": "no_section",
                "denominator": None, "numerator": None, "ratio": None,
                "denominator_scope": DENOMINATOR_SCOPE,
                "numerator_scope": NUMERATOR_SCOPE,
                "sample_scope": sample_scope, "sample_set": sample_set,
                "error": "缺少可扫描节 %s（可能已加壳/改名）" % section,
                "caveats": list(CAVEATS)}
    res = res if res is not None else recdesc.descend(path, section)
    obj = objdump if objdump is not None else objdump_instructions(path, sec)

    ours = [i for i in res["instructions"] if i.get("status", "ok") == "ok"]
    theirs = obj["instructions"]
    by_addr = {i["addr"]: i for i in ours}
    tby = {i["addr"]: i for i in theirs}

    matched, ours_only = [], []
    len_conflict_n = 0
    len_conflict_sample = []
    objdump_only_n = 0
    objdump_only_sample = []
    for i in ours:
        t = tby.get(i["addr"])
        if t is None:
            ours_only.append(i["addr"])
        elif t["length"] == i["length"]:
            matched.append(i["addr"])
        else:
            len_conflict_n += 1
            if len(len_conflict_sample) < 20:
                len_conflict_sample.append({"addr": i["addr"],
                                            "ours_len": i["length"],
                                            "objdump_len": t["length"],
                                            "objdump_text": t["text"]})
    for t in theirs:
        if t["addr"] not in by_addr:
            objdump_only_n += 1
            if len(objdump_only_sample) < 20:
                objdump_only_sample.append(t["addr"])

    # 仅我方地址再分两类：落在 objdump 某条指令内部（我方失步）vs 完全未被列出
    t_sorted = sorted(((t["addr"], t["length"]) for t in theirs))
    starts = [a for a, _l in t_sorted]
    inside_objdump = unlisted = 0
    import bisect
    for a in ours_only:
        k = bisect.bisect_right(starts, a) - 1
        if k >= 0 and starts[k] < a < starts[k] + t_sorted[k][1]:
            inside_objdump += 1
        else:
            unlisted += 1

    denom = len(theirs) if obj["status"] == "ok" else None
    ours_total = len(ours)
    ok = (obj["status"] == "ok"
          and ours_total == len(matched) + len_conflict_n + len(ours_only)
          and denom == len(matched) + len_conflict_n + objdump_only_n)
    rep = {
        "path": str(path), "section": section, "status": obj["status"],
        "sample_scope": sample_scope, "sample_set": sample_set,
        "denominator_scope": DENOMINATOR_SCOPE,
        "numerator_scope": NUMERATOR_SCOPE,
        "numerator": len(matched) if denom is not None else None,
        "denominator": denom,
        "ratio": (len(matched) / denom) if denom else None,
        "ratio_addr_only": ((len(matched) + len_conflict_n) / denom)
                           if denom else None,
        "ours_total": ours_total,
        "matched": len(matched),
        "len_conflict": len_conflict_n,
        "len_conflict_sample": len_conflict_sample,
        "ours_only": len(ours_only),
        "ours_only_sample": ours_only[:20],
        "ours_only_inside_objdump": inside_objdump,
        "ours_only_unlisted": unlisted,
        "objdump_only": objdump_only_n,
        "objdump_only_sample": objdump_only_sample,
        "objdump_bad": obj["bad"],
        "identity_ok": ok,
        "section_bytes": sec["size"],
        "ours_bytes": _merge_len([(i["addr"], i["addr"] + i["length"])
                                  for i in ours]),
        "objdump_bytes": _merge_len([(t["addr"], t["addr"] + t["length"])
                                     for t in theirs]),
        "matched_bytes": _merge_len([(a, a + by_addr[a]["length"])
                                     for a in matched]),
        "byte_coverage_ours": (_merge_len([(i["addr"], i["addr"] + i["length"])
                                           for i in ours]) / sec["size"])
                              if sec["size"] else None,
        "objdump_version": _objdump_version(objdump_exe()) if obj["status"] == "ok"
                           else None,
        "objdump_command": obj.get("command"),
        "objdump_error": obj.get("error"),
        "recdesc_stats": dict(res.get("stats") or {}),
        "caveats": list(CAVEATS),
    }
    return rep


def aggregate(reports, scope, sample_set=None, note=None):
    """批量汇总：只允许 full / sampled 两种口径，sampled 必须给子集名单。"""
    if scope not in ("full", "sampled"):
        raise ValueError("scope 只能是 full / sampled")
    if scope == "sampled" and not sample_set:
        raise ValueError("sampled 汇总必须列出子集名单（sample_set）")
    usable = [r for r in reports if r.get("denominator")]
    num = sum(r["numerator"] for r in usable)
    den = sum(r["denominator"] for r in usable)
    bad = [r for r in reports if r.get("status") != "ok"]
    return {
        "scope": scope, "sample_set": sample_set, "note": note,
        "samples_total": len(reports), "samples_measured": len(usable),
        "samples_unavailable": len(bad),
        "unavailable": [{"path": r["path"], "error": r.get("objdump_error")
                         or r.get("error")} for r in bad],
        "numerator": num, "denominator": den,
        "ratio": (num / den) if den else None,
        "denominator_scope": DENOMINATOR_SCOPE,
        "numerator_scope": NUMERATOR_SCOPE,
        "identity_ok": all(r.get("identity_ok") for r in usable),
        "rows": [{"path": os.path.basename(r["path"]),
                  "numerator": r.get("numerator"),
                  "denominator": r.get("denominator"),
                  "ratio": r.get("ratio")} for r in reports],
    }


def render(rep):
    lines = ["── 覆盖率（分子/分母/口径）──",
             "文件: %s  节: %s" % (rep["path"], rep["section"]),
             "分母口径: %s" % rep["denominator_scope"],
             "分子口径: %s" % rep["numerator_scope"]]
    if rep["status"] != "ok":
        lines.append("状态: %s —— 分母不可得，ratio 不写 0" % rep["status"])
        if rep.get("error") or rep.get("objdump_error"):
            lines.append("原因: %s" % (rep.get("error") or rep.get("objdump_error")))
        return "\n".join(lines)
    lines += [
        "分子 %d / 分母 %d = %.4f（同址同长）" % (rep["numerator"],
                                                rep["denominator"],
                                                rep["ratio"]),
        "我方条数 %d = 同址同长 %d + 同址不同长 %d + 仅我方 %d"
        % (rep["ours_total"], rep["matched"], rep["len_conflict"],
           rep["ours_only"]),
        "分母条数 %d = 同址同长 %d + 同址不同长 %d + 仅 objdump %d"
        % (rep["denominator"], rep["matched"], rep["len_conflict"],
           rep["objdump_only"]),
        "字节口径（并列，不替代）: 我方 %d / 节 %d = %.4f"
        % (rep["ours_bytes"], rep["section_bytes"], rep["byte_coverage_ours"]),
        "objdump %s；bad %d 条" % (rep["objdump_version"], rep["objdump_bad"]),
        "恒等式: %s" % ("成立" if rep["identity_ok"] else "不成立（报告无效）"),
        "样本口径: %s%s" % (rep["sample_scope"],
                          ("  子集=%s" % ",".join(rep["sample_set"]))
                          if rep.get("sample_set") else ""),
    ]
    for c in rep["caveats"]:
        lines.append("  ! %s" % c)
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rekit coverage",
        description="覆盖率报告：分子/分母/分母口径（分母来自外部 objdump）")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = build(a.file, a.section)
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(render(rep))
    return 0 if rep["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
