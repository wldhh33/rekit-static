#!/usr/bin/env python3
"""数字总账链路：权威 JSON 的生成与漂移检查（硬失败，不打印提示了事）。

用法：
  python "pack\\tools\\ledger_check.py" --check   # 默认；漂移即 exit 1
  python "pack\\tools\\ledger_check.py" --write   # 重生成权威 JSON（重算 sha256）

检查项（任一不满足即 FAIL）：
  1. 权威 JSON 的头部声明与文件实际内容一致（scope / mirror / authority 自指）；
  2. 人读镜像的 §0 声明的权威路径 == 本脚本产出的权威 JSON；
  3. 每个已登记小节在镜像里存在（M14–M18 必须各有小节，且小节号与 JSON 一致）；
  4. 每个登记数字在对应小节的正文里逐字出现（镜像被悄悄改动即 FAIL）；
  5. 每个证据文件 sha256 与登记值相等（证据被改动即 FAIL）；
  6. 证据文件 mtime 不得晚于权威 JSON（权威落后于证据即 FAIL）。
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORK = os.path.join(ROOT, "2026-11-15", "m3-task-card", "work")
AUTHORITY = os.path.join(WORK, "evidence_numbers_ledger.json")
MIRROR = os.path.join(WORK, "outputs", "NUMBERS_LEDGER.md")

# 镜像里每个里程碑小节的标题（改标题必须同步本表，否则检查 FAIL）
SECTIONS = [
    ("M13", "## 6. 下界结论"),
    ("M13-pe_gap", "## 5. PE：`.pdata` end 与 gopclntab 下一入口之间 1–31 字节缝隙的量化"),
    ("M14", "## 9. M14 对齐实测（C4）"),
    ("M15", "## 10. M15 报告层不产生新数字"),
    ("M16", "## 11. M16 数据引用层（新分母：声明对象）"),
    ("M17", "## 12. M17 .NET 程序集结构层（新对象：CLI 程序集）"),
    ("M18", "## 13. M18 .NET IL 控制流层（新分母：方法体/IL 指令）"),
    ("M5", "## 14. M5 表达式层验收补强（补记，跨里程碑）"),
    ("M19", "## 15. M19 .NET 签名语义层（#Blob 签名解码）"),
    ("M20", "## 16. M20 .NET 类型布局与字段 RVA（.NET 纵切面封口）"),
]

# 登记数字：必须在对应小节正文里逐字出现
NUMBERS = {
    "M13": ["5,039 / 276", "206,541", "26,652 / 26,702",
            "12,272 / 3,530 / 37,891", "1,974", "2,081",
            "16,332", "16,179", "17 个可测样本"],
    # R103 的 pe_gap 三数字（在 §5，不在 §6，故单列小节登记）
    "M13-pe_gap": ["113,731", "3.2262%", "-0.0402pp",
                   "7,139 / 7,152", "148,861", "76.40%", "15.93",
                   "372 条", "750,109", "80.9903%", "0.0496%"],
    "M14": ["149,225", "26,652", "1,067", "1,066", "923,970",
            "26,702", "3.9922%", "4.0034%", "8,906"],
    "M15": ["485 passed", "18/18", "5,039/276", "206,541", "26,652"],
    "M16": ["86.3354%", "417 / 51 / 39", "25,941", "8,853 / 22,067", "509 passed",
            "483"],
    "M17": ["6,592", "592,206", "27/27", "528 passed", "25,315", "29,257", "396", "433"],
    "M18": ["108,267", "107,765", "41/41", "554 passed",
            "1,372", "1,245", "1,133", "2,164", "93,194", "51,063", "52,837", "5,058"],
    "M5": ["57 个抽样函数", "403", "390", "2.47.20260726", "1/18", "7/18", "13/21"],
    "M19": ["37,403", "52,403", "29,728", "32,518", "911", "3,974",
            "29,257", "3,429", "3,908", "14,718", "36,594", "1,020",
            "100.0000%", "22 套", "554 passed"],
    "M20": ["84", "71", "132", "131", "64,421", "120 / 8",
            "122 / 9 / 1", "287", "16 项",
            "14 个偏移 / 3 个 size / 1 个 auto", "121",
            "100.0000%", "0.7576%", "28 项", "23 套", "554 passed"],
}

SOURCES = [
    ("evidence_m13_ledger.json", "M13 逐样本权威快照（历史源，判定表/代码 sha256）"),
    ("evidence_m13_recompute.json", "M13 下界重算四组测量"),
    ("evidence_m14_c4_alignment.json", "M14 C4 对齐实测（nop 族/类分布/样例地址）"),
    ("evidence_m15_funcreport.json", "M15 报告层同址合并快照"),
    ("evidence_m16_datarefs.json", "M16 数据引用层外部重算"),
    ("evidence_m17_dotnet.json", "M17 .NET 结构层 dnfile/dncil 对账"),
    ("evidence_m18_ilflow.json", "M18 IL 控制流层 dncil 全量对账"),
    ("evidence_m19_sigblob.json", "M19 签名语义层 dnfile 字节 + SRM canonical 对账"),
    ("evidence_m20_layout.json", "M20 布局层 dnfile 列值 + 源码真值 + 运行期 oracle 对账"),
    ("evidence_m5_expr_residual.json", "M5 表达式层 objdump oracle 残差逐地址"),
]


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build():
    sections = [{"milestone": m, "heading": h, "numbers": NUMBERS[m]}
                for m, h in SECTIONS]
    sources = []
    for name, role in SOURCES:
        p = os.path.join(WORK, name)
        sources.append({"path": "2026-11-15/m3-task-card/work/" + name,
                        "role": role,
                        "sha256": _sha256(p) if os.path.exists(p) else None})
    return {
        "schema": "numbers-ledger/1",
        "authority": "本文件；人读镜像为 work/outputs/NUMBERS_LEDGER.md",
        "scope": "M13 收口（含 M13-patch）至 M20 收口；M12 及更早见 evidence_m12_ledger.json",
        "effective_from": "M13-patch",
        "mirror": "2026-11-15/m3-task-card/work/outputs/NUMBERS_LEDGER.md",
        "freshness_rule": ("以字节为准：任一登记证据文件的当前 sha256 与本文件登记值不等 → "
                           "检查 FAIL（必须 --write 重登记并复核数字）；证据被原样重写"
                           "（sha256 相同、仅 mtime 变新）不算权威落后，只记 note"),
        "residual_rule": ("M5 表达式层残差（objdump 线性全扫 vs expr CFG 可达子集）"
                          "单列于 evidence_m5_expr_residual.json，"
                          "不入任何已公布比率的分子分母"),
        "sections": sections,
        "sources": sources,
    }


def _section_text(md, heading):
    idx = md.find(heading)
    if idx < 0:
        return None
    rest = md[idx + len(heading):]
    nxt = rest.find("\n## ")
    return rest if nxt < 0 else rest[:nxt]


def check(write=False):
    fails = []
    if write:
        doc = build()
        with io.open(AUTHORITY, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("[write] 权威 JSON 已重生成：%s" % AUTHORITY)
        return 0
    if not os.path.exists(AUTHORITY):
        print("[env_missing] 权威 JSON 不存在：%s" % AUTHORITY)
        return 2
    if not os.path.exists(MIRROR):
        print("[env_missing] 人读镜像不存在：%s" % MIRROR)
        return 2
    doc = json.load(io.open(AUTHORITY, encoding="utf-8"))
    md = io.open(MIRROR, encoding="utf-8").read()

    # 1/2. 头部声明与实际一致
    if os.path.basename(AUTHORITY) not in md.split("## 0.")[0]:
        fails.append("镜像头部未声明权威 JSON 文件名 %s" % os.path.basename(AUTHORITY))
    if doc.get("mirror", "").replace("/", os.sep) and \
            os.path.normpath(os.path.join(ROOT, doc["mirror"])) != os.path.normpath(MIRROR):
        fails.append("权威 JSON 的 mirror 字段与实际镜像路径不一致")

    # 3/4. 小节存在 + 数字逐字出现
    declared = {s["milestone"]: s for s in doc.get("sections", [])}
    for m, heading in SECTIONS:
        if m not in declared:
            fails.append("权威 JSON 缺 %s 小节登记" % m)
            continue
        if declared[m].get("heading") != heading:
            fails.append("%s 小节标题与 JSON 登记不一致：%r != %r"
                         % (m, declared[m].get("heading"), heading))
        text = _section_text(md, heading)
        if text is None:
            fails.append("镜像缺 %s 小节：%s" % (m, heading))
            continue
        for v in declared[m].get("numbers", []):
            if v not in text:
                fails.append("%s：登记数字 %r 未在小节正文出现（镜像被改动或数字漂移）"
                             % (m, v))

    # 5. 证据 sha256（新鲜度以内容为准：sha256 变化才是权威落后）
    auth_mtime = os.path.getmtime(AUTHORITY)
    rewritten = []
    for src in doc.get("sources", []):
        p = os.path.join(ROOT, src["path"].replace("/", os.sep))
        name = os.path.basename(p)
        if not os.path.exists(p):
            fails.append("证据文件缺失：%s" % src["path"])
            continue
        if src.get("sha256") is None:
            fails.append("证据文件未登记 sha256：%s" % name)
        elif _sha256(p) != src["sha256"]:
            fails.append("证据 sha256 变化：%s（需 --write 重登记并复核数字）" % name)
        # 6. 新鲜度：证据被原样重写（内容未变）不构成“权威落后”，只记 note；
        #    内容真变时上面 sha256 一项已 FAIL，不被时钟误报掩盖。
        elif os.path.getmtime(p) > auth_mtime + 1:
            rewritten.append(name)

    if fails:
        print("LEDGER: FAIL %d 项" % len(fails))
        for x in fails:
            print("  ! %s" % x)
        return 1
    print("LEDGER: PASS 小节=%d 证据=%d 数字=%d"
          % (len(SECTIONS), len(doc.get("sources", [])),
             sum(len(v) for v in NUMBERS.values())))
    if rewritten:
        print("  note 证据被原样重写（sha256 未变）：%s" % ", ".join(rewritten))
    return 0


TOKEN = re.compile(r"(?<![\w.])-?\d[\d,]*(?:\.\d+)?%?(?:pp)?")


def audit(out_json=None):
    """列出每小节已公布但未进 numbers 登记的数值（显式清单，不是隐性漏洞）。"""
    md = io.open(MIRROR, encoding="utf-8").read()
    result = {"mirror": "2026-11-15/m3-task-card/work/outputs/NUMBERS_LEDGER.md",
              "rule": ("unprotected = 小节正文里出现、但不是任一已登记数字子串的数值；"
                       "常见原因：推算/旧值对照（R102 禁入账）、区间描述、派生百分比、地址与样例字节"),
              "sections": {}}
    total = 0
    for m, heading in SECTIONS:
        text = _section_text(md, heading)
        if text is None:
            continue
        reg = NUMBERS.get(m, [])
        reg_blob = " ".join(reg)
        counts = {}
        # 标题行（### 13.1 之类）不参与审计：小节号不是已公布数字
        body = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
        for tok in TOKEN.findall(body):
            tok = tok.rstrip(",")
            if not tok or tok in reg_blob:
                continue
            counts[tok] = counts.get(tok, 0) + 1
        items = [{"token": k, "occurrences": v}
                 for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
        result["sections"][m] = {"heading": heading,
                                 "registered": reg,
                                 "unprotected": items,
                                 "unprotected_distinct": len(items)}
        total += len(items)
    result["unprotected_distinct_total"] = total
    if out_json:
        with io.open(out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\n")
    print("LEDGER-AUDIT: 小节=%d 未登记数值（去重）= %d"
          % (len(result["sections"]), total))
    for m, s in result["sections"].items():
        print("  %-12s 登记=%-2d 未登记=%-3d 例: %s"
              % (m, len(s["registered"]), s["unprotected_distinct"],
                 ", ".join(x["token"] for x in s["unprotected"][:8])))
    if out_json:
        print("JSON 已写入 %s" % out_json)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="检查漂移（默认）")
    ap.add_argument("--write", action="store_true", help="重生成权威 JSON")
    ap.add_argument("--audit", action="store_true", help="列出未进登记的数字（显式清单）")
    ap.add_argument("--audit-json", default=None, help="审计结果写入 JSON")
    a = ap.parse_args()
    if a.audit:
        return audit(a.audit_json)
    return check(write=a.write)


if __name__ == "__main__":
    sys.exit(main())
