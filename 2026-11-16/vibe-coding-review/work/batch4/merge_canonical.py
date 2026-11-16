# -*- coding: utf-8 -*-
"""把 规则库_R33-R119.md 的规范定义合并进 pack/rules.json，并产出机器可读镜像。

原则：
- 只新增 canonical 字段，不删除、不覆盖 mine_rules.py 生成的 statement/source/status/alternates。
- 以 Markdown 为唯一人读来源，本脚本解析 Markdown，避免二次抄写导致漂移。
- 可重复运行（幂等）。
"""
import json
import os
import re
import sys

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
MD = os.path.join(ROOT, "pack", "02_规则库", "规则库_R33-R119.md")
RULES = os.path.join(ROOT, "pack", "rules.json")
OUT = os.path.join(ROOT, "2026-11-16", "vibe-coding-review", "work", "batch4")

# 附录 A：9 条撞号裁决（与 规则库_R33-R119.md 附录 A 一致）
VERDICTS = {
    "R18": "范围外(R01-R32)：以 规则库_R01-R32.md:41 为准；RE-ROADMAP.md:68 是归档清单误匹配。置信度高。",
    "R19": "范围外(R01-R32)：以 规则库_R01-R32.md:46 为准；RE-ROADMAP.md:69 是 M4 技术要点摘要。置信度高。",
    "R21": "范围外(R01-R32)：以 规则库_R01-R32.md:50 为准；RE-ROADMAP.md:69 是归档清单误匹配。置信度高。",
    "R25": "范围外(R01-R32)：以 规则库_R01-R32.md:63 为准；PROGRESS.md:46 是实证描述，不是定义。置信度高。",
    "R27": "范围外(R01-R32)：以 规则库_R01-R32.md:67 为准；PROGRESS.md:45 是三板斧总述。置信度高。",
    "R48": "非撞号：同一规则两处记录。规则句取 PROGRESS.md:73，三分支细化取 CHANGELOG.md:23。置信度高。",
    "R75": "旧 source 是提及行非定义行：定义取 PROGRESS.md:158 / CHANGELOG.md:68；CHANGELOG.md:79 仅引用前文。置信度高。",
    "R102": "同一规则长短两版：完整版取 CHANGELOG.md:96；PROGRESS.md:264 为摘要。置信度高。",
    "R110": "同一规则长短两版：完整版取 CHANGELOG.md:103；PROGRESS.md:306 为摘要；窗口大小材料不足。置信度高。",
}

# 附录 B：21 条多写法唯一化（与 规则库_R33-R119.md 附录 B 一致）
UNIQUE = {
    "R12": "以 规则库_R01-R32.md:27 原文为准（范围外）。",
    "R15": "以 规则库_R01-R32.md:34 原文为准（范围外）。",
    "R23": "以 规则库_R01-R32.md:56 原文为准（范围外）。",
    "R24": "以 规则库_R01-R32.md:58 原文为准（范围外）。",
    "R30": "以 规则库_R01-R32.md:78 原文为准（范围外）。",
    "R31": "以 规则库_R01-R32.md:80 原文为准（范围外）。",
    "R45": "两句话版（CHANGELOG.md:32）：禁止把猜测当已知；不禁止提出有证据的候选。",
    "R69": "三分类+证据要求+禁止『疑似』（CHANGELOG.md:60）。",
    "R71": "跳 legacy 前缀+REX 后 opcode；ff 还须核 ModRM.reg（PROGRESS.md:151）。",
    "R74": "每条硬不变量至少一条独立来源路径，来源须写入文档（PROGRESS.md:158）。",
    "R77": "四类齐全：取输入/取被测输出/仅定位自证/当期望值（PROGRESS.md:180）。",
    "R84": "含 --selftest 五类注入；不 import rekit.expr/elf/pe、不复用中间结果（CHANGELOG.md:79）。",
    "R92": "scope=full/sampled，sampled 必须附名单，缺名单 ValueError（CHANGELOG.md:86）。",
    "R94": "四分类+定义，decoder_defect>0 必须修复或登记（CHANGELOG.md:88）。",
    "R95": "五项结构判据+禁止按结果挑样+合成/真实分栏+登记表三栏（CHANGELOG.md:89 + PROGRESS.md:238）。",
    "R108": "只合成+source 三元组+缺失二分+同源生成（CHANGELOG.md:102）。",
    "R113": "四级二分恒等式+RVA=0 逐类计数+unclassified 单列（CHANGELOG.md:105）。",
    "R116": "两层终结符清单+EH 边界切块+越界单列（CHANGELOG.md:106，剔除混入的 R117 文本）。",
    "R117": "EH 只单列结构不建 CFG 边；leave 建边并检查越区（CHANGELOG.md:106）。",
    "R118": "五类原因+bad_parent 为必要补充（CHANGELOG.md:106，剔除混入的 R119 文本）。",
    "R119": "分母为 0 一律 FAIL+口径文档代码双写死+可失败自证（CHANGELOG.md:106 + PROGRESS.md:330）。",
}

FIELDS = [("canonical", "规则原意"), ("constraint_object", "约束对象"),
          ("check_method", "判定方式"), ("enforced_at", "落地位置"),
          ("basis", "依据")]


def parse_md(path):
    text = open(path, encoding="utf-8").read()
    blocks = re.split(r"\n#### ", text)
    out = {}
    for b in blocks[1:]:
        m = re.match(r"(R\d{2,3})\s*·\s*(.+)", b)
        if not m:
            continue
        rid = m.group(1)
        title = m.group(2).strip()
        rec = {"id": rid, "title": title}
        for key, label in FIELDS:
            mm = re.search(r"^- \*\*" + re.escape(label) + r"\*\*：(.+)$", b, re.M)
            rec[key] = mm.group(1).strip() if mm else ""
        mm = re.search(r"^- \*\*状态\*\*：(.+)$", b, re.M)
        rec["status"] = mm.group(1).strip() if mm else ""
        out[rid] = rec
    return out


def confidence(status_text):
    if "材料不足" in status_text:
        return "partial"
    if "文档级" in status_text:
        return "documented"
    return "high"


def main():
    md = parse_md(MD)
    expected = ["R%02d" % i for i in range(33, 120)]
    missing = [r for r in expected if r not in md]
    extra = [r for r in md if r not in expected]
    if missing or extra:
        print("PARSE ERROR missing=%s extra=%s" % (missing, extra))
        sys.exit(1)

    doc = json.load(open(RULES, encoding="utf-8"))
    by_id = {r["id"]: r for r in doc["rules"]}

    merged = 0
    for rid in expected:
        rec = md[rid]
        target = by_id.get(rid)
        if target is None:
            print("WARN rules.json missing", rid)
            continue
        target["title"] = rec["title"]
        target["canonical"] = rec["canonical"]
        target["constraint_object"] = rec["constraint_object"]
        target["check_method"] = rec["check_method"]
        target["enforced_at"] = rec["enforced_at"]
        target["basis"] = rec["basis"]
        target["canonical_status"] = rec["status"]
        target["confidence"] = confidence(rec["status"])
        merged += 1

    for rid, v in VERDICTS.items():
        if rid in by_id:
            by_id[rid]["verdict"] = v
    for rid, u in UNIQUE.items():
        if rid in by_id:
            by_id[rid]["unique_wording"] = u

    doc["canonical_coverage"] = {
        "generated_at": "2026-11-16",
        "generated_by": "2026-11-16\\vibe-coding-review\\work\\batch4\\merge_canonical.py",
        "source_md": "pack\\02_规则库\\规则库_R33-R119.md",
        "merged_rules": merged,
        "range": "R33–R119",
        "field_policy": "只新增 canonical 字段；statement/source/status/alternates 等 mined 字段保持原样",
    }
    json.dump(doc, open(RULES, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

    cover = {
        "schema": "canonical_coverage/1",
        "generated_at": "2026-11-16",
        "source_md": "pack\\02_规则库\\规则库_R33-R119.md",
        "total": len(expected),
        "fully_defined": sum(1 for r in expected if md[r]["canonical"]),
        "material_insufficient": [r for r in expected if "材料不足" in md[r]["status"]],
        "doc_level_only": [r for r in expected if confidence(md[r]["status"]) == "documented"],
        "suspects_adjudicated": len(VERDICTS),
        "multi_candidate_unique": len(UNIQUE),
        "rules": [
            {
                "id": r,
                "title": md[r]["title"],
                "canonical": md[r]["canonical"],
                "constraint_object": md[r]["constraint_object"],
                "check_method": md[r]["check_method"],
                "enforced_at": md[r]["enforced_at"],
                "basis": md[r]["basis"],
                "canonical_status": md[r]["status"],
                "confidence": confidence(md[r]["status"]),
            }
            for r in expected
        ],
    }
    json.dump(cover, open(os.path.join(OUT, "canonical_coverage.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    print("merged=%d total=%d" % (merged, len(expected)))
    print("material_insufficient=%s" % cover["material_insufficient"])
    print("doc_level_only=%s" % cover["doc_level_only"])
    print("suspects=%d multi_unique=%d" % (len(VERDICTS), len(UNIQUE)))


if __name__ == "__main__":
    main()
