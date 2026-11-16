# 用 pack/rules.json 的 canonical 字段重建 batch4/canonical_coverage.json，保持三处一致。
# 只重建 87 条 R33–R119 的条目；不触碰 mined 字段。
import json
import os

ROOT = r"D:\数据\下载\逆向学习工作体系_2026-11-15"
REG = os.path.join(ROOT, "pack", "rules.json")
COV = os.path.join(ROOT, r"2026-11-16\vibe-coding-review\work\batch4\canonical_coverage.json")

FIELDS = ["id", "title", "canonical", "constraint_object", "check_method",
          "enforced_at", "basis", "canonical_status", "confidence"]


def main():
    reg = json.load(open(REG, encoding="utf-8"))
    cov = json.load(open(COV, encoding="utf-8"))
    by_id = {r["id"]: r for r in reg["rules"]}
    out = []
    for e in cov["rules"]:
        r = by_id[e["id"]]
        if "canonical" not in r:
            raise SystemExit("rule %s has no canonical field" % e["id"])
        out.append({k: r.get(k, e.get(k)) for k in FIELDS})
    cov["rules"] = out
    cov["generated_at"] = "2026-11-16（8 项裁决后重建）"
    cov["material_insufficient"] = []
    cov["doc_level_only"] = [e["id"] for e in out
                             if "文档级" in (e.get("canonical_status") or "")]
    cov["fully_defined"] = len(out)
    cov["adjudication_record"] = r"2026-11-16\vibe-coding-review\work\batch5\RULE_ADJUDICATIONS.md"
    with open(COV, "w", encoding="utf-8") as f:
        json.dump(cov, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("entries =", len(out), "doc_level_only =", len(cov["doc_level_only"]))


if __name__ == "__main__":
    main()
