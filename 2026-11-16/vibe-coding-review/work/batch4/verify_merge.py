# -*- coding: utf-8 -*-
"""校验 merge 只新增/改写 canonical 字段，mined 字段与备份逐条一致。"""
import json

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
B = ROOT + r"\2026-11-16\vibe-coding-review\work\batch4\rules.before_canonical.json"
N = ROOT + r"\pack\rules.json"

old = json.load(open(B, encoding="utf-8"))
new = json.load(open(N, encoding="utf-8"))
o = {r["id"]: r for r in old["rules"]}
n = {r["id"]: r for r in new["rules"]}

MINED = ["statement", "source", "kind", "milestone", "status", "agree_sources",
         "n_candidates", "closest_other_wording", "alternates"]
bad = []
for rid in o:
    for k in MINED:
        if o[rid].get(k) != n[rid].get(k):
            bad.append((rid, k))
            break

new_only = set(n["R01"] if False else [])  # noqa
added = sorted(set(n["R01"].keys()) - set(o["R01"].keys())) if "R01" in o else []
print("rules old/new:", len(o), len(n))
print("mined-field mismatches:", bad[:10], "count=", len(bad))
print("fields added to R01:", added)
print("stats identical:", old["stats"] == new["stats"], new["stats"])
print("canonical_coverage:", new.get("canonical_coverage", {}).get("merged_rules"))
print("R49 status:", n["R49"].get("canonical_status"), "| confidence:", n["R49"].get("confidence"))
print("R45 verdict-ish unique:", n["R45"].get("unique_wording"))
print("R75 verdict:", n["R75"].get("verdict"))
print("R119 title:", n["R119"].get("title"))
