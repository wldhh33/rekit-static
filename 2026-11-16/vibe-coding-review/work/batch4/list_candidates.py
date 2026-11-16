# -*- coding: utf-8 -*-
"""List all multi_candidate and suspect rules with alternates for adjudication."""
import json
import os

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
d = json.load(open(os.path.join(ROOT, "pack", "rules.json"), encoding="utf-8"))

def show(r):
    print("=" * 80)
    print("%s [%s] src=%s n=%s agree=%s sim=%s" % (
        r["id"], r["status"], r["source"], r["n_candidates"], r["agree_sources"],
        r.get("closest_other_wording")))
    print("  STMT:", r["statement"])
    for a in r.get("alternates", []):
        print("  ALT :", a["text"], "||", a["src"])

print("### MULTI_CANDIDATE (%d)" % sum(1 for r in d["rules"] if r["status"] == "multi_candidate"))
for r in d["rules"]:
    if r["status"] == "multi_candidate":
        show(r)
print("\n### SUSPECT (%d)" % sum(1 for r in d["rules"] if r["status"] == "suspect"))
for r in d["rules"]:
    if r["status"] == "suspect":
        show(r)
