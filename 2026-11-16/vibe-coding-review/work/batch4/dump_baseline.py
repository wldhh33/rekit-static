# -*- coding: utf-8 -*-
"""Dump R33-R119 baseline from pack/rules.json for convergence work."""
import json
import os

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
OUT = os.path.join(ROOT, "2026-11-16", "vibe-coding-review", "work", "batch4")

d = json.load(open(os.path.join(ROOT, "pack", "rules.json"), encoding="utf-8"))
rs = [r for r in d["rules"] if int(r["id"][1:]) >= 33]
lines = ["%s | %s | %s | %s" % (r["id"], r["status"], r["source"], r["statement"]) for r in rs]
open(os.path.join(OUT, "baseline_r33_r119.txt"), "w", encoding="utf-8").write("\n".join(lines))
print("rules=%d" % len(rs))
print("multi(R33+)=%s" % [r["id"] for r in rs if r["status"] == "multi_candidate"])
print("suspect(R33+)=%s" % [r["id"] for r in rs if r["status"] == "suspect"])
print("terse(R33+)=%s" % [r["id"] for r in rs if r["status"] == "terse"])
