# -*- coding: utf-8 -*-
"""生成 batch4 回退清单 MANIFEST.sha256（相对路径 + 回退说明）。"""
import hashlib
import os

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
OUT = os.path.join(ROOT, "2026-11-16", "vibe-coding-review", "work", "batch4")

FILES = [
    r"pack\02_规则库\规则库_R33-R119.md",
    r"pack\rules.json",
    r"2026-11-16\vibe-coding-review\work\batch4\canonical_coverage.json",
    r"2026-11-16\vibe-coding-review\work\batch4\human_decisions.md",
    r"2026-11-16\vibe-coding-review\work\batch4\rules.before_canonical.json",
    r"2026-11-16\vibe-coding-review\work\batch4\merge_canonical.py",
    r"2026-11-16\vibe-coding-review\work\batch4\verify_merge.py",
    r"2026-11-16\vibe-coding-review\work\batch4\dump_baseline.py",
    r"2026-11-16\vibe-coding-review\work\batch4\list_candidates.py",
    r"2026-11-16\vibe-coding-review\work\batch4\baseline_r33_r119.txt",
    r"2026-11-15\m3-task-card\work\HANDOFF.md",
]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


lines = [
    "# B4 规则史收敛回退清单（2026-11-16）",
    "# 回退 rules.json：copy batch4\\rules.before_canonical.json -> pack\\rules.json（sha256 见下）",
    "# 回退新增文件：删除 pack\\02_规则库\\规则库_R33-R119.md、batch4\\canonical_coverage.json、batch4\\human_decisions.md",
    "# 回退 HANDOFF：删 B4 行与 O5 行更新即可（内容已在本清单记录哈希）",
]
for rel in FILES:
    p = os.path.join(ROOT, rel)
    lines.append("%s  %s" % (sha(p), rel))

open(os.path.join(OUT, "MANIFEST.sha256"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("wrote %d entries" % len(FILES))
print("rules.json now :", sha(os.path.join(ROOT, r"pack\rules.json")))
print("rules baseline :", sha(os.path.join(OUT, "rules.before_canonical.json")))
