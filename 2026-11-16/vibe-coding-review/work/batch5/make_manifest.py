# 生成 batch5 的 sha256 清单（回退依据）。只读文件、只写 MANIFEST.sha256。
import hashlib
import os

ROOT = r"D:\数据\下载\逆向学习工作体系_2026-11-15"
FILES = [
    r"pack\rules.json",
    r"pack\02_规则库\规则库_R33-R119.md",
    r"2026-11-16\vibe-coding-review\work\batch4\canonical_coverage.json",
    r"2026-11-16\vibe-coding-review\work\batch4\human_decisions.md",
    r"2026-11-16\vibe-coding-review\work\batch5\RULE_ADJUDICATIONS.md",
    r"2026-11-16\vibe-coding-review\work\batch5\apply_adjudications.py",
    r"2026-11-16\vibe-coding-review\work\batch5\patch_authority.py",
    r"2026-11-16\vibe-coding-review\work\batch5\sync_coverage.py",
    r"2026-11-16\vibe-coding-review\work\batch5\check_r95_manifest.py",
]
OUT = os.path.join(ROOT, r"2026-11-16\vibe-coding-review\work\batch5\MANIFEST.sha256")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


lines = []
for rel in FILES:
    p = os.path.join(ROOT, rel)
    lines.append("%s  %s" % (sha(p), rel))
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print("\n".join(lines))
