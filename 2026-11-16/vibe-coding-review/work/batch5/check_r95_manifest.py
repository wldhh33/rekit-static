# 只读核对 R95「sha256 / 许可 / 可再分发或仅本地」三栏逐样本完整性。
# 不修改任何样本或清单，只输出统计。
import json
import os

WORK = r"D:\数据\下载\逆向学习工作体系_2026-11-15"

FILES = [
    ("M2", os.path.join(WORK, r"2026-11-15\m2-task-card\work\sample_manifest.json")),
    ("M9", os.path.join(WORK, r"2026-11-15\m3-task-card\work\m9_sample_manifest.json")),
]


def main():
    for tag, path in FILES:
        if not os.path.exists(path):
            print("[%s] MISSING %s" % (tag, path))
            continue
        d = json.load(open(path, encoding="utf-8"))
        samples = d.get("samples") or []
        print("[%s] %s" % (tag, path))
        print("  样本数 = %d" % len(samples))
        miss = {"sha256": [], "license": [], "redistributable/local_only": []}
        for s in samples:
            sid = s.get("id") or s.get("file") or "?"
            sha = s.get("sha256") or s.get("sha256_actual")
            if not sha:
                miss["sha256"].append(sid)
            if not s.get("license"):
                miss["license"].append(sid)
            has_red = bool(s.get("redistributable"))
            has_local = "local_only" in s
            if not (has_red or has_local):
                miss["redistributable/local_only"].append(sid)
        for k, v in miss.items():
            print("  缺 %s: %d %s" % (k, len(v), v if v else ""))
        keys = set()
        for s in samples:
            keys |= set(s.keys())
        print("  字段并集: %s" % ", ".join(sorted(keys)))
        print()


if __name__ == "__main__":
    main()
