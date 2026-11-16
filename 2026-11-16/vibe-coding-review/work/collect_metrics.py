"""采集提案所依赖的项目量化指标，输出 metrics.json。

用法（在任意目录）：
    python collect_metrics.py

只读：不修改 pack 下任何文件。所有数字可在同一台机器上复跑得到相同值
（git 相关字段除外，因为本次核查时尚未初始化仓库）。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
WORK = os.path.join(ROOT, "2026-11-15", "m3-task-card", "work")
PACK = os.path.join(ROOT, "pack")
TMP_PACK = os.path.join(ROOT, "tmp", "pack")


def walk_files(folder):
    out = []
    for base, _, names in os.walk(folder):
        for n in names:
            p = os.path.join(base, n)
            out.append((p, os.path.getsize(p)))
    return out


def loc(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return len(f.read().splitlines())


def find_rekit_root(base):
    if not os.path.isdir(base):
        return None
    for d in os.listdir(base):
        cand = os.path.join(base, d, "rekit")
        if os.path.isdir(cand):
            return cand
    return None


def py_hashes(folder):
    out = {}
    for n in sorted(os.listdir(folder)):
        if n.endswith(".py"):
            p = os.path.join(folder, n)
            out[n] = hashlib.sha256(open(p, "rb").read()).hexdigest()
    return out


def main():
    rekit = os.path.join(WORK, "rekit")  # 指向 pack 源码的目录联接
    tests = os.path.join(WORK, "tests")

    modules = sorted(f for f in os.listdir(rekit) if f.endswith(".py"))
    test_py = sorted(f for f in os.listdir(tests) if f.startswith("test_") and f.endswith(".py"))
    verify_py = sorted(f for f in os.listdir(tests) if f.startswith("verify_") and f.endswith(".py"))

    pack_rekit = find_rekit_root(PACK)
    tmp_rekit = find_rekit_root(TMP_PACK)

    docs = {}
    for name in ("CHARTER.md", "PROGRESS.md", "CHANGELOG.md", "RE-ROADMAP.md"):
        p = os.path.join(WORK, "pack03", name)
        docs[name] = {
            "bytes": os.path.getsize(p),
            "lines": loc(p),
        }

    rule_text = "".join(
        open(os.path.join(WORK, "pack03", n), encoding="utf-8").read()
        for n in ("CHARTER.md", "PROGRESS.md", "CHANGELOG.md")
    )
    rule_ids = sorted({int(x) for x in re.findall(r"\bR(\d{1,3})\b", rule_text)})

    evidence = [f for f in os.listdir(WORK) if f.startswith("evidence_")]

    sample_dirs = {}
    for sub in ("samples", "tests/samples", "tests/fixtures"):
        d = os.path.join(WORK, sub)
        if os.path.isdir(d):
            files = walk_files(d)
            sample_dirs[sub] = {
                "files": len(files),
                "bytes": sum(s for _, s in files),
            }

    manifest = os.path.join(WORK, "m9_sample_manifest.json")
    manifest_samples = None
    if os.path.exists(manifest):
        manifest_samples = len(json.load(open(manifest, encoding="utf-8")).get("samples", []))

    surface = {}
    mcp = open(os.path.join(rekit, "mcp.py"), encoding="utf-8").read()
    cli = open(os.path.join(rekit, "cli.py"), encoding="utf-8").read()
    surface["mcp_tools"] = sorted(set(re.findall(r'"(rekit_[a-z_]+)"', mcp)))
    surface["mcp_bytes"] = len(mcp.encode())
    surface["cli_lines"] = len(cli.splitlines())
    surface["cli_subcommands_matched"] = re.findall(r'argv\[0\]\s*==\s*"([a-z_]+)"', cli)

    argv_counts = {}
    for n in verify_py:
        body = open(os.path.join(tests, n), encoding="utf-8").read()
        argv_counts[n] = body.count("add_argument(")

    out = {
        "generated_from": ROOT,
        "rekit": {
            "modules": len(modules),
            "loc": sum(loc(os.path.join(rekit, m)) for m in modules),
            "module_names": modules,
        },
        "tests": {
            "py_files": len([f for f in os.listdir(tests) if f.endswith(".py")]),
            "test_modules": len(test_py),
            "test_loc": sum(loc(os.path.join(tests, n)) for n in test_py),
            "verify_scripts": len(verify_py),
            "verify_loc": sum(loc(os.path.join(tests, n)) for n in verify_py),
            "verify_names": verify_py,
            "verify_argparse_counts": argv_counts,
        },
        "docs_pack03": docs,
        "docs_total_bytes": sum(v["bytes"] for v in docs.values()),
        "rules": {
            "unique_ids": len(rule_ids),
            "min": rule_ids[0],
            "max": rule_ids[-1],
            "gaps": [i for i in range(1, rule_ids[-1] + 1) if i not in rule_ids],
        },
        "evidence_files_in_work_root": len(evidence),
        "evidence_bytes": sum(os.path.getsize(os.path.join(WORK, f)) for f in evidence),
        "samples": sample_dirs,
        "sample_manifest_entries": manifest_samples,
        "copies": {
            "pack_rekit": pack_rekit,
            "pack_modules": len([f for f in os.listdir(pack_rekit) if f.endswith(".py")]) if pack_rekit else None,
            "tmp_pack_rekit": tmp_rekit,
            "tmp_pack_modules": len([f for f in os.listdir(tmp_rekit) if f.endswith(".py")]) if tmp_rekit else None,
            "pack_vs_work_identical": (
                py_hashes(pack_rekit) == py_hashes(rekit) if pack_rekit else None
            ),
        },
        "pack_dirs_on_disk": sorted(os.listdir(PACK)),
        "tmp_pack_dirs": sorted(os.listdir(TMP_PACK)) if os.path.isdir(TMP_PACK) else [],
        "git": {"initialized": os.path.isdir(os.path.join(ROOT, ".git"))},
        "surface": surface,
    }

    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics.json")
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1, sort_keys=True)
    print("written:", dst)
    print("modules=%d loc=%d verify=%d/%d rules=%d gaps=%d"
          % (out["rekit"]["modules"], out["rekit"]["loc"],
             out["tests"]["verify_scripts"], out["tests"]["verify_loc"],
             out["rules"]["unique_ids"], len(out["rules"]["gaps"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
