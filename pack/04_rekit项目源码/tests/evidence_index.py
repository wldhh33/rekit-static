#!/usr/bin/env python3
"""evidence_index.py — `work/evidence_*` 证据文件索引（U1-b，2026-11-17）。

索引内容（每个证据文件一行）：
  sha256 / size / mtime / run_id（来源 verification 目录）/ sections（覆盖小节）

判据（任一不满足 exit 1）：
  1. 覆盖率：`work/evidence_*` 每个文件都必须在索引里；
  2. 存在性：索引里每个文件都必须真实存在；
  3. 一致性：重算 sha256 / size 必须与索引相等。

用法（仓库根执行）：
  python tests/evidence_index.py --write    # 重建索引（索引文件本身不匹配 evidence_*）
  python tests/evidence_index.py --check    # 校验（默认）
  python tests/evidence_index.py --self-test  # 可失败自证（临时目录，不碰真实证据）

索引文件：work/EVIDENCE_INDEX.json（大写，避免被 evidence_* 通配捕获）。
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime

SCHEMA = 1
EVIDENCE_GLOB_PREFIX = "evidence_"
INDEX_NAME = "EVIDENCE_INDEX.json"
RUN_ID_RE = re.compile(r"\d{8}T\d{6}-[0-9a-f]{4}")
HEAD_RE = re.compile(r"^\s*(?:§\s*\S.*|#{1,4}\s+\S.*|={2,}[^=].*|.*[^=]={2,}\s*)$")
MAX_SECTIONS = 100


def repo_root():
    # tests/ -> 04_rekit项目源码/ -> pack/ -> 工作区根
    # 先 realpath 解析目录联接：work\tests 是 junction，从该入口进来会多一级 2026-11-15
    here = os.path.realpath(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(here))))


def work_dir(root):
    return os.path.join(root, "2026-11-15", "m3-task-card", "work")


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_runs(work):
    """返回 {run_id: [日志绝对路径]}；verification 目录缺失时返回空表。"""
    runs = {}
    vroot = os.path.join(work, "verification")
    if not os.path.isdir(vroot):
        return runs
    for name in sorted(os.listdir(vroot)):
        d = os.path.join(vroot, name)
        if not os.path.isdir(d) or not RUN_ID_RE.fullmatch(name):
            continue
        files = []
        for fname in os.listdir(d):
            if fname.endswith(".log") or fname == "summary.json":
                files.append(os.path.join(d, fname))
        runs[name] = files
    return runs


def attribute_run_id(filename, runs, text):
    """来源 run_id：先查 verification 日志；多个 run 都提到则不猜，记 ambiguous。"""
    hits = [rid for rid, files in runs.items()
            if any(_contains(f, filename) for f in files)]
    if len(hits) == 1:
        return hits[0], hits, "verification_log"
    if len(hits) > 1:
        return None, sorted(hits), "ambiguous"
    in_file = sorted(set(RUN_ID_RE.findall(text)))
    if in_file:
        return in_file[-1], in_file, "evidence_content"
    return None, [], "not_found"


def _contains(path, needle):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if needle in line:
                    return True
    except OSError:
        return False
    return False


def sections_of(path, text):
    """JSON：顶层键；文本：标题行。返回 (sections, kind)。"""
    if path.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            return [], "json_unparsable"
        if isinstance(data, dict):
            return list(data)[:MAX_SECTIONS], "json_top_level_keys"
        return [], "json_not_object"
    heads = []
    for line in text.splitlines():
        line = line.strip()
        if line and HEAD_RE.match(line) and line not in heads:
            heads.append(line[:120])
        if len(heads) >= MAX_SECTIONS:
            break
    return heads, "text_headings"


def build_entry(path, runs):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    run_id, run_ids, source = attribute_run_id(os.path.basename(path), runs, text)
    sections, kind = sections_of(path, text)
    st = os.stat(path)
    return {
        "sha256": sha256_of(path),
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        "run_id": run_id,
        "run_ids": run_ids,
        "run_id_source": source,
        "sections": sections,
        "sections_kind": kind,
    }


def evidence_files(work):
    if not os.path.isdir(work):
        return []
    return sorted(os.path.join(work, n) for n in os.listdir(work)
                  if n.startswith(EVIDENCE_GLOB_PREFIX)
                  and os.path.isfile(os.path.join(work, n)))


def cmd_write(root):
    work = work_dir(root)
    runs = collect_runs(work)
    entries = {}
    for path in evidence_files(work):
        entries[os.path.basename(path)] = build_entry(path, runs)
    index = {
        "schema": SCHEMA,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "work_dir": os.path.relpath(work, root).replace("\\", "/"),
        "rules": {
            "coverage": "work/evidence_* 每个文件都必须在 entries 中",
            "existence": "entries 中每个文件都必须存在",
            "consistency": "重算 sha256/size 必须与 entries 相等",
            "run_id": "先查 work/verification/<run_id>/ 日志是否提到文件名："
                      "恰好 1 个 run 提到才填；多个 run 提到记 ambiguous 并列出；"
                      "没有提到再看文件内容里的 run id；都没有写 null",
            "sections": "JSON 取顶层键；文本取标题行（§ / # / === 形式）",
        },
        "entries": entries,
    }
    out = os.path.join(work, INDEX_NAME)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("evidence_index: 写入 %d 条 -> %s" % (len(entries), out))
    return 0


def check(root):
    work = work_dir(root)
    index_path = os.path.join(work, INDEX_NAME)
    if not os.path.exists(index_path):
        print("evidence_index: FAIL 索引不存在（先跑 --write）：%s" % index_path)
        return 1
    with open(index_path, "r", encoding="utf-8") as f:
        index = json.load(f)
    entries = index.get("entries") or {}
    problems = []

    files = evidence_files(work)
    names = {os.path.basename(p) for p in files}
    missing_in_index = sorted(names - set(entries))
    if missing_in_index:
        problems.append("覆盖率: %d 个证据文件不在索引: %s"
                        % (len(missing_in_index), ", ".join(missing_in_index)))
    if not files:
        problems.append("覆盖率: work/evidence_* 为空，分母为 0 不能判 PASS")

    for name, ent in sorted(entries.items()):
        path = os.path.join(work, name)
        if not os.path.exists(path):
            problems.append("存在性: 索引条目 %s 指向的文件不存在" % name)
            continue
        got = sha256_of(path)
        if got != ent.get("sha256"):
            problems.append("一致性: %s sha256 不符（索引 %s，实测 %s）"
                            % (name, ent.get("sha256"), got))
        size = os.stat(path).st_size
        if size != ent.get("size"):
            problems.append("一致性: %s size 不符（索引 %s，实测 %d）"
                            % (name, ent.get("size"), size))

    stale = sorted(set(entries) - names)
    if stale:
        problems.append("存在性: 索引有 %d 条已无对应文件: %s"
                        % (len(stale), ", ".join(stale)))

    if problems:
        print("evidence_index: FAIL（%d 项）" % len(problems))
        for p in problems:
            print("  - " + p)
        return 1
    print("evidence_index: PASS  索引 %d 条 / 磁盘证据 %d 个，sha256 全部一致"
          % (len(entries), len(files)))
    return 0


def self_test():
    """可失败自证：干净样本 PASS，三类破坏各自 FAIL。"""
    tmp = tempfile.mkdtemp(prefix="rekit_evidence_")
    fails = 0
    try:
        work = work_dir(tmp)
        os.makedirs(os.path.join(work, "verification", "20260101T000000-abcd"))
        os.makedirs(os.path.join(work, "verification", "20260102T000000-abcd"))
        with open(os.path.join(work, "verification", "20260102T000000-abcd", "suite.log"),
                  "w", encoding="utf-8") as f:
            f.write("run evidence_demo.log verdict PASS\n")
        with open(os.path.join(work, "evidence_demo.log"), "w", encoding="utf-8") as f:
            f.write("==== 1. 概览 ====\nPASS\n==== 2. 分母 ====\n12\n")
        with open(os.path.join(work, "evidence_data.json"), "w", encoding="utf-8") as f:
            json.dump({"summary": {"n": 12}, "rows": [1, 2]}, f)
        assert cmd_write(tmp) == 0
        cases = []

        def expect(label, want, mutate):
            rc = mutate()
            ok = (rc == want)
            cases.append((label, want, rc, ok))
            return ok

        ok1 = expect("干净索引", 0, lambda: check(tmp))

        ent = json.load(open(os.path.join(work, INDEX_NAME),
                             encoding="utf-8"))["entries"]["evidence_demo.log"]
        good_attr = ent["run_id"] == "20260102T000000-abcd" and \
            ent["run_id_source"] == "verification_log"
        cases.append(("唯一 run 引用 → 填 run_id", "bool", None, good_attr))
        with open(os.path.join(work, "verification", "20260101T000000-abcd",
                               "suite.log"), "w", encoding="utf-8") as f:
            f.write("旧日志也提到 evidence_demo.log\n")
        cmd_write(tmp)
        ent = json.load(open(os.path.join(work, INDEX_NAME),
                             encoding="utf-8"))["entries"]["evidence_demo.log"]
        amb = ent["run_id"] is None and ent["run_id_source"] == "ambiguous" and \
            len(ent["run_ids"]) == 2
        cases.append(("两个 run 引用 → ambiguous 不猜", "bool", None, amb))

        def add_stray():
            p = os.path.join(work, "evidence_stray.log")
            with open(p, "w", encoding="utf-8") as f:
                f.write("stray\n")
            rc = check(tmp)
            os.remove(p)
            return rc
        ok2 = expect("新增证据未入索引", 1, add_stray)

        def remove_file():
            p = os.path.join(work, "evidence_demo.log")
            data = open(p, "rb").read()
            os.remove(p)
            rc = check(tmp)
            open(p, "wb").write(data)
            return rc
        ok3 = expect("索引条目文件缺失", 1, remove_file)

        def tamper():
            p = os.path.join(work, "evidence_demo.log")
            data = open(p, "rb").read()
            open(p, "ab").write(b"tampered\n")
            rc = check(tmp)
            open(p, "wb").write(data)
            return rc
        ok4 = expect("证据文件被改动", 1, tamper)

        for label, want, rc, ok in cases:
            if want == "bool":
                print("  [%s] %s" % ("PASS" if ok else "FAIL", label))
            else:
                print("  [%s] %s  期望 exit=%d 实得 %d"
                      % ("PASS" if ok else "FAIL", label, want, rc))
            if not ok:
                fails += 1
        print("evidence_index self-test: %s（%d/%d）"
              % ("PASS" if fails == 0 else "FAIL", len(cases) - fails, len(cases)))
        return 0 if fails == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(description="work/evidence_* 证据索引")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--write", action="store_true", help="重建索引")
    g.add_argument("--check", action="store_true", help="校验索引（默认）")
    g.add_argument("--self-test", action="store_true", help="可失败自证")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    root = repo_root()
    if args.write:
        return cmd_write(root)
    return check(root)


if __name__ == "__main__":
    sys.exit(main())
