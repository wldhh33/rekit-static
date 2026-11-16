#!/usr/bin/env python3
r"""会话开工自检：10 秒内看清"现在在哪、缺什么"。纯标准库，只读，不写任何文件。

用法:  python "pack\tools\status.py"
退出码: 0 = 无阻断问题 / 1 = HANDOFF 缺失或不完整 / 2 = 找不到工作区
"""
import json
import os
import subprocess
import sys

SECTIONS = ["1. 当前进度", "2. 未完成清单", "3. 已否决方案",
            "4. 待确认问题", "5. 新增证据文件", "6. 下一位第一条命令"]
MOJIBAKE = set("鍥椤婧爜姣鏃璺笌绔犵▼")


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    pack = os.path.dirname(here)
    root = os.path.dirname(pack)
    work = os.path.join(root, "2026-11-15", "m3-task-card", "work")
    if not os.path.isdir(work):
        print(f"VERDICT: FAIL exit=2 (work dir not found: {work})")
        return 2

    rows, hard_fail = [], False

    # ---- 1. HANDOFF：存在 / 6 段齐全 / 每段非空 / <=150 行
    ho = os.path.join(work, "HANDOFF.md")
    if not os.path.isfile(ho):
        rows.append("[FAIL] HANDOFF.md 缺失 -> 先按模板补齐再开工")
        hard_fail = True
    else:
        with open(ho, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        missing, empty = [], []
        for i, sec in enumerate(SECTIONS):
            idx = next((k for k, ln in enumerate(lines) if ln.strip().startswith("## " + sec)), None)
            if idx is None:
                missing.append(sec)
                continue
            nxt = next((k for k in range(idx + 1, len(lines)) if lines[k].startswith("## ")), len(lines))
            body = [ln for ln in lines[idx + 1:nxt] if ln.strip()]
            if not body:
                empty.append(sec)
        if missing or empty or len(lines) > 150:
            bits = []
            if missing:
                bits.append("缺段=" + ",".join(missing))
            if empty:
                bits.append("空段=" + ",".join(empty))
            if len(lines) > 150:
                bits.append(f"超长={len(lines)}行>150")
            rows.append("[FAIL] HANDOFF: " + "; ".join(bits))
            hard_fail = True
        else:
            rows.append(f"[PASS] HANDOFF: 6/6 段非空, {len(lines)} 行")

    # ---- 2a. 最近一次门禁 verdict：存在则必须 PASS，不能只当 info
    latest = os.path.join(work, "verification", "latest", "summary.json")
    if not os.path.isfile(latest):
        rows.append("[WARN] verification/latest: 缺失（还没跑过门禁）")
    else:
        try:
            sm = json.load(open(latest, encoding="utf-8"))
            full = sm.get("scope", "all") == "all"
            ok = sm.get("verdict") == "PASS" and sm.get("exit") == 0
            rows.append("[%s] verification/latest: %s scope=%s run_id=%s pytest=%s ledger=%s"
                        % ("PASS" if ok and full else ("FAIL" if not ok else "WARN"),
                           sm.get("verdict"), sm.get("scope", "unknown"),
                           sm.get("run_id"),
                           (sm.get("pytest") or {}).get("passed"),
                           (sm.get("ledger") or {}).get("verdict")))
            if not ok:
                hard_fail = True
            elif not full:
                rows.append("[WARN] 最近一次门禁不是全量（只跑了 %d 套），不能当作发布证据"
                            % len(sm.get("suites", [])))
        except (OSError, ValueError) as e:
            rows.append("[FAIL] verification/latest 不可读: %r" % (e,))
            hard_fail = True

    # ---- 2b. 总账：权威 JSON + 漂移/新鲜度检查（硬失败）
    auth = os.path.join(work, "evidence_numbers_ledger.json")
    mirror = os.path.join(work, "outputs", "NUMBERS_LEDGER.md")
    if not os.path.isfile(auth):
        rows.append("[FAIL] numbers ledger: 权威 JSON 缺失 %s"
                    % os.path.relpath(auth, root))
        hard_fail = True
    elif not os.path.isfile(mirror):
        rows.append("[FAIL] numbers ledger: 人读镜像缺失")
        hard_fail = True
    else:
        chk = os.path.join(here, "ledger_check.py")
        p = subprocess.run([sys.executable, chk, "--check"],
                           cwd=root, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        lines = (p.stdout or "").strip().splitlines()
        head = next((l for l in lines if l.startswith("LEDGER:")),
                    lines[-1] if lines else "no output")
        rows.append("[%s] numbers ledger: %s"
                    % ("PASS" if p.returncode == 0 else "FAIL", head))
        if p.returncode != 0:
            hard_fail = True

    # ---- 2c. git：未初始化=已知状态(WARN)；已初始化但命令失败=FAIL
    gitdir = os.path.join(root, ".git")
    if not os.path.isdir(gitdir):
        rows.append("[WARN] git: 未初始化（维护窗口处理，不阻断）")
    else:
        p = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        if p.returncode != 0:
            rows.append("[FAIL] git: status 失败 rc=%d %s"
                        % (p.returncode, (p.stderr or "").strip()[:80]))
            hard_fail = True
        else:
            rows.append("[PASS] git: 已初始化，工作树 %d 项变更"
                        % len([l for l in p.stdout.splitlines() if l.strip()]))

    rules = os.path.join(pack, "rules.json")
    try:
        doc = json.load(open(rules, encoding="utf-8"))
        st = doc.get("stats", {})
        rows.append("[info] rules registry: %d 条 (互证 %d / 撞号 %d / 过短 %d)" % (
            len(doc.get("rules", [])), st.get("corroborated", 0), st.get("suspect", 0), st.get("terse", 0)))
    except OSError:
        rows.append("[info] rules registry: 缺失 (n/a)")

    # ---- 3. 样本清单条目数
    man = os.path.join(work, "m9_sample_manifest.json")
    try:
        with open(man, encoding="utf-8") as f:
            m = json.load(f)
        n = len(m["samples"]) if isinstance(m, dict) and isinstance(m.get("samples"), list) else len(m)
        rows.append(f"[PASS] sample manifest: {n} 条")
    except Exception as e:
        rows.append(f"[WARN] sample manifest: {type(e).__name__}")

    # ---- 4. pack 目录：可访问性 + mojibake 检测
    bad, total = [], 0
    try:
        for name in os.listdir(pack):
            if not os.path.isdir(os.path.join(pack, name)):
                continue
            total += 1
            try:
                os.scandir(os.path.join(pack, name)).close()
            except OSError:
                bad.append(name)
            if any(ch in MOJIBAKE or 0xE000 <= ord(ch) <= 0xF8FF for ch in name):
                bad.append(name)
    except OSError as e:
        rows.append(f"[WARN] pack 不可读: {e}")
    if bad:
        rows.append(f"[WARN] pack 目录名损坏/不可访问 {len(set(bad))}/{total} 个 (见 PATH_MAP.md)")
    else:
        rows.append(f"[PASS] pack 目录: {total} 个均可访问")

    # ---- 5. 规模计数（只数文件名，不读内容）
    tests = os.path.join(work, "tests")
    src = os.path.join(work, "rekit")
    try:
        names = os.listdir(tests)
        nt = sum(1 for x in names if x.startswith("test_") and x.endswith(".py"))
        nv = sum(1 for x in names if x.startswith("verify_") and x.endswith(".py"))
        nm = sum(1 for x in os.listdir(src) if x.endswith(".py"))
        rows.append(f"[info] 规模: rekit 模块 {nm} / 测试 {nt} / 验证脚本 {nv}")
    except OSError as e:
        rows.append(f"[WARN] 规模统计失败: {e}")

    print("\n".join(rows))
    print(f"VERDICT: {'FAIL' if hard_fail else 'PASS'} exit={1 if hard_fail else 0}")
    return 1 if hard_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
