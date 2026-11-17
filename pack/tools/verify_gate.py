r"""外部门禁：唯一判定语义 = tests\vharness.py（本脚本不再维护第二份登记表/判定口径）。

串行做三件事：
  1. 委托 `vharness --all --json`（或 --only 透传）跑全部已登记验证脚本，读它的 JSON 判 verdict；
  2. 跑 pytest（tests -q）；
  3. 跑 `ledger_check.py --check`（总账漂移/新鲜度，硬失败）。

用法:
  python "pack\tools\verify_gate.py" --list        # 委托 vharness --list
  python "pack\tools\verify_gate.py" --run         # 全量执行
  python "pack\tools\verify_gate.py" --run --only verify_map,verify_iat
退出码: 0 = 全 PASS / 1 = 有 FAIL / 2 = 环境缺失或登记错误（fail-closed）
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
ROOT = os.path.dirname(PACK)
WORK = os.path.join(ROOT, "2026-11-15", "m3-task-card", "work")
TESTS = os.path.join(WORK, "tests")
VHARNESS = os.path.join(TESTS, "vharness.py")
LEDGER = os.path.join(HERE, "ledger_check.py")
BINUTILS = os.path.join(ROOT, "2026-11-15", "m2-task-card", "work", "tools",
                        "binutils-2.47", "mingw64", "bin")


def env():
    e = dict(os.environ)
    e["LC_ALL"] = "C"                      # objdump 遇中文路径会 Illegal byte sequence
    e["PYTHONIOENCODING"] = "utf-8"
    if os.path.isdir(BINUTILS):
        e["PATH"] = BINUTILS + os.pathsep + e.get("PATH", "")
    return e


def tail(text, n=160):
    lines = [l for l in text.splitlines() if l.strip()]
    return lines[-1][:n] if lines else ""


def run_one(cmd, log_path, timeout):
    t0 = time.time()
    with open(log_path, "wb") as lf:
        lf.write(("CMD: %s\n\n" % " ".join(cmd)).encode("utf-8"))
        lf.flush()
        try:
            p = subprocess.run(cmd, cwd=WORK, env=env(), timeout=timeout,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired as e:
            out, rc = (e.output or b"") + b"\n<TIMEOUT>", 124
        except OSError as e:
            out, rc = str(e).encode("utf-8"), 127
        lf.write(out)
    return rc, time.time() - t0, out.decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args()

    if not os.path.isfile(VHARNESS):
        print("VERDICT: FAIL exit=2 (vharness.py not found)")
        return 2

    if a.list or not a.run:
        rc, sec, out = run_one([sys.executable, VHARNESS, "--list"],
                               os.path.join(WORK, "verification", "gate_list.log"),
                               a.timeout)
        sys.stdout.write(out)
        return rc

    # run_id 唯一后缀：避免跨会话同秒撞目录
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + os.urandom(2).hex()
    outdir = os.path.join(WORK, "verification", run_id)
    os.makedirs(outdir, exist_ok=True)
    vjson = os.path.join(outdir, "vharness.json")

    cmd = [sys.executable, VHARNESS, "--json", vjson,
           "--logdir", outdir, "--timeout", str(a.timeout)]
    cmd += ["--only", a.only] if a.only else ["--all"]
    vrc, vsec, vout = run_one(cmd, os.path.join(outdir, "vharness.log"), a.timeout)
    print(vout.strip())
    if not os.path.isfile(vjson):
        print("VERDICT: FAIL exit=2 (vharness 未产出 JSON)")
        return 2
    doc = json.load(open(vjson, encoding="utf-8"))
    suites = []
    for d in doc.get("suites", []):
        stem = d["suite"][:-3] if d["suite"].endswith(".py") else d["suite"]
        code = d.get("exit")
        reason = next((c["reason_code"] for c in d.get("cases", [])
                       if c.get("reason_code")), None)
        suites.append({
            "name": stem,
            "cmd": stem + ".py",
            "exit": code,
            "legacy_exit": d.get("legacy_exit"),
            "seconds": d.get("duration_s"),
            "cases": d.get("cases", []),
            "cases_pass": d.get("totals", {}).get("pass"),
            "reason": reason,
            "requires_missing": d.get("requires_missing", []),
            "log": os.path.relpath(os.path.join(outdir, stem + ".log"), ROOT),
            "last_line": d.get("last_line", ""),
            "selfproof_artifact": d.get("meta", {}).get("selfproof_artifact"),
            "verdict": "PASS" if code == 0 else ("ENV_MISSING" if code == 2 else "FAIL"),
        })
    bad = sum(1 for s in suites if s["verdict"] != "PASS")

    prc, psec, pout = run_one([sys.executable, "-m", "pytest", "tests", "-q"],
                              os.path.join(outdir, "pytest.log"), a.timeout)
    passed = failed = skipped = 0
    for line in reversed([l for l in pout.splitlines() if l.strip()]):
        if " passed" in line or "failed" in line or "error" in line:
            m = re.search(r"(\d+) passed", line)
            f = re.search(r"(\d+) (?:failed|error)", line)
            s = re.search(r"(\d+) skipped", line)
            passed = int(m.group(1)) if m else passed
            failed = int(f.group(1)) if f else failed
            skipped = int(s.group(1)) if s else skipped
            break
    pv = "PASS" if prc == 0 and passed > 0 and failed == 0 else "FAIL"
    if pv == "FAIL":
        bad += 1
    print("%s %-26s %6.1fs exit=%-3d passed=%d failed=%d skipped=%d"
          % (pv, "pytest", psec, prc, passed, failed, skipped))

    lrc, lsec, lout = run_one([sys.executable, LEDGER, "--check"],
                              os.path.join(outdir, "ledger_check.log"), a.timeout)
    lv = "PASS" if lrc == 0 else ("FAIL" if lrc == 1 else "FAIL")
    if lv == "FAIL":
        bad += 1
    print("%s %-26s %6.1fs exit=%-3d %s" % (lv, "ledger_check", lsec, lrc, tail(lout, 120)))

    status = "PASS" if bad == 0 and vrc == 0 else "FAIL"
    code = 2 if vrc == 2 else (0 if status == "PASS" else 1)
    summary = {"schema": "verify_summary/2", "run_id": run_id,
               "scope": ("all" if not a.only else "only:" + a.only),
               "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "python": sys.version.split()[0], "work": WORK,
               "delegated_to": os.path.relpath(VHARNESS, ROOT),
               "suites": suites,
               "vharness": {"cmd": "python tests/vharness.py --all --json",
                            "exit": vrc, "seconds": round(vsec, 1),
                            "pass": doc.get("totals", {}).get("pass"),
                            "fail": doc.get("totals", {}).get("fail"),
                            "env_missing": doc.get("totals", {}).get("env_skip"),
                            "total": doc.get("totals", {}).get("suites"),
                            "json": os.path.relpath(vjson, ROOT),
                            "log": os.path.relpath(os.path.join(outdir, "vharness.log"), ROOT)},
               "pytest": {"cmd": "python -m pytest tests -q", "exit": prc,
                          "seconds": round(psec, 1), "passed": passed,
                          "failed": failed, "skipped": skipped,
                          "log": os.path.relpath(os.path.join(outdir, "pytest.log"), ROOT),
                          "verdict": pv},
               "ledger": {"cmd": "python pack/tools/ledger_check.py --check",
                          "exit": lrc, "verdict": lv,
                          "last_line": tail(lout, 200),
                          "log": os.path.relpath(os.path.join(outdir, "ledger_check.log"), ROOT)},
               "verdict": status, "exit": code}
    path = os.path.join(outdir, "summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    latest = os.path.join(WORK, "verification", "latest")
    os.makedirs(latest, exist_ok=True)
    shutil.copy(path, os.path.join(latest, "summary.json"))
    print("summary: " + os.path.relpath(path, ROOT))
    print("VERDICT: %s suites=%d pass=%s fail=%s pytest=%d ledger=%s exit=%d"
          % (status, len(suites), doc.get("totals", {}).get("pass"),
             doc.get("totals", {}).get("fail"), passed, lv, code))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
