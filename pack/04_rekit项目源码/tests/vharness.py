#!/usr/bin/env python3
# tests/vharness.py — 验证脚本统一包装层（O2-a）
# 框架默认：空比对一律 FAIL(empty_comparison)；缺自证一律 FAIL(selfproof_missing)。
# 只包装不修改 verify_*.py：按登记表原样执行，解析其汇总行，既有判据与数字不动。
# 用法：--list | --all [--json P] | --only a,b | --selftest；退出 0/1/2。
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
SUMMARY = re.compile(r"检查=(\d+)\s+PASS=(\d+)\s+FAIL=(\d+)\s+SKIP=(\d+)")
OKLINE = re.compile(r"(?:E9 )?VERDICT:\s*PASS|结果:\s*PASS|判定：失败 0 项|^PASS|^OK:")
SELFTEST_MARK = re.compile(r"\[selftest\]|自证|注入|负控")

# 登记表：argv 与 verify_gate 现行全量参数一致。
# sp=("flag",期望退出码) 支持 --selftest；("inline",正则) 自证内联在正常输出；
# None 表示该脚本当前没有自证 -> 框架判 selfproof_missing。
# 最小分母：旧脚本自身的比对对象数不得低于登记值（单对象 universe 不能 PASS）。
# SUMMARY 型取“检查=N”的 N；其余取“带数字的证据行”数（实测值，2026-11-16）。
MIN_DENOM = {
    "verify_c4_alignment.py": 3, "verify_callfacts.py": 21,
    "verify_callgraph.py": 25, "verify_coverage.py": 21,
    "verify_datarefs.py": 12, "verify_disasm.py": 20, "verify_dotnet.py": 27,
    "verify_expr.py": 768, "verify_fingerprint.py": 62, "verify_funcreport.py": 16,
    "verify_gopclntab.py": 25, "verify_iat.py": 15, "verify_ilflow.py": 41,
    "verify_map.py": 27, "verify_paramdecl.py": 34, "verify_recdesc.py": 115,
    "verify_sigblob.py": 17,
    "verify_layout.py": 28,
    "verify_api.py": 35,
    "verify_dist.py": 41,
    "verify_sitejoin.py": 9, "verify_struct.py": 21, "verify_strxref.py": 24,
    "verify_switchcand.py": 73, "verify_vexaudit.py": 15,
}

# 外部工具依赖：缺工具 -> env_missing(exit 2)，不静默跳过。
REQUIRES = {
    "verify_c4_alignment.py": ("objdump",), "verify_callfacts.py": ("objdump",),
    "verify_callgraph.py": ("objdump",), "verify_coverage.py": ("objdump",),
    "verify_disasm.py": ("objdump",), "verify_expr.py": ("objdump",),
    "verify_funcreport.py": ("objdump",), "verify_gopclntab.py": ("objdump",),
    "verify_map.py": ("objdump",), "verify_recdesc.py": ("objdump",),
    "verify_struct.py": ("objdump",), "verify_switchcand.py": ("objdump",),
    "verify_vexaudit.py": ("objdump",), "verify_iat.py": ("objdump",),
    "verify_sitejoin.py": ("objdump",),
    "verify_sigblob.py": ("pwsh",),
    "verify_layout.py": ("powershell",),
}

SUITES = {
    "verify_c4_alignment.py": ([], ("flag", 0)),
    "verify_callfacts.py": ([], ("flag", 0)),
    "verify_callgraph.py": ([], ("flag", 0)),
    "verify_coverage.py": ([], ("flag", 0)),
    "verify_datarefs.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_disasm.py": (["--all"], ("flag", 0)),
    "verify_dotnet.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_expr.py": ([], ("flag", 0)),
    "verify_fingerprint.py": (["--all", "--matrix"], ("flag", 0)),
    "verify_funcreport.py": ([], ("flag", 0)),
    "verify_gopclntab.py": ([], ("inline", r"✓", r"✓ .*status=unknown funcs=0")),
    "verify_iat.py": (["--all"], ("flag", 0)),
    "verify_ilflow.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_map.py": (["--all"], ("flag", 1)),
    "verify_paramdecl.py": ([], ("flag", 0)),
    "verify_recdesc.py": (["--all"], ("flag", 0)),
    "verify_sigblob.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_layout.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_api.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_dist.py": ([], ("inline", r"\[PASS\] selfproof")),
    "verify_sitejoin.py": ([], ("flag", 0)),
    "verify_struct.py": ([], ("flag", 0)),
    "verify_strxref.py": ([], ("flag", 0)),
    "verify_switchcand.py": ([], ("flag", 0)),
    "verify_vexaudit.py": ([], ("flag", 0, r"负控.*已检出")),
}


class Suite:
    """单套结果；两条默认规则在 exit_code() 处强制生效，无宽松模式。"""

    def __init__(self, name, requires=()):
        self.name = name
        self.cases = []
        self.meta = {}
        self.sp = None
        self.t0 = time.time()
        self.started = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.env_missing = [r for r in requires if shutil.which(r) is None]

    def _add(self, cid, ok, reason=None, detail=""):
        self.cases.append({"id": cid, "verdict": "PASS" if ok else "FAIL",
                           "reason_code": reason, "detail": detail})

    def case(self, cid, expected, actual, detail=""):
        empty = expected is None or (
            isinstance(expected, (str, list, tuple, dict, set)) and not expected)
        if empty:
            self._add(cid, False, "empty_expectation", detail or "期望值为空")
        elif actual is None:
            self._add(cid, False, "missing_actual", detail or "实际值为空")
        elif expected != actual:
            self._add(cid, False, "mismatch",
                      "%s | expected=%r actual=%r" % (detail, expected, actual))
        else:
            self._add(cid, True, None, detail)

    def require_nonempty(self, n, what):
        ok = isinstance(n, int) and n > 0
        self._add("nonempty:" + what, ok, None if ok else "empty_comparison",
                  "分母=%r（%s）" % (n, what))

    def require_denominator(self, n, what, minimum):
        """分母必须 >= minimum：挡住“单对象 universe 也 PASS”。"""
        ok = isinstance(n, int) and n >= minimum and n > 0
        reason = None
        if not ok:
            reason = "empty_comparison" if not isinstance(n, int) or n <= 0 \
                else "denominator_below_min"
        self._add("denominator:" + what, ok, reason,
                  "分母=%r 下限=%r（%s）" % (n, minimum, what))

    def selfproof(self, artifact):
        """只认工件（注入 ID + 基线 + 观察到的失败行）；布尔值一律 FAIL。"""
        if not isinstance(artifact, dict):
            self.sp = False
            self._add("selfproof", False, "selfproof_not_artifact",
                      "自证不是工件：%r（布尔/函数不算证据）" % (artifact,))
            return
        need = ("id", "baseline", "observed")
        missing = [k for k in need if not str(artifact.get(k) or "").strip()]
        same = artifact.get("baseline") == artifact.get("observed")
        ok = not missing and not same
        reason = None
        if missing:
            reason = "selfproof_incomplete"
        elif same:
            reason = "selfproof_baseline_equals_observed"
        elif not artifact.get("fail_line"):
            ok, reason = False, "selfproof_no_failure_line"
        self.sp = ok
        self._add("selfproof", ok, reason,
                  "id=%s baseline=%r observed=%r"
                  % (artifact.get("id"), artifact.get("baseline"),
                     artifact.get("observed")))

    def exit_code(self):
        if self.sp is None:
            self.sp = False
            self._add("selfproof", False, "selfproof_missing", "未调用 selfproof()")
        if self.env_missing:
            return 2
        return 0 if all(c["verdict"] == "PASS" for c in self.cases) else 1

    def emit(self, path=None):
        code = self.exit_code()
        doc = {"schema": "vharness/1", "suite": self.name, "started_at": self.started,
               "duration_s": round(time.time() - self.t0, 2), "meta": self.meta,
               "requires_missing": self.env_missing, "cases": self.cases,
               "totals": {"cases": len(self.cases),
                          "pass": sum(c["verdict"] == "PASS" for c in self.cases),
                          "fail": sum(c["verdict"] == "FAIL" for c in self.cases),
                          "env_skip": 1 if self.env_missing else 0},
               "exit": code}
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False, indent=1)
        return doc


def _env():
    e = dict(os.environ)
    e["LC_ALL"], e["PYTHONIOENCODING"] = "C", "utf-8"
    p = HERE
    for _ in range(8):
        if os.path.isdir(os.path.join(p, "pack")):
            break
        p = os.path.dirname(p)
    b = os.path.join(p, "2026-11-15", "m2-task-card", "work", "tools",
                     "binutils-2.47", "mingw64", "bin")
    if os.path.isdir(b):
        e["PATH"] = b + os.pathsep + e.get("PATH", "")
    return e


def _run(name, argv, timeout):
    cmd = [sys.executable, os.path.join(WORK, "tests", name)] + list(argv)
    p = subprocess.run(cmd, cwd=WORK, env=_env(), timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


FAILTOK = re.compile(r"FAIL|False|不成立|偏离|检出|不一致|mismatch|!=|失败|错误|异常|reject|refus|detect")


def _artifact(name, baseline, observed, fail_re=None):
    """把两次真实运行拼成工件：注入 ID + 基线 + 观察到的失败行。

    fail_re：该套点名登记的「失败/拒绝行」正则（注入后的观察结果）。
    未登记时才退回通用失败词表；两者都找不到 -> 工件无失败行 -> FAIL。
    """
    fail = ""
    pat = re.compile(fail_re) if fail_re else FAILTOK
    for line in observed.splitlines():
        if line.strip() and pat.search(line):
            fail = line.strip()
            break
    return {"id": name + ":--selftest", "baseline": baseline.strip()[:200],
            "observed": observed.strip()[-200:], "fail_line": fail[:200]}


def _digit_lines(out):
    n = 0
    for line in out.splitlines():
        t = line.strip()
        if not t or t.startswith("CMD:") or t.startswith("="):
            continue
        if re.search(r"\d", t):
            n += 1
    return n


def run_legacy(name, cfg, timeout=1800):
    """原样执行旧脚本，只解析汇总；不碰其判据，只加三道框架门。"""
    argv, sp = cfg
    s = Suite(name, requires=REQUIRES.get(name, ()))
    if s.env_missing:
        # 缺外部工具：显式 env_missing(exit 2)，不静默跳过、不判 PASS
        s._add("env:" + ",".join(s.env_missing), False, "env_missing",
               "缺少工具 %r" % (s.env_missing,))
        s.sp = False
        s.meta.update(legacy_exit=None, last_line="missing:%s" % (s.env_missing,))
        return s, "", 2
    rc, out = _run(name, argv, timeout)
    s.output = out
    tail = [x for x in out.splitlines() if x.strip()]
    last = tail[-1] if tail else ""
    s.meta.update(legacy_exit=rc, last_line=last)
    if not tail:
        s._add("output", False, "empty_comparison", "脚本无输出")
    m = SUMMARY.search(out)
    if m:
        total, ps, fs, sk = (int(x) for x in m.groups())
        s.meta["legacy_counts"] = {"checks": total, "pass": ps, "fail": fs, "skip": sk}
        s.require_nonempty(total, "检查项")
        s.require_denominator(total, "检查项", MIN_DENOM.get(name, 2))
        s.case("legacy_summary", {"checks": total, "fail": 0, "exit": 0},
               {"checks": total, "fail": fs, "exit": rc}, last)
    else:
        ok = rc == 0 and bool(last) and bool(OKLINE.search(last))
        s.require_nonempty(1 if last else 0, "汇总行")
        s.require_denominator(_digit_lines(out), "证据行", MIN_DENOM.get(name, 2))
        s.case("legacy_exit", 0, rc, last)
        if not ok and rc == 0:
            s._add("legacy_verdict", False, "empty_comparison",
                   "无可识别汇总行：%r" % last)
    if sp is None:
        s.sp = False
        s._add("selfproof", False, "selfproof_missing", "该脚本没有自证（sp=None）")
    elif sp[0] == "inline":
        # sp = ("inline", 标记) 或 ("inline", 标记, 失败行正则)
        fail_re = sp[2] if len(sp) > 2 else None
        pick = fail_re or sp[1]
        hit = next((l for l in out.splitlines() if re.search(pick, l)), "")
        if not hit:
            s.sp = False
            s._add("selfproof", False, "selfproof_missing",
                   "inline 标记 %r 未命中" % (pick,))
        else:
            artifact = _artifact(name, last, hit, fail_re)
            s.meta["selfproof_artifact"] = artifact
            s.selfproof(artifact)
    else:
        erc, eout = _run(name, list(argv) + ["--selftest"], timeout)
        s.meta["selftest_exit"] = erc
        if erc != sp[1]:
            s.sp = False
            s._add("selfproof", False, "selfproof_missing",
                   "--selftest exit=%d（期望 %d）" % (erc, sp[1]))
        else:
            artifact = _artifact(name, last, eout, sp[2] if len(sp) > 2 else None)
            s.meta["selfproof_artifact"] = artifact
            s.selfproof(artifact)
    return s, last, rc


def selfcheck():
    """框架自身可失败自证：五类输入必须各自落到预期退出码。"""
    def rc(fn):
        s = Suite("probe")
        fn(s)
        return s.exit_code()
    good = {"id": "probe:--selftest", "baseline": "clean=pass",
            "observed": "injected=FAIL", "fail_line": "injected=FAIL"}
    probes = [
        ("empty_comparison", rc(lambda s: s.require_nonempty(0, "x")) == 1),
        ("empty_expectation", rc(lambda s: s.case("c", [], [])) == 1),
        ("selfproof_missing", rc(lambda s: s.case("c", 1, 1)) == 1),
        ("boolean_selfproof_rejected",
         rc(lambda s: (s.case("c", 1, 1), s.selfproof(True))) == 1),
        ("baseline_equals_observed",
         rc(lambda s: (s.case("c", 1, 1), s.selfproof(dict(good, observed="clean=pass")))) == 1),
        ("no_failure_line",
         rc(lambda s: (s.case("c", 1, 1),
                       s.selfproof(dict(good, fail_line="")))) == 1),
        ("denominator_below_min",
         rc(lambda s: (s.case("c", 1, 1), s.require_denominator(1, "x", 2),
                       s.selfproof(good))) == 1),
        ("clean_pass",
         rc(lambda s: (s.case("c", 1, 1), s.require_denominator(2, "x", 2),
                       s.selfproof(good))) == 0),
    ]
    bad = [n for n, ok in probes if not ok]
    for n, ok in probes:
        print("[%s] %s" % ("PASS" if ok else "FAIL", n))
    print("框架自证：%d/%d → %s" % (len(probes) - len(bad), len(probes),
                                "PASS" if not bad else "FAIL"))
    return 0 if not bad else 1


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--json", default="")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--logdir", default="", help="把每套的完整 stdout 写到该目录")
    a = ap.parse_args(argv)
    if a.selftest:
        return selfcheck()
    names = sorted(SUITES)
    if a.only:
        want = {x.strip() if x.strip().endswith(".py") else x.strip() + ".py"
                for x in a.only.split(",")}
        names = [n for n in names if n in want]
    if a.list or not (a.all or a.only):
        for n in names:
            print("%-26s argv=%-18s sp=%s"
                  % (n, " ".join(SUITES[n][0]) or "-", SUITES[n][1]))
        print("共 %d 个脚本；加 --all 执行" % len(names))
        return 0
    docs, bad, env, legacy, t0 = [], 0, 0, 0, time.time()
    for n in names:
        s, last, rc = run_legacy(n, SUITES[n], a.timeout)
        d = s.emit()
        if a.logdir:
            os.makedirs(a.logdir, exist_ok=True)
            with open(os.path.join(a.logdir, n[:-3] + ".log"),
                      "w", encoding="utf-8") as f:
                f.write("CMD: %s %s\n\n"
                        % (n, " ".join(SUITES[n][0])))
                f.write(getattr(s, "output", "") or "<env_missing>")
        docs.append(dict(d, legacy_exit=rc, last_line=last))
        bad += d["exit"] == 1
        env += d["exit"] == 2
        legacy += rc == 0 and not any(c["verdict"] == "FAIL"
                                      for c in d["cases"] if c["id"] != "selfproof")
        reason = next((c["reason_code"] for c in d["cases"] if c["reason_code"]), "-")
        print("%s %-26s cases=%-3d pass=%-3d exit=%-3d %5.1fs reason=%s"
              % ("PASS" if d["exit"] == 0 else ("SKIP" if d["exit"] == 2 else "FAIL"),
                 n, d["totals"]["cases"], d["totals"]["pass"], d["exit"],
                 d["duration_s"], reason))
    code = 2 if env and not bad else (1 if bad else 0)
    run = {"schema": "vharness_run/1", "suites": docs,
           "totals": {"suites": len(docs),
                      "legacy_pass": legacy,
                      "pass": sum(d["exit"] == 0 for d in docs),
                      "fail": bad, "env_skip": env},
           "duration_s": round(time.time() - t0, 1), "exit": code}
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(run, f, ensure_ascii=False, indent=1)
    print("HARNESS: %s suites=%d legacy_pass=%d harness_pass=%d selfproof_missing=%d exit=%d"
          % ("PASS" if code == 0 else "FAIL", len(docs), legacy,
             run["totals"]["pass"], bad, code))
    return code


if __name__ == "__main__":
    sys.exit(main())
