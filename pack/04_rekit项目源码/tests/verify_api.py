#!/usr/bin/env python3
# tests/verify_api.py — 库接口（import）与命令行（subprocess）一致性判据
#
# 目的：证明 `rekit.api` 的库路径与 `rekit <cmd> --json` 的命令行路径给出
#       同一批数字，而不是"两边各写一套、没人对过"。
# 判据：
#   (a) 三个示例（PE / ELF / .NET）必须真的用 import 调用 rekit.api：
#       源码扫描禁止 subprocess / os.chdir / os.getcwd 出现在示例里；
#   (b) 每个示例在 work 目录与临时目录各跑一次，输出必须完全相同（证明不依赖 cwd）；
#   (c) 示例 JSON 的每个字段与对应 CLI --json 的字段逐项相等：
#       PE/ELF 对 `rekit info <f> --json`，.NET 对 `rekit dotnet <f> --json`；
#       另用 `rekit.api.probe_dotnet` 对 `info` 的 dotnet.is_cli 做一次交叉；
#   (d) 公开面固定：`rekit.api.__all__` 必须等于 LIBRARY_API.md 声明的集合
#       （新增/删除导出必须同时改契约，防止包被整体冻结成 API）；
#   (e) 空比对一律 FAIL（expected 为 None / 空容器即失败），分母为 0 也 FAIL；
#   (f) 可失败自证：篡改一份示例期望值、传入空期望，比较器必须报不一致；
#   (g) 失败语义：给错格式（parse_pe 收到 ELF / parse_elf 收到 PE）必须抛
#       rekit.api.FormatMismatch——不是 AssertionError、不是别的；同一判据用
#       `python -O` 再跑一次（断言被剥掉也必须照样抛），并自证该判据可失败。
#
# 样本：PE/ELF 用仓库内 fixtures（无需恢复）；.NET 用 m3 samples 的
#       `samples\m17\_gen\RekitSample.dll`（fresh clone 需先跑 setup.ps1 恢复）。
# 缺 .NET 样本 -> env_missing(exit 2)，不静默跳过。任何 FAIL -> exit 1。
import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
SRC = os.path.dirname(os.path.realpath(HERE))        # pack\04_rekit项目源码
EXAMPLES = os.path.join(SRC, "examples")
PE = os.path.join(WORK, "tests", "fixtures", "minipe.exe")
ELF = os.path.join(WORK, "tests", "fixtures", "bin_ls.elf")
DOTNET = os.path.join(WORK, "samples", "m17", "_gen", "RekitSample.dll")
OUT_JSON = os.path.join(WORK, "evidence_api_parity.json")
PY = sys.executable
API_SURFACE = {"build_info", "detect_format", "parse_pe", "parse_elf",
               "build_dotnet", "probe_dotnet",
               "RekitError", "FormatMismatch", "MalformedBinary"}

# 子进程探针：只用 rekit.api 调用，回报异常类型；opt 字段证明 -O 真的生效。
CHILD = (
    "import json,sys\n"
    "sys.path.insert(0, %r)\n"
    "import rekit.api as api\n"
    "kind, path = sys.argv[1], sys.argv[2]\n"
    "fn = api.parse_pe if kind == 'pe' else api.parse_elf\n"
    "out = {'opt': sys.flags.optimize}\n"
    "try:\n"
    "    fn(path)\n"
    "except BaseException as e:\n"
    "    out.update(exc=type(e).__name__, ours=isinstance(e, api.FormatMismatch),\n"
    "               assertion=isinstance(e, AssertionError), msg=str(e)[:80])\n"
    "else:\n"
    "    out.update(exc='NO_RAISE', ours=False, assertion=False, msg='')\n"
    "print(json.dumps(out))\n"
) % SRC
ERR_KEYS = ("exc", "ours", "assertion", "opt")

sys.path.insert(0, WORK)

CHECKS = []


def _add(cid, name, ok, detail):
    CHECKS.append({"id": cid, "name": name,
                   "status": "PASS" if ok else "FAIL", "detail": detail})
    print("[%s] %s %s :: %s" % ("PASS" if ok else "FAIL", cid, name, detail))


def _empty(v):
    """空期望：None 或空容器。0 / False 不是空。"""
    return v is None or (isinstance(v, (str, list, dict, tuple, set)) and len(v) == 0)


def _same(expected, actual):
    return not _empty(expected) and actual is not None and expected == actual


def _cmp(cid, name, expected, actual, what=""):
    if _empty(expected):
        _add(cid, name, False, "expected 为空（空比对一律 FAIL）" + what)
        return False
    if actual is None:
        _add(cid, name, False, "actual 缺失" + what)
        return False
    ok = expected == actual
    if ok:
        _add(cid, name, True, "%s 相等" % (what or "值"))
    else:
        _add(cid, name, False, "%s expected=%r actual=%r"
             % (what or "值", expected, actual))
    return ok


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + (os.pathsep + env["PYTHONPATH"]
                               if env.get("PYTHONPATH") else "")
    return env


def _run_json(argv, cwd):
    p = subprocess.run(argv, cwd=cwd, env=_env(), capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=180)
    if p.returncode != 0:
        raise RuntimeError("%s rc=%d stderr=%s"
                           % (argv[-3:], p.returncode,
                              (p.stderr or "").strip()[:200]))
    return json.loads(p.stdout)


def _example(name, sample, cwd):
    return _run_json([PY, os.path.join(EXAMPLES, name), sample], cwd)


def _raise_probe(kind, path, optimize):
    """在子进程里用 rekit.api 解析错格式文件，回报异常类型与 -O 是否生效。"""
    argv = [PY] + (["-O"] if optimize else []) + ["-c", CHILD, kind, path]
    p = subprocess.run(argv, cwd=WORK, env=_env(), capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=180)
    lines = (p.stdout or "").strip().splitlines()
    if p.returncode != 0 or not lines:
        return {"exc": "rc=%d" % p.returncode, "ours": False,
                "assertion": False, "opt": -1,
                "stderr": (p.stderr or "").strip()[:200]}
    return json.loads(lines[-1])


def _norm(got):
    """只比对判据关心的四个字段；异常消息文本不在契约里。"""
    return {k: got.get(k) for k in ERR_KEYS}


def _rel(p):
    """证据里的路径与克隆位置无关。"""
    return os.path.relpath(p, WORK).replace(os.sep, "/")


def _sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _scan_sources():
    """示例必须用 import：禁 subprocess / chdir / getcwd。"""
    hits = []
    for name in sorted(os.listdir(EXAMPLES)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(EXAMPLES, name), encoding="utf-8") as f:
            text = f.read()
        for banned in ("import subprocess", "from subprocess", "subprocess.",
                       "os.chdir", "os.getcwd", "Popen("):
            if banned in text:
                hits.append("%s:%s" % (name, banned))
    _add("example.import-only", "示例不含 subprocess/chdir/getcwd", not hits,
         "命中=%s" % (";".join(hits) if hits else "无"))
    for name in ("pe_report.py", "elf_report.py", "dotnet_report.py"):
        ok = os.path.isfile(os.path.join(EXAMPLES, name))
        _add("example.present:" + name, "示例存在", ok,
             os.path.join("examples", name) if ok else "缺失")


def main():
    missing = [p for p in (PE, ELF) if not os.path.isfile(p)]
    if missing or not os.path.isfile(DOTNET):
        print("ENV_MISSING: 缺少样本 %s；PE/ELF 来自仓库 fixtures，"
              ".NET 需恢复 m3 samples（m17\\_gen\\RekitSample.dll，跑 setup.ps1）"
              % ", ".join(_rel(p) for p in missing + ([DOTNET] if not os.path.isfile(DOTNET) else [])))
        return 2

    _scan_sources()

    import rekit.api as api  # noqa: E402

    _cmp("api.surface", "rekit.api.__all__ 与契约一致", sorted(API_SURFACE),
         sorted(api.__all__), "公开符号")

    # ---- (g) 失败语义：错格式必须抛 FormatMismatch，-O 下同样成立
    got_pe = _norm(_raise_probe("pe", ELF, False))
    got_elf = _norm(_raise_probe("elf", PE, False))
    want = {"exc": "FormatMismatch", "ours": True, "assertion": False, "opt": 0}
    _cmp("err.pe-on-elf", "parse_pe 收到 ELF 抛 FormatMismatch", want, got_pe,
         "异常类型")
    _cmp("err.elf-on-pe", "parse_elf 收到 PE 抛 FormatMismatch", want, got_elf,
         "异常类型")
    want_o = dict(want, opt=1)
    _cmp("err.opt.pe-on-elf", "python -O 下 parse_pe 仍抛 FormatMismatch", want_o,
         _norm(_raise_probe("pe", ELF, True)), "异常类型")
    _cmp("err.opt.elf-on-pe", "python -O 下 parse_elf 仍抛 FormatMismatch", want_o,
         _norm(_raise_probe("elf", PE, True)), "异常类型")
    tampered_err = dict(want, exc="AssertionError")
    no_raise = {"exc": "NO_RAISE", "ours": False, "assertion": False, "opt": 0}
    ok_err = (_same(want, got_pe)
              and not _same(tampered_err, got_pe)
              and not _same(no_raise, got_pe)
              and not _same({}, got_pe))
    _add("err.selfproof", "失败语义判据可失败自证（错类型/未抛出/空期望均检出）", ok_err,
         "篡改=不等 未抛出=不等 空期望=FAIL")

    with tempfile.TemporaryDirectory(prefix="rekit_api_") as tmp:
        # ---- (b) cwd 无关：work 与临时目录两次输出必须相同
        runs = {}
        for name, sample in (("pe_report.py", PE), ("elf_report.py", ELF),
                             ("dotnet_report.py", DOTNET)):
            here = _example(name, sample, WORK)
            there = _example(name, sample, tmp)
            runs[name] = there
            _cmp("cwd." + name, "示例不依赖 cwd", here, there, "work vs tmp")

        ex_pe = runs["pe_report.py"]
        ex_elf = runs["elf_report.py"]
        ex_dn = runs["dotnet_report.py"]

        info_pe = _run_json([PY, "-m", "rekit.cli", "info", PE, "--json"], tmp)
        info_elf = _run_json([PY, "-m", "rekit.cli", "info", ELF, "--json"], tmp)
        info_dn = _run_json([PY, "-m", "rekit.cli", "info", DOTNET, "--json"], tmp)
        cli_dn = _run_json([PY, "-m", "rekit.cli", "dotnet", DOTNET, "--json"], tmp)

        # ---- (c) PE 逐项
        _cmp("pe.format", "PE 格式标识", info_pe["format"], ex_pe["format"])
        _cmp("pe.machine", "PE 机器类型", info_pe["arch"], ex_pe["machine"])
        _cmp("pe.bits", "PE 位数", info_pe["bits"], ex_pe["bits"])
        _cmp("pe.entry", "PE 入口", info_pe["entry"], ex_pe["entry"])
        _cmp("pe.image_base", "PE 镜像基址", info_pe["image_base"], ex_pe["image_base"])
        _cmp("pe.subsystem", "PE 子系统", info_pe["subsystem"], ex_pe["subsystem"])
        _cmp("pe.nsections", "PE 节数", info_pe["nsections"], ex_pe["nsections"])
        _cmp("pe.sections", "PE 节表", info_pe["sections"], ex_pe["sections"])
        _cmp("pe.imports", "PE 导入 DLL 列表", info_pe["imports"], ex_pe["imports"])

        # ---- (c) ELF 逐项
        _cmp("elf.format", "ELF 格式标识", info_elf["format"], ex_elf["format"])
        _cmp("elf.entry", "ELF 入口", info_elf["entry"], ex_elf["entry"])
        _cmp("elf.nsections", "ELF 节数", info_elf["nsections"], ex_elf["nsections"])
        _cmp("elf.sections", "ELF 节表", info_elf["sections"], ex_elf["sections"])
        _cmp("elf.security", "ELF 安全属性", info_elf["security"], ex_elf["security"])

        # ---- (c) .NET 逐项
        _cmp("dn.status", ".NET 状态", cli_dn["status"], ex_dn["status"])
        _cmp("dn.assembly", ".NET 程序集", cli_dn["assembly"], ex_dn["assembly"])
        _cmp("dn.file", ".NET 文件头三元组", cli_dn["file"], ex_dn["file"])
        _cmp("dn.denominators", ".NET 分母", cli_dn["denominators"],
             ex_dn["denominators"])
        _cmp("dn.ntypes", ".NET 类型条数", len(cli_dn["types"]), ex_dn["ntypes"])
        _cmp("dn.nmethods", ".NET 方法条数", len(cli_dn["methods"]),
             ex_dn["nmethods"])
        probe = api.probe_dotnet(DOTNET)
        _cmp("dn.probe", "probe_dotnet 与 info.dotnet.is_cli", info_dn["dotnet"]["is_cli"],
             probe["is_cli"], "is_cli")

        # ---- (e) 分母不得为 0
        _add("guard.pe", "PE 比对对象非空", ex_pe["nsections"] > 0 and
             len(ex_pe["sections"]) > 0, "节数=%d" % ex_pe["nsections"])
        _add("guard.elf", "ELF 比对对象非空", ex_elf["nsections"] > 0 and
             len(ex_elf["sections"]) > 0, "节数=%d" % ex_elf["nsections"])
        _add("guard.dn", ".NET 比对对象非空", ex_dn["ntypes"] > 0 and
             ex_dn["nmethods"] > 0, "类型=%d 方法=%d"
             % (ex_dn["ntypes"], ex_dn["nmethods"]))

        # ---- (f) 可失败自证：篡改期望 / 空期望必须被比较器检出
        tampered = dict(ex_pe)
        tampered["entry"] = ex_pe["entry"] + 1
        ok = (_same(ex_pe["entry"], info_pe["entry"])
              and not _same(tampered["entry"], info_pe["entry"])
              and not _same(None, info_pe["entry"])
              and not _same([], []))
        _add("selfproof", "比较器可失败自证（篡改/空期望检出）", ok,
             "基线=相等 篡改=不等 空期望=FAIL")

        counts = {"pe": 9, "elf": 5, "dn": 7, "errors": 5}
        payload = {
            "schema": 1,
            "status": "fail" if any(c["status"] == "FAIL" for c in CHECKS)
                      else "pass",
            "checks": CHECKS,
            "samples": {
                "pe": {"path": _rel(PE), "sha256": _sha(PE),
                       "bytes": os.path.getsize(PE)},
                "elf": {"path": _rel(ELF), "sha256": _sha(ELF),
                        "bytes": os.path.getsize(ELF)},
                "dotnet": {"path": _rel(DOTNET), "sha256": _sha(DOTNET),
                           "bytes": os.path.getsize(DOTNET),
                           "requires": "m3 samples（setup.ps1 恢复）"},
            },
            "cli": {"info": "rekit info <f> --json",
                    "dotnet": "rekit dotnet <f> --json"},
            "compared": counts,
        }
        with open(OUT_JSON, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=0 → %s"
          % (len(CHECKS), len(CHECKS) - len(failed), len(failed),
             "FAIL" if failed else "PASS"))
    print("证据: %s" % os.path.basename(OUT_JSON))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
