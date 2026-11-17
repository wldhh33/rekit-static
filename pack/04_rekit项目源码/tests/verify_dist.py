#!/usr/bin/env python3
# tests/verify_dist.py — 可分发性判据：wheel 装到仓库外干净环境后与仓库内源码逐字节对拍
#
# 目的：证明 rekit 能打成一个自包含的包，装到一台没有这个仓库的机器上就能用，
#       且「仓库内 python -m rekit」与「干净环境里装的 rekit」对同一输入给出
#       完全相同的 --json 输出。
# 判据：
#   (a) 用现有 pyproject.toml 构建 sdist + wheel（python -m build --no-isolation）：
#       wheel 只含 rekit/**（+ dist-info），sdist 只含包本体与元数据；两者都不得出现
#       tests / examples / samples / tools / fixtures；
#   (b) METADATA：无 Requires-Dist（dependencies=[] 属实）、Requires-Python >=3.8、
#       console script `rekit = rekit.cli:main`；requires-python 另做静态扫描
#       （3.9+ 专属语法 / 内置泛型注解 / PEP 604 / 3.9+ 专属 API）；
#   (c) 在仓库外的系统临时目录新建 venv，--no-index 安装 wheel（非 -e）；
#   (d) 从仓库外 cwd 跑 `rekit --help`、info PE/ELF/.NET、ilflow .NET；
#       import 到的 rekit 必须来自 venv site-packages，不得来自仓库源码；
#   (e) 关键：仓库内 `python -m rekit` 与安装版 `rekit` 对同一输入 --json
#       **stdout 逐字节相同**、退出码相同、stderr 相同；不一致即 FAIL 并给出首个差异位置；
#   (f) 路径字段：--json 唯一的路径派生字段是 "path"，两边传入同一绝对路径，
#       要求该字段逐字节相等（不做任何排除；一旦路径不同，字节比较会先失败）；
#   (g) cwd 无关：安装版在两个不同 cwd 下输出必须相同；
#   (h) 可失败自证：篡改一字节 / 改动 path 字段必须被检出；空比对（b"" vs b""）判 FAIL。
#
# 样本：PE/ELF 用仓库内 fixtures；.NET 用 m3 samples（fresh clone 需 setup.ps1 恢复）。
# 缺样本 / build / setuptools -> ENV_MISSING(exit 2)，不静默跳过。任何 FAIL -> exit 1。
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
SRC = os.path.dirname(os.path.realpath(HERE))        # pack\04_rekit项目源码
PE = os.path.join(WORK, "tests", "fixtures", "minipe.exe")
ELF = os.path.join(WORK, "tests", "fixtures", "bin_ls.elf")
DOTNET = os.path.join(WORK, "samples", "m17", "_gen", "RekitSample.dll")
OUT_JSON = os.path.join(WORK, "evidence_dist.json")
PY = sys.executable

CASES = [
    ("info.pe", ["info", PE, "--json"]),
    ("info.elf", ["info", ELF, "--json"]),
    ("info.dotnet", ["info", DOTNET, "--json"]),
    ("ilflow.dotnet", ["ilflow", DOTNET, "--json"]),
]

# 3.9+ 专属 API（语法层面的 ast.Match / 注解层面的内置泛型另由 _py39_hits 检查）
API39 = re.compile(r"\b(removeprefix|removesuffix|zoneinfo|graphlib|tomllib|"
                   r"functools\.cache|math\.lcm)\b")

UNAVAILABLE = [
    {"item": "examples\\（PE / ELF / .NET 三份 import 示例）",
     "impact": "wheel 不含；脱离仓库无法运行",
     "why": "示例按 __file__ 定位仓库源码，不是包内模块"},
    {"item": "tests\\ 与 tests\\fixtures（minipe.exe / bin_ls.elf）",
     "impact": "pip 安装后没有 fixture，pytest / verify 套不可用",
     "why": "MANIFEST.in prune tests；判据随仓库发布，不进分发包"},
    {"item": "samples\\（m17\\_gen\\RekitSample.dll 等 .NET 样本）",
     "impact": "dotnet / ilflow / layout / sigblob 需调用方自带 .NET 文件",
     "why": "样本被 .gitignore 排除，体积大，不是运行时资产"},
    {"item": "samples\\、tools\\（binutils）、work\\ 下的门禁脚本",
     "impact": "gate.ps1 / setup.ps1 / verify_* 不可用",
     "why": "属于仓库交付物与资产恢复流程，不是 wheel 内容"},
    {"item": "coverage 命令",
     "impact": "运行期需要外部 objdump（GNU binutils）",
     "why": "调用 PATH 里的 objdump，不是 pip 依赖，无法写进 dependencies"},
]

PACK = os.path.dirname(SRC)
README = os.path.join(PACK, "README.md")
LIBAPI = os.path.join(PACK, "03_路线图与章程", "LIBRARY_API.md")
# 文档里唯一的版本声明行：`- **支持的 Python 版本**：3.8+（实测 …）`
DECL_RE = re.compile(r"支持的 Python 版本\*\*[：:]\s*(\d+\.\d+)\+")

CHECKS = []


def _add(cid, name, ok, detail):
    CHECKS.append({"id": cid, "name": name,
                   "status": "PASS" if ok else "FAIL", "detail": detail})
    print("[%s] %s %s :: %s" % ("PASS" if ok else "FAIL", cid, name, detail))


def _rel(p):
    try:
        r = os.path.relpath(p, WORK)
    except ValueError:            # 跨盘符（仓库在 D:、临时 venv 在 C:）
        return p
    return r if not r.startswith("..") else p


def _scrub(text, tmp):
    """证据不得含绝对路径/临时目录名：每次构建临时目录都不同，写进去会让索引 sha256 漂移。"""
    for a, b in ((os.path.realpath(tmp), "<tmp>"), (tmp, "<tmp>"),
                 (os.path.realpath(SRC), "<src>"), (SRC, "<src>"),
                 (os.path.realpath(WORK), "<work>"), (WORK, "<work>")):
        text = text.replace(a, b)
    return text


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _clean_env():
    e = {k: v for k, v in os.environ.items()
         if k.upper() not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")}
    e["PYTHONIOENCODING"] = "utf-8"
    return e


def _run(argv, cwd, timeout=300):
    p = subprocess.run(argv, cwd=cwd, env=_clean_env(), timeout=timeout,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.returncode, p.stdout, p.stderr


def _bytes_same(a, b):
    """空比对一律不成立：b"" vs b"" 必须判 FAIL。"""
    return bool(a) and bool(b) and a == b


def _first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            line = a[:i].count(b"\n") + 1
            return ("第 %d 行第 %d 字节: repo=%r installed=%r"
                    % (line, i, a[max(0, i - 20):i + 20], b[max(0, i - 20):i + 20]))
    if len(a) != len(b):
        return "长度不同 repo=%d installed=%d（前缀相同）" % (len(a), len(b))
    return ""


def _py39_hits(pkg_dir):
    """静态扫描 3.9+ 专属语法/注解/API；返回命中列表（空 = 未发现）。"""
    hits = []
    for fn in sorted(os.listdir(pkg_dir)):
        if not fn.endswith(".py"):
            continue
        path = os.path.join(pkg_dir, fn)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        for m in API39.finditer(src):
            hits.append("%s:%s" % (fn, m.group(1)))
        tree = ast.parse(src, filename=path)
        future = any(isinstance(n, ast.ImportFrom) and n.module == "__future__"
                     and any(a.name == "annotations" for a in n.names)
                     for n in tree.body)
        bad = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Match):
                bad.append("match-stmt")
        if not future:
            anns = []
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    a = n.args
                    for arg in a.posonlyargs + a.args + a.kwonlyargs:
                        if arg.annotation:
                            anns.append(arg.annotation)
                    for arg in (a.vararg, a.kwarg):
                        if arg is not None and arg.annotation:
                            anns.append(arg.annotation)
                    if n.returns:
                        anns.append(n.returns)
                elif isinstance(n, ast.AnnAssign):
                    anns.append(n.annotation)
            for ann in anns:
                for m in ast.walk(ann):
                    if (isinstance(m, ast.Subscript) and isinstance(m.value, ast.Name)
                            and m.value.id in ("list", "dict", "tuple", "set",
                                               "frozenset", "type")):
                        bad.append("builtin-generic:" + m.value.id)
                    if isinstance(m, ast.BinOp) and isinstance(m.op, ast.BitOr):
                        bad.append("pep604-union")
        if bad:
            hits.append("%s:%s" % (fn, ",".join(sorted(set(bad)))))
    return hits


def _banned(paths):
    parts = {"tests", "examples", "samples", "tools", "fixtures"}
    return [p for p in paths
            if any(seg in parts for seg in p.replace("\\", "/").split("/"))]


def _declared_python():
    """从 pyproject 与两份文档读取「最低 Python 版本」，返回 {来源: '3.8'|None}。"""
    vals = {}
    with open(os.path.join(SRC, "pyproject.toml"), encoding="utf-8") as f:
        m = re.search(r'requires-python\s*=\s*">=(\d+\.\d+)"', f.read())
    vals["pyproject"] = m.group(1) if m else None
    for label, path in (("README", README), ("LIBRARY_API", LIBAPI)):
        try:
            with open(path, encoding="utf-8") as f:
                m = DECL_RE.search(f.read())
            vals[label] = m.group(1) if m else None
        except OSError:
            vals[label] = None
    return vals


def _meta_matches(req_py, decl):
    """METADATA 的 Requires-Python 是否等于文档声明（空声明一律不成立）。"""
    return decl is not None and req_py == [">=" + decl]


def main():
    missing = [p for p in (PE, ELF, DOTNET) if not os.path.isfile(p)]
    if missing:
        print("ENV_MISSING: 缺少样本 %s；PE/ELF 来自仓库 fixtures，"
              ".NET 需恢复 m3 samples（m17\\_gen\\RekitSample.dll，跑 setup.ps1）"
              % ", ".join(_rel(p) for p in missing))
        return 2

    for mod in ("build", "setuptools"):
        rc, _, _ = _run([PY, "-c", "import %s" % mod], SRC)
        if rc != 0:
            print("ENV_MISSING: 缺少构建依赖 %s；执行 `python -m pip install build setuptools`" % mod)
            return 2

    tmp = tempfile.mkdtemp(prefix="rekit_dist_")
    real_tmp, real_src = os.path.realpath(tmp), os.path.realpath(SRC)
    if real_tmp.startswith(real_src + os.sep):
        print("ENV_MISSING: 临时目录落在仓库内（%s），无法证明仓库外可用" % tmp)
        return 2
    try:
        dist = os.path.join(tmp, "dist")
        # ---- (a) 构建
        rc, out, err = _run([PY, "-m", "build", "--no-isolation", "--outdir", dist],
                            SRC, timeout=600)
        tail = (out + err).decode("utf-8", "replace").strip().splitlines()
        _add("build.exit", "构建 sdist + wheel", rc == 0, "exit=%d" % rc)
        whl = [os.path.join(dist, n) for n in os.listdir(dist) if n.endswith(".whl")]
        sdz = [os.path.join(dist, n) for n in os.listdir(dist) if n.endswith(".tar.gz")]
        _add("build.artifacts", "两个产物都存在", len(whl) == 1 and len(sdz) == 1,
             "wheel=%s sdist=%s" % ([os.path.basename(x) for x in whl],
                                    [os.path.basename(x) for x in sdz]))
        if not whl or not sdz:
            return _finish(None)

        # ---- (a) wheel 内容
        with zipfile.ZipFile(whl[0]) as z:
            wnames = z.namelist()
            meta = z.read("rekit-0.1.0.dist-info/METADATA").decode("utf-8")
            eps = z.read("rekit-0.1.0.dist-info/entry_points.txt").decode("utf-8")
        wtop = sorted({n.split("/")[0] for n in wnames})
        wallowed = {"rekit", "rekit-0.1.0.dist-info"}
        _add("wheel.contents", "wheel 只含 rekit/** + dist-info，无异物",
             set(wtop) == wallowed and not _banned(wnames),
             "顶层=%s 异物=%s" % (wtop, _banned(wnames) or "无"))

        # ---- (a) sdist 内容
        with tarfile.open(sdz[0]) as t:
            snames = [m.name for m in t.getmembers() if "/" in m.name]
        srel = [n.split("/", 1)[1] for n in snames]
        stop = sorted({r.split("/")[0] for r in srel})
        sallowed = {"rekit", "rekit.egg-info", "rekit-0.1.0.egg-info", "PKG-INFO",
                    "README.md", "pyproject.toml", "setup.cfg", "MANIFEST.in"}
        _add("sdist.contents", "sdist 只含包本体 + 元数据（tests/examples 已 prune）",
             set(stop) <= sallowed and not _banned(srel),
             "顶层=%s 异物=%s" % (stop, _banned(srel) or "无"))

        # ---- (b) METADATA
        lines = meta.splitlines()
        req_py = [l.split(":", 1)[1].strip() for l in lines
                  if l.lower().startswith("requires-python:")]
        req_dist = [l for l in lines if l.lower().startswith("requires-dist:")]
        _add("meta.deps", "METADATA 无 Requires-Dist（dependencies=[] 属实）",
             req_dist == [] and "dependencies = []" in open(
                 os.path.join(SRC, "pyproject.toml"), encoding="utf-8").read(),
             "Requires-Dist=%r" % (req_dist,))
        decl = _declared_python()
        minpy = decl.get("pyproject")
        _add("meta.python.doc", "pyproject / README / LIBRARY_API 的 Python 版本声明一致",
             None not in decl.values() and len(set(decl.values())) == 1,
             "声明=%r" % (decl,))
        _add("meta.python", "METADATA Requires-Python 与文档声明一致",
             _meta_matches(req_py, minpy), "METADATA=%r 声明=%r" % (req_py, minpy))
        try:
            cur = tuple(int(x) for x in minpy.split("."))
        except (AttributeError, ValueError):
            cur = None
        _add("interp.satisfies", "当前解释器满足文档声明的最低版本",
             cur is not None and sys.version_info[:2] >= cur,
             "当前=%d.%d 声明>=%s" % (sys.version_info[0], sys.version_info[1], minpy))
        _add("meta.python.selfproof", "版本比对器可失败自证（伪造版本/空声明必须不等）",
             _meta_matches([">=" + (minpy or "")], minpy)
             and not _meta_matches([">=99.0"], minpy)
             and not _meta_matches([], None),
             "正确=匹配 伪造>=99.0=不等 空声明=不等")
        _add("meta.entry", "console script `rekit = rekit.cli:main`",
             "rekit = rekit.cli:main" in eps, eps.strip().replace("\n", " | "))
        hits = _py39_hits(os.path.join(SRC, "rekit"))
        _add("meta.py38scan", "文档声明的下限之上无 3.9+ 语法/API（仅静态扫描，不作承诺）",
             not hits and minpy is not None and tuple(int(x) for x in minpy.split(".")) < (3, 9),
             "命中=%s（范围：语法/注解/3.9+ 专属 API，不含运行时行为）"
             % (hits or "无"))

        # ---- (c) 仓库外干净 venv 安装 wheel
        venv = os.path.join(tmp, "venv")
        rc, out, err = _run([PY, "-m", "venv", venv], tmp, timeout=300)
        vpy = os.path.join(venv, "Scripts" if os.name == "nt" else "bin",
                           "python.exe" if os.name == "nt" else "python")
        rk = os.path.join(venv, "Scripts" if os.name == "nt" else "bin",
                          "rekit.exe" if os.name == "nt" else "rekit")
        rc2, out2, err2 = (1, b"", b"") if rc != 0 else _run(
            [vpy, "-m", "pip", "install", "--no-index", "--no-deps",
             "--disable-pip-version-check", whl[0]], tmp, timeout=300)
        tail = (out2 + err2).decode("utf-8", "replace").strip().splitlines()
        _add("venv.install", "仓库外 venv 装 wheel（--no-index，非 -e）",
             rc == 0 and rc2 == 0 and os.path.isfile(rk), "pip exit=%d" % rc2)
        if rc != 0 or rc2 != 0 or not os.path.isfile(rk):
            return _finish(tmp)

        # ---- (d) import 来源 + 包内异物
        rc, out, err = _run(
            [vpy, "-c", "import rekit, rekit.api; print(rekit.__file__)"], tmp)
        found = out.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        fpath = os.path.realpath(found[0]) if found[0] else ""
        in_venv = (rc == 0 and fpath.startswith(os.path.realpath(venv) + os.sep)
                   and not fpath.startswith(real_src + os.sep))
        _add("import.file", "import 到的 rekit 来自 venv site-packages",
             in_venv, "venv site-packages（未使用仓库源码）" if in_venv
             else "实际来源=%s" % _rel(fpath))
        rc, out, err = _run(
            [vpy, "-c", "import importlib.metadata as m;"
                        "print(chr(10).join(str(x) for x in m.files('rekit')))"], tmp)
        files = out.decode("utf-8", "replace").split()
        _add("dist.noextras", "安装清单不含 samples/tests/tools/fixtures/examples",
             rc == 0 and bool(files) and not _banned(files),
             "文件数=%d 异物=%s" % (len(files), _banned(files) or "无"))

        # ---- (d) 安装版 --help
        rc_h, out_h, err_h = _run([rk, "--help"], tmp)
        first = (out_h.decode("utf-8", "replace").splitlines() or [""])[0]
        _add("cli.help.exit", "安装版 rekit --help 退出 0",
             rc_h == 0 and b"usage" in out_h.lower(), "exit=%d 首行=%s" % (rc_h, first))
        rc_hr, out_hr, _ = _run([PY, "-m", "rekit", "--help"], SRC)
        _add("cli.help.equal", "安装版与仓库内 --help 逐字节相同", _bytes_same(out_hr, out_h),
             "repo==installed" if _bytes_same(out_hr, out_h)
             else _first_diff(out_hr, out_h))

        # ---- (e)(f)(g) 逐字节对拍
        cwd2 = os.path.join(tmp, "cwd2")
        os.makedirs(cwd2, exist_ok=True)
        case_ev = []
        repo_out = {}
        for cid, args in CASES:
            rc_r, out_r, err_r = _run([PY, "-m", "rekit"] + args, SRC)
            rc_i, out_i, err_i = _run([rk] + args, tmp)
            rc_i2, out_i2, _ = _run([rk] + args, cwd2)
            same = _bytes_same(out_r, out_i)
            _add("bytes." + cid, "repo vs installed stdout 逐字节相同", same,
                 "stdout 逐字节相同" if same else _first_diff(out_r, out_i))
            _add("rc." + cid, "退出码相同", rc_r == rc_i and rc_r == 0,
                 "repo=%d installed=%d" % (rc_r, rc_i))
            _add("stderr." + cid, "stderr 相同（均为空输出）", err_r == err_i == b"",
                 "均为空" if err_r == err_i == b"" else "repo=%r installed=%r"
                 % (err_r[:60], err_i[:60]))
            path_ok, pv = False, "JSON 解析失败"
            try:
                jr, ji = json.loads(out_r.decode("utf-8")), json.loads(out_i.decode("utf-8"))
                want = args[1]
                path_ok = jr.get("path") == ji.get("path") == want
                pv = ("path=%s" % _rel(jr.get("path")) if path_ok
                      else "repo=%r installed=%r" % (jr.get("path"), ji.get("path")))
            except Exception as e:  # noqa: BLE001
                pv = "JSON 解析失败: %s" % e
            _add("path." + cid, "唯一路径派生字段 path 两边相同（不排除）", path_ok, pv)
            _add("cwd." + cid, "安装版两个不同 cwd 输出相同",
                 _bytes_same(out_i, out_i2), "tmp vs cwd2")
            repo_out[cid] = out_r
            case_ev.append({"case": cid, "args": args[:1] + ["<sample>"] + args[2:],
                            "rc_repo": rc_r, "rc_installed": rc_i,
                            "stdout_equal": same, "stderr_equal": err_r == err_i,
                            "path_equal": path_ok, "cwd_independent": _bytes_same(out_i, out_i2)})

        # ---- (h) 可失败自证
        base = repo_out["info.pe"]
        tampered = base.replace(b'"nsections": 2', b'"nsections": 3', 1)
        if tampered == base:                      # 兜底：改最后一个字节
            tampered = base[:-1] + bytes([base[-1] ^ 1])
        esc = json.dumps(PE, ensure_ascii=False)[1:-1].encode("utf-8")
        pathmut = base.replace(esc, esc + b"_x", 1)
        if pathmut == base:                       # 兜底：追加一段
            pathmut = base + b" "
        loc = _first_diff(base, tampered)
        ok = (_bytes_same(base, base)
              and not _bytes_same(base, tampered)
              and not _bytes_same(base, pathmut)
              and not _bytes_same(b"", b"")
              and "字节" in loc)
        _add("selfproof", "逐字节比较器可失败自证（篡改/路径变化/空比对均检出）", ok,
             "篡改=不等 path变化=不等 空比对=FAIL 差异定位=%s" % (loc or "无"))

        return _finish(tmp, {
            "wheel": os.path.basename(whl[0]),
            "sdist": os.path.basename(sdz[0]),
            "wheel_files": len(wnames), "sdist_files": len(snames) + 1,
            "wheel_top": wtop, "sdist_top": stop,
            "requires_python": req_py, "requires_dist": req_dist,
            "declared_python": minpy,
            "declaration_sources": decl,
            "cases": case_ev,
        })  # noqa: E501
    finally:
        try:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        except Exception:  # noqa: BLE001
            pass


def _finish(tmp, artifact=None):
    payload = {
        "schema": 1,
        "status": "fail" if any(c["status"] == "FAIL" for c in CHECKS) else "pass",
        "checks": CHECKS,
        "artifact": artifact or {},
        "venv": {"location": "系统临时目录（每次新建，仓库外）",
                 "install": "--no-index --no-deps <wheel>（非 -e）"},
        "unavailable": UNAVAILABLE,
        "samples": {
            "pe": {"path": _rel(PE), "sha256": _sha(PE), "bytes": os.path.getsize(PE)},
            "elf": {"path": _rel(ELF), "sha256": _sha(ELF), "bytes": os.path.getsize(ELF)},
            "dotnet": {"path": _rel(DOTNET), "sha256": _sha(DOTNET),
                       "bytes": os.path.getsize(DOTNET),
                       "requires": "m3 samples（setup.ps1 恢复）"},
        },
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        raw = json.dumps(payload, ensure_ascii=False, indent=1)
        f.write(_scrub(raw, tmp) if tmp else raw)
    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=0 → %s"
          % (len(CHECKS), len(CHECKS) - len(failed), len(failed),
             "FAIL" if failed else "PASS"))
    print("证据: %s" % os.path.basename(OUT_JSON))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
