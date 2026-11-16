#!/usr/bin/env python3
# tests/verify_expr.py — M5 第一单元验收：抽样规则 + Ghidra 对读（弱参照）
#
# 抽样规则（写死，可复现，无随机数）：
#   1) 样本池 = 三个二进制里【边界已声明】的函数：
#        cli-64.exe   PE / MSVC  —— 有 .pdata
#        bin_ls.elf   ELF PIE glibc —— 有 .eh_frame FDE
#        dyn_static   ELF 静态链接 —— 有 .eh_frame FDE，规模大
#   2) 按指令数分层（S1 ≤10、S2 11–30、S3 31–100、S4 >100），
#      每个(二进制, 层)内按地址升序，等距取 min(4, n) 个：
#        idx_k = floor(k * n / m), k = 0..m-1
#   3) 额外强制覆盖（若该二进制存在该类别，必须各取 1 个；不存在则显式记"无此类"）：
#        A 含导入调用（IAT 槽间接 call）
#        B 含回边（循环）
#        C 含间接 jmp（switch/跳转表形态 → 我方 abstain）
#        D 含 SIMD abstain（VEX/EVEX 或 SSE）
#        E 该二进制最大函数
#   4) 目标样本量 ≥ 30 个函数。
#
# Ghidra 的角色是【弱参照】，不是基准：
#   - 只对读三件可机械比对的事：函数入口是否存在、基本块数、直接调用目标集合；
#   - 调用集只判等 .text 内的目标；.plt/.got/导入目标两边口径不同，单列计数；
#   - 大小不一致不判错（Ghidra 可能切分/合并函数），只记录；
#   - 反编译 C 文本只用于人工阅读，不做文本 diff（措辞不同不算分歧）。
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import coverage, disasm, expr, pe, recdesc  # noqa: E402

OBJ_LINE = re.compile(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(.*)$")

SAMPLES = [
    ("tests/fixtures/cli-64.exe", "PE/MSVC"),
    ("tests/fixtures/bin_ls.elf", "ELF/PIE"),
    ("tests/fixtures/dyn_static", "ELF/static"),
]
STRATA = [("S1", 1, 10), ("S2", 11, 30), ("S3", 31, 100), ("S4", 101, 10 ** 9)]
PER_STRATUM = 4
CATS = ["indirect_call", "loop", "indirect_jmp", "simd", "largest"]


def _pool(path):
    res = recdesc.descend(path)
    imp = expr._import_names(path)
    funcs = [f for f in expr.list_functions(res) if f["boundary"] == "declared"]
    lifted = {f["addr"]: expr.lift_function(res, f["addr"], imp) for f in funcs}
    return res, funcs, lifted


def _cats(r):
    cats = set()
    # PE 的 IAT 与 ELF 的 GOT/PLT 都是“间接 call”，类别名不绑定某一格式
    if any(c["indirect"] for c in r["events"]["calls"]):
        cats.add("indirect_call")
    if any(b["target"] <= b["addr"] for b in r["events"]["branches"]):
        cats.add("loop")
    if any(j["target"] is None for j in r["events"]["jumps"]):
        cats.add("indirect_jmp")
    if any(("VEX" in a["reason"]) or ("SIMD" in a["reason"])
           for a in r["abstains"]):
        cats.add("simd")
    return cats


def sample():
    """返回 {binary: {"picked": [...], "strata": {...}, "cats": {...}}}。"""
    out = {}
    for rel, label in SAMPLES:
        path = os.path.join(WORK, rel)
        if not os.path.exists(path):
            out[rel] = {"label": label, "missing": True, "picked": []}
            continue
        res, funcs, lifted = _pool(path)
        picked, strata_tbl = [], {}
        for name, lo, hi in STRATA:
            sub = sorted([f for f in funcs if lo <= f["insns"] <= hi],
                         key=lambda f: f["addr"])
            strata_tbl[name] = len(sub)
            m = min(PER_STRATUM, len(sub))
            for k in range(m):
                picked.append((name, "等距", sub[int(k * len(sub) / m)]["addr"]
                               if m else None))
        # 类别强制覆盖
        cat_note = {}
        for cat in CATS:
            if cat == "largest":
                cand = max(funcs, key=lambda f: f["insns"]) if funcs else None
            else:
                cand = next((f for f in sorted(funcs, key=lambda f: f["addr"])
                             if cat in _cats(lifted[f["addr"]])), None)
            if cand is None:
                cat_note[cat] = "该二进制无此类"
                continue
            cat_note[cat] = "0x%x" % cand["addr"]
            picked.append(("CAT", cat, cand["addr"]))
        addrs, seen = [], set()
        for _s, _why, a in picked:
            if a is not None and a not in seen:
                seen.add(a)
                addrs.append({"addr": a, "stratum": _s, "why": _why})
        out[rel] = {"label": label, "strata": strata_tbl, "cats": cat_note,
                    "picked": addrs, "pool": len(funcs),
                    "res": res, "lifted": lifted}
    return out


# ── Ghidra 侧 ────────────────────────────────────────────────────────
def ghidra_session(path, addrs, sec_va):
    """返回 {addr(我方地址空间): metrics}；Ghidra 不可用则抛 ImportError。"""
    os.environ.setdefault("GHIDRA_INSTALL_DIR", r"D:\tools\ghidra_12.2")
    import pyghidra
    pyghidra.start()            # ghidra.* 模块只有在 start() 之后才可导入
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.app.decompiler import DecompInterface

    out = {}
    with pyghidra.open_program(path, analyze=True,
                               project_location=tempfile.mkdtemp(prefix="rkgh_")) as flat:
        prog = flat.getCurrentProgram()
        fm = prog.getFunctionManager()
        monitor = flat.getMonitor()
        blk = prog.getMemory().getBlock(".text")
        delta = blk.getStart().getOffset() - sec_va
        dec = DecompInterface()
        dec.openProgram(prog)
        bbm = BasicBlockModel(prog)
        space = prog.getAddressFactory().getDefaultAddressSpace()
        for a in addrs:
            entry = space.getAddress(a + delta)
            f = fm.getFunctionAt(entry)
            if f is None:
                # 入口不在 Ghidra 函数起点：记录它落在哪个函数内部，归因用
                cont = fm.getFunctionContaining(entry)
                out[a] = {"found": False,
                          "containing": (cont.getEntryPoint().getOffset() - delta
                                         if cont else None),
                          "containing_name": cont.getName() if cont else None}
                continue
            body = f.getBody()
            nblk = 0
            it = bbm.getCodeBlocksContaining(body, monitor)
            while it.hasNext():
                it.next()
                nblk += 1
            calls = sorted(fn.getEntryPoint().getOffset() - delta
                           for fn in f.getCalledFunctions(monitor))
            c = None
            try:
                res = dec.decompileFunction(f, 60, monitor)
                if res and res.decompileCompleted():
                    c = res.getDecompiledFunction().getC()
            except Exception:
                c = None
            out[a] = {"found": True, "name": f.getName(),
                      "size": body.getNumAddresses(), "blocks": nblk,
                      "calls": calls, "c": c,
                      "delta": delta}
    return out


def compare(ours, gh, sec_range):
    """机械比对：入口/块数/直接调用集；返回 (ok_dict, notes)。"""
    notes = []
    if not gh.get("found"):
        cont = gh.get("containing")
        if cont is None:
            return {"entry": False}, [
                "Ghidra 在该地址完全没有函数：入口落在 Ghidra 未识别区段；"
                "我方边界来自 .pdata/FDE，不因 Ghidra 缺失而改变"]
        return {"entry": False}, [
            "入口落在 Ghidra 函数 0x%x（%s）内部：Ghidra 把该段并入更大函数/未单独切分；"
            "我方按权威声明边界单列，此项不是表达式分歧"
            % (cont, gh.get("containing_name"))]
    ok = {"entry": True}
    nblk = len(ours["blocks"])          # 我方 blocks 是块字典列表，不是数量
    ok["blocks_equal"] = nblk == gh["blocks"]
    ok["blocks_delta"] = gh["blocks"] - nblk
    # 判等范围限定在 .text：.plt/.got/导入表里的 thunk 目标两边口径天然不同
    # （我方记 PLT 桩地址，Ghidra 可能报解析后的导入函数），单列计数不判等。
    lo, hi = sec_range
    mine_all = sorted(c["target"] for c in ours["events"]["calls"]
                      if c["target"] is not None)
    mine = [x for x in mine_all if lo <= x < hi]
    theirs_all = sorted(gh["calls"])
    theirs = [x for x in theirs_all if lo <= x < hi]
    ok["calls_mine"] = mine
    ok["calls_ghidra"] = theirs
    ok["calls_mine_out_of_text"] = len(mine_all) - len(mine)
    ok["calls_ghidra_out_of_text"] = len(theirs_all) - len(theirs)
    ok["calls_equal"] = mine == theirs
    only_mine = [x for x in mine if x not in theirs]
    only_gh = [x for x in theirs if x not in mine]
    if ok["calls_mine_out_of_text"] or ok["calls_ghidra_out_of_text"]:
        notes.append(".text 外调用目标：我方 %d 个（PLT/GOT 桩）、Ghidra %d 个"
                     "（thunk/导入）；不参与判等，单列"
                     % (ok["calls_mine_out_of_text"],
                        ok["calls_ghidra_out_of_text"]))
    # 尾跳转呈现差异：我方记 jmp，Ghidra 反编译常把尾调用显示成 call。
    # 这类差异不算分歧，但必须写明，不能默认"归一化掉"。
    our_jumps = set(j["target"] for j in ours["events"]["jumps"]
                    if j["target"] is not None)
    tail_gh = [x for x in only_gh if x in our_jumps]
    other_gh = [x for x in only_gh if x not in our_jumps]
    if only_mine:
        notes.append("仅我方有调用目标 %s：目标可能不是 Ghidra 认定的函数（thunk/代码中段）"
                     % ", ".join("0x%x" % x for x in only_mine[:4]))
    if tail_gh:
        notes.append("Ghidra 以调用呈现 %s：我方对应尾跳转（jmp），同一控制转移、呈现不同"
                     % ", ".join("0x%x" % x for x in tail_gh[:4]))
    # 函数域大小作为归因证据：Ghidra 函数明显更大时，多出的调用来自被并入的相邻函数
    our_size = (ours["range"][1] - ours["range"][0]) if ours["range"][1] else 0
    gh_size = gh.get("size") or 0
    if other_gh:
        if gh_size > our_size * 1.3:
            notes.append("仅 Ghidra 有调用目标 %s：Ghidra 函数域 %d 字节 > 我方 %d 字节，"
                         "多为其把相邻/内联段并入本函数后引入的调用"
                         % (", ".join("0x%x" % x for x in other_gh[:4]),
                            gh_size, our_size))
        else:
            notes.append("仅 Ghidra 有调用目标 %s：其 thunk/IAT 解析，或我方在该块 abstain"
                         % ", ".join("0x%x" % x for x in other_gh[:4]))
    if gh["blocks"] != nblk:
        indirect = sum(1 for j in ours["events"]["jumps"] if j["target"] is None)
        if gh_size > our_size * 1.3:
            why = "Ghidra 函数域更大，块数差来自并入的相邻函数"
        elif indirect and gh["blocks"] - nblk >= 10:
            # 我方按 R45 不猜间接跳转目标 → 跳转表 case 块不可达；Ghidra 可能恢复了 switch
            why = ("函数域相同，块数差主要来自 %d 处间接 jmp 目标未解析（R45 不猜），"
                   "其后 case 块不可达；Ghidra 可能恢复了跳转表" % indirect)
        elif indirect:
            why = ("函数域相同，差异较小（尾跳转/不可达填充）；另有 %d 处间接 jmp "
                   "目标未解析（不猜）" % indirect)
        else:
            why = "函数域相同，差异来自块切分口径（尾跳转/不可达填充）"
        notes.append("基本块数不一致（我方 %d 块/%d 字节，Ghidra %d 块/%d 字节）：%s"
                     % (nblk, our_size, gh["blocks"], gh_size, why))
    return ok, notes


def _image_base(path):
    with open(path, "rb") as f:
        if f.read(2) != b"MZ":
            return 0
    return pe.parse(path)["image_base"]


def _objdump_version():
    """记录 oracle 工具版本；取不到就写 unknown（不猜）。"""
    exe = coverage.objdump_exe()
    if exe is None:
        return "unknown"
    try:
        p = subprocess.run([exe, "--version"], capture_output=True,
                           env=dict(os.environ, LC_ALL="C"))
        first = p.stdout.decode("utf-8", "replace").splitlines()
        return first[0].strip() if first else "unknown"
    except OSError:
        return "unknown"


def _objdump_rows(path, sec, base):
    """外部 oracle：objdump 全节线性反汇编，地址归一到我方地址空间。"""
    exe = coverage.objdump_exe()
    if exe is None:
        return None
    env = dict(os.environ, LC_ALL="C")
    start, stop = base + sec["va"], base + sec["va"] + sec["size"]
    p = subprocess.run([exe, "-d", "-M", "intel", "--insn-width=16",
                        "--start-address=0x%x" % start,
                        "--stop-address=0x%x" % stop, path],
                       capture_output=True, env=env)
    if p.returncode != 0:
        return None
    rows = {}
    for ln in p.stdout.decode("utf-8", "replace").splitlines():
        m = OBJ_LINE.match(ln)
        if m:
            rows[int(m.group(1), 16) - base] = {
                "size": len(m.group(2).split()), "text": m.group(3).strip()}
    return rows


_PREFIX = {"lock", "rep", "repz", "repnz", "repe", "repne", "data16",
           "addr32", "bnd", "notrack", "xacquire", "xrelease",
           "cs", "ds", "es", "fs", "gs", "ss"}


def _split_insn(text):
    """拆出 (助记符, 操作数)：objdump 会把 rex.W 等前缀单列在前。"""
    parts = text.split()
    i = 0
    while i < len(parts):
        low = parts[i].lower()
        if low in _PREFIX or low.startswith("rex."):
            i += 1
            continue
        break
    if i >= len(parts):
        return "", ""
    return parts[i].lower(), " ".join(parts[i + 1:])


def _mnem(text):
    return _split_insn(text)[0]


def _op_target(text):
    """objdump intel 语法里的直接目标；寄存器/内存间接形返回 None。"""
    op = _split_insn(text)[1].lower()
    if "*" in op or "[" in op or "ptr" in op:
        return None
    m = re.match(r"(?:0x)?([0-9a-f]+)\b", op.strip())
    return int(m.group(1), 16) if m else None


def oracle_check(rel, res, picked, lifted, rows, base):
    """外部 oracle：指令边界/控制转移目标/下层账目，逐抽样函数复算。

    返回 (fails, residual)：residual 是「objdump 线性扫描比 expr 多解」的
    已知残差（CFG 可达子集 vs 线性全扫），不判失败，但必须显式报出。
    """
    fails, residual = [], []
    by_origin = {}
    for ins in res["instructions"]:
        by_origin.setdefault(ins.get("origin"), []).append(ins["addr"])
    for p in picked:
        a = p["addr"]
        r = lifted[a]
        lo, hi = r["range"][0], r["range"][1]
        ins_addrs = by_origin.get(a, [])
        if r["stats"]["insns"] != len(ins_addrs):
            fails.append("%s 0x%x: stats.insns=%d != 下层归属指令数 %d"
                         % (rel, a, r["stats"]["insns"], len(ins_addrs)))
        if r["stats"]["lifted"] + r["stats"]["abstained"] != r["stats"]["insns"]:
            fails.append("%s 0x%x: lifted+abstained=%d+%d != insns=%d"
                         % (rel, a, r["stats"]["lifted"],
                            r["stats"]["abstained"], r["stats"]["insns"]))
        for x in ins_addrs:
            if x in rows:
                continue
            if hi is not None and not (lo <= x < hi):
                continue
            fails.append("%s 0x%x: 指令 0x%x 不是 objdump 指令起点"
                         % (rel, a, x))
        for ab in r["abstains"]:
            if ab["addr"] not in rows:
                fails.append("%s 0x%x: abstain 0x%x 不是 objdump 指令起点"
                             % (rel, a, ab["addr"]))
        want = ("complete" if not r["abstains"] else
                ("partial" if r["boundary"] == "declared"
                 else "inferred-partial"))
        if r["verdict"] != want:
            fails.append("%s 0x%x: verdict=%s 与 abstain/boundary 不一致"
                         % (rel, a, r["verdict"]))
        if hi is not None:
            n_obj = sum(1 for x in rows if lo <= x < hi)
            if n_obj < r["stats"]["insns"]:
                fails.append("%s 0x%x: objdump 范围内指令数 %d < 我方 insns=%d"
                             % (rel, a, n_obj, r["stats"]["insns"]))
            elif n_obj > r["stats"]["insns"]:
                # 残差逐地址落盘：objdump 线性扫描到、我方 CFG 未归属的指令起点。
                ours = set(ins_addrs)
                extra = sorted(x for x in rows if lo <= x < hi and x not in ours)
                residual.append({"function": a, "objdump_only": n_obj - r["stats"]["insns"],
                                 "addrs": extra})
        for kind, evs in (("calls", r["events"]["calls"]),
                          ("branches", r["events"]["branches"]),
                          ("jumps", r["events"]["jumps"])):
            for e in evs:
                # 声明域外的尾跳转（如函数末尾跳进相邻 thunk）不参与 objdump 对照：
                # objdump 从节头线性扫描，遇到域内数据表会错位，域外字节不归本函数。
                if hi is None or not (lo <= e["addr"] < hi):
                    continue
                row = rows.get(e["addr"])
                if row is None:
                    fails.append("%s 0x%x: %s 站点 0x%x 不在 objdump 里"
                                 % (rel, a, kind, e["addr"]))
                    continue
                mn = _mnem(row["text"])
                if kind == "calls" and mn != "call":
                    fails.append("%s 0x%x: call 站点 0x%x objdump 助记符是 %s"
                                 % (rel, a, e["addr"], mn))
                    continue
                if kind == "jumps" and mn != "jmp":
                    fails.append("%s 0x%x: jump 站点 0x%x objdump 助记符是 %s"
                                 % (rel, a, e["addr"], mn))
                    continue
                if kind == "branches" and not (
                        (mn.startswith("j") and mn != "jmp")
                        or mn.startswith("loop")):
                    fails.append("%s 0x%x: branch 站点 0x%x objdump 助记符是 %s"
                                 % (rel, a, e["addr"], mn))
                    continue
                tg = _op_target(row["text"])
                if e["target"] is None:
                    if tg is not None:
                        fails.append("%s 0x%x: %s 0x%x 判间接，objdump 却是直接"
                                     "目标 0x%x" % (rel, a, kind, e["addr"],
                                                    tg - base))
                elif tg is None or tg != e["target"] + base:
                    fails.append("%s 0x%x: %s 0x%x 目标 0x%x != objdump %s"
                                 % (rel, a, kind, e["addr"], e["target"],
                                    ("0x%x" % (tg - base))
                                    if tg is not None else "间接形式"))
    return fails, residual


def selftest():
    """可失败自证：篡改直接调用目标 / lifted 账目 → 外部 oracle 必须报错。"""
    import copy
    plan = sample()
    rel = SAMPLES[0][0]
    info = plan[rel]
    path = os.path.join(WORK, rel)
    sec = disasm.find_section(path, ".text")
    base = _image_base(path)
    rows = _objdump_rows(path, sec, base)
    if rows is None:
        print("[selftest] objdump 不可用，无法建立外部 oracle → 未检出")
        return 1
    clean, _ = oracle_check(rel, info["res"], info["picked"], info["lifted"],
                            rows, base)

    forged = copy.deepcopy(info["lifted"])
    tgt = None
    for a in [p["addr"] for p in info["picked"]]:
        r = forged[a]
        for e in r["events"]["calls"]:
            if not e["indirect"] and e["target"] is not None:
                e["target"] += 1
                tgt = a
                break
        if tgt is not None:
            break
    hit_t = False
    if tgt is not None:
        fails_t, _ = oracle_check(rel, info["res"], info["picked"], forged,
                                  rows, base)
        hit_t = any("目标" in x for x in fails_t)

    forged2 = copy.deepcopy(info["lifted"])
    a0 = info["picked"][0]["addr"]
    forged2[a0]["stats"]["lifted"] += 1
    fails_s, _ = oracle_check(rel, info["res"], info["picked"], forged2,
                              rows, base)
    hit_s = any("lifted+abstained" in x for x in fails_s)

    ok = not clean and hit_t and hit_s
    if clean:
        print("[selftest] 未篡改时的既有失败（前 3 条）：%s" % clean[:3])
    print("[selftest] 未篡改 oracle 失败 %d 项；篡改直接调用目标 → 检出=%s；"
          "篡改 lifted 账目 → 检出=%s（期望 True/True）→ %s"
          % (len(clean), hit_t, hit_s, "检出" if ok else "未检出"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="只跑某个样本（子串匹配）")
    ap.add_argument("--json", default=None, help="把结果写成 JSON")
    ap.add_argument("--manual", type=int, default=6,
                    help="人工对读样本数（打印两侧文本）")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--oracle-only", action="store_true",
                    help="只跑外部 oracle（objdump 对照）并写 JSON，跳过 Ghidra 弱参照")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    print("=" * 78)
    print("M5-U1 表达式恢复验收：抽样规则 + Ghidra 弱参照对读")
    print("=" * 78)
    plan = sample()
    total = 0
    for rel, info in plan.items():
        print("\n[样本] %s  %s" % (rel, info.get("label")))
        if info.get("missing"):
            print("  文件缺失，跳过")
            continue
        print("  声明边界函数池: %d 个" % info["pool"])
        print("  分层规模: %s" % ", ".join(
            "%s=%d" % (k, v) for k, v in info["strata"].items()))
        print("  类别覆盖: %s" % ", ".join("%s=%s" % (k, v)
                                           for k, v in info["cats"].items()))
        print("  抽样函数: %d 个（去重后）" % len(info["picked"]))
        total += len(info["picked"])
    print("\n抽样总量: %d 个函数（规则见文件头；等距取点，无随机数）" % total)

    # 外部 oracle（不依赖 Ghidra）：objdump 反汇编 + 下层账目，逐抽样函数复算。
    oracle_fails = []
    oracle_detail = {}
    for rel, info in plan.items():
        if info.get("missing") or (args.only and args.only not in rel):
            continue
        path = os.path.join(WORK, rel)
        sec = disasm.find_section(path, ".text")
        base = _image_base(path)
        rows = _objdump_rows(path, sec, base)
        if rows is None:
            oracle_fails.append("%s: objdump 不可用，外部 oracle 无法建立" % rel)
            print("[oracle] %s：objdump 不可用 → FAIL" % rel)
            continue
        fails, residual = oracle_check(rel, info["res"], info["picked"],
                                       info["lifted"], rows, base)
        oracle_fails.extend(fails)
        print("[oracle] %s：%d 个抽样函数 × objdump 反汇编对照 → %s"
              % (rel, len(info["picked"]),
                 "PASS" if not fails else "FAIL %d 项" % len(fails)))
        residual_total = sum(x["objdump_only"] for x in residual)
        if residual:
            print("[oracle] %s：已知残差——objdump 线性扫描比 expr 多解 %d 条"
                  "（%d 个抽样函数；CFG 可达子集 vs 线性全扫，未逐指令归因）"
                  % (rel, residual_total, len(residual)))
        oracle_detail[rel] = {
            "sample": rel,
            "picked_functions": len(info["picked"]),
            "residual_insns": residual_total,
            "residual_function_count": len(residual),
            "residual_functions": residual,
        }

    report = {
        "oracle": {
            "kind": "objdump 整节线性反汇编（外部 oracle）",
            "objdump": _objdump_version(),
            "criteria": ("残差口径：objdump 线性全扫 vs expr/recdesc 的 CFG 可达子集；"
                         "残差单列，不入任何已公布比率的分子分母；未逐指令归因"),
            "samples": oracle_detail,
            "residual_total": sum(x["residual_insns"]
                                  for x in oracle_detail.values()),
            "fails": oracle_fails,
        },
        "plan": {}, "results": {}, "summary": {},
    }
    for rel, info in ({} if args.oracle_only else plan).items():
        if info.get("missing") or (args.only and args.only not in rel):
            continue
        path = os.path.join(WORK, rel)
        lifted = info["lifted"]
        addrs = [p["addr"] for p in info["picked"]]
        sec = disasm.find_section(path, ".text")
        sec_va = sec["va"]
        sec_range = (sec["va"], sec["va"] + sec["size"])
        try:
            gh = ghidra_session(path, addrs, sec_va)
        except ImportError as e:
            print("\n[NO-GHIDRA] %s：%s —— 本样本降级为“无 Ghidra 参照”，"
                  "只报我方结果，不假装对过" % (rel, e))
            report["results"][rel] = {"no_ghidra": str(e)}
            continue
        print("\n[对读] %s" % rel)
        rows = []
        for a in addrs:
            r = lifted[a]
            ok, notes = compare(r, gh[a], sec_range)
            rows.append({"addr": a, "ours": {
                "insns": r["stats"]["insns"], "blocks": len(r["blocks"]),
                "abstained": r["stats"]["abstained"],
                "verdict": r["verdict"],
                "size": (r["range"][1] - r["range"][0]) if r["range"][1] else None,
                "cats": sorted(_cats(r))}, "gh": {
                    "found": gh[a].get("found"),
                    "blocks": gh[a].get("blocks"),
                    "size": gh[a].get("size"),
                    "name": gh[a].get("name")}, "ok": ok, "notes": notes})
            print("  0x%-8x 我方: 指令%3d 块%2d abstain%2d %-7s | Ghidra: %s 块%s 大小%s"
                  % (a, r["stats"]["insns"], len(r["blocks"]),
                     r["stats"]["abstained"], r["verdict"],
                     ("有" if gh[a].get("found") else "无"),
                     gh[a].get("blocks"), gh[a].get("size")))
            for n in notes:
                print("      - %s" % n)
        report["results"][rel] = rows

        # 汇总
        n = len(rows)
        found = sum(1 for x in rows if x["gh"]["found"])
        blk_eq = sum(1 for x in rows if x["ok"].get("blocks_equal"))
        call_eq = sum(1 for x in rows if x["ok"].get("calls_equal"))
        print("  -- 汇总: 入口存在 %d/%d（Ghidra 未切分不算我方错）｜ 重叠集内块数相等 %d/%d"
              " ｜ 重叠集内调用集相等 %d/%d"
              % (found, n, blk_eq, found, call_eq, found))
        report["summary"][rel] = {"n": n, "entry": found, "blocks_eq": blk_eq,
                                  "calls_eq": call_eq, "total": n}

        # 弃权原因（按指令计）：每条都带 missing，验收要看"缺什么"而不是只数个数
        reasons = {}
        for x in rows:
            for ab in lifted[x["addr"]]["abstains"]:
                key = "%s ｜ 缺: %s" % (ab["reason"], ab["missing"])
                reasons[key] = reasons.get(key, 0) + 1
        if reasons:
            print("  -- 抽样函数弃权原因（按指令计，共 %d 条）:" % sum(reasons.values()))
            for k, v in sorted(reasons.items(), key=lambda kv: -kv[1]):
                print("      %3d × %s" % (v, k))
        report.setdefault("abstain_reasons", {})[rel] = reasons

        # 人工对读
        if args.manual:
            print("\n  ── 人工对读样本（我方伪 C / Ghidra C 并列）──")
            picked = [x for x in rows if x["gh"]["found"]][:args.manual]
            for x in picked:
                a = x["addr"]
                print("\n  ### FUNC 0x%x  类别=%s" % (a, ",".join(x["ours"]["cats"]) or "-"))
                print("  --- 我方 ---")
                for line in lifted[a]["text"].splitlines()[:40]:
                    print("  | " + line)
                c = gh[a].get("c")
                print("  --- Ghidra（%s）---" % gh[a].get("name"))
                if c:
                    for line in c.splitlines()[:40]:
                        print("  | " + line)
                else:
                    print("  | (Ghidra 反编译失败)")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("\nJSON 已写入 %s" % args.json)
    if oracle_fails:
        print("\nFAIL: 表达式层外部 oracle 不成立 %d 项" % len(oracle_fails))
        for x in oracle_fails[:20]:
            print("  ! %s" % x)
        return 1
    if args.oracle_only:
        print("\nPASS（仅外部 oracle：objdump 反汇编对照 + 下层账目；"
              "残差单列、未逐指令归因）")
    else:
        print("\nPASS（表达式层外部 oracle：objdump 反汇编对照 + 下层账目；"
              "Ghidra 仅弱参照；分歧不静默丢弃）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
