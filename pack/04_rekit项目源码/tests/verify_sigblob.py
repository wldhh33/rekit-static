#!/usr/bin/env python3
# tests/verify_sigblob.py — M19 .NET 签名语义层外部独立对拍
#
# 期望值全部来自独立来源，不取自被测实现：
#   (a) dnfile 独立读 MethodDef/MemberRef/StandAloneSig/Field 四张表：
#       原始 #Blob 索引、blob 内容偏移/长度/字节；与 rekit 逐行逐字节比较。
#       行数与「索引为 0 的行数」也独立重算。
#   (b) 微软 SRM（System.Reflection.Metadata）的 DecodeSignature 经 pwsh 编译
#       的 sigref.ps1 输出 canonical 文本；与 rekit 的方法签名逐行整串比较。
#       字段/局部变量签名只比 kind（不解类型）。
#       rekit 报 undecoded 而 SRM 能解 -> 视为 rekit 少解；SRM 报错而 rekit
#       报 decoded_clean -> 视为 rekit 多解。两者都算 FAIL。
#   (c) M17 dotnet 的 signature_len / signature_hex 前缀逐行相等（同源重算）。
#   (d) 可失败自证（工件形式，首版即带）：干净样本 PASS；注入 blob 字节后
#       canonical 相对基线漂移必须被检出；blob 索引 +1 必须报索引不一致；
#       blob 长度前缀篡改必须报 undecoded/trailing_bytes；SRM 侧 canonical
#       改一字必须被检出；空比对必须 FAIL。
#
# 样本：受控 RekitSample.dll、FlowSample.dll、真实 System.Console.dll、
#       mscorlib.dll（沿用 M17/M18 同一批；读不出如实 unknown 并单列）。
# 工具缺失 -> env_missing（exit 2，fail-closed）；任何 FAIL -> exit 1。
import collections
import json
import logging
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
sys.path.insert(0, WORK)

from rekit import dotnet as DN                     # noqa: E402
from rekit import sigblob as SB                    # noqa: E402

REKIT = os.path.join(WORK, "samples", "m17", "_gen", "RekitSample.dll")
FLOW = os.path.join(WORK, "samples", "m18", "_gen", "FlowSample.dll")
CONSOLE = r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\7.0.20\System.Console.dll"
MSCORLIB = r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
SIGREF = os.path.join(HERE, "sigref.ps1")
OUT_JSON = os.path.join(WORK, "evidence_m19_sigblob.json")

SAMPLES = (("rekit", REKIT), ("flow", FLOW),
           ("console", CONSOLE), ("mscorlib", MSCORLIB))
LIST_OF = (("methods", "MethodDef"), ("memberrefs", "MemberRef"),
           ("standalonesigs", "StandAloneSig"), ("fields", "Field"))


def _evidence_path(p):
    """证据里的路径必须与克隆位置无关：work 内写相对路径（/ 分隔）；
    仓库外样本（mscorlib / System.Console）保留绝对路径。绝对路径进证据会让
    sha256 随克隆目录变化，ledger_check 在异地克隆必然 FAIL。"""
    try:
        rel = os.path.relpath(p, WORK)
    except ValueError:
        return p
    return rel.replace(os.sep, "/") if not rel.startswith("..") else p


CHECKS = []


def _add(cid, name, status, detail):
    CHECKS.append({"id": cid, "name": name, "status": status,
                   "detail": detail})
    print("[%s] %s %s :: %s" % (status, cid, name, detail))


def _guard(n, what):
    """空比对保护：分母为 0 返回 False（调用方必须 FAIL）。"""
    if n <= 0:
        print("  !! 空比对：%s 的分母为 0，不得判 PASS" % what)
        return False
    return True


# ── dnfile 侧 ───────────────────────────────────────────────────────
def _dn_pe(path):
    import dnfile
    return dnfile.dnPE(data=open(path, "rb").read())


def _dn_rows(md, name):
    t = getattr(md, name, None)
    return t.rows if t is not None else []


def _our_map(rep):
    out = {}
    for lst, tname in LIST_OF:
        for it in rep[lst]:
            out[(tname, it["row"])] = it
    return out


def compare_bytes(tag, path, rep, pe=None):
    """dnfile 独立读索引/偏移/长度/字节，逐行比对。"""
    if pe is None:
        pe = _dn_pe(path)
    md = pe.net.mdtables
    ours = _our_map(rep)
    probs = []
    n = 0

    def bad(kind, tname, row, tok, detail):
        probs.append({"kind": kind, "table": tname, "row": row,
                      "token": tok,
                      "line": "[FAIL] m19-bytes token=%s table=%s row=%d "
                              "%s: %s" % (tok, tname, row, kind, detail)})

    for tname in ("MethodDef", "MemberRef", "StandAloneSig", "Field"):
        dnrows = _dn_rows(md, tname)
        rd = rep["denominators"][tname]
        tok = "0x%02x000000" % {"MethodDef": 0x06, "MemberRef": 0x0A,
                                "StandAloneSig": 0x11, "Field": 0x04}[tname]
        if len(dnrows) != rd["rows"]:
            bad("row_count", tname, 0, tok,
                "dnfile=%d rekit=%d" % (len(dnrows), rd["rows"]))
        dn_has = sum(1 for r in dnrows
                     if int(r.struct.Signature_BlobIndex) != 0)
        if dn_has != rd["has_blob_index"]:
            bad("has_blob_count", tname, 0, tok,
                "dnfile=%d rekit=%d" % (dn_has, rd["has_blob_index"]))
        for i, r in enumerate(dnrows, 1):
            idx = int(r.struct.Signature_BlobIndex)
            it = ours.get((tname, i))
            rowtok = "0x%02x%06x" % (
                {"MethodDef": 0x06, "MemberRef": 0x0A,
                 "StandAloneSig": 0x11, "Field": 0x04}[tname], i)
            if idx == 0:
                if it is not None:
                    bad("no_blob_row_stored", tname, i, rowtok,
                        "索引为 0 却有 rekit 明细")
                continue
            n += 1
            if it is None:
                bad("missing_rekit_row", tname, i, rowtok, "rekit 无该行明细")
                continue
            if it["blob_index"] != idx:
                bad("blob_index", tname, i, rowtok,
                    "dnfile=%d rekit=%d" % (idx, it["blob_index"]))
            try:
                s = r.Signature
                if s is None:
                    raise RuntimeError("dnfile Signature 为空")
                base = pe.get_offset_from_rva(s.rva)
                off = base + (s.raw_size - s.item_size)
                val, ln = s.value, int(s.item_size)
            except Exception as e:                # dnfile 读不出
                if it["status"] != "unreadable":
                    bad("dnfile_unreadable", tname, i, rowtok,
                        "%s: %s；rekit status=%s"
                        % (type(e).__name__, e, it["status"]))
                continue
            if it["status"] == "unreadable":
                bad("rekit_unreadable", tname, i, rowtok,
                    "dnfile 可读但 rekit 记 unreadable")
                continue
            if it["blob_off"] != off:
                bad("blob_off", tname, i, rowtok,
                    "dnfile=0x%x rekit=%r" % (off, it["blob_off"]))
            if it["blob_len"] != ln:
                bad("blob_len", tname, i, rowtok,
                    "dnfile=%d rekit=%r" % (ln, it["blob_len"]))
            if it["blob_hex"] != val.hex():
                bad("blob_bytes", tname, i, rowtok, "字节内容不一致")
    return probs, n


# ── SRM 侧 ──────────────────────────────────────────────────────────
def _run_sigref(path):
    if not shutil.which("pwsh"):
        raise RuntimeError("env_missing: pwsh 不在 PATH")
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", SIGREF,
         "-Path", path],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=1800)
    if p.returncode != 0:
        raise RuntimeError("sigref exit=%d: %s"
                           % (p.returncode, (p.stderr or "").strip()[:400]))
    data = json.loads(p.stdout)
    return data["rows"]


def compare_srm_rows(tag, rows, rep):
    """SRM canonical / kind 与 rekit 逐行比较。"""
    ours = _our_map(rep)
    probs = []
    n = 0
    for r in rows:
        tname, i, tok, st = r["table"], r["row"], r["token"], r["status"]
        it = ours.get((tname, i))
        if st == "none":
            if it is not None:
                probs.append({
                    "kind": "no_blob_row_stored", "token": tok,
                    "line": "[FAIL] m19-srm token=%s SRM=no_blob "
                            "但 rekit 有明细" % tok})
            continue
        if it is None:
            probs.append({"kind": "missing_rekit_row", "token": tok,
                          "line": "[FAIL] m19-srm token=%s rekit 无该行"
                                  % tok})
            continue
        if st in ("field", "local"):
            n += 1
            want = "field" if st == "field" else "local"
            if it["kind"] != want:
                probs.append({
                    "kind": "kind_mismatch", "token": tok,
                    "line": "[FAIL] m19-srm token=%s kind SRM=%s rekit=%s"
                            % (tok, want, it["kind"])})
            elif it["status"] != "length_only":
                probs.append({
                    "kind": "length_only_expected", "token": tok,
                    "line": "[FAIL] m19-srm token=%s SRM=%s 但 rekit status=%s"
                            % (tok, st, it["status"])})
            continue
        if st == "error":
            n += 1
            if it["status"] == "decoded" and not it["unknown"]:
                probs.append({
                    "kind": "rekit_over_decoded", "token": tok,
                    "line": "[FAIL] m19-srm token=%s SRM 报错(%s) 但 rekit "
                            "decoded_clean" % (tok, r.get("error"))})
            continue
        # method
        n += 1
        if it["status"] != "decoded":
            probs.append({
                "kind": "rekit_under_decoded", "token": tok,
                "line": "[FAIL] m19-srm token=%s SRM 解出但 rekit status=%s "
                        "reason=%s" % (tok, it["status"], it["reason"])})
            continue
        got = (it["signature"] or {}).get("canonical")
        want = r.get("canonical")
        if got != want:
            probs.append({
                "kind": "canonical", "token": tok,
                "line": "[FAIL] m19-srm token=%s canonical 不一致 "
                        "SRM=%s rekit=%s" % (tok, want, got)})
    return probs, n


def compare_srm(tag, path, rep):
    return compare_srm_rows(tag, _run_sigref(path), rep)


# ── M17 交叉核对 ────────────────────────────────────────────────────
def compare_m17(tag, path, rep):
    m17 = DN.build(path, detail_methods=None, detail_insns=None)
    if m17.get("status") != DN.STATUS_OK:
        return [{"kind": "m17_status", "token": None,
                 "line": "[FAIL] m19-m17 status=%s" % m17.get("status")}], 0
    by_row = {m["row"]: m for m in m17.get("methods") or []}
    probs = []
    n = 0
    for it in rep["methods"]:
        m = by_row.get(it["row"])
        if m is None:
            continue
        n += 1
        tok = it["token"]
        if it["blob_len"] != m["signature_len"]:
            probs.append({
                "kind": "signature_len", "token": tok,
                "line": "[FAIL] m19-m17 token=%s signature_len M17=%r M19=%r"
                        % (tok, m["signature_len"], it["blob_len"])})
        pref = m.get("signature_hex")
        if pref and it["blob_hex"] and not it["blob_hex"].startswith(pref):
            probs.append({
                "kind": "signature_hex", "token": tok,
                "line": "[FAIL] m19-m17 token=%s signature_hex 前缀不一致"
                        % tok})
    return probs, n


# ── 分母 / 漂移 ─────────────────────────────────────────────────────
def check_denominators(tag, rep):
    bad = []
    total = 0
    for tname in ("MethodDef", "MemberRef", "StandAloneSig", "Field"):
        d = rep["denominators"][tname]
        total += d["rows"]
        if not d.get("identity_rows_ok"):
            bad.append(tname + ".identity_rows_ok")
        if not d.get("identity_read_ok"):
            bad.append(tname + ".identity_read_ok")
        if tname == "Field":
            if not d.get("identity_length_ok"):
                bad.append("Field.identity_length_ok")
            if d.get("non_field_signature"):
                bad.append("Field.non_field_signature=%d"
                           % d["non_field_signature"])
        else:
            if not d.get("identity_decode_ok"):
                bad.append(tname + ".identity_decode_ok")
            if not d.get("identity_unknown_ok"):
                bad.append(tname + ".identity_unknown_ok")
    ok = _guard(total, "den-" + tag) and not bad and bool(
        rep["denominators"].get("identity_ok"))
    _add("den-" + tag, "四张表分母恒等式", "PASS" if ok else "FAIL",
         "rows=%d 坏恒等式=%s identity_ok=%s"
         % (total, bad, rep["denominators"].get("identity_ok")))


def _canon_by_token(rep):
    out = {}
    for lst in ("methods", "memberrefs", "standalonesigs"):
        for it in rep[lst]:
            if it["status"] == "decoded":
                out[it["token"]] = it["signature"]["canonical"]
    return out


def _drift(rep, baseline):
    probs = []
    for lst in ("methods", "memberrefs", "standalonesigs"):
        for it in rep[lst]:
            if it["status"] != "decoded":
                continue
            base = baseline.get(it["token"])
            got = it["signature"]["canonical"]
            if base is not None and base != got:
                probs.append({
                    "kind": "canonical_drift", "token": it["token"],
                    "line": "[FAIL] m19-drift token=%s baseline=%s observed=%s"
                            % (it["token"], base, got)})
    return probs


# ── 自证 ────────────────────────────────────────────────────────────
def selfproof():
    rep0 = SB.build(REKIT, limit=None)
    if rep0.get("status") != "ok":
        _add("selfproof", "比对器可失败自证", "FAIL",
             "基线样本 status=%s" % rep0.get("status"))
        return
    baseline = _canon_by_token(rep0)
    target = next((it for it in rep0["methods"]
                   if it["status"] == "decoded"
                   and "String" in it["signature"]["canonical"]), None)
    if target is None:
        _add("selfproof", "比对器可失败自证", "FAIL",
             "受控样本里找不到含 String 的方法签名")
        return
    tok = target["token"]
    blob = bytearray(open(REKIT, "rb").read())
    pos = bytes.fromhex(target["blob_hex"]).find(b"\x0e")
    tampered = pos >= 0
    tmpdir = tempfile.mkdtemp(prefix="rekit_m19_")
    try:
        # 1) blob 字节注入：String(0x0e) -> Int32(0x08)，相对基线必须漂移
        t1 = os.path.join(tmpdir, "byte.dll")
        shutil.copyfile(REKIT, t1)
        buf = bytearray(blob)
        if tampered:
            buf[target["blob_off"] + pos] = 0x08
            open(t1, "wb").write(buf)
        rep1 = SB.build(t1, limit=None)
        drift = _drift(rep1, baseline)
        drift_hit = next((p["line"] for p in drift if p["token"] == tok), "")
        # 2) blob 索引 +1：改 rekit 报告副本，dnfile 读干净文件必须报索引不一致
        rep_idx = json.loads(json.dumps(rep0))
        it_idx = next(it for it in rep_idx["methods"]
                      if it["token"] == tok)
        it_idx["blob_index"] += 1
        bprobs, _bn = compare_bytes("selfproof", REKIT, rep_idx)
        idx_hit = next((p["line"] for p in bprobs
                        if p["kind"] == "blob_index" and p["token"] == tok),
                       "")
        # 3) blob 长度前缀篡改：多 1 字节 -> undecoded/trailing_bytes
        t3 = os.path.join(tmpdir, "len.dll")
        shutil.copyfile(REKIT, t3)
        buf3 = bytearray(open(t3, "rb").read())
        ln = target["blob_len"]
        pre = 1 if ln < 0x80 else 2 if ln < 0x4000 else 4
        pre_off = target["blob_off"] - pre
        tamper_len = (ln + 1) if ln < 0x80 else ln
        if ln < 0x80:
            buf3[pre_off] = tamper_len
            open(t3, "wb").write(buf3)
        rep3 = SB.build(t3, limit=None)
        it3 = next(it for it in rep3["methods"] if it["token"] == tok)
        len_hit = (it3["status"] == "undecoded"
                   and it3["reason"] in ("trailing_bytes", "truncated_signature")
                   and it3["blob_len"] == ln + 1)
        # 4) SRM 侧 canonical 改一字 -> 必须被检出
        rows0 = _run_sigref(REKIT)
        rep_srm = json.loads(json.dumps(rep0))
        it_srm = next(it for it in rep_srm["methods"] if it["token"] == tok)
        it_srm["signature"]["canonical"] += "X"
        sprobs, _sn = compare_srm_rows("selfproof", rows0, rep_srm)
        srm_hit = next((p["line"] for p in sprobs
                        if p["kind"] == "canonical" and p["token"] == tok), "")
        # 5) 空比对必须 FAIL
        empty_reject = not _guard(0, "selfproof-empty")
        ok = (tampered and bool(drift_hit) and bool(idx_hit)
              and len_hit and bool(srm_hit) and empty_reject)
        if ok:
            print("[PASS] selfproof 注入ID=blob-byte:%s 基线=%s 观察=%s"
                  % (tok, baseline.get(tok), drift_hit))
        _add("selfproof", "比对器可失败自证", "PASS" if ok else "FAIL",
             "字节注入=%s 索引+1=%s 长度前缀=%s SRM改字=%s 空比对=%s"
             % (drift_hit, idx_hit, len_hit, srm_hit, empty_reject))
    except Exception as e:
        _add("selfproof", "比对器可失败自证", "FAIL",
             "%s: %s" % (type(e).__name__, e))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── 主流程 ──────────────────────────────────────────────────────────
def main():
    try:
        import dnfile  # noqa: F401
    except Exception as e:
        print("env_missing: 缺少 dnfile（%s）" % e)
        return 2
    if not shutil.which("pwsh"):
        print("env_missing: pwsh 不在 PATH（SRM 参考解码需要）")
        return 2
    logging.disable(logging.CRITICAL)

    evidence = {}
    for tag, path in SAMPLES:
        if not os.path.exists(path):
            _add("sample-" + tag, "样本存在", "FAIL", "缺文件 %s" % path)
            continue
        try:
            rep = SB.build(path, limit=None)
        except Exception as e:
            _add("sample-" + tag, "样本可构建", "FAIL",
                 "%s: %s" % (type(e).__name__, e))
            continue
        if rep.get("status") != "ok":
            _add("sample-" + tag, "样本可构建", "FAIL",
                 "status=%s reason=%s" % (rep.get("status"),
                                          rep.get("reason")))
            continue
        check_denominators(tag, rep)
        try:
            bprobs, bn = compare_bytes(tag, path, rep)
        except Exception as e:
            _add("bytes-" + tag, "dnfile 字节边界逐行对拍", "FAIL",
                 "%s: %s" % (type(e).__name__, e))
            bprobs, bn = [], 0
        bok = _guard(bn, "bytes-" + tag) and not bprobs
        _add("bytes-" + tag, "dnfile 字节边界逐行对拍",
             "PASS" if bok else "FAIL",
             "行=%d 问题=%d%s" % (bn, len(bprobs),
                                 "" if not bprobs
                                 else " 首条=" + bprobs[0]["line"]))
        try:
            sprobs, sn = compare_srm(tag, path, rep)
            srm_error = None
        except Exception as e:
            sprobs, sn, srm_error = [], 0, "%s: %s" % (type(e).__name__, e)
        sok = _guard(sn, "srm-" + tag) and not sprobs and srm_error is None
        _add("srm-" + tag, "SRM canonical 逐行对拍",
             "PASS" if sok else "FAIL",
             "行=%d 问题=%d%s" % (sn, len(sprobs),
                                 "" if not sprobs
                                 else " 首条=" + sprobs[0]["line"])
             if srm_error is None else "环境/解码失败：" + srm_error)
        mprobs, mn = compare_m17(tag, path, rep)
        mok = _guard(mn, "m17-" + tag) and not mprobs
        _add("m17-" + tag, "与 M17 signature_len 逐行相等",
             "PASS" if mok else "FAIL",
             "行=%d 问题=%d%s" % (mn, len(mprobs),
                                 "" if not mprobs
                                 else " 首条=" + mprobs[0]["line"]))
        den = rep["denominators"]
        evidence[tag] = {
            "path": _evidence_path(path),
            "denominators": {k: den[k] for k in
                             ("MethodDef", "MemberRef", "StandAloneSig",
                              "Field", "identity_ok", "ratios")},
            "counts": rep["counts"],
            "bytes_rows": bn, "bytes_problems": len(bprobs),
            "srm_rows": sn, "srm_problems": len(sprobs),
            "srm_error": srm_error,
            "m17_rows": mn, "m17_problems": len(mprobs),
        }

    selfproof()

    failed = [c for c in CHECKS if c["status"] == "FAIL"]
    n_skip = sum(1 for c in CHECKS if c["status"] == "SKIP")
    payload = {"schema": 1, "status": "fail" if failed else "pass",
               "checks": CHECKS, "samples": evidence}
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=1)
    print("\n== 汇总 ==  检查=%d PASS=%d FAIL=%d SKIP=%d → %s"
          % (len(CHECKS), len(CHECKS) - len(failed) - n_skip, len(failed),
             n_skip, "FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
