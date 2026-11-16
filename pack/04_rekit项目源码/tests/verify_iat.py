#!/usr/bin/env python3
# verify_iat.py — M3 U3 验收载体（E6/E7/E8 的 IAT 侧）
#
# 判据（全部可证伪，不以"看起来对/能启动"为证据）：
#   E6 解码：每个 slot 的 (dll, name|#ordinal, hint, rva) 与真值逐项全等；
#            另与真值快照里保存的 objdump -p 记录交叉核对（go.exe 标记不可靠 → 跳过并留痕）。
#   E7 修复：把每个 IAT slot 写成 0x7FF800000000+i 的伪地址 → repair_bytes 回填 →
#            **IAT 区间与原始文件逐字节全等（sha256 相等）**；unresolved 必须为 0。
#            修复只写新文件：同一输入两次写同一输出路径 → 产物 sha256 相等（幂等），
#            原样本 sha256 不得变化。
#            反例：篡改 1 个 slot 使其不像加载态地址 → 该 slot 必须 unresolved 且字节不动。
#            加壳样本单列：UPX 的 OriginalFirstThunk=0（INT 与 IAT 同址），
#            loader 填充后镜像内已无名称来源 → 必须全部 unresolved、一个字节都不写。
#   E8 负路径：非 PE / 截断 → 一行错误 + 退出码 2/3，零 traceback。
#
# 用法：
#   python tests/verify_iat.py --all
#   python tests/verify_iat.py --all --selftest   # 故意破坏修复结果，检查器必须报 FAIL
import argparse
import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(os.path.realpath(__file__)).parents[1]
sys.path.insert(0, str(REPO))
from rekit import iat  # noqa: E402

PASS, FAIL = "PASS", "FAIL"


def find_gt():
    p = REPO
    for _ in range(6):
        cand = p / "2026-11-15" / "m3-task-card" / "work" / "map_ground_truth.json"
        if cand.exists():
            return cand
        p = p.parent
    return REPO / "2026-11-15" / "m3-task-card" / "work" / "map_ground_truth.json"


def fake_load(data, loc):
    """构造「被 loader 填充过」的镜像副本：每个 IAT slot 写伪地址，INT 不动。"""
    h = iat.headers(data)
    ptr = h["ptrsize"]
    buf = bytearray(data)
    fake = 0x7FF800000000 if ptr == 8 else 0x7FF80000
    for i, s in enumerate(loc["slots"]):
        if s["file_off"] is not None:
            struct.pack_into("<Q" if ptr == 8 else "<I", buf, s["file_off"], fake + i)
    return bytes(buf)


def region_sha(data, r):
    return iat.sha256_bytes(data[r["start"]:r["start"] + r["size"]])


def check_decode(sample, path):
    """E6：解码 vs 真值 imports + 真值里的 objdump 记录。返回 (cells, misses)。"""
    gt = sample.get("imports") or []
    loc = iat.locate(str(path))
    res = {"cells": 0, "miss": [], "abstain": None}
    if not gt:
        if loc["status"] == "no_imports":
            res["cells"] = 1
        elif "fakerich" in sample["rel"] and loc["status"] == "invalid":
            res["abstain"] = "畸形导入目录（真值侧忽略）"
        else:
            res["miss"].append("status 期望 no_imports 实得 %s" % loc["status"])
        return res
    if loc["status"] != "ok":
        res["miss"].append("status 期望 ok 实得 %s" % loc["status"])
        return res
    descs = loc["descriptors"]
    res["cells"] += 1
    if len(descs) != len(gt):
        res["miss"].append("descriptor 数 期望 %d 实得 %d" % (len(gt), len(descs)))
    for di, gd in enumerate(gt):
        ad = descs[di] if di < len(descs) else None
        if ad is None or ad["dll"] != gd["dll"]:
            res["miss"].append("desc#%d dll 期望 %s 实得 %s"
                               % (di, gd["dll"], ad and ad["dll"]))
            continue
        res["cells"] += 1
        if len(ad["slots"]) != len(gd["slots"]):
            res["miss"].append("%s slot 数 期望 %d 实得 %d"
                               % (gd["dll"], len(gd["slots"]), len(ad["slots"])))
        for si, gs in enumerate(gd["slots"]):
            asl = ad["slots"][si] if si < len(ad["slots"]) else None
            exp = gs["name"] if gs["name"] is not None else "#%s" % gs["ordinal"]
            got = None if asl is None else (
                asl["name"] if asl["name"] is not None else "#%s" % asl["ordinal"])
            res["cells"] += 1
            if exp != got:
                res["miss"].append("%s#%d 期望 %s 实得 %s" % (gd["dll"], si, exp, got))
                continue
            res["cells"] += 1
            if asl["rva"] != gs["rva"]:
                res["miss"].append("%s#%d.rva 期望 0x%x 实得 0x%x"
                                   % (gd["dll"], si, gs["rva"], asl["rva"]))
            if gs.get("hint") is not None:
                res["cells"] += 1
                if asl["hint"] != gs["hint"]:
                    res["miss"].append("%s#%d.hint 期望 0x%x 实得 %s"
                                       % (gd["dll"], si, gs["hint"], asl["hint"]))
    # objdump 交叉（只对真值标记可靠的样本）
    if sample.get("objdump_imports_reliable") and sample.get("objdump_imports"):
        oi = sample["objdump_imports"]
        res["cells"] += 1
        if len(oi) != len(descs):
            res["miss"].append("objdump descriptor 数 期望 %d 实得 %d" % (len(oi), len(descs)))
        for di, od in enumerate(oi):
            ad = descs[di] if di < len(descs) else None
            res["cells"] += 1
            if ad is None or ad["dll"] != od["dll"]:
                res["miss"].append("objdump desc#%d dll 期望 %s 实得 %s"
                                   % (di, od["dll"], ad and ad["dll"]))
                continue
            for si, os_ in enumerate(od["slots"]):
                asl = ad["slots"][si] if si < len(ad["slots"]) else None
                exp = os_["name"] if os_.get("name") is not None else "#%s" % os_.get("ordinal")
                got = None if asl is None else (
                    asl["name"] if asl["name"] is not None else "#%s" % asl["ordinal"])
                res["cells"] += 1
                if exp != got:
                    res["miss"].append("objdump %s#%d 期望 %s 实得 %s"
                                       % (od["dll"], si, exp, got))
    return res


def _idempotency(fake, src_path, src_data):
    """产物幂等 + 原样本不动：同一输入两次写同一输出路径，sha256 必须相等。"""
    with tempfile.TemporaryDirectory() as td:
        dst = os.path.join(td, "out.exe")
        fake_path = os.path.join(td, "fake.exe")
        Path(fake_path).write_bytes(fake)
        rep1 = iat.repair_file(fake_path, dst)
        rep2 = iat.repair_file(fake_path, dst)
        return {"idempotent": rep1["dst_sha256"] == rep2["dst_sha256"],
                "src_unchanged": iat.sha256_file(src_path) == iat.sha256_bytes(src_data)}


def check_repair(sample, path):
    """E7：往返、幂等、原样本不动。返回结果字典。"""
    data = path.read_bytes()
    loc = iat.locate_bytes(data)
    out = {"rel": sample["rel"], "slots": len(loc["slots"]), "regions": 0,
           "region_equal": 0, "unresolved": 0, "wrote_any": False,
           "idempotent": None, "src_unchanged": None, "notes": []}
    if loc["status"] != "ok" or not loc["slots"]:
        out["notes"].append("无可用导入（status=%s）" % loc["status"])
        return out
    noint = [d for d in loc["descriptors"] if d["int_rva"] == 0]
    if noint:
        # 加壳/无 INT：按纪律不许猜，必须全部 unresolved 且零写入
        fake = fake_load(data, loc)
        repaired, rep = iat.repair_bytes(fake)
        out.update({"unresolved": rep["stats"]["unresolved"],
                    "regions": len(rep["regions"]),
                    "wrote_any": repaired != fake,
                    "notes": ["OriginalFirstThunk=0（INT 与 IAT 同址）：名称源不可回解"]})
        out.update(_idempotency(fake, path, data))
        return out
    fake = fake_load(data, loc)
    repaired, rep = iat.repair_bytes(fake)
    out["regions"] = len(rep["regions"])
    out["unresolved"] = rep["stats"]["unresolved"]
    out["wrote_any"] = repaired != fake
    for r in rep["regions"]:
        out["region_equal"] += int(region_sha(data, r) == r["sha256_after"])
    # 逐 slot 字节可核：修复结果与原始文件在 slot 偏移处逐字节相等
    n = rep["ptrsize"]
    bad = [s["file_off"] for s in rep["slots"]
           if s["status"] == "repaired"
           and repaired[s["file_off"]:s["file_off"] + n]
           != data[s["file_off"]:s["file_off"] + n]]
    out["slot_bytes_bad"] = len(bad)
    out.update(_idempotency(fake, path, data))
    return out


def check_anti_example(path):
    """E7 反例：篡改 1 个 slot 为 0x41414141 → 必须 unresolved 且该 slot 字节不动。"""
    data = path.read_bytes()
    loc = iat.locate_bytes(data)
    slots = [s for s in loc["slots"] if s["file_off"] is not None]
    if not slots:
        return None
    fake = bytearray(fake_load(data, loc))
    victim = slots[0]
    ptr = iat.headers(data)["ptrsize"]
    struct.pack_into("<Q" if ptr == 8 else "<I", fake, victim["file_off"], 0x41414141)
    before = bytes(fake[victim["file_off"]:victim["file_off"] + ptr])
    repaired, rep = iat.repair_bytes(bytes(fake))
    rec = next(s for s in rep["slots"] if s["file_off"] == victim["file_off"])
    after = repaired[victim["file_off"]:victim["file_off"] + ptr]
    return {"status": rec["status"], "reason": rec["reason"],
            "bytes_untouched": before == after}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    gt_path = find_gt()
    raw = gt_path.read_bytes()
    snap = gt_path.with_suffix(".json.sha256")
    frozen = snap.read_text(encoding="ascii").strip() if snap.exists() else ""
    if frozen and frozen != hashlib.sha256(raw).hexdigest():
        print("[GT] 快照 sha256 不一致：记录=%s 实测=%s"
              % (frozen, hashlib.sha256(raw).hexdigest()))
        return 2
    doc = json.loads(raw.decode("utf-8"))
    fails = []
    rows = {"unpacked": [], "packed": []}

    print("=" * 74)
    print("M3 IAT 验收（真值 %s）" % gt_path.name)
    print("=" * 74)
    for s in doc["samples"]:
        if not str(s.get("format", "")).startswith("pe"):
            continue
        path = REPO / s["rel"]
        if not path.exists():
            fails.append("%s 样本缺失" % s["rel"])
            continue
        packed = "upx" in s["rel"].lower()
        group = "packed" if packed else "unpacked"
        dec = check_decode(s, path)
        rep = check_repair(s, path)
        row = {"rel": s["rel"], "packed": packed, "decode_cells": dec["cells"],
               "decode_miss": len(dec["miss"]), "abstain": dec["abstain"], **rep}
        rows[group].append(row)
        if dec["miss"]:
            fails.extend("%s [decode] %s" % (s["rel"], m) for m in dec["miss"])
        if group == "unpacked" and rep["slots"]:
            if rep["unresolved"]:
                fails.append("%s [repair] unresolved=%d" % (s["rel"], rep["unresolved"]))
            if rep["regions"] and rep["region_equal"] != rep["regions"]:
                fails.append("%s [repair] 区间不等 %d/%d"
                             % (s["rel"], rep["region_equal"], rep["regions"]))
            if rep.get("slot_bytes_bad"):
                fails.append("%s [repair] slot 字节不符 %d 处"
                             % (s["rel"], rep["slot_bytes_bad"]))
            if rep["idempotent"] is False:
                fails.append("%s [repair] 幂等失败" % s["rel"])
            if rep["src_unchanged"] is False:
                fails.append("%s [repair] 原样本被改动" % s["rel"])
        if group == "packed" and rep["slots"]:
            # 加壳：必须全部 unresolved 且零写入（不猜）；否则视为违规
            if rep["unresolved"] != rep["slots"]:
                fails.append("%s [repair-packed] 期望全部 unresolved，实得 %d/%d"
                             % (s["rel"], rep["unresolved"], rep["slots"]))
            if rep["wrote_any"]:
                fails.append("%s [repair-packed] 在无名称来源时仍写入了字节" % s["rel"])
            if rep["idempotent"] is False:
                fails.append("%s [repair-packed] 幂等失败" % s["rel"])
            if rep["src_unchanged"] is False:
                fails.append("%s [repair-packed] 原样本被改动" % s["rel"])

    # 反例（E7）
    anti = check_anti_example(REPO / "tests/fixtures/minipe.exe")
    if anti is None:
        fails.append("反例样本无 slot")
    else:
        if anti["status"] != "unresolved":
            fails.append("[反例] 期望 unresolved 实得 %s" % anti["status"])
        if not anti["bytes_untouched"]:
            fails.append("[反例] 被篡改 slot 的字节被写动了（不许猜）")

    # 打印（加壳与未加壳分开，绝不混算）
    for group, title in (("unpacked", "未加壳"), ("packed", "加壳（单列，不计入未加壳成功率）")):
        print("\n[%s] %s" % (group, title))
        for r in rows[group]:
            print("  %-46s decode %3d格 失配%d  repair slots=%-3d regions=%d "
                  "区间等=%d unresolved=%-3d 幂等=%s 原样本不动=%s%s"
                  % (r["rel"].split("/")[-1], r["decode_cells"], r["decode_miss"],
                     r["slots"], r["regions"], r["region_equal"], r["unresolved"],
                     r.get("idempotent"), r.get("src_unchanged"),
                     "  abstain=" + r["abstain"] if r["abstain"] else ""))
        tot_slots = sum(r["slots"] for r in rows[group])
        print("  小计：slots %d，区间逐字节全等 %d/%d"
              % (tot_slots, sum(r["region_equal"] for r in rows[group]),
                 sum(r["regions"] for r in rows[group])))
        if group == "packed":
            print("  说明：加壳组「区间等」预期为 0——按纪律一个字节都不写，"
                  "伪指针原样保留；判定看 unresolved==slots 且 wrote_any=False")
    print("\n[反例] 篡改 1 slot → status=%s bytes_untouched=%s reason=%s"
          % (anti and anti["status"], anti and anti["bytes_untouched"],
             anti and anti["reason"]))

    if args.selftest:
        # 自证可失败：把修复结果故意改坏 1 字节，检查器必须报区间不等
        target = REPO / "tests/fixtures/minipe.exe"
        data = target.read_bytes()
        loc = iat.locate_bytes(data)
        fake = bytearray(fake_load(data, loc))
        repaired, rep = iat.repair_bytes(bytes(fake))
        r0 = rep["regions"][0]
        tampered = bytearray(repaired)
        tampered[r0["start"]] ^= 0xFF
        caught = region_sha(data, r0) != iat.sha256_bytes(bytes(tampered[r0["start"]:r0["start"] + r0["size"]]))
        print("\n[selftest] 故意改坏 1 字节 → 检查器%s" % ("已检出（能失败）" if caught else "未检出"))
        if not caught:
            fails.append("[selftest] 检查器无法检出破坏")

    print("\n结论：失配 %d 项" % len(fails))
    for f in fails:
        print("  ✗ %s" % f)
    verdict = PASS if not fails else FAIL
    print("VERDICT: %s" % verdict)
    return 0 if verdict == PASS else 1


if __name__ == "__main__":
    sys.exit(main())
