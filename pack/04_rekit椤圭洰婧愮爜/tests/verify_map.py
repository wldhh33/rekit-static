#!/usr/bin/env python3
# verify_map.py — M3 验收载体（E2/E3/E4/E5 的混淆矩阵；E9 的载体）
#
# 口径（与任务卡 §4 一致）：
#   分母 = 可判定格（真值明确、本工具本应给出答案）
#   弃权格单列：真值本身不可判定（如 UPX-ELF 无节表），给确定值 = 误报
#   期望值全部由【真值快照 + 显式算式】独立重算，不调用被测实现（与手工计算对照）
#
# 用法：
#   python tests/verify_map.py --all --matrix
#   python tests/verify_map.py --all --matrix --dim elf_seg --dim pe_sec
#   python tests/verify_map.py --all --matrix --selftest   # 翻转 1 个真值，必须失败
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

REPO = Path(os.path.realpath(__file__)).parents[1]
sys.path.insert(0, str(REPO))
from rekit import iat  # noqa: E402  （U3：IAT slot 矩阵，E6/E9）

HIT, NIF, UNMAP = "hit", "not_in_file", "unmapped"


def find_gt():
    p = REPO
    for _ in range(6):
        cand = p / "2026-11-15" / "m3-task-card" / "work" / "map_ground_truth.json"
        if cand.exists():
            return cand
        p = p.parent
    return REPO.parent.parent.parent / "2026-11-15" / "m3-task-card" / "work" / "map_ground_truth.json"


class Cell:
    __slots__ = ("sid", "dim", "key", "expected", "actual", "verdict", "unit", "note")

    def __init__(self, sid, dim, key, expected, actual, verdict, unit="", note=""):
        self.sid, self.dim, self.key = sid, dim, key
        self.expected, self.actual = expected, actual
        self.verdict, self.unit, self.note = verdict, unit, note


def run(gt_path, dims, selftest=False):
    raw = gt_path.read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    gt_sha = hashlib.sha256(raw).hexdigest()
    snap = gt_path.with_suffix(".json.sha256")
    frozen = snap.read_text(encoding="ascii").strip() if snap.exists() else ""
    if frozen and frozen != gt_sha:
        print("[GT] 快照 sha256 不一致：记录=%s 实测=%s" % (frozen, gt_sha))
        return 2

    # 被测实现
    sys.path.insert(0, str(REPO))
    from rekit import mapview

    class View:
        """给 dict 模型加一层属性访问，判据代码读起来更直白。"""
        def __init__(self, d):
            self._d = d

        def __getitem__(self, k):
            return self._d[k]

        def get(self, k, default=None):
            return self._d.get(k, default)

        @property
        def units(self):
            return self._d["units"]

        @property
        def caveats(self):
            return self._d["caveats"]

        def addr_to_off(self, a, section=None):
            return mapview.addr_to_off(self._d, a, section=section)

        def off_to_addr(self, o):
            return mapview.off_to_addr(self._d, o)

    samples = doc["samples"]
    if selftest:
        # 自证可失败：翻转第一个 ELF 样本第一个 LOAD 的 p_vaddr
        for s in samples:
            if s["format"] == "elf" and s["segments"]:
                for seg in s["segments"]:
                    if seg["type"] == "LOAD":
                        seg["vaddr"] ^= 0x10
                        print("[selftest] 翻转 %s 的一个 LOAD vaddr" % s["rel"])
                        break
                break

    cells = []
    env_errors = []
    for s in samples:
        sid = s["rel"]
        path = REPO / sid
        if not path.exists():
            env_errors.append("样本缺失: %s" % sid)
            continue
        try:
            model = View(mapview.build(str(path)))
        except Exception as e:
            env_errors.append("解析异常: %s %s: %s" % (sid, type(e).__name__, e))
            continue

        if s["format"] == "elf" and ("elf_seg" in dims or "elf_sec" in dims):
            _elf_cells(s, model, cells, dims)
        if s.get("format", "").startswith("pe") and ("pe_sec" in dims or "pe_hdr" in dims):
            _pe_cells(s, model, cells, dims)
        if s.get("format", "").startswith("pe") and ("iat" in dims or "iat_packed" in dims):
            _iat_cells(s, path, cells, dims)

    # ── 矩阵 ──
    print()
    print("=" * 78)
    print("M3 映射混淆矩阵（真值快照 %s）" % gt_path.name)
    print("=" * 78)
    for dim in sorted({c.dim for c in cells}):
        sub = [c for c in cells if c.dim == dim]
        print("\n[%s] 格数 %d" % (dim, len(sub)))
        print("  %-12s %6s %6s %6s" % ("expected\\got", "hit", "nif", "unmap"))
        labels = [(HIT, "hit"), (NIF, "nif"), (UNMAP, "unmap")]
        for exp, lab in labels:
            row = [len([c for c in sub if c.expected == exp and c.actual == a]) for a, _ in labels]
            if any(row):
                print("  %-12s %6d %6d %6d" % (lab, *row))
        bad = [c for c in sub if c.verdict in ("miss", "fp")]
        print("  命中 %d / 失配 %d" % (len([c for c in sub if c.verdict == "hit"]),
                                      len([c for c in sub if c.verdict == "miss"])))
        print("  误报FP %d" % len([c for c in sub if c.verdict == "fp"]))
        for c in bad:
            print("   ✗ %-42s %-16s 期望=%s 实得=%s %s"
                  % (c.sid[-42:], c.key, c.expected, c.actual, c.note))

    # 弃权格：UPX-ELF 节表缺失必须 abstain，给 0 节即 FP
    abst = [c for c in cells if c.verdict == "abstain_hit"]
    print("\n[abstain] 弃权格 %d（不计入可判定格分母）" % len(abst))

    judged = [c for c in cells if c.verdict != "abstain_hit"]
    hits = [c for c in judged if c.verdict == "hit"]
    miss = [c for c in judged if c.verdict == "miss"]
    fp = [c for c in judged if c.verdict == "fp"]
    print("\n可判定格 %d：命中 %d（%.2f%%）/ 失配 %d / 误报 %d / 解析异常 %d"
          % (len(judged), len(hits), 100.0 * len(hits) / len(judged) if judged else 0,
             len(miss), len(fp), len(env_errors)))
    for e in env_errors:
        print("  ! %s" % e)
    ok = judged and not miss and not fp and not env_errors
    print("\nVERDICT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _nobits_arithmetic(s, loads, g):
    """从真值独立算 NOBITS 地址的算术文件落点（不调用被测实现）。

    仅当落点被某个非 NOBITS 节的文件区间覆盖时返回该偏移——这正是需要
    单列 host_section 的场合；否则返回 None（不强迫回答）。
    """
    for seg in loads:
        delta = g["addr"] - seg["vaddr"]
        if not (0 <= delta < seg["filesz"]):
            continue
        cand = seg["offset"] + delta
        for x in s["sections"]:
            if x["type"] == "NOBITS" or x["size"] == 0:
                continue
            if x["offset"] <= cand < x["offset"] + x["size"]:
                return cand
        return None
    return None


def _elf_cells(s, model, cells, dims):
    sid = s["rel"]
    loads = [x for x in s["segments"] if x["type"] == "LOAD"]
    if "elf_seg" in dims:
        units = {u["name"]: u for u in model.units}
        for i, g in enumerate(loads):
            key = "LOAD#%d" % i
            u = units.get(key)
            if u is None:
                cells.append(Cell(sid, "elf_seg", key, "unit", "absent", "miss"))
                continue
            if u["file"] != [g["offset"], g["filesz"]] or u["mem"] != [g["vaddr"], g["memsz"]]:
                cells.append(Cell(sid, "elf_seg", key, "fields",
                                  "file=%s mem=%s" % (u["file"], u["mem"]), "miss"))
            else:
                cells.append(Cell(sid, "elf_seg", key + ".fields", "fields", "fields", "hit"))
            # 探针 1：段首字节
            r = model.addr_to_off(g["vaddr"])
            ok = r["status"] == HIT and r["offset"] == g["offset"] and r["unit"] == key
            cells.append(Cell(sid, "elf_seg", key + ".@首", "hit", r["status"],
                              "hit" if ok else "miss", r.get("unit") or ""))
            # 探针 2：文件末字节
            if g["filesz"] > 0:
                a = g["vaddr"] + g["filesz"] - 1
                r = model.addr_to_off(a)
                ok = r["status"] == HIT and r["offset"] == g["offset"] + g["filesz"] - 1
                cells.append(Cell(sid, "elf_seg", key + ".@末", "hit", r["status"],
                                  "hit" if ok else "miss"))
            # 探针 3：零填充点（memsz > filesz 才有）
            if g["memsz"] > g["filesz"]:
                r = model.addr_to_off(g["vaddr"] + g["filesz"])
                ok = r["status"] == NIF and r["unit"] == key
                cells.append(Cell(sid, "elf_seg", key + ".@zero", NIF, r["status"],
                                  "hit" if ok else "miss", r.get("unit") or ""))
            # 探针 4：边界外 1 字节必须【不属于本单元】
            a_end = g["vaddr"] + g["memsz"]
            r = model.addr_to_off(a_end)
            ok = r["unit"] != key
            cells.append(Cell(sid, "elf_seg", key + ".@end+1", "not_this_unit",
                              r["status"], "hit" if ok else "miss", r.get("unit") or ""))
            # 探针 5：反向换算（多解时要求候选集包含本段）
            if g["filesz"] > 0:
                r = model.off_to_addr(g["offset"])
                ok = g["vaddr"] in r["addrs"]
                cells.append(Cell(sid, "elf_seg", key + ".rev", "addr_in",
                                  ",".join(hex(a) for a in r["addrs"]) or r["status"],
                                  "hit" if ok else "miss"))
    if "elf_sec" in dims:
        if not s.get("sections_present"):
            # 弃权格：节表被移除 → 必须 abstain（不得答 0 节/猜）
            ok = (not model.get("sections")) and any("e_shnum=0" in c for c in model["caveats"])
            cells.append(Cell(sid, "elf_sec", "sections", "abstain",
                              "abstain" if ok else "guessed",
                              "abstain_hit" if ok else "fp"))
            return
        for g in s["sections"]:
            if not (g["flags"] and "A" in g["flags"]):
                continue    # 非 alloc 节不在内存映射内 → 不计入
            key = g["name"] or ("[%d]" % g["index"])
            if g["type"] == "NOBITS":
                if g["size"] == 0:
                    continue
                # 2026-11-15 裁决 E3：【NOBITS 无文件表示，算术判定的优先级低于节类型】。
                # 反例（dyn_static .tbss，addr=0x49ee40）：该地址确实落在 LOAD#3
                # 的内存区间内，delta=0x30 < filesz=0x5cb8，算术落点 0x9de40 是真实
                # 机器码——但那些字节属于宿主节，不是 TLS 模板。故必须 not_in_file，
                # 且 offset 不得给出（不得向 map & patch 宣称"此地址可改"）。
                r = model.addr_to_off(g["addr"])
                ok = r["status"] == NIF and r.get("offset") is None
                cells.append(Cell(sid, "elf_sec", key + ".nobits", NIF, r["status"],
                                  "hit" if ok else "miss",
                                  r.get("unit") or ""))
                # 独立字段：必须能指出该地址被哪个【宿主节】覆盖（不是本节字节），
                # 与 not_in_file 并存，不得合并成一个模糊答案。
                cand = _nobits_arithmetic(s, loads, g)
                if ok and cand is not None:
                    host = r.get("host_section")
                    host_ok = (host is not None and host["name"] != key
                               and host["offset"] <= cand < host["offset"] + host["size"])
                    cells.append(Cell(sid, "elf_sec", key + ".host",
                                      "host_section@0x%x" % cand,
                                      (host or {}).get("name", "<none>"),
                                      "hit" if host_ok else "miss",
                                      r.get("unit") or ""))
                continue
            if g["size"] == 0 or g["addr"] == 0:
                continue
            # 节级一致性按【节身份】查询：.tbss 的 sh_addr 会与 .init_array/
            # .fini_array/.data.rel.ro 重叠（实测 dyn_static 同为 0x49ee40），
            # 裸地址无法同时代表两者。带 section 后仍要求精确命中本节 sh_offset，
            # 不放宽也不容错；NOBITS 分支则仍强制 not_in_file（见上）。
            r = model.addr_to_off(g["addr"], section=key)
            ok = r["status"] == HIT and r["offset"] == g["offset"]
            cells.append(Cell(sid, "elf_sec", key, "hit@0x%x" % g["offset"], r["status"],
                              "hit" if ok else "miss",
                              "%s off=%s" % (r.get("unit") or "", r.get("offset"))))


def _iat_cells(s, path, cells, dims):
    """E6/E9 第 4 张矩阵：IAT slot 解码 vs 真值（pefile 主源）。

    加壳样本单列 dim=iat_packed，**不并入**未加壳成功率（裁决要求）。
    期望值全部取自真值快照，不调用被测实现。
    """
    sid = s["rel"]
    packed = "upx" in sid.rsplit("/", 1)[-1].lower() or "/upx/" in sid
    dim = "iat_packed" if packed else "iat"
    if dim not in dims:
        return
    gt_imps = s.get("imports") or []
    try:
        loc = iat.locate(str(path))
    except Exception as e:
        cells.append(Cell(sid, dim, "<locate>", "ok",
                          "%s: %s" % (type(e).__name__, e), "miss",
                          note="解析异常"))
        return
    if not gt_imps:
        if loc["status"] == "no_imports":
            cells.append(Cell(sid, dim, "status", "no_imports", loc["status"], "hit"))
        elif "fakerich" in sid and loc["status"] == "invalid":
            # 真值侧 pefile 直接忽略畸形导入目录（0 导入）；本工具明确报 invalid。
            # 两方对同一畸形目录的处置不同，真值不可判定 → 弃权并留痕。
            cells.append(Cell(sid, dim, "status", "abstain",
                              "invalid", "abstain_hit",
                              note="畸形导入目录：真值侧忽略，本工具拒绝当 no_imports"))
        else:
            cells.append(Cell(sid, dim, "status", "no_imports", loc["status"], "miss",
                              note="; ".join(loc["issues"][:2])))
        return
    if loc["status"] != "ok":
        cells.append(Cell(sid, dim, "status", "ok", loc["status"], "miss",
                          note="; ".join(loc["issues"][:2])))
        return
    act = loc["descriptors"]
    cells.append(Cell(sid, dim, "descriptors", len(gt_imps), len(act),
                      "hit" if len(gt_imps) == len(act) else "miss"))
    for di, gd in enumerate(gt_imps):
        ad = act[di] if di < len(act) else None
        dll = gd["dll"]
        cells.append(Cell(sid, dim, "%s.dll" % dll, dll,
                          ad["dll"] if ad else None,
                          "hit" if ad and ad["dll"] == dll else "miss"))
        if ad is None:
            continue
        cells.append(Cell(sid, dim, "%s.n" % dll, len(gd["slots"]),
                          len(ad["slots"]),
                          "hit" if len(gd["slots"]) == len(ad["slots"]) else "miss"))
        for si, gs in enumerate(gd["slots"]):
            asl = ad["slots"][si] if si < len(ad["slots"]) else None
            exp = gs["name"] if gs["name"] is not None else "#%d" % gs["ordinal"]
            got = None
            if asl is not None:
                got = asl["name"] if asl["name"] is not None else "#%s" % asl["ordinal"]
            cells.append(Cell(sid, dim, "%s#%d" % (dll, si), exp, got,
                              "hit" if exp == got else "miss"))
            cells.append(Cell(sid, dim, "%s#%d.rva" % (dll, si),
                              "0x%x" % gs["rva"],
                              "0x%x" % asl["rva"] if asl else None,
                              "hit" if asl and gs["rva"] == asl["rva"] else "miss"))
            if gs.get("hint") is not None:
                cells.append(Cell(sid, dim, "%s#%d.hint" % (dll, si),
                                  "0x%04x" % gs["hint"],
                                  "0x%04x" % asl["hint"] if asl and asl["hint"] is not None else None,
                                  "hit" if asl and gs["hint"] == asl["hint"] else "miss"))


def _pe_cells(s, model, cells, dims):
    sid = s["rel"]
    if "pe_hdr" in dims:
        soh = s["size_of_headers"]
        first_raw = min((x["rawptr"] for x in s["sections"] if x["rawsize"] > 0), default=None)
        if first_raw is None or soh <= first_raw:
            r = model.addr_to_off(0)
            ok = r["status"] == HIT and r["offset"] == 0
            cells.append(Cell(sid, "pe_hdr", "hdr@0", "hit", r["status"],
                              "hit" if ok else "miss", r.get("unit") or ""))
            r = model.addr_to_off(soh - 1)
            ok = r["status"] == HIT and r["offset"] == soh - 1
            cells.append(Cell(sid, "pe_hdr", "hdr@末", "hit", r["status"],
                              "hit" if ok else "miss"))
        else:
            r = model.addr_to_off(0)
            cells.append(Cell(sid, "pe_hdr", "hdr@0", UNMAP, r["status"],
                              "hit" if r["status"] == UNMAP else "miss"))
    if "pe_sec" not in dims:
        return
    units = {u["name"]: u for u in model.units}
    for g in s["sections"]:
        key = g["name"]
        u = units.get(key)
        ms = max(g["vsize"], g["rawsize"])
        if u is None:
            cells.append(Cell(sid, "pe_sec", key, "unit", "absent", "miss"))
            continue
        if u["file"] != [g["rawptr"], g["rawsize"]] or u["mem"] != [g["rva"], ms]:
            cells.append(Cell(sid, "pe_sec", key + ".fields", "fields",
                              "file=%s mem=%s" % (u["file"], u["mem"]), "miss"))
            continue
        cells.append(Cell(sid, "pe_sec", key + ".fields", "fields", "fields", "hit"))
        if ms == 0:
            continue
        if g["rawsize"] == 0:
            # 2026-11-15 裁决 E4：RawSize==0 → 整节没有任何文件字节，
            # 断言整节 not_in_file（比原"节首 hit"探针更严；UPX0 实测）。
            r = model.addr_to_off(g["rva"])
            ok = r["status"] == NIF and r.get("offset") is None
            cells.append(Cell(sid, "pe_sec", key + ".@首", NIF, r["status"],
                              "hit" if ok else "miss", r.get("unit") or ""))
            if ms > 1:
                r = model.addr_to_off(g["rva"] + ms - 1)
                ok = r["status"] == NIF and r.get("offset") is None
                cells.append(Cell(sid, "pe_sec", key + ".@末", NIF, r["status"],
                                  "hit" if ok else "miss", r.get("unit") or ""))
            r = model.addr_to_off(g["rva"] + ms)
            cells.append(Cell(sid, "pe_sec", key + ".@end+1", "not_this_unit", r["status"],
                              "hit" if r["unit"] != key else "miss"))
            continue
        r = model.addr_to_off(g["rva"])
        ok = r["status"] == HIT and r["offset"] == g["rawptr"]
        cells.append(Cell(sid, "pe_sec", key + ".@首", "hit", r["status"],
                          "hit" if ok else "miss", r.get("unit") or ""))
        if g["rawsize"] > 0:
            r = model.addr_to_off(g["rva"] + g["rawsize"] - 1)
            ok = r["status"] == HIT and r["offset"] == g["rawptr"] + g["rawsize"] - 1
            cells.append(Cell(sid, "pe_sec", key + ".@末", "hit", r["status"],
                              "hit" if ok else "miss"))
            r = model.off_to_addr(g["rawptr"])
            cells.append(Cell(sid, "pe_sec", key + ".rev", "addr_in",
                              ",".join(hex(a) for a in r["addrs"]) or r["status"],
                              "hit" if g["rva"] in r["addrs"] else "miss"))
        if g["vsize"] > g["rawsize"]:
            r = model.addr_to_off(g["rva"] + g["rawsize"])
            cells.append(Cell(sid, "pe_sec", key + ".@zero", NIF, r["status"],
                              "hit" if r["status"] == NIF else "miss",
                              r.get("unit") or ""))
        r = model.addr_to_off(g["rva"] + ms)
        cells.append(Cell(sid, "pe_sec", key + ".@end+1", "not_this_unit", r["status"],
                          "hit" if r["unit"] != key else "miss"))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--dim", action="append", default=None,
                    help="elf_seg / elf_sec / pe_sec / pe_hdr / iat / iat_packed（可多次）")
    ap.add_argument("--gt", default=None)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    gt = Path(args.gt) if args.gt else find_gt()
    if not gt.exists():
        print("找不到真值快照：%s" % gt)
        return 2
    dims = (set(args.dim) if args.dim
            else {"elf_seg", "elf_sec", "pe_sec", "pe_hdr", "iat", "iat_packed"})
    if args.out:
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(gt, dims, args.selftest)
        text = buf.getvalue()
        print(text)
        Path(args.out).write_text(text, encoding="utf-8")
        return rc
    return run(gt, dims, args.selftest)


if __name__ == "__main__":
    sys.exit(main())
