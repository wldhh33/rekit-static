#!/usr/bin/env python3
# rekit.iat — IAT 定位 / slot 解码 / 修复雏形（M3 U3，2026-11-15）
#
# 净室纪律：
#   1. 只读文件外部字节；不运行样本、不依赖原样本之外的模块。
#   2. 任何写回都写到【新文件】，落盘前拒绝 dst == src（含同一真实路径/同一文件）。
#   3. 回解只用镜像内仍可信的 INT（OriginalFirstThunk）与描述符；
#      INT 缺失 / slot 值不像加载态地址 → unresolved，绝不猜，也不写该 slot。
#   4. 修复正确性用「IAT 区间字节 sha256 与原始文件逐字节相等」证明，
#      不以"看起来对/能启动"作证据；验证脚本可用 --selftest 故意破坏自证能失败。
import argparse
import hashlib
import json
import os
import struct
import sys

MAGIC_PE32, MAGIC_PE32PLUS = 0x10B, 0x20B
MAX_THUNKS = 65536          # 防御性上限：thunk 链无终止时不死循环


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── 头部（纯 bytes，供修复路径复用） ─────────────────────────────

def headers(data):
    if data[:2] != b"MZ":
        raise ValueError("no MZ")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("no PE sig")
    nsect = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    optsize = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (MAGIC_PE32, MAGIC_PE32PLUS):
        raise ValueError("unknown optional header magic 0x%x" % magic)
    plus = magic == MAGIC_PE32PLUS
    image_base = (struct.unpack_from("<Q", data, opt + 24)[0] if plus
                  else struct.unpack_from("<I", data, opt + 28)[0])
    size_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_headers = struct.unpack_from("<I", data, opt + 60)[0]
    ndirs_off = opt + (108 if plus else 92)
    ndirs = struct.unpack_from("<I", data, ndirs_off)[0]
    dirs = [struct.unpack_from("<II", data, ndirs_off + 4 + i * 8)
            for i in range(min(ndirs, 16))]
    sect_off = opt + optsize
    sections = []
    for i in range(nsect):
        o = sect_off + i * 40
        if o + 40 > len(data):
            raise struct.error("section table truncated")
        name = data[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        sections.append({"name": name, "vsize": vsize, "va": va,
                         "rawsize": rawsize, "rawptr": rawptr})
    return {"bits": 64 if plus else 32, "ptrsize": 8 if plus else 4,
            "image_base": image_base, "size_image": size_image,
            "size_headers": size_headers, "dirs": dirs, "sections": sections}


def rva_to_off(h, rva):
    """RVA → 文件偏移；虚拟尾部/无文件字节/超范围一律 None（不逼近）。"""
    for s in h["sections"]:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rawsize"]):
            delta = rva - s["va"]
            if s["rawsize"] == 0 or delta >= s["rawsize"]:
                return None
            return s["rawptr"] + delta
    if 0 <= rva < h["size_headers"]:
        return rva
    return None


def _cstr(data, off):
    if off is None or off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off)
    if end == -1:
        return None
    return data[off:end].decode("ascii", "replace")


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _ptr(data, off, bits):
    return (struct.unpack_from("<Q", data, off)[0] if bits == 64
            else struct.unpack_from("<I", data, off)[0])


def _decode_thunk(h, data, val):
    """解码 thunk 值：序号导入 = 最高位标志；否则 hint/name RVA。"""
    flag = 1 << (h["bits"] - 1)
    if val & flag:
        return {"ordinal": val & 0xFFFF, "name": None, "hint": None,
                "hint_name_rva": None}
    off = rva_to_off(h, val)
    if off is None:
        return None
    return {"ordinal": None, "name": _cstr(data, off + 2),
            "hint": _u16(data, off), "hint_name_rva": val}


# ── 定位与解码 ───────────────────────────────────────────────────

def locate_bytes(data):
    """返回 {status, ...}；status ∈ ok / no_imports / invalid。

    每个 slot 记录：
      rva        IAT 槽位 RVA（与 pefile ImportData.address-ImageBase 同口径）
      file_off   槽位文件偏移（None = 该 RVA 无文件字节）
      value      文件里的槽值（原文件通常等于 INT 项）
      int_value  INT 项值（权威名称来源）
      dll/name/ordinal/hint   解码结果；解不出 → name/ordinal 均为 None
      issue      不一致/解不出的原因（不猜）

    可修复性不是"跑一遍才知道"：每个 descriptor 带 repairable/reason，
    顶层 caveats 给出人话解释——加壳样本查 IAT 时不会只看到一堆 unresolved。
    """
    h = headers(data)
    ptr = h["ptrsize"]
    imp_rva, _imp_sz = h["dirs"][1]
    out = {"status": "no_imports", "bits": h["bits"],
           "image_base": h["image_base"], "descriptors": [], "slots": [],
           "issues": [], "caveats": [], "repairable": None}
    if not imp_rva:
        out["caveats"].append("无导入目录（DataDirectory[1].RVA=0）：没有 IAT 可定位")
        return out
    off = rva_to_off(h, imp_rva)
    if off is None:
        out["status"] = "invalid"
        out["issues"].append("导入目录 RVA 0x%x 无文件字节" % imp_rva)
        out["caveats"].append("导入目录无文件背书：不猜导入项，标 invalid")
        return out
    while off + 20 <= len(data):
        int_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", data, off)
        if not any((int_rva, _ts, _fwd, name_rva, iat_rva)):
            break
        dll = _cstr(data, rva_to_off(h, name_rva))
        desc = {"dll": dll, "int_rva": int_rva, "iat_rva": iat_rva,
                "slots": [], "issues": [], "repairable": True, "reason": None}
        if iat_rva == 0:
            desc["issues"].append("FirstThunk=0，无 IAT 槽位")
            desc["repairable"] = False
            desc["reason"] = "FirstThunk=0：没有可回写的槽位"
            out["descriptors"].append(desc)
            out["issues"].append("%s: FirstThunk=0" % dll)
            off += 20
            continue
        if int_rva == 0:
            # 结构性不可修复（UPX 实测）：INT 与 IAT 同址 → 名称源就是 IAT 自身。
            # loader 用已解析地址覆盖 IAT 时，名称源同时被覆盖，镜像内不再有第二份名字表。
            desc["repairable"] = False
            desc["reason"] = ("OriginalFirstThunk=0（INT 与 IAT 同址）：loader 填充后"
                              "名称源被覆盖，加载态不可回解——需先脱壳")
        thunk_rva = int_rva or iat_rva
        toff = rva_to_off(h, thunk_rva)
        slot_off0 = rva_to_off(h, iat_rva)
        count = 0
        while toff is not None and count < MAX_THUNKS:
            int_val = _ptr(data, toff, h["bits"])
            if int_val == 0:
                break
            slot_rva = iat_rva + count * ptr
            slot_off = rva_to_off(h, slot_rva)
            val = _ptr(data, slot_off, h["bits"]) if slot_off is not None else None
            rec = {"index": len(out["slots"]),
                   "desc_index": len(out["descriptors"]),
                   "dll": dll, "rva": slot_rva, "file_off": slot_off,
                   "value": val, "int_value": int_val, "int_rva": thunk_rva + count * ptr,
                   "name": None, "ordinal": None, "hint": None, "issue": None}
            dec = _decode_thunk(h, data, int_val)
            if dec is None:
                rec["issue"] = "INT 项 0x%x 无文件字节" % int_val
            else:
                rec.update({k: dec[k] for k in ("name", "ordinal", "hint")})
                if val is not None and val != int_val:
                    # 绑定导入/已加载镜像：文件槽值与 INT 不同，不能拿 INT 冒充原值
                    rec["issue"] = "IAT 槽值 0x%x != INT 项 0x%x（绑定或已加载）" % (val, int_val)
            if rec["issue"]:
                desc["issues"].append("slot#%d: %s" % (count, rec["issue"]))
            desc["slots"].append(rec)
            out["slots"].append(rec)
            toff += ptr
            count += 1
        if count == 0:
            desc["issues"].append("thunk 链为空或不可读")
        out["descriptors"].append(desc)
        out["issues"].extend("%s: %s" % (dll, x) for x in desc["issues"])
        off += 20
    # 全局序号统一重排，避免跨 descriptor 重复
    for i, rec in enumerate(out["slots"]):
        rec["index"] = i
    out["status"] = "ok" if out["descriptors"] else "no_imports"
    # 可修复性汇总：所有 descriptor 都可修才算可修（一处不可修，整份镜像就不能完整回解）
    bad = [d for d in out["descriptors"] if not d["repairable"]]
    if out["descriptors"]:
        out["repairable"] = not bad
        if bad:
            kinds = sorted({d["reason"] for d in bad})
            out["caveats"].append(
                "不可完整修复：%d/%d 个描述符的名称源在加载态丢失（%s）；"
                "修复时这些 slot 一律 unresolved，不猜"
                % (len(bad), len(out["descriptors"]), "；".join(kinds)))
            if all(d["int_rva"] == 0 for d in out["descriptors"]):
                out["caveats"].append(
                    "全部描述符 OriginalFirstThunk=0（IAT 自身即名称源）——"
                    "该结构常见于加壳/自解压镜像；是否加壳由指纹层判定，此处只报结构后果："
                    "要修复必须先脱壳，本工具不做脱壳")
    return out


def locate(path):
    with open(path, "rb") as f:
        data = f.read()
    r = locate_bytes(data)
    r["path"] = path
    return r


# ── 修复雏形 ─────────────────────────────────────────────────────

def repair_bytes(data, strict=True):
    """把「被 loader 填过指针」的镜像副本回解成原始 IAT 槽值。

    回解依据：描述符 + INT（loader 不会改 INT）。写回目标 = INT 项值。
    写入条件（全部满足才写，否则 unresolved 且该 slot 字节不动）：
      - 有 INT 且 INT 项可解码
      - 槽位有文件落点
      - 当前槽值非 0 且 >= ImageBase（加载态指针的合理量级；strict=False 可跳过）
    返回 (new_bytes, report)；new_bytes 是新对象，不修改入参 data。
    """
    h = headers(data)
    loc = locate_bytes(data)
    out = bytearray(data)
    slots = []
    regions = []
    for desc in loc["descriptors"]:
        offs = [s["file_off"] for s in desc["slots"] if s["file_off"] is not None]
        region = None
        if offs:
            start, end = min(offs), max(offs) + h["ptrsize"]
            region = {"dll": desc["dll"], "start": start, "size": end - start,
                      "sha256_before": sha256_bytes(bytes(out[start:end]))}
        repaired = unresolved = 0
        for rec in desc["slots"]:
            new = dict(rec)
            new["status"] = "unresolved"
            if rec["file_off"] is None:
                new["reason"] = "槽位 RVA 无文件字节（虚拟尾部）"
            elif rec["ordinal"] is None and rec["name"] is None:
                new["reason"] = rec["issue"] or "INT 不可解码"
            elif rec["value"] is None:
                new["reason"] = "槽值不可读"
            elif rec["value"] == 0:
                new["reason"] = "槽值为 0（无已解析指针）"
            elif strict and rec["value"] < h["image_base"]:
                new["reason"] = "槽值 0x%x < ImageBase 0x%x，不像加载态地址" % (
                    rec["value"], h["image_base"])
            else:
                target = rec["int_value"]
                struct.pack_into("<Q" if h["bits"] == 64 else "<I",
                                 out, rec["file_off"], target)
                new["status"] = "repaired"
                new["repaired_value"] = target
                new["reason"] = "按 INT 项回填"
                repaired += 1
            if new["status"] == "unresolved":
                unresolved += 1
            slots.append(new)
        if region is not None:
            region["sha256_after"] = sha256_bytes(bytes(out[start:end]))
            region["repaired"] = repaired
            region["unresolved"] = unresolved
            regions.append(region)
    report = {"bits": h["bits"], "image_base": h["image_base"],
              "ptrsize": h["ptrsize"],
              "descriptors": len(loc["descriptors"]),
              "repairable": loc["repairable"],
              "caveats": loc["caveats"],
              "slots": slots,
              "regions": regions,
              "stats": {"slots": len(slots),
                        "repaired": sum(1 for s in slots if s["status"] == "repaired"),
                        "unresolved": sum(1 for s in slots if s["status"] == "unresolved"),
                        "regions": len(regions),
                        "descriptors": len(loc["descriptors"])},
              "problems": list(loc["issues"])}
    return bytes(out), report


def repair_file(src, dst):
    """读 src → 修复 → 写 dst（新文件）。dst 与 src 相同则拒绝，原样本永不被改。"""
    if os.path.exists(dst) and os.path.samefile(src, dst):
        raise ValueError("拒绝覆盖输入样本：%s" % dst)
    if os.path.realpath(src) == os.path.realpath(dst):
        raise ValueError("拒绝覆盖输入样本：%s" % dst)
    with open(src, "rb") as f:
        data = f.read()
    new, report = repair_bytes(data)
    tmp = dst + ".tmp"
    with open(tmp, "wb") as f:
        f.write(new)
    os.replace(tmp, dst)
    report["src_sha256"] = sha256_bytes(data)
    report["dst_sha256"] = sha256_bytes(new)
    report["dst"] = dst
    return report


def render_text(path, loc):
    lines = ["IAT: %s" % path,
             "Format: PE%d  ImageBase 0x%x  status=%s"
             % (loc["bits"], loc["image_base"], loc["status"])]
    if loc["status"] == "no_imports":
        lines.append("(no_imports)")
        return "\n".join(lines)
    lines.append("Repair: %s"
                 % ("可以（全部描述符有独立 INT 名称源）" if loc["repairable"]
                    else "不可完整修复（详见下方 caveat）"))
    for c in loc["caveats"]:
        lines.append("  ! %s" % c)
    for d in loc["descriptors"]:
        lines.append("  %s  INT=0x%x  IAT=0x%x  slots=%d%s%s"
                     % (d["dll"], d["int_rva"], d["iat_rva"], len(d["slots"]),
                        "  issues=%d" % len(d["issues"]) if d["issues"] else "",
                        "" if d["repairable"] else "  [不可修复]"))
        for s in d["slots"]:
            label = s["name"] if s["name"] is not None else "#%s" % s["ordinal"]
            lines.append("    [%02d] RVA 0x%x  file 0x%x  %-8s hint=%s%s"
                         % (s["index"], s["rva"],
                            s["file_off"] if s["file_off"] is not None else -1,
                            label,
                            "-" if s["hint"] is None else "0x%04x" % s["hint"],
                            "  ! " + s["issue"] if s["issue"] else ""))
    return "\n".join(lines)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(prog="rekit.cli iat",
                                 description="IAT 定位/解码（--repair-out 写新文件）")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--repair-out", default=None,
                    help="把输入当作已加载镜像，回解 IAT 并写到该新文件（拒绝覆盖输入）")
    args = ap.parse_args(argv)
    if not os.path.exists(args.file):
        print("rekit: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        with open(args.file, "rb") as f:
            data = f.read()
        headers(data)                     # 分诊：非 PE → ValueError → 2
    except ValueError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except (struct.error, IndexError) as e:
        print("rekit: %s: 解析失败: %s" % (args.file, e), file=sys.stderr)
        return 3
    try:
        if args.repair_out:
            rep = repair_file(args.file, args.repair_out)
            if args.json:
                print(json.dumps(rep, ensure_ascii=False, indent=2))
            else:
                print("Repair: %s -> %s" % (args.file, args.repair_out))
                print("slots %d  repaired %d  unresolved %d  regions %d"
                      % (rep["stats"]["slots"], rep["stats"]["repaired"],
                         rep["stats"]["unresolved"], rep["stats"]["regions"]))
                if rep["stats"]["unresolved"]:
                    print("Repair: 未完成（%d slots 无名称源/非加载态，按纪律不猜）"
                          % rep["stats"]["unresolved"])
                    for c in rep["caveats"]:
                        print("  ! %s" % c)
                for r in rep["regions"]:
                    print("  %-10s file 0x%x..0x%x  sha %s"
                          % (r["dll"], r["start"], r["start"] + r["size"],
                             r["sha256_after"][:16]))
                print("dst_sha256 %s" % rep["dst_sha256"])
            return 0 if rep["stats"]["unresolved"] == 0 else 4
        loc = locate_bytes(data)
        if args.json:
            print(json.dumps(loc, ensure_ascii=False, indent=2))
        else:
            print(render_text(args.file, loc))
        return 0
    except (struct.error, IndexError) as e:
        print("rekit: %s: 解析失败: %s" % (args.file, e), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
