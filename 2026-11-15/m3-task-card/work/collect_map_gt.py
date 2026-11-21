#!/usr/bin/env python3
# collect_map_gt.py — M3 真值采集与冻结（U0，2026-11-15）
#
# 目的：在写任何换算实现之前，先用【外部工具】把 18 个样本的映射真值采下来并冻结，
#       后续实现只许对这份快照负责；发现快照错必须重新取证 + 留痕，不得为了矩阵好看改真值。
#
# 真值来源（双源，按条目区分强度）：
#   ELF：GNU readelf -hW/-lW/-SW（进程独立） + pyelftools（实现独立）
#   PE ：pefile（主源） + GNU objdump -h/-p（进程独立，用于交叉核对）
#
# 用法：
#   python collect_map_gt.py [--repo <rekit 仓库根>] [--out map_ground_truth.json]
#                            [--binutils <bin 目录>]
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

FIXTURES = ["bin_ls.elf", "cli-64.exe", "dyn_execstack", "dyn_nopie", "dyn_norelro",
            "dyn_pie", "dyn_static", "minidll.dll", "minipe.exe", "minipe_fakerich.exe"]
SAMPLES_DIR = "tests/samples/fingerprint"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd):
    """跑外部工具；返回 (stdout, stderr, returncode)。编码替换式解码，避免非 ASCII 崩。"""
    p = subprocess.run(cmd, capture_output=True)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    return out, err, p.returncode


def tool_version(name):
    out, _err, _rc = run([name, "--version"])
    return out.splitlines()[0].strip() if out else "?"


# ── ELF：readelf 解析 ────────────────────────────────────────────────

def parse_readelf_segments(text):
    segs = []
    in_table = False
    for line in text.splitlines():
        if line.strip().startswith("Type") and "Offset" in line:
            in_table = True
            continue
        if not in_table:
            continue
        if not line.strip():
            break
        if line.startswith("  Section to Segment"):
            break
        tok = line.split()
        # Type Off VirtAddr PhysAddr FileSiz MemSiz Flg Align
        if len(tok) < 8:
            continue
        try:
            segs.append({"type": tok[0], "offset": int(tok[1], 16),
                         "vaddr": int(tok[2], 16), "paddr": int(tok[3], 16),
                         "filesz": int(tok[4], 16), "memsz": int(tok[5], 16),
                         "flags": "".join(tok[6:-1]), "align": int(tok[-1], 16)})
        except ValueError:
            continue
    return segs


SEC_RE = re.compile(
    r"^\s*\[\s*(\d+)\]\s+(.*?)\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
    r"([0-9a-f]+)\s+([0-9a-f]{1,2})\s+(\S*)\s+(\d+)\s+(\d+)\s+(\d+)\s*$")
# 2026-11-15 采集器修正 #1：原用 \s{2,} 分隔节名与类型，节名恰好填满 18 列时只有 1 个空格，
# 导致 .note.gnu.property / .note.gnu.build-id / .gnu_debugaltlink 三类长名节被漏读
# （bin_ls: readelf=27 vs pyelftools=30）。改为 \s+ 并从右往左锚定十六进制字段：
# 节名/类型可为空或有空格，但 Address/Off/Size/ES 及 Lk/Inf/Al 是纯十六进制/十进制，
# 不会与类型名混淆（ELF 节类型名均含非十六进制字母，故不会错位）。


def parse_readelf_sections(text):
    secs = []
    for line in text.splitlines():
        m = SEC_RE.match(line)
        if not m:
            continue
        idx, name, typ, addr, off, size, es, flg, lk, inf, al = m.groups()
        secs.append({"index": int(idx), "name": name.strip(), "type": typ,
                     "addr": int(addr, 16), "offset": int(off, 16),
                     "size": int(size, 16), "entsize": int(es, 16),
                     "flags": flg, "link": int(lk), "info": int(inf),
                     "align": int(al)})
    return secs


def parse_readelf_header(text):
    info = {}
    for line in text.splitlines():
        if line.strip().startswith("Type:"):
            info["type"] = line.split(":", 1)[1].strip().split()[0]
        elif line.strip().startswith("Entry point address:"):
            info["entry"] = int(line.split(":", 1)[1].strip(), 16)
        elif line.strip().startswith("Number of section headers:"):
            info["e_shnum"] = int(line.split(":", 1)[1].strip())
    return info


# ── PE：pefile 主源 + objdump 交叉 ──────────────────────────────────

OBJ_SEC_RE = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+([0-9a-f]{8})\s+([0-9a-f]{16})\s+([0-9a-f]{16})\s+"
    r"([0-9a-f]{8})\s+(\S+)\s*$")


def parse_objdump_sections(text):
    secs = []
    for line in text.splitlines():
        m = OBJ_SEC_RE.match(line)
        if not m:
            continue
        idx, name, size, vma, _lma, fileoff, _algn = m.groups()
        secs.append({"index": int(idx), "name": name, "size": int(size, 16),
                     "vma_abs": int(vma, 16), "fileoff": int(fileoff, 16)})
    return secs


IMPORT_DESC_RE = re.compile(
    r"^\s*([0-9a-f]{8})\t([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+"
    r"([0-9a-f]{8})\s+([0-9a-f]{8})\s*$")
IMPORT_SLOT_RE = re.compile(r"^\s*([0-9a-f]{8})\s+(<none>|\d+)\s+([0-9a-f]{4})\s+(\S+)\s*$")


def parse_objdump_imports(text):
    """返回 [{dll, first_thunk, slots:[{rva, name|None, ordinal|None, hint}]}]"""
    imports, cur, in_tables = [], None, False
    for line in text.splitlines():
        if line.startswith("The Import Tables"):
            in_tables = True
            continue
        if not in_tables:
            continue
        m = IMPORT_DESC_RE.match(line)
        if m:
            vals = [int(g, 16) for g in m.groups()]
            if not any(vals[1:]):
                continue   # 终止 descriptor：objdump 会打印其所在 RVA（首位非零）+ 后 5 个零
            cur = {"dll": None, "descriptor_rva": vals[0],
                   "first_thunk": vals[5], "slots": []}
            imports.append(cur)
            continue
        s = line.strip()
        if s.startswith("DLL Name:"):
            if cur is not None:
                cur["dll"] = s.split(":", 1)[1].strip()
            continue
        ms = IMPORT_SLOT_RE.match(line)
        if ms and cur is not None:
            rva, ordv, hint, member = ms.groups()
            cur["slots"].append({"rva": int(rva, 16),
                                 "ordinal": None if ordv == "<none>" else int(ordv),
                                 "hint": int(hint, 16), "name": member})
    return imports


def collect_pe(path, pefile_mod):
    pe = pefile_mod.PE(str(path), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    gt = {"format": "pe32plus" if pe.OPTIONAL_HEADER.Magic == 0x20B else "pe32",
          "image_base": image_base,
          "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
          "size_of_headers": pe.OPTIONAL_HEADER.SizeOfHeaders,
          "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
          "sections": [], "imports": [], "pefile_ok": True}
    for s in pe.sections:
        gt["sections"].append({
            "name": s.Name.rstrip(b"\x00").decode("ascii", "replace"),
            "rva": s.VirtualAddress, "vsize": s.Misc_VirtualSize,
            "rawptr": s.PointerToRawData, "rawsize": s.SizeOfRawData,
            "chars": s.Characteristics})
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                slots = []
                for imp in entry.imports:
                    # 采集器修正 #4（权威工具语义）：pefile 的 ImportData.address 是
                    # **绝对 VA**（实测 cli-64: 0x140003000），而 objdump/PE 规范里的
                    # IAT 槽位是 RVA。统一减 ImageBase 归一到 RVA，否则整张 IAT 表错位。
                    slots.append({"rva": imp.address - image_base,
                                  "ordinal": imp.ordinal if imp.name is None else None,
                                  "name": (imp.name.decode("ascii", "replace")
                                           if imp.name is not None else None),
                                  "hint": imp.hint})
                gt["imports"].append({
                    "dll": entry.dll.decode("ascii", "replace"),
                    "first_thunk": entry.struct.FirstThunk,
                    "slots": slots})
    except Exception as e:  # 解析失败也要留痕，不静默
        gt["imports_error"] = "%s: %s" % (type(e).__name__, e)
    # 交叉：objdump -h / -p（进程独立）
    out_h, _e, _rc = run([BINUTILS["objdump"], "-h", str(path)])
    out_p, _e2, _rc2 = run([BINUTILS["objdump"], "-p", str(path)])
    obj_secs = parse_objdump_sections(out_h)
    obj_imps = parse_objdump_imports(out_p)
    gt["objdump_sections"] = [{"name": s["name"], "vma_abs": s["vma_abs"],
                               "size": s["size"], "fileoff": s["fileoff"]}
                              for s in obj_secs]
    gt["objdump_imports"] = [{"dll": i["dll"], "first_thunk": i["first_thunk"],
                              "n_slots": len(i["slots"]),
                              "slots": [{"rva": s["rva"], "name": s["name"],
                                         "ordinal": s["ordinal"]} for s in i["slots"]]}
                             for i in obj_imps]
    # 一致性核对（真值双源不一致必须显式记录，不许挑顺眼的）
    #
    # 2026-11-15 采集器修正 #2（口径）：objdump -h 的 "Size" 列对 PE 等于
    #   min(VirtualSize, SizeOfRawData)（实测 6 节全成立：.text 0x17bc vs raw 0x1800；
    #   .data 0x648 vs raw 0x200），它不是 VirtualSize 的同名词，也不是 RawSize。
    #   故改用【可证伪不变量】核对：objdump.size == min(vsize, rawsize)，
    #   并另用 SizeOfImage 公式（见下）独立约束 vsize，避免"用错列"却当成真值分歧。
    diffs = []
    size_caveats = []
    if len(obj_secs) != len(gt["sections"]):
        diffs.append("节数 pefile=%d objdump=%d" % (len(gt["sections"]), len(obj_secs)))
    else:
        for a, b in zip(gt["sections"], obj_secs):
            # 2026-11-15 采集器修正 #3：COFF 长节名（/nn）pefile 原样返回，
            # objdump 会去 string table 解析——两者指的是同一节，仅呈现不同。
            # 名字不作为判据，记在 name_resolved 里留档。
            if a["name"].startswith("/"):
                a["name_resolved"] = b["name"]
            elif a["name"] != b["name"]:
                diffs.append("节名 %r != %r" % (a["name"], b["name"]))
            if a["rva"] + image_base != b["vma_abs"]:
                diffs.append("%s RVA pefile=0x%x objdump=0x%x"
                             % (a["name"], a["rva"] + image_base, b["vma_abs"]))
            if a["rawptr"] != b["fileoff"]:
                diffs.append("%s RawPtr pefile=0x%x objdump=0x%x"
                             % (a["name"], a["rawptr"], b["fileoff"]))
            # Size 列只在两种已知怪癖之外遵守 min(vsize, rawsize)：
            #   ① rawsize == 0（纯内存节，如 UPX0）→ objdump 报 vsize；
            #   ② 压缩调试节 .zdebug_* → BFD 透明解压，报的是解压后大小。
            # 这两类记 caveat 并保留实测数字，不进 diffs（不是真值分歧）。
            if a["rawsize"] == 0:
                if b["size"] != a["vsize"]:
                    diffs.append("%s rawsize=0 时 objdump size=0x%x != vsize 0x%x"
                                 % (a["name"], b["size"], a["vsize"]))
                else:
                    size_caveats.append("%s: rawsize=0，objdump 报 vsize" % a["name"])
            elif b["size"] != min(a["vsize"], a["rawsize"]):
                if b["size"] > min(a["vsize"], a["rawsize"]) and (
                        a["name"].startswith("/") or a["name"].startswith(".zdebug")):
                    size_caveats.append("%s(%s): 压缩调试节，objdump 报解压后 0x%x（头部 vsize=0x%x rawsize=0x%x）"
                                        % (a["name"], a.get("name_resolved", "?"), b["size"],
                                           a["vsize"], a["rawsize"]))
                else:
                    diffs.append("%s size 不变量 min(vsize=0x%x,rawsize=0x%x)=0x%x != objdump 0x%x"
                                 % (a["name"], a["vsize"], a["rawsize"],
                                    min(a["vsize"], a["rawsize"]), b["size"]))
    gt["size_caveats"] = size_caveats
    # SizeOfImage 公式核对：align_up(max(va+vsize), SectionAlignment)
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    if gt["sections"]:
        img_end = max((s["rva"] + s["vsize"]) for s in gt["sections"])
        img_calc = (img_end + sa - 1) // sa * sa
        if img_calc != gt["size_of_image"]:
            diffs.append("SizeOfImage 公式=0x%x pefile=0x%x" % (img_calc, gt["size_of_image"]))
        gt["size_of_image_calc"] = img_calc
    else:
        gt["size_of_image_calc"] = None
        gt["no_sections"] = True
    gt["section_alignment"] = sa
    m_img = re.search(r"^SizeOfImage\s+([0-9a-fA-F]+)", out_p, re.M)
    gt["objdump_size_of_image"] = int(m_img.group(1), 16) if m_img else None
    if m_img and int(m_img.group(1), 16) != gt["size_of_image"]:
        diffs.append("SizeOfImage pefile=0x%x objdump=0x%x"
                     % (gt["size_of_image"], int(m_img.group(1), 16)))
    # 数据目录交叉（进程独立）：Export / Import / BaseReloc / IAT 四项 RVA+Size
    dd = {}
    for line in out_p.splitlines():
        m = re.match(r"^Entry\s+([0-9a-f]+)\s+([0-9a-f]{16})\s+([0-9a-f]{8})\s+(.+?)\s*$", line)
        if m:
            dd[int(m.group(1), 16)] = {"rva": int(m.group(2), 16), "size": int(m.group(3), 16),
                                       "name": m.group(4)}
    gt["objdump_dirs"] = {k: v for k, v in dd.items() if k in (0, 1, 5, 12)}
    for idx, label in ((0, "Export"), (1, "Import"), (5, "BaseReloc"), (12, "IAT")):
        if idx in dd:
            pe_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            if dd[idx]["rva"] != pe_dir.VirtualAddress or dd[idx]["size"] != pe_dir.Size:
                diffs.append("%s 目录 pefile=0x%x/0x%x objdump=0x%x/0x%x"
                             % (label, pe_dir.VirtualAddress, pe_dir.Size,
                                dd[idx]["rva"], dd[idx]["size"]))
    # 导入 descriptor 级核对；若 objdump 把导入表解释到错误节（Go 的 /nn 长节名会让
    # objdump 的 RVA→节映射错位，实测 hello_go.exe 把 .idata 解释成 .zdebug_info 且
    # 打印出一堆 ASCII 垃圾），则判为 objdump 该段不可靠，记 caveat 不做逐项比对。
    gt["objdump_imports_reliable"] = all(i["dll"] for i in obj_imps)
    if not gt["objdump_imports_reliable"]:
        gt["objdump_imports_caveat"] = (
            "objdump 对导入表解释不可靠（DLL 名缺失/落错节）；"
            "IAT 真值以 pefile + 数据目录(RVA/Size) 为准，见 objdump_dirs[12]")
    if gt["objdump_imports_reliable"]:
        if len(obj_imps) != len(gt["imports"]):
            diffs.append("导入 descriptor 数 pefile=%d objdump=%d"
                         % (len(gt["imports"]), len(obj_imps)))
        else:
            for a, b in zip(gt["imports"], obj_imps):
                if (a["dll"] or "").lower() != (b["dll"] or "").lower():
                    diffs.append("DLL 名 %r != %r" % (a["dll"], b["dll"]))
                if a["first_thunk"] != b["first_thunk"]:
                    diffs.append("%s FirstThunk pefile=0x%x objdump=0x%x"
                                 % (a["dll"], a["first_thunk"], b["first_thunk"]))
                if [s["rva"] for s in a["slots"]] != [s["rva"] for s in b["slots"]]:
                    diffs.append("%s slot 序列不一致" % a["dll"])
                else:
                    an = [(s["name"], s["ordinal"]) for s in a["slots"]]
                    bn = [(s["name"], s["ordinal"]) for s in b["slots"]]
                    if an != bn:
                        diffs.append("%s slot 符号名/序号不一致" % a["dll"])
    gt["cross_check_diffs"] = diffs
    return gt


def collect_elf(path, elftools_mod):
    h, _eh, _rc = run([BINUTILS["readelf"], "-hW", str(path)])
    l, _el, _rc2 = run([BINUTILS["readelf"], "-lW", str(path)])
    s, se, _rc3 = run([BINUTILS["readelf"], "-SW", str(path)])
    header = parse_readelf_header(h)
    gt = {"format": "elf", "header": header,
          "segments": parse_readelf_segments(l),
          "sections": parse_readelf_sections(s),
          "sections_present": "There are no sections" not in s,
          "readelf_sections_stderr": se.strip()[:200]}
    # pyelftools 交叉（实现独立）
    from elftools.elf.elffile import ELFFile
    py_segs, py_secs = [], []
    with open(path, "rb") as f:
        e = ELFFile(f)
        for seg in e.iter_segments():
            py_segs.append({"type": seg["p_type"], "offset": seg["p_offset"],
                            "vaddr": seg["p_vaddr"], "filesz": seg["p_filesz"],
                            "memsz": seg["p_memsz"]})
        for sec in e.iter_sections():
            py_secs.append({"name": sec.name, "type": sec["sh_type"],
                            "addr": sec["sh_addr"], "offset": sec["sh_offset"],
                            "size": sec["sh_size"]})
    diffs = []
    loads_r, loads_p = ([x for x in gt["segments"] if x["type"] == "LOAD"],
                        [x for x in py_segs if x["type"] == "PT_LOAD"])
    if len(loads_r) != len(loads_p):
        diffs.append("LOAD 段数 readelf=%d pyelftools=%d" % (len(loads_r), len(loads_p)))
    else:
        for a, b in zip(loads_r, loads_p):
            for k in ("offset", "vaddr", "filesz", "memsz"):
                if a[k] != b[k]:
                    diffs.append("LOAD@0x%x %s readelf=0x%x pyelftools=0x%x"
                                 % (a["vaddr"], k, a[k], b[k]))
    if gt["sections_present"]:
        if len(gt["sections"]) != len(py_secs):
            diffs.append("节数 readelf=%d pyelftools=%d"
                         % (len(gt["sections"]), len(py_secs)))
        else:
            for a, b in zip(gt["sections"], py_secs):
                if a["name"] != b["name"]:
                    diffs.append("节名 %r != %r" % (a["name"], b["name"]))
                if a["addr"] != b["addr"] or a["offset"] != b["offset"]:
                    diffs.append("%s addr/off readelf=0x%x/0x%x pyelftools=0x%x/0x%x"
                                 % (a["name"], a["addr"], a["offset"], b["addr"], b["offset"]))
    gt["pyelftools_segments"] = py_segs
    gt["pyelftools_sections"] = py_secs
    gt["cross_check_diffs"] = diffs
    return gt


def discover(repo):
    paths = [repo / "tests" / "fixtures" / n for n in FIXTURES]
    samples = repo / SAMPLES_DIR
    for p in sorted(samples.rglob("*")):
        if p.is_file():
            paths.append(p)
    return [p for p in paths if p.exists()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[3]
                                          / "pack" / "04_rekit项目源码"))
    ap.add_argument("--out", default=str(Path(__file__).with_name("map_ground_truth.json")))
    ap.add_argument("--binutils", default=str(Path(__file__).with_name("tools")
                                             / "binutils-2.47" / "mingw64" / "bin"))
    args = ap.parse_args()
    BINUTILS["readelf"] = str(Path(args.binutils) / "readelf.exe")
    BINUTILS["objdump"] = str(Path(args.binutils) / "objdump.exe")
    repo = Path(args.repo)
    import pefile
    from elftools.elf.elffile import ELFFile  # noqa: F401  （可用性前置检查）

    doc = {"frozen_at": "", "tools": {}, "samples": []}
    doc["tools"]["readelf"] = tool_version(BINUTILS["readelf"])
    doc["tools"]["objdump"] = tool_version(BINUTILS["objdump"])
    doc["tools"]["pefile"] = getattr(pefile, "__version__", "?")
    import elftools
    doc["tools"]["pyelftools"] = getattr(elftools, "__version__", "?")
    doc["tools"]["binutils_dir"] = args.binutils

    for p in discover(repo):
        rel = str(p.relative_to(repo)).replace("\\", "/")
        with open(p, "rb") as f:
            magic = f.read(20)
        rec = {"rel": rel, "size": p.stat().st_size, "sha256": sha256(p)}
        try:
            if magic[:4] == b"\x7fELF":
                rec.update(collect_elf(p, None))
            elif magic[:2] == b"MZ":
                rec.update(collect_pe(p, pefile))
            else:
                rec["skip"] = "非 ELF/PE"
        except Exception as e:
            rec["error"] = "%s: %s" % (type(e).__name__, e)
        doc["samples"].append(rec)
        print("[gt] %-58s %s" % (rel, rec.get("error") or
                                 ("diffs=%d" % len(rec.get("cross_check_diffs", [])))))

    import datetime
    doc["frozen_at"] = datetime.datetime.now().isoformat(timespec="seconds")
    payload = json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.write(payload + "\n")
    digest = hashlib.sha256((payload + "\n").encode("utf-8")).hexdigest()
    with open(args.out + ".sha256", "w", encoding="ascii", newline="\n") as f:
        f.write(digest + "\n")
    print("\n[gt] 样本 %d 个；冻结快照 %s" % (len(doc["samples"]), args.out))
    print("[gt] sha256(snapshot) = %s" % digest)
    bad = [s["rel"] for s in doc["samples"] if s.get("cross_check_diffs")]
    print("[gt] 双源不一致的样本：%s" % (bad or "无"))


BINUTILS = {}


if __name__ == "__main__":
    sys.exit(main())
