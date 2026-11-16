#!/usr/bin/env python3
"""M2 任务卡前置勘察：用 pyelftools / pefile 读取 rekit 现有 10 个 fixtures 的
外部可见特征（壳/编译器/stripped/安全态），作为任务卡样本表的实测依据。

只用第三方权威解析库，不 import rekit（净室：先看权威工具怎么说）。
用法: python probe_fixtures.py <fixtures_dir>
"""
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
import pefile


def probe_elf(p: Path) -> dict:
    with p.open("rb") as f:
        e = ELFFile(f)
        out = {
            "kind": "ELF",
            "class": e.elfclass,
            "type": e.header.e_type,
            "machine": e.header.e_machine,
            "sections": [s.name for s in e.iter_sections()],
        }
        out["has_symtab"] = ".symtab" in out["sections"]
        out["has_dynsym"] = ".dynsym" in out["sections"]
        comment = ""
        if ".comment" in out["sections"]:
            raw = e.get_section_by_name(".comment").data()
            comment = raw.replace(b"\x00", b" ").decode("ascii", "replace").strip()
        out["comment"] = comment
        dyn = e.get_section_by_name(".dynamic")
        out["needed"] = []
        out["flags_1"] = None
        out["flags"] = None
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    out["needed"].append(tag.needed)
                elif tag.entry.d_tag == "DT_FLAGS_1":
                    out["flags_1"] = hex(tag.entry.d_val)
                elif tag.entry.d_tag == "DT_FLAGS":
                    out["flags"] = hex(tag.entry.d_val)
        out["go_buildinfo"] = ".go.buildinfo" in out["sections"]
        out["note_go"] = any("go.buildid" in s.name for s in e.iter_sections())
        return out


def probe_pe(p: Path) -> dict:
    pe = pefile.PE(str(p), fast_load=True)
    pe.parse_data_directories()
    dc = pe.OPTIONAL_HEADER.DllCharacteristics
    out = {
        "kind": "PE",
        "magic": hex(pe.OPTIONAL_HEADER.Magic),
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections": [s.Name.rstrip(b"\x00").decode("ascii", "replace")
                     for s in pe.sections],
        "dll_chars": hex(dc),
        "NX_COMPAT": bool(dc & 0x0100),
        "DYNAMICBASE": bool(dc & 0x0040),
        "HIGH_ENTROPY_VA": bool(dc & 0x0020),
        "GUARD_CF": bool(dc & 0x4000),
        "NO_SEH": bool(dc & 0x0400),
        "ptr_symtab": pe.FILE_HEADER.PointerToSymbolTable,
        "num_symbols": pe.FILE_HEADER.NumberOfSymbols,
        "imphash": pe.get_imphash() if hasattr(pe, "get_imphash") else None,
    }
    out["has_rich"] = b"Rich" in pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders]
    out["exports"] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        out["exports"] = [e.name.decode() if e.name else "#%d" % e.ordinal
                          for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
    pe.close()
    return out


def main() -> int:
    base = Path(sys.argv[1])
    result = {}
    for p in sorted(base.iterdir()):
        if not p.is_file():
            continue
        try:
            head = p.open("rb").read(4)
        except OSError:
            continue
        try:
            if head == b"\x7fELF":
                result[p.name] = probe_elf(p)
            elif head[:2] == b"MZ":
                result[p.name] = probe_pe(p)
        except Exception as exc:  # 勘察脚本：单样本失败不影响其余
            result[p.name] = {"error": "%s: %s" % (type(exc).__name__, exc)}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
