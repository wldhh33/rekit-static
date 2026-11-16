#!/usr/bin/env python3
"""M2 任务卡：候选样本预期状态实测（busybox / putty / go / rust）。
用法: python probe_samples.py <samples_dir>
输出 JSON 到 stdout。
"""
import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
import pefile


def elf_summary(p: Path) -> dict:
    with p.open("rb") as f:
        e = ELFFile(f)
        names = [s.name for s in e.iter_sections()]
        out = {
            "format": "ELF%d" % e.elfclass,
            "type": e.header.e_type,
            "machine": e.header.e_machine,
            "n_sections": len(names),
            "has_symtab": ".symtab" in names,
            "has_dynsym": ".dynsym" in names,
            "has_comment": ".comment" in names,
            "upx_like": sorted(n for n in names if n.upper().startswith("UPX")),
            "go_buildinfo": ".go.buildinfo" in names,
            "note_sections": [n for n in names if n.startswith(".note")],
            "interp": None,
            "needed": [],
        }
        if ".comment" in names:
            raw = e.get_section_by_name(".comment").data()
            out["comment"] = raw.replace(b"\x00", b"\n").decode("ascii", "replace").strip()
        if ".interp" in names:
            out["interp"] = e.get_section_by_name(".interp").data().rstrip(b"\x00").decode()
        dyn = e.get_section_by_name(".dynamic")
        if dyn is not None:
            for t in dyn.iter_tags():
                if t.entry.d_tag == "DT_NEEDED":
                    out["needed"].append(t.needed)
        # Go 指纹：pclntab 节 / .gopclntab / 字符串
        out["has_gopclntab"] = any("gopclntab" in n for n in names)
        return out


def pe_summary(p: Path) -> dict:
    pe = pefile.PE(str(p), fast_load=True)
    dc = pe.OPTIONAL_HEADER.DllCharacteristics
    out = {
        "format": "PE32+" if pe.OPTIONAL_HEADER.Magic == 0x20B else "PE32",
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections": [s.Name.rstrip(b"\x00").decode("ascii", "replace") for s in pe.sections],
        "dll_chars": hex(dc),
        "NX_COMPAT": bool(dc & 0x0100),
        "DYNAMICBASE": bool(dc & 0x0040),
        "HIGH_ENTROPY_VA": bool(dc & 0x0020),
        "GUARD_CF": bool(dc & 0x4000),
        "ptr_symtab": pe.FILE_HEADER.PointerToSymbolTable,
        "has_rich_in_headers": b"Rich" in pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders],
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
    }
    pe.close()
    return out


def main() -> int:
    base = Path(sys.argv[1])
    res = {}
    for p in sorted(base.iterdir()):
        if not p.is_file():
            continue
        head = p.open("rb").read(4)
        try:
            if head == b"\x7fELF":
                res[p.name] = elf_summary(p)
            elif head[:2] == b"MZ":
                res[p.name] = pe_summary(p)
        except Exception as exc:
            res[p.name] = {"error": "%s: %s" % (type(exc).__name__, exc)}
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
