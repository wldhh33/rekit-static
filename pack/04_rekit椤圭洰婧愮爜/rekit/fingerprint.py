#!/usr/bin/env python3
# rekit.fingerprint — M2 指纹层（净室观察法）
# 2026-11-15 U1：骨架 + 静态维度（编译器指纹 / stripped / 加固位）
#
# 净室纪律（写在代码里，避免越界）：
#   1. 只用文件里外部可见的字节特征，不读外部签名库、不运行样本、不脱壳。
#   2. 强结论（packer/compiler 非 none/unknown）必须 ≥2 条独立证据；
#      证据不足一律给 unknown / hint，并列出缺哪条证据。
#   3. 已知边界：
#      - UPX 正判规则按公开格式（节名 UPX0/1/2/3 + "UPX!" 魔数）实现，
#        但【尚无 UPX 正样本验证】（E2/E3 挂起，见任务卡 G1）；
#        因此 upx 正判只作 confidence 输出，不参与本轮达标。
#      - Rust 的 ELF 侧检测（.comment 里 "rustc version"）无本机样本验证；
#        Rust 的 PE 侧已用 rustc 1.99.1 实构样本验证。
#      - MSVC 版本映射表仅 30729→19.29（VS2019 16.11）有样本实证（cli-64.exe），
#        其余项为公开工具集版本表，标为「待样本验证」。
import argparse
import json
import os
import re
import struct
import sys

from . import elf, pe

TOP_LEVEL_KEYS = ("format", "packer", "compiler", "stripped",
                  "mitigations", "evidence")

# UPX 公开格式特征：打包后原节被改名/新增为 UPX0/UPX1（PE）；
# "UPX!" 是 UPX 自己的 pack header 魔数（PE/ELF 皆有）。
UPX_SECTIONS = {"UPX0", "UPX1", "UPX2", "UPX3"}

# 常见壳的节名线索 —— 只做 hint（confidence < 0.5），不参与达标计数
PACKER_SECTION_HINTS = {
    ".aspack": ("aspack", "ASPack 节名 .aspack"),
    ".adata": ("aspack", "ASPack 节名 .adata"),
    ".mpress1": ("mpress", "MPRESS 节名 .MPRESS1"),
    ".mpress2": ("mpress", "MPRESS 节名 .MPRESS2"),
    ".themida": ("themida", "Themida/WinLicense 节名 .themida"),
    ".winlice": ("themida", "Themida/WinLicense 节名 .winlice"),
    ".vmp0": ("vmprotect", "VMProtect 节名 .vmp0"),
    ".vmp1": ("vmprotect", "VMProtect 节名 .vmp1"),
}

# MSVC 工具集 build 号 → 版本（build 在 comp.id 低 16 位；见 11-12 Rich 头定标）
# 仅 30729 有本机样本实证；其余为公开版本表，待样本验证。
MSVC_BUILD_VERSION = {
    30319: "19.00", 30423: "19.10", 30424: "19.11", 30425: "19.12",
    30426: "19.13", 30427: "19.14", 30428: "19.15", 30429: "19.16",
    30430: "19.20", 30431: "19.21", 30432: "19.22", 30433: "19.23",
    30434: "19.24", 30435: "19.25", 30436: "19.26", 30437: "19.27",
    30438: "19.28", 30705: "19.30", 30707: "19.31", 30709: "19.32",
    30711: "19.33", 30729: "19.29",
}

DLLCHAR = {"nx": 0x0100, "dynamicbase": 0x0040, "high_entropy_va": 0x0020,
           "cfg": 0x4000, "no_seh": 0x0400, "force_integrity": 0x0080,
           "terminal_server_aware": 0x8000}

GO_VERSION_RE = re.compile(rb"go1\.\d+(?:\.\d+)?")
GCC_COMMENT_RE = re.compile(rb"GCC: \(([^)]*)\)\s*([0-9][0-9.]*)")
RUSTC_COMMENT_RE = re.compile(rb"rustc(?: version)? ([0-9]+\.[0-9]+\.[0-9]+)")
RUST_TOOLCHAIN_RE = re.compile(rb"toolchains[\\/]([0-9]+\.[0-9]+\.[0-9]+)-")
RUSTC_COMMIT_RE = re.compile(rb"rustc/([0-9a-f]{40})")


def detect_format(path):
    """与 cli.detect_format 同语义的本地实现（避免 fingerprint↔cli 循环导入）。"""
    with open(path, "rb") as f:
        head = f.read(0x40)
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ" and len(head) >= 0x40:
        e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
        with open(path, "rb") as f:
            f.seek(e_lfanew)
            if f.read(4) == b"PE\x00\x00":
                return "pe"
    return None


# ── 壳识别 ────────────────────────────────────────────────────

def detect_packer(data, sec_names, extra_evidence=None):
    """返回 {name, confidence, evidence[]}。

    强判门槛 = 2 条独立证据；单证据降级为 unknown（避免把字符串巧合当壳）。
    未加壳样本输出 none + 三条"缺席证据"，便于人工复核。
    extra_evidence 供调用方补结构性证据（如 ELF 节表被移除）。
    """
    ev = []
    upx_secs = sorted(n for n in sec_names if n.upper() in UPX_SECTIONS)
    if upx_secs:
        ev.append("节名命中 UPX 打包节: %s" % ",".join(upx_secs))
    upx_hits = []
    start = 0
    while len(upx_hits) < 8:
        off = data.find(b"UPX!", start)
        if off == -1:
            break
        upx_hits.append(off)
        start = off + 1
    if upx_hits:
        ev.append("文件偏移 %s 处发现 UPX! 魔数（共 %d 处）"
                  % (", ".join("0x%x" % o for o in upx_hits[:4]), len(upx_hits)))
    for e in (extra_evidence or []):
        ev.append(e)
    if len(ev) >= 2:
        return {"name": "upx", "confidence": 0.95, "evidence": ev}

    hints = []
    for nm in sec_names:
        hit = PACKER_SECTION_HINTS.get(nm.lower())
        if hit and hit[0] not in [h[0] for h in hints]:
            hints.append(hit)
    if hints:
        return {"name": hints[0][0], "confidence": 0.3, "hint": True,
                "evidence": [h[1] for h in hints]}
    if ev:
        return {"name": "unknown", "confidence": 0.4, "evidence": ev}
    return {"name": "none", "confidence": 0.9,
            "evidence": ["无 UPX0/UPX1/UPX2/UPX3 节名",
                         "文件中不存在 UPX! 魔数",
                         "无已知壳节名线索"]}


# ── 编译器指纹 ────────────────────────────────────────────────

def _unknown(reason):
    return {"family": "unknown", "version": None, "confidence": 0.2,
            "evidence": [reason]}


def elf_compiler(data, secmap):
    names = set(secmap)
    go_secs = sorted(n for n in names
                     if n == ".go.buildinfo" or n == ".note.go.buildid"
                     or "gopclntab" in n)
    if go_secs:
        ev = ["Go 专有节: %s" % ",".join(go_secs)]
        ver = None
        if ".go.buildinfo" in secmap:
            off, size = secmap[".go.buildinfo"]
            m = GO_VERSION_RE.search(data[off:off + size])
            if m:
                ver = m.group(0).decode()[2:]  # 去掉 "go" 前缀，与 gcc/msvc 版本口径一致
                ev.append(".go.buildinfo 内含版本串 go%s" % ver)
        return {"family": "go", "version": ver,
                "confidence": 0.9 if ver else 0.8, "evidence": ev}

    comment = b""
    if ".comment" in secmap:
        off, size = secmap[".comment"]
        comment = data[off:off + size]
    m = RUSTC_COMMENT_RE.search(comment)
    if m:
        return {"family": "rust", "version": m.group(1).decode(),
                "confidence": 0.9,
                "evidence": [".comment 含 rustc 版本串: %s" % m.group(0).decode()]}
    m = GCC_COMMENT_RE.search(comment)
    if m:
        return {"family": "gcc", "version": m.group(2).decode(),
                "confidence": 0.95,
                "evidence": [".comment 含 GCC 标识: %s" % m.group(0).decode().strip(),
                             "宿主串: %s" % m.group(1).decode()]}
    if comment:
        return _unknown("有 .comment 但无 GCC/rustc 标识: %r"
                        % comment.split(b"\x00")[0][:60])
    return _unknown("节表中无 .comment（strip 后不可判定，禁止猜测）")


def pe_compiler(data, sec_names, rich):
    if b"Go buildinf:" in data:
        ev = ["数据段含 Go buildinf 魔数"]
        m = GO_VERSION_RE.search(data)
        ver = m.group(0).decode()[2:] if m else None
        if ver:
            ev.append("版本串 go%s" % ver)
        if any(n.startswith("/") for n in sec_names):
            ev.append("COFF 长节名 /nn 形态（Go 链接器特征）")
        return {"family": "go", "version": ver,
                "confidence": 0.9 if ver else 0.8, "evidence": ev}

    rust_ev = []
    if b"rustc" in data:
        rust_ev.append("含 rustc 路径串")
    if b"rustlib" in data or b"library/std" in data or b"library\\std" in data:
        rust_ev.append("含 rustlib / library/std 路径")
    if len(rust_ev) >= 2 or (rust_ev and b"\\rustc\\" in data):
        ver = None
        m = RUST_TOOLCHAIN_RE.search(data)
        if m:
            ver = m.group(1).decode()
            rust_ev.append("toolchains/<ver>-x86_64 版本串 %s" % ver)
        m = RUSTC_COMMIT_RE.search(data)
        if m:
            rust_ev.append("rustc/<commit> 提交号 %s…" % m.group(1).decode()[:12])
        if ver is None:
            rust_ev.append("rustc 默认不嵌版本号（仅 commit），version 维度记 None")
        return {"family": "rust", "version": ver, "confidence": 0.85,
                "evidence": rust_ev}

    if rich is not None:
        # Rich 头的 comp.id 里不同工具（cl/link/cvtres/masm）各占一项，
        # build 号并不唯一。规则：只承认版本表内的 build，取"实例数最多"的那个，
        # 并把全部 build 列进证据，避免拿最大值瞎猜（cli-64.exe 的 32532 不在表内）。
        builds = [(cnt, cid & 0xFFFF) for (cid, cnt) in rich["pairs"]]
        known = [(cnt, b) for (cnt, b) in builds if b in MSVC_BUILD_VERSION]
        known.sort(reverse=True)
        all_builds = sorted({b for (_cnt, b) in builds if b})
        if known:
            cnt, build = known[0]
            ver = MSVC_BUILD_VERSION[build]
            ev = ["Rich 头 %d 对（key=0x%08X）" % (len(rich["pairs"]), rich["key"]),
                  "已映射 build=%d（实例数 %d）→ MSVC %s" % (build, cnt, ver),
                  "全部 build: %s" % ",".join(str(b) for b in all_builds)]
            return {"family": "msvc", "version": ver, "confidence": 0.9,
                    "evidence": ev}
        ev = ["Rich 头 %d 对（key=0x%08X）" % (len(rich["pairs"]), rich["key"]),
              "build 均不在已知映射表: %s" % ",".join(str(b) for b in all_builds)]
        return {"family": "msvc", "version": None, "confidence": 0.75,
                "evidence": ev}

    return _unknown("无 Rich 头、无 Go/Rust 指纹（自构造或非主流工具链，禁止猜测）")


# ── 分析主函数 ────────────────────────────────────────────────

def _elf_analyze(path, data):
    # UPX 打包 ELF 会把节表整个移除（e_shnum=e_shoff=0），elf.parse 依赖节表会失败。
    # 因此先取头部结构性证据，再决定是否降级输出。
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    structural = []
    if e_shnum == 0 and e_shoff == 0:
        structural.append("ELF 节表被移除（e_shnum=0, e_shoff=0）")
    try:
        r = elf.parse(path)
    except Exception as exc:
        packer = detect_packer(data, [], structural)
        if packer["name"] != "upx":
            raise
        return {"format": "ELF",
                "packer": packer,
                "compiler": _unknown("加壳后 .comment/符号表已被压缩，静态不可判定（禁止猜测）"),
                "stripped": "unknown",
                "mitigations": {"nx": "unknown", "relro": "unknown",
                                "pie": "unknown", "bind_now": "unknown",
                                "wx_segments": [],
                                "note": "加壳态不可靠，须先脱壳再判"},
                "evidence": ["EP: ELF 结构解析降级（%s: %s）"
                             % (type(exc).__name__, exc)]
                            + ["packer: " + e for e in packer["evidence"]]}
    secmap = {nm: (off, size) for (nm, _t, _a, off, size) in r["sections"]}
    names = list(secmap)
    sec = r["security"]
    stripped = ".symtab" not in secmap
    packer = detect_packer(data, names, structural)
    compiler = elf_compiler(data, secmap)
    mitigations = {"nx": sec["nx"], "relro": sec["relro"], "pie": sec["pie"],
                   "bind_now": sec["bind_now"],
                   "wx_segments": sec["wx_segments"]}
    evidence = (["EP: format=ELF%d" % (64 if data[4] == 2 else 32),
                 "packer: " + "; ".join(packer["evidence"])]
                + ["compiler: " + e for e in compiler["evidence"]]
                + ["stripped: " + ("无 .symtab 节" if stripped else "存在 .symtab 节")])
    return {"format": "ELF", "packer": packer, "compiler": compiler,
            "stripped": stripped, "mitigations": mitigations,
            "evidence": evidence}


def _pe_analyze(path, data):
    r = pe.parse(path)
    sec_names = [nm for (_va, _vs, _rp, _rs, nm) in r["sections"]]
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    ptr_symtab = struct.unpack_from("<I", data, e_lfanew + 12)[0]
    num_symbols = struct.unpack_from("<I", data, e_lfanew + 16)[0]
    coff = "present" if (ptr_symtab and num_symbols) else "absent"
    # 注意：pe.parse 的 "chars" 是 COFF Characteristics，不是 DllCharacteristics。
    # DllCharacteristics 在 OptionalHeader 偏移 70（PE32/PE32+ 同偏移），单独取。
    dll_chars = struct.unpack_from("<H", data, e_lfanew + 24 + 70)[0]
    packer = detect_packer(data, sec_names)
    compiler = pe_compiler(data, sec_names, r["rich"])
    mitigations = {k: bool(dll_chars & bit) for k, bit in DLLCHAR.items()}
    mitigations["dll_characteristics"] = "0x%04X" % dll_chars
    evidence = (["EP: format=PE%s" % ("32+" if r["magic"] == 0x20B else "32"),
                 "packer: " + "; ".join(packer["evidence"])]
                + ["compiler: " + e for e in compiler["evidence"]]
                + ["COFF 符号表: %s (ptr=0x%x n=%d)" % (coff, ptr_symtab, num_symbols)])
    return {"format": "PE", "packer": packer, "compiler": compiler,
            "stripped": "n/a", "coff_symbols": coff,
            "mitigations": mitigations, "evidence": evidence}


def analyze(path, fmt=None):
    """指纹分析的唯一入口；返回固定 6 键 + PE 附加 coff_symbols。"""
    data = open(path, "rb").read()
    fmt = fmt or detect_format(path)
    if fmt == "elf":
        return _elf_analyze(path, data)
    if fmt == "pe":
        return _pe_analyze(path, data)
    raise ValueError("无法识别的格式（非 ELF / 非 PE）: %s" % path)


# ── CLI ───────────────────────────────────────────────────────

def render_text(path, fp):
    lines = ["Fingerprint: %s" % path,
             "Format:      %s" % fp["format"],
             "Packer:      %s (confidence %.2f)"
             % (fp["packer"]["name"], fp["packer"]["confidence"]),
             "Compiler:    %s%s (confidence %.2f)"
             % (fp["compiler"]["family"],
                " " + fp["compiler"]["version"] if fp["compiler"]["version"] else "",
                fp["compiler"]["confidence"])]
    if fp["format"] == "ELF":
        m = fp["mitigations"]
        st = fp["stripped"]
        lines.append("Stripped:    %s" % (st if isinstance(st, str)
                                          else ("yes" if st else "no")))
        lines.append("Mitigations: NX %s | RELRO %s | PIE %s | W+X %s"
                     % (m["nx"], m["relro"], m["pie"],
                        ",".join(m["wx_segments"]) or "none"))
    else:
        m = fp["mitigations"]
        lines.append("COFF syms:   %s（PE 不适用 stripped 语义）" % fp["coff_symbols"])
        lines.append("Mitigations: NX %s | ASLR %s | HighEntropyVA %s | CFG %s | DllChar %s"
                     % (m["nx"], m["dynamicbase"], m["high_entropy_va"],
                        m["cfg"], m["dll_characteristics"]))
    lines.append("Evidence:")
    for e in fp["evidence"]:
        lines.append("  - %s" % e)
    return "\n".join(lines)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    ap = argparse.ArgumentParser(
        prog="rekit.cli fingerprint",
        description="指纹层：壳 / 编译器 / stripped / 加固（净室观察法）")
    ap.add_argument("file", help="待分析文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    args = ap.parse_args(argv)

    if not os.path.exists(args.file):
        print("rekit: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        fmt = detect_format(args.file)
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    if fmt is None:
        print("rekit: %s: 无法识别的格式（非 ELF / 非 PE）" % args.file,
              file=sys.stderr)
        return 2
    try:
        fp = analyze(args.file, fmt)
    except Exception as e:
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(fp, ensure_ascii=False, indent=2))
    else:
        print(render_text(args.file, fp))
    return 0


if __name__ == "__main__":
    sys.exit(main())
