#!/usr/bin/env python3
# rekit.gopclntab — Go 运行时函数表（pclntab / .gopclntab）解析
#
# 性质（M11 定级）：这是 Go 链接器写入二进制的**运行时必需表**，不是调试信息。
#   · runtime 用它做 PC→函数/行号/栈展开查询；删掉它程序无法运行；
#   · stripped（`-s -w`）只去掉 .symtab/.debug_*，不会去掉 pclntab；
#   · 因此它属于 declared 级证据：函数入口/结束由链接器写死，不是字节模式猜测。
#   但它**只覆盖 Go 函数**：汇编 stub、C 代码、外部目标文件的函数不一定在内。
#
# 版本与字段差异（只实现能验证的；其余一律 status="unknown"，不猜）：
#   magic 0xFFFFFFF1  go1.20+（当前实测 go1.27.3）
#                     header: nfunc,nfiles,textStart,funcname,cu,filetab,pctab,
#                             pcln（后五项为偏移，均 uintptr）
#                     functab: (2*nfunc+1) 个 uint32 字段，即 nfunc 条
#                             {entryoff,funcoff} + 1 个 endoff 哨兵
#                     entry VA = textStart + entryoff；_func.entry 为 uint32 偏移
#                     funcoff 相对 pclnOffset（funcdata 紧随 functab 之后）
#   magic 0xFFFFFFF0  go1.18–1.19，布局同上（**无实测样本**，按规范同构实现，
#                     未经 debug/gosym 对拍；命中时返回值带"未验证"warning）
#   magic 0xFFFFFFFA  go1.16–1.17，header 无 textStart；functab 字段宽 ptrSize，
#                     entry 为绝对 VA；_func 首字段是 uintptr entry（nameOff 在 +ptrSize）
#                     （**无实测样本**，同上按未验证处理）
#   magic 0xFFFFFFFB  go1.2–1.15 旧布局：**未实现**，返回 unknown
#
# header 的 textStart 字段可能未重定位（本机 go1.27.3 实测为 0）。
#   Go 官方 debug/gosym 的做法是「不读该字段，用调用方给出的 text 起点」
#   （pclntab.go:261 "use the start PC instead of reading from the table,
#    which may be unrelocated"）。本模块同此：0 或不在 .text 内 → 取 .text 基址
#   并写 warning；这是与官方一致的行为，不是猜。
#
# 定位方式：
#   ELF: 节名 `.gopclntab`（缺失时按 magic 扫描）
#   PE : 表在 .rdata 内无独立节名，按 magic 扫描（多候选逐个整表校验）
#
# 校验（任何一条不成立 → 该候选整表不采用，绝不半信半疑）：
#   1) pad=0、ptrSize∈{4,8}；2) nfunc∈[1,2e6]；3) 偏移链单调且不越界；
#   4) functab 含 nfunc+1 条且不越界；5) 入口严格递增且落在 .text 内；
#   6) funcoff（相对 pclnOffset）落在 functab 之后、表内；
#   7) 末条哨兵 entry 大于最后一个入口且不超过 .text 末尾。
import struct
import sys

MAGIC_GO120 = 0xFFFFFFF1
MAGIC_GO118 = 0xFFFFFFF0
MAGIC_GO116 = 0xFFFFFFFA
MAGIC_GO12 = 0xFFFFFFFB

SUPPORT = {
    MAGIC_GO120: {"version": "go1.20+", "header": "with_textstart", "functab": "u32off"},
    MAGIC_GO118: {"version": "go1.18-1.19", "header": "with_textstart", "functab": "u32off"},
    MAGIC_GO116: {"version": "go1.16-1.17", "header": "no_textstart", "functab": "ptr"},
}
UNSUPPORTED = {
    MAGIC_GO12: "go1.2-1.15 旧布局（functab 紧接 header、无 funcnametab 偏移语义），未实现",
}

CAVEATS = [
    "gopclntab 是 Go 链接器产出的运行时必需表（declared 级），不是调试信息，stripped 也不会移除",
    "只覆盖 Go 函数：汇编 stub、C 代码、外部目标文件的函数不保证在内，缺失不等于不存在",
    "版本支持：go1.20+ 有 go1.27.3 实测并与 debug/gosym 对拍通过；go1.16–1.19 分支"
    "按规范实现但无样本对拍（结果带未验证 warning）；go1.2–1.15 与未知 magic 返回 unknown，不猜",
    "header.textStart 可能未重定位（go1.27.3 实测为 0）：与 Go 官方 gosym 一致改用 .text 基址并记 warning",
    "entry/end 仅在整表校验通过时采用；任一入口不落在 .text 或表越界 → 该候选整表 unknown",
    "funcoff 相对 pclnOffset（Go 1.18+ funcdata 紧随 functab），不是相对文件/节起点",
    "表内含链接器标记 go:buildid / go:textfipsstart / go:textfipsend：不是函数，"
    "以 is_marker 标出，接入时应排除并单列计数（type:.eq/.hash 与 go:struct{}.X 是真代码）",
]

_MAX_FUNC = 2_000_000
# 链接器写入的「非代码标记」：在表内有条目，但内容不是函数代码。
#   go:buildid       PE 把 build id 数据放在 .text 开头（占位数据，不可当指令解）
#   go:textfipsstart FIPS 代码区间起点标记（零长，区间=到下一入口的对齐填充）
#   go:textfipsend   FIPS 代码区间终点标记（零长）
# type:.eq.* / type:.hash.* 与 go:struct{...}.* 是编译器/链接器**生成的真实代码**，
# 不是标记，仍然作为函数。
_MARKERS = {"go:buildid", "go:textfipsstart", "go:textfipsend"}
_MAGIC_BYTES = ((MAGIC_GO120, b"\xf1\xff\xff\xff"),
                (MAGIC_GO118, b"\xf0\xff\xff\xff"),
                (MAGIC_GO116, b"\xfa\xff\xff\xff"),
                (MAGIC_GO12, b"\xfb\xff\xff\xff"))
_MAX_CANDIDATES_PER_MAGIC = 128


def _u(blob, off, size):
    if size == 8:
        return struct.unpack_from("<Q", blob, off)[0]
    return struct.unpack_from("<I", blob, off)[0]


def _cstr(blob, off, limit):
    if off < 0 or off >= limit:
        return None
    end = blob.find(b"\x00", off, limit)
    if end < 0:
        return None
    try:
        return blob[off:end].decode("utf-8", "replace")
    except Exception:
        return None


def _header_sane(blob):
    """粗筛：只用来在多候选里挑「像真表」的那个来报错，不参与结论。"""
    if len(blob) < 16:
        return False
    magic = struct.unpack_from("<I", blob, 0)[0]
    return (magic in SUPPORT or magic in UNSUPPORTED) and \
        blob[4] == 0 and blob[5] == 0 and blob[7] in (4, 8)


def _parse_blob(blob, text_lo, text_hi, warnings, where):
    """blob 从 pcHeader magic 开始。返回 (result, None) 或 (None, reason)。"""
    if len(blob) < 16:
        return None, "表长度不足 16 字节"
    magic = struct.unpack_from("<I", blob, 0)[0]
    pad1, pad2, _min_lc, ptr_size = blob[4], blob[5], blob[6], blob[7]
    if pad1 or pad2:
        return None, "pcHeader.pad 非 0（0x%02x,0x%02x）" % (pad1, pad2)
    if ptr_size not in (4, 8):
        return None, "pcHeader.ptrSize=%d 不是 4/8" % ptr_size
    if magic in UNSUPPORTED:
        return None, "magic 0x%08x：%s" % (magic, UNSUPPORTED[magic])
    if magic not in SUPPORT:
        return None, "未知 magic 0x%08x（支持 0x%08x/0x%08x/0x%08x）" % (
            magic, MAGIC_GO120, MAGIC_GO118, MAGIC_GO116)
    spec = SUPPORT[magic]
    if magic != MAGIC_GO120:
        warnings.append("%s 版式按规范同构实现，本仓库无该版本实测样本、"
                        "未经 debug/gosym 对拍，结论按未验证处理" % spec["version"])

    p = 8
    nfunc = _u(blob, p, ptr_size); p += ptr_size
    nfiles = _u(blob, p, ptr_size); p += ptr_size
    text_start = 0
    if spec["header"] == "with_textstart":
        text_start = _u(blob, p, ptr_size); p += ptr_size
    fn_off = _u(blob, p, ptr_size); p += ptr_size
    cu_off = _u(blob, p, ptr_size); p += ptr_size
    ft_off = _u(blob, p, ptr_size); p += ptr_size
    pc_off = _u(blob, p, ptr_size); p += ptr_size
    pcln_off = _u(blob, p, ptr_size); p += ptr_size

    if not (1 <= nfunc <= _MAX_FUNC):
        return None, "nfunc=%d 超出合理范围" % nfunc
    if not (0 <= fn_off <= cu_off <= ft_off <= pc_off <= pcln_off < len(blob)):
        return None, "表偏移不满足 0<=funcname<=cu<=filetab<=pctab<=pcln<len"
    if text_start and not (text_lo <= text_start < text_hi):
        return None, "pcHeader.textStart=0x%x 不在 .text [0x%x,0x%x)" % (
            text_start, text_lo, text_hi)
    if not text_start:
        warnings.append("pcHeader.textStart=0（未重定位）；与 Go 官方 gosym 一致，"
                        "采用 .text 基址 0x%x" % text_lo)
        text_start = text_lo

    fsize = 4 if spec["functab"] == "u32off" else ptr_size
    fields = 2 * nfunc + 1                     # nfunc 条 {entry,funcoff} + 1 哨兵
    fb_len = fields * fsize
    if pcln_off + fb_len > len(blob):
        return None, "functab 越界：nfunc=%d fsize=%d 需 %d 字节，仅剩 %d" % (
            nfunc, fsize, fb_len, len(blob) - pcln_off)

    def _field(i):
        return _u(blob, pcln_off + i * fsize, fsize)

    funcs = []
    prev = None
    for i in range(nfunc):
        entryoff = _field(2 * i)
        funcoff = _field(2 * i + 1)
        entry = text_start + entryoff if spec["functab"] == "u32off" else entryoff
        if prev is not None and entry <= prev:
            return None, "第 %d 个入口 0x%x 未严格大于前一个 0x%x" % (i, entry, prev)
        prev = entry
        if not (text_lo <= entry < text_hi):
            return None, "第 %d 个入口 0x%x 不在 .text [0x%x,0x%x)" % (
                i, entry, text_lo, text_hi)
        if not (fb_len <= funcoff < len(blob) - pcln_off):
            return None, "第 %d 个 funcoff=0x%x 越界（应落在 [0x%x,0x%x)）" % (
                i, funcoff, fb_len, len(blob) - pcln_off)
        func_off = pcln_off + funcoff
        name_field = 4 if spec["functab"] == "u32off" else ptr_size
        if func_off + name_field + 4 > len(blob):
            return None, "第 %d 个 _func@0x%x 越界" % (i, func_off)
        name_off = struct.unpack_from("<I", blob, func_off + name_field)[0]
        # nameOff=0 合法：指向 funcnametab 首个名字（Go 官方 gosym 也是无条件查表）
        name = _cstr(blob, fn_off + name_off, cu_off) if name_off < cu_off - fn_off else None
        funcs.append({"entry": entry, "funcoff": funcoff, "func_off": func_off,
                      "name": name or "sub_%x" % entry, "name_ok": name is not None,
                      "is_marker": name in _MARKERS})

    sentinel = _field(2 * nfunc)
    text_end = text_start + sentinel if spec["functab"] == "u32off" else sentinel
    if sentinel and not (prev < text_end <= text_hi):
        return None, "末条哨兵 entry=0x%x 不在 (0x%x,0x%x]" % (
            text_end, prev, text_hi)

    # 结束地址：下一条入口；最后一条用表内哨兵（不是 .text 节末尾，二者相差对齐填充）
    for i, f in enumerate(funcs):
        f["end"] = funcs[i + 1]["entry"] if i + 1 < len(funcs) else text_end
    if funcs and funcs[-1]["end"] <= funcs[-1]["entry"]:
        return None, "末条 end=0x%x 不大于 entry=0x%x" % (
            funcs[-1]["end"], funcs[-1]["entry"])

    names_bad = sum(1 for f in funcs if not f["name_ok"])
    markers = sum(1 for f in funcs if f["is_marker"])
    if names_bad:
        warnings.append("%d 个函数名解析失败，已回退为 sub_<addr>" % names_bad)
    if markers:
        warnings.append("%d 条链接器标记（go:buildid/textfips*）不是函数，"
                        "应作为 marker 排除" % markers)
    return {
        "status": "ok",
        "reason": None,
        "magic": magic,
        "version": spec["version"],
        "ptr_size": ptr_size,
        "text_start": text_start,
        "text_end": text_end,
        "nfunc": nfunc,
        "nfiles": nfiles,
        "n_markers": markers,
        "funcs": funcs,
        "warnings": warnings,
        "where": where,
    }, None


def _elf_text_range(data):
    from . import elf
    shs = elf.section_headers(data)
    text = next((s for s in shs if s["name"] == ".text" and s["size"] > 0), None)
    if text is None:
        return None, None
    return (text["addr"], text["addr"] + text["size"]), \
        next((s for s in shs if s["name"] in (".gopclntab", ".data.rel.ro.gopclntab")
              and s["size"] > 0), None)


def _pe_text_range(data):
    from . import pe
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp()
    try:
        os.write(fd, data)
        os.close(fd)
        r = pe.parse(tmp)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    base = r["image_base"]
    text = next((s for s in r["sections"] if s[4] == ".text" and s[1] > 0), None)
    if text is None:
        return None, None
    lo = base + text[0]
    return (lo, lo + max(text[1], text[3])), None


def _scan_candidates(data):
    """按文件偏移返回候选 magic 命中 (off, magic)，供逐个整表校验。

    每种 magic 单独限额：若全局限额，普通二进制里大量 0xfb 假命中会把真正的
    0xf1 表挤掉（go1.20+ 的 magic 先扫，但也要保证后面的版本有机会）。
    """
    hits = []
    for magic, mb in _MAGIC_BYTES:
        start = n = 0
        while n < _MAX_CANDIDATES_PER_MAGIC:
            i = data.find(mb, start)
            if i < 0:
                break
            hits.append((i, magic))
            start = i + 1
            n += 1
    hits.sort()
    return hits


def parse(path):
    """解析 path 的 Go pclntab。返回 dict；失败时 status ∈ {"missing","unknown"}。"""
    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        trange, tab = _elf_text_range(data)
    elif data[:2] == b"MZ":
        trange, tab = _pe_text_range(data)
    else:
        return {"status": "missing", "reason": "非 ELF/PE", "funcs": [],
                "warnings": [], "version": None, "magic": None, "nfunc": 0}
    if trange is None:
        return {"status": "missing", "reason": "找不到 .text 节", "funcs": [],
                "warnings": [], "version": None, "magic": None, "nfunc": 0}

    attempts = []
    if tab is not None:                                  # ELF 有独立节名：优先
        attempts.append((tab["offset"], tab["size"],
                         "elf_section:%s" % tab["name"]))
    seen = {a[0] for a in attempts}
    for off, _magic in _scan_candidates(data):
        if off not in seen:
            attempts.append((off, len(data) - off, "magic_scan@0x%x" % off))
            seen.add(off)
    if not attempts:
        return {"status": "missing", "reason": "找不到 pcHeader magic",
                "funcs": [], "warnings": [], "version": None, "magic": None,
                "nfunc": 0, "text_range": trange}

    errors = []
    for off, size, where in attempts:
        blob = data[off:off + size]
        warnings = []
        res, err = _parse_blob(blob, trange[0], trange[1], warnings, where)
        if res is not None:
            res["file_offset"] = off
            res["text_range"] = trange
            return res
        errors.append((where, err, _header_sane(blob), blob[:4]))

    # 全部候选失败：区分「没有可信表」与「表在但结构不合法」。
    #   · 无任何候选通过 pad/ptrSize 粗筛 → missing（普通 C/C++/Rust 二进制的
    #     随机 magic 命中，不能算 unknown，否则等于暗示这里可能有一张破损的 Go 表）
    #   · 有粗筛通过的候选 → unknown，并用它的具体错误解释（不猜、不半信）
    sane = [e for e in errors if e[2]]
    if not sane:
        return {"status": "missing",
                "reason": "%d 个 magic 命中均未通过 pcHeader 粗筛（pad/ptrSize）"
                          % len(errors),
                "funcs": [], "warnings": [], "version": None, "magic": None,
                "nfunc": 0, "candidates": len(errors), "text_range": trange}
    best = sane[0]
    magic = struct.unpack_from("<I", best[3], 0)[0] if len(best[3]) == 4 else None
    return {"status": "unknown", "reason": best[1], "funcs": [],
            "warnings": [], "version": None, "magic": magic, "nfunc": 0,
            "where": best[0], "text_range": trange,
            "candidates": len(errors)}


if __name__ == "__main__":
    for p in sys.argv[1:]:
        r = parse(p)
        print(p, r["status"], r.get("version"), r.get("nfunc"),
              r.get("reason"), r.get("warnings"))
