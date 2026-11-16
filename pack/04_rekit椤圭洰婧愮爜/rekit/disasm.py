#!/usr/bin/env python3
# rekit.disasm — x86-64 线性扫描（M4 首日子单元：只解【指令边界】，不解助记符）
#
# 为什么只做边界：
#   边界（起始地址 + 长度）是可被外部工具逐条核对的硬事实；助记符/操作数是
#   另一层语义，混在一起会让"边界错了"被"文本看起来像"掩盖。M3 的教训是
#   先把可证伪的那一层做干净（R38：用原件字节证明，而不是"看起来对"）。
#
# 边界判据（与 objdump -d 对拍时逐条比 addr + length）：
#   - 长度只由字节规则决定：legacy 前缀 → REX → opcode（1/2/3 字节映射）
#     → ModRM/SIB/disp → imm；
#   - 表外/未实现（VEX C4|C5、EVEX 0x62、非法单字节 opcode）一律返回
#     status="unsupported" 并【停止】，绝不猜一个长度让整条链悄悄错位。
#
# 线性扫描的已知盲区（也写在 CAVEATS 里，CLI 会打印）：
#   1) 无法区分代码与数据：跳转表、对齐填充（0xCC/0x90）、内联字面量都会被当指令；
#   2) 不跟踪跳转，不做递归下降：函数之间的交错数据区照扫不误；
#   3) 不支持 VEX/EVEX（AVX/AVX-512）→ abstain 停止，所以含 AVX 的函数扫不到底；
#   4) x87/3DNow 只按长度表计长，不校验语义；
#   5) 前缀序列超过 15 字节的非法编码不单独报错（按表继续）。
import json
import struct
import sys

CAVEATS = [
    "线性扫描无法区分代码与数据：跳转表/对齐填充/内联字面量会被当作指令",
    "不跟踪跳转、不做递归下降：函数尾部的交错数据区会被继续当作指令",
    "VEX/EVEX（AVX/AVX-512）已按前缀+map+ModRM/SIB/disp+imm 计长，但仍不解助记符；"
    "保留位非法的伪 VEX/EVEX 编码一律 abstain（不猜长度）",
    "x87/3DNow 仅按长度表计长，不校验语义",
    "超过 15 字节的非法前缀序列不单独报错（按表继续）",
]

_LEGACY_PREFIX = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65,
                  0x66, 0x67, 0xF0, 0xF2, 0xF3}

# 单字节映射：无 ModRM 的合法指令
_NO_MODRM_1 = (set(range(0x50, 0x60)) | set(range(0x90, 0x9A)) |
               {0x9B, 0x9C, 0x9D, 0x9E, 0x9F} |
               set(range(0x6C, 0x70)) | set(range(0xA4, 0xA8)) |
               set(range(0xAA, 0xB0)) |
               {0xC3, 0xC9, 0xCB, 0xCC, 0xCF, 0xD7,
                0xF1, 0xF4, 0xF5} | set(range(0xF8, 0xFE)) |
               set(range(0xEC, 0xF0)))

# 64 位模式下非法（objdump 会印 (bad)）：不猜长度，abstain
_INVALID_1 = {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F,
              0x27, 0x2F, 0x37, 0x3F, 0x60, 0x61, 0x82, 0x9A,
              0xCE, 0xD4, 0xD5, 0xD6, 0xEA}

# 立即数族：有/无 ModRM 必须分开（0xB8+r 与 0x04 这类根本没有 ModRM 字节）
_NO_MODRM_IMM8 = ({0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C,
                   0x6A, 0xA8, 0xCD, 0xE4, 0xE5, 0xE6, 0xE7} |
                  set(range(0xB0, 0xB8)))
_NO_MODRM_IMM_OSZ = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D,
                     0x68, 0xA9}
_MODRM_IMM8 = {0x6B, 0x80, 0x83, 0xC0, 0xC1, 0xC6}
_MODRM_IMM_OSZ = {0x69, 0x81, 0xC7}
_MOFFS_1 = {0xA0, 0xA1, 0xA2, 0xA3}
_REL8_1 = set(range(0x70, 0x80)) | {0xEB, 0xE0, 0xE1, 0xE2, 0xE3}
_REL32_1 = {0xE8, 0xE9}

# 两字节映射（0F xx）：无 ModRM 的合法指令
# 0F C8..CF = BSWAP r32/r64：无 ModRM，REX.B 只扩寄存器号（实测 bin_ls 0x101ec
# 的 `41 0f cb` = bswap r11d，漏掉后会被当 ModRM 多吃 1 字节）
_NO_MODRM_2 = {0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E,
               0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
               0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA} | set(range(0xC8, 0xD0))
_IMM8_2 = {0x0F, 0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC,
           0xBA, 0xC2, 0xC4, 0xC5, 0xC6}
_REL32_2 = set(range(0x80, 0x90))
# 0F 78/79：66 前缀才是 imm8（EXTRQ/INSERTQ），否则是 VMREAD/VMWRITE（无 imm）
_COND_IMM8_2 = {0x78, 0x79}

# ── VEX / EVEX（M5 第一单元补表） ──────────────────────────────────────
# 长度仍只由字节规则决定：前缀长度 + opcode + ModRM/SIB/disp + imm。
# 前缀形态：
#   VEX2  C5 | R vvvv L pp        map 隐含 0F
#   VEX3  C4 | R X B mmmmm | W vvvv L pp
#   EVEX  62 | R X B R' 0 0 mm | W vvvv 1 pp | z L'L b V' aaa
# 立即数规则：map=0F3A 一律 imm8；map=0F38 无 imm8；map=0F 仅下列 opcode 带 imm8。
# VEX3 两个 payload 字节的每一位都有定义（R X B mmmmm / W vvvv L pp），没有保留位；
# EVEX 的 P0[3:2] 必须为 0、P1[2] 必须为 1，否则是伪 EVEX（多半是数据）→ abstain
# 停止，绝不按"看起来像 AVX"硬解长度。
_VEX_IMM8_0F = {0xC2, 0xC4, 0xC5, 0xC6, 0x70, 0x71, 0x72, 0x73}
_VEX_NO_MODRM_0F = {0x77}          # vzeroupper / vzeroall
_VEX_MAP = {1: 0x0F, 2: 0x38, 3: 0x3A}


class Unsupported(Exception):
    """解码器主动弃权。category 供 M9 逐条归因，不允许只留一句 abstain。

    category 的取值与含义（都是“在这个位置不猜长度”的原因，不是结论）：
      truncated          所需字节越界/截断（可能到节尾，也可能本来就落在数据里）
      prefix_over_15     legacy 前缀累计超过 15 字节（x86 上限，编码非法）
      vex_legacy_prefix  VEX/EVEX 前出现 legacy/REX 前缀（编码非法）
      vex_map_undefined  VEX3 mmmmm 不在 {1,2,3}（编码非法）
      evex_reserved      EVEX P0[3:2]≠0 或 P1[2]=0（伪 EVEX/编码非法）
      evex_map0          EVEX map=0（编码非法）
      invalid_opcode     64 位模式下的非法单字节 opcode（objdump 印 (bad)）
    """

    def __init__(self, reason, category="other"):
        Exception.__init__(self, reason)
        self.reason = reason
        self.category = category


def _need(pos, n, end):
    if pos + n > end:
        raise Unsupported("越界：需要 %d 字节，只剩 %d" % (n, end - pos),
                          "truncated")


def _modrm_len(data, pos, end):
    """返回 ModRM(+SIB+disp) 占用的字节数；disp 越界在这里就报，不留半截长度。"""
    _need(pos, 1, end)
    m = data[pos]
    mod, rm = m >> 6, m & 7
    n = 1
    if mod == 3:
        return n
    if rm == 4:                       # SIB
        _need(pos + 1, 1, end)
        sib = data[pos + 1]
        n += 1
        base = sib & 7
        if mod == 0 and base == 5:
            _need(pos + n, 4, end)
            n += 4
        elif mod == 1:
            _need(pos + n, 1, end)
            n += 1
        elif mod == 2:
            _need(pos + n, 4, end)
            n += 4
        return n
    if mod == 0 and rm == 5:          # RIP+disp32
        _need(pos + n, 4, end)
        n += 4
    elif mod == 1:
        _need(pos + n, 1, end)
        n += 1
    elif mod == 2:
        _need(pos + n, 4, end)
        n += 4
    return n


def sweep_bytes(data, file_off, base_va, size, limit=None,
                model=None, section=None):
    """从 (file_off, base_va) 起线性扫描 size 字节（可选 limit 上限）。

    model/section：M3 的映射模型（rekit.mapview.build）。给了就复用
    mapview.addr_to_off 为每条指令标注文件落点，并逐条核对它算出的 offset
    与本节算术 offset 是否一致——两套换算任何一条不一致都记入 map_mismatches，
    不静默取其一。

    返回 {"instructions": [...], "caveats": CAVEATS, "stopped": {...}|None,
          "map_stats": {...}|None, "map_mismatches": [...]}
    instructions[].status: ok | unsupported（unsupported 时 length=0，字节不消耗）
    instructions[].map: addr_to_off 的结果（无 model 时为 None）
    """
    if model is not None:
        from . import mapview
    limit = size if limit is None else min(size, limit)
    end = min(len(data), file_off + limit)
    out = []
    pos = file_off
    stopped = None
    map_stats, mismatches = None, []
    if model is not None:
        map_stats = {mapview.HIT: 0, mapview.NOT_IN_FILE: 0,
                     mapview.UNMAPPED: 0, mapview.MULTI: 0}
    while pos < end:
        va = base_va + (pos - file_off)
        try:
            ln, meta = _decode_any(data, pos, end)
        except Unsupported as e:
            stopped = {"addr": va, "off": pos, "reason": e.reason,
                       "category": e.category,
                       "bytes": data[pos:pos + 16].hex()}
            out.append({"addr": va, "off": pos, "length": 0,
                        "bytes": data[pos:pos + 1].hex(),
                        "status": "unsupported", "opcode_map": None,
                        "category": e.category,
                        "map": None})
            break
        if pos + ln > end:
            stopped = {"addr": va, "off": pos, "reason": "指令跨出扫描窗口",
                       "category": "truncated",
                       "bytes": data[pos:end].hex()}
            break
        mres = None
        if model is not None:
            mres = mapview.addr_to_off(model, va, section)
            map_stats[mres["status"]] = map_stats.get(mres["status"], 0) + 1
            if mres["status"] != mapview.HIT or mres["offset"] != pos:
                mismatches.append({"addr": va, "section_offset": pos,
                                   "status": mres["status"],
                                   "map_offset": mres.get("offset"),
                                   "unit": mres.get("unit")})
        out.append({"addr": va, "off": pos, "length": ln,
                    "bytes": data[pos:pos + ln].hex(" "),
                    "status": "ok", "opcode_map": meta.get("opcode_map"),
                    "map": mres})
        pos += ln
    return {"instructions": out, "caveats": list(CAVEATS),
            "bytes_scanned": pos - file_off, "stopped": stopped,
            "map_stats": map_stats, "map_mismatches": mismatches}


def _decode_any(data, pos, end):
    """带 group3（F6/F7）处理的长度解码。"""
    return _decode_full(data, pos, end)


def _vex_evex_len(data, pos, end, start, lead, meta):
    """VEX2/VEX3/EVEX 长度：前缀 + opcode + ModRM/SIB/disp + imm。

    只解长度，不解助记符。保留位不合法一律 Unsupported（伪 AVX 多半是数据）。
    """
    if lead == 0xC5:                       # VEX2：map 隐含 0F
        _need(pos, 1, end)
        pos += 1
        return _vex_body(data, pos, end, start, 0x0F, meta)
    if lead == 0xC4:                       # VEX3：mmmmm 选 map
        _need(pos, 2, end)
        b1 = data[pos]
        pos += 2
        mm = b1 & 0x1F
        if mm not in _VEX_MAP:
            raise Unsupported("VEX3 map=%d 未定义（非法编码）" % mm,
                              "vex_map_undefined")
        return _vex_body(data, pos, end, start, _VEX_MAP[mm], meta)
    _need(pos, 3, end)                     # EVEX：P0[1:0] 选 map
    p0, p1 = data[pos], data[pos + 1]
    pos += 3
    if p0 & 0x0C:
        raise Unsupported("EVEX P0[3:2] 保留位非 0（非法编码）", "evex_reserved")
    if not (p1 & 0x04):
        raise Unsupported("EVEX P1[2] 保留位=0（非法编码）", "evex_reserved")
    mm = p0 & 0x03
    if mm == 0:
        raise Unsupported("EVEX map=0 未定义（非法编码）", "evex_map0")
    return _vex_body(data, pos, end, start, _VEX_MAP[mm], meta, evex=True)


def _vex_body(data, pos, end, start, map_id, meta, evex=False):
    _need(pos, 1, end)
    op = data[pos]
    pos += 1
    meta["opcode"] = op
    meta["opcode_map"] = {0x0F: "vex:0f", 0x38: "vex:38", 0x3A: "vex:3a"}[map_id]
    # map=0F 的 77 是唯一无 ModRM 的 VEX 编码（vzeroupper/vzeroall）；EVEX 无此形态
    if map_id == 0x0F and op in _VEX_NO_MODRM_0F and not evex:
        return pos - start, meta
    pos += _modrm_len(data, pos, end)
    if map_id == 0x3A or (map_id == 0x0F and op in _VEX_IMM8_0F):
        _need(pos, 1, end)
        pos += 1
    return pos - start, meta


def _decode_full(data, pos, end):
    start = pos
    has66 = False
    addr_size_32 = False
    n_legacy = 0
    while pos < end and data[pos] in _LEGACY_PREFIX:
        b = data[pos]
        has66 = has66 or b == 0x66
        addr_size_32 = addr_size_32 or b == 0x67
        pos += 1
        n_legacy += 1
        if pos - start > 15:
            raise Unsupported("前缀超过 15 字节", "prefix_over_15")
    rex_w = False
    has_rex = False
    if pos < end and 0x40 <= data[pos] <= 0x4F:
        rex_w = bool(data[pos] & 0x08)
        has_rex = True
        pos += 1
    _need(pos, 1, end)
    op = data[pos]
    pos += 1
    meta = {"opcode": op, "opcode_map": 1}
    if op in (0xC4, 0xC5, 0x62):
        if n_legacy or has_rex:
            # VEX/EVEX 不允许前导 legacy/REX 前缀；出现即非法编码，不猜长度
            raise Unsupported("VEX/EVEX 前出现 legacy/REX 前缀（非法编码）",
                              "vex_legacy_prefix")
        return _vex_evex_len(data, pos, end, start, op, meta)
    if op == 0x0F:
        _need(pos, 1, end)
        op2 = data[pos]
        pos += 1
        meta = {"opcode": op2, "opcode_map": 2}
        if op2 in (0x38, 0x3A):
            _need(pos, 1, end)
            op3 = data[pos]
            pos += 1
            meta = {"opcode": op3,
                    "opcode_map": 0x3A if op2 == 0x3A else 0x38}
            pos += _modrm_len(data, pos, end)
            if op2 == 0x3A:
                _need(pos, 1, end)
                pos += 1
            return pos - start, meta
        if op2 in _NO_MODRM_2:
            return pos - start, meta
        if op2 in _REL32_2:
            _need(pos, 4, end)
            return pos + 4 - start, meta
        modrm_at = pos
        pos += _modrm_len(data, modrm_at, end)
        if op2 in _IMM8_2:
            _need(pos, 1, end)
            pos += 1
        elif op2 in _COND_IMM8_2 and has66:
            _need(pos, 1, end)
            pos += 1
        return pos - start, meta
    if op in _INVALID_1:
        raise Unsupported("64 位模式下的非法单字节 opcode 0x%02x" % op,
                          "invalid_opcode")
    if op in _NO_MODRM_1:
        return pos - start, meta
    if op in _MOFFS_1:
        _need(pos, 8 if not addr_size_32 else 4, end)
        return pos + (4 if addr_size_32 else 8) - start, meta
    if op in _REL8_1:
        _need(pos, 1, end)
        return pos + 1 - start, meta
    if op in _REL32_1:
        _need(pos, 4, end)
        return pos + 4 - start, meta
    if op in (0xC2, 0xCA):
        _need(pos, 2, end)
        return pos + 2 - start, meta
    if op == 0xC8:
        _need(pos, 3, end)
        return pos + 3 - start, meta
    # 无 ModRM 的立即数族：必须在读 ModRM 之前判（B8+r / 04 / A8 等没有 ModRM 字节）
    if op in _NO_MODRM_IMM8:
        _need(pos, 1, end)
        return pos + 1 - start, meta
    if op in _NO_MODRM_IMM_OSZ:
        n = 2 if has66 else 4
        _need(pos, n, end)
        return pos + n - start, meta
    if 0xB8 <= op <= 0xBF:
        n = 8 if rex_w else (2 if has66 else 4)
        _need(pos, n, end)
        return pos + n - start, meta
    modrm_at = pos
    pos += _modrm_len(data, modrm_at, end)
    if op in _MODRM_IMM8:
        _need(pos, 1, end)
        pos += 1
    elif op in _MODRM_IMM_OSZ:
        n = 2 if has66 else 4
        _need(pos, n, end)
        pos += n
    elif op in (0xF6, 0xF7):
        reg = (data[modrm_at] >> 3) & 7
        if reg in (0, 1):
            n = 1 if op == 0xF6 else (2 if has66 else 4)
            _need(pos, n, end)
            pos += n
    return pos - start, meta


def find_section(path, name=".text"):
    """返回 {"name","va","off","size","arch"}；找不到返回 None。

    非 ELF/非 PE（含 MZ 开头但无 PE 签名）抛 ValueError——与"节不存在"区分，
    避免把格式不认识报成"找不到 .text"。
    """
    from . import elf, pe
    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        for s in elf.section_headers(data):
            if s["name"] == name and s["size"] > 0:
                return {"name": name, "va": s["addr"], "off": s["offset"],
                        "size": s["size"], "arch": "elf"}
        return None
    is_pe = False
    if data[:2] == b"MZ" and len(data) >= 0x40:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        is_pe = data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"
    if not is_pe:
        raise ValueError("无法识别的格式（非 ELF / 非 PE）")
    r = pe.parse(path)
    for (va, vsize, rawptr, rawsize, nm) in r["sections"]:
        if nm == name and rawsize > 0:
            return {"name": name, "va": va, "off": rawptr,
                    "size": min(rawsize, vsize or rawsize), "arch": "pe"}
    return None


def sweep_file(path, section=".text", limit=None):
    from . import mapview
    data = open(path, "rb").read()
    sec = find_section(path, section)
    if sec is None:
        raise ValueError("找不到可扫描节 %s" % section)
    # 复用 M3 换算：每条指令的 addr 用 addr_to_off 独立算一次文件落点，
    # 结果写进 instructions[i].map，并与本节算术 offset 逐条核对。
    model = mapview.build(path)
    out = sweep_bytes(data, sec["off"], sec["va"], sec["size"], limit,
                      model=model, section=section)
    out["section"] = sec
    out["path"] = str(path)
    return out


def render_text(path, res):
    sec = res.get("section") or {}
    ins = res["instructions"]
    ok = [i for i in ins if i["status"] == "ok"]
    lines = [
        "DISASM: %s  section=%s  VA=0x%x  off=0x%x  size=0x%x"
        % (path, sec.get("name", "?"), sec.get("va", 0), sec.get("off", 0),
           sec.get("size", 0)),
        "instructions: %d（边界已解 %d）  bytes_scanned=0x%x"
        % (len(ins), len(ok), res["bytes_scanned"]),
        "note: 只解【指令边界】，不解助记符；objdump 对齐见 tests/verify_disasm.py",
    ]
    st = res.get("stopped")
    if st:
        lines.append("stopped: addr=0x%x off=0x%x reason=%s bytes=%s"
                     % (st["addr"], st["off"], st["reason"], st["bytes"]))
    ms = res.get("map_stats")
    if ms is not None:
        lines.append("文件落点（复用 mapview.addr_to_off 逐条换算）: "
                     "hit=%d not_in_file=%d unmapped=%d multi=%d；与本节算术不一致 %d 条"
                     % (ms["hit"], ms["not_in_file"], ms["unmapped"], ms["multi"],
                        len(res["map_mismatches"])))
        for m in res["map_mismatches"][:5]:
            lines.append("  ✗ addr=0x%x 本节 off=0x%x 但 addr_to_off=%s(off=%s,unit=%s)"
                         % (m["addr"], m["section_offset"], m["status"],
                            m["map_offset"], m["unit"]))
    lines.append("caveats（线性扫描盲区，别把结果都当指令）:")
    for c in res["caveats"]:
        lines.append("  ! %s" % c)
    for i in ins[:200]:
        unit = (i.get("map") or {}).get("unit") or "-"
        lines.append("  %016x  %08x  %2d  %-8s %s%s"
                     % (i["addr"], i["off"], i["length"], unit, i["bytes"],
                        "" if i["status"] == "ok" else "  <unsupported>"))
    if len(ins) > 200:
        lines.append("  ...（共 %d 条，仅显示前 200 条）" % len(ins))
    return "\n".join(lines)


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="rekit disasm",
                                 description="x86-64 线性扫描（只解指令边界）")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--limit", type=lambda s: int(s, 0), default=None,
                    help="最多扫描多少字节（默认整节）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        with open(args.file, "rb"):
            pass
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    try:
        res = sweep_file(args.file, args.section, args.limit)
    except ValueError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except (struct.error, IndexError) as e:
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(render_text(args.file, res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
