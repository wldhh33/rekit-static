#!/usr/bin/env python3
# rekit.expr — 函数内表达式恢复（M5 第一单元）
#
# 输入完全复用 M4：recdesc.descend() 给出的指令边界（addr/length/bytes/opcode/
# opcode_map）与基本块（start/end/insns/terminator/function/boundary）以及函数域
# （.pdata / FDE / st_size 声明的 start..end）。本模块不做跨过程分析：
# 调用目标只用作“调用点”显示，不内联、不跟参数、不推断返回值。
#
# 输出是【逐语句的伪 C】，不是"看起来合理"的反编译：
#   - 每条语句都能回指到一条具体指令地址与原始字节；
#   - 支持的 opcode 子集是白名单，表外一律 abstain，并在 abstain 记录里写
#     `missing`（缺什么信息才能恢复），绝不猜一个表达式来填空；
#   - 间接 jmp/call 的目标（跳转表、虚表、IAT 指针值）已知不可静态判定：
#     只渲染调用/跳转形态，target 一律 None，不尝试构造 switch；
#   - 函数边界只认权威声明；没有声明的函数默认跳过并计入 skipped
#     （--include-inferred 可强制提升，但单独计数，绝不与声明域混算）。
#
# 表达式的诚实边界（写进输出 caveats）：
#   1) 无语义分析/值编号/别名分析：寄存器与内存表达式保持逐指令形态，
#      同一变量在不同行的名字相同不代表已经做了数据流合并；
#   2) 不定类型：宽度只来自操作数宽度（REX.W / 66 / 字节形式），不推断 C 类型；
#   3) 标志位只在本基本块内跟踪；跨块标志、OF/PF 一律 abstain；
#   4) SIMD/浮点（VEX/EVEX 与大多数 0F 指令）只解长度（disasm 已支持），
#      表达式层 abstain——向量寄存器与浮点语义不在本单元范围。
import json
import struct
import sys

from . import disasm, pe, recdesc

CAVEATS = [
    "逐指令形态：不做值编号/别名分析，“同名变量”不等于已合并同一存储",
    "不推断 C 类型；宽度只来自操作数宽度（REX.W / 66 / 字节形式）",
    "标志位只在同一基本块内跟踪；跨块标志、OF/PF 一律 abstain",
    "SIMD/浮点（VEX/EVEX 及多数 0F 指令）只解长度，表达式层 abstain",
    "只做函数内：调用点不内联、不跟参数、不推断返回值",
    "函数边界只认权威声明（.pdata / FDE / st_size）；未声明者默认跳过",
    "间接 jmp/call 目标不可静态确定：target=None，不猜、不构造 switch",
    "跳转表候选需 --switch-candidates 显式开启：单列、带证据等级与被拒理由，"
    "不进表达式/确定边/CFG 口径（R45 只禁“把猜测当已知”，不禁“提出有证据的候选”）",
]

_REG64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
_REG32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
          "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"]
_REG16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
          "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"]
_REG8 = ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
         "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"]
_REG8_NO_REX = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]

_ALU = {0x00: "add", 0x08: "or", 0x10: "adc", 0x18: "sbb",
        0x20: "and", 0x28: "sub", 0x30: "xor", 0x38: "cmp"}
_GROUP1 = {0: "add", 1: "or", 2: "adc", 3: "sbb",
           4: "and", 5: "sub", 6: "xor", 7: "cmp"}
_GROUP2 = {0: "rol", 1: "ror", 2: "rcl", 3: "rcr",
           4: "shl", 5: "shr", 6: "sal", 7: "sar"}

# 0F 二级 opcode 的弃权分类：只用于把 abstain 原因写准（不影响长度解码）。
# 分类依据是 Intel 手册的 opcode map 分组，不是"看起来像"。
_0F_SIMD = (set(range(0x10, 0x18)) | set(range(0x28, 0x30)) |
            set(range(0x50, 0x80)) | set(range(0xC2, 0xC7)) |
            set(range(0xD0, 0x100)))
_0F_BIT = {0xA3, 0xAB, 0xB3, 0xBB, 0xBA, 0xBC, 0xBD}
_0F_SYS = ({0x00, 0x01, 0x06, 0x07, 0x08, 0x09, 0x0D, 0x18, 0x19, 0x1A,
            0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x78, 0x79, 0xA0, 0xA1, 0xA8,
            0xA9, 0xAA} | set(range(0x30, 0x38)))

# jcc 条件（0x70..0x7F / 0F 80..8F 同一编码）
_CC_SIGNED = {0x0C: "<", 0x0D: ">=", 0x0E: "<=", 0x0F: ">"}
_CC_UNSIGNED = {0x02: "<u", 0x03: ">=u", 0x06: "<=u", 0x07: ">u"}
_CC_EQ = {0x04: "==", 0x05: "!="}
_CC_SIGN = {0x08: "<0", 0x09: ">=0"}
# 明确 abstain 的条件码：OF（溢出）/PF（奇偶）需要未建模的标志位
_CC_ABSTAIN = {0x00: "jo（依赖 OF）", 0x01: "jno（依赖 OF）",
               0x0A: "jp（依赖 PF）", 0x0B: "jnp（依赖 PF）"}
_CC_NAME = {0x00: "jo", 0x01: "jno", 0x02: "jb", 0x03: "jae", 0x04: "je",
            0x05: "jne", 0x06: "jbe", 0x07: "ja", 0x08: "js", 0x09: "jns",
            0x0A: "jp", 0x0B: "jnp", 0x0C: "jl", 0x0D: "jge", 0x0E: "jle",
            0x0F: "jg"}
# 表达式里用 C 运算符（不是助记符）：add → +
_OP_TEXT = {"add": "+", "sub": "-", "and": "&", "or": "|", "xor": "^",
            "imul": "*"}


class LiftError(Exception):
    """单条指令无法恢复：必须带 reason + missing（缺什么信息）。"""

    def __init__(self, reason, missing):
        Exception.__init__(self, reason)
        self.reason = reason
        self.missing = missing


def _fail(reason, missing):
    raise LiftError(reason, missing)


# ── 操作数解码 ───────────────────────────────────────────────────────
def _prefixes(raw):
    i, p66, p67, rep, seg = 0, False, False, None, None
    while i < len(raw) and raw[i] in disasm._LEGACY_PREFIX:
        b = raw[i]
        if b == 0x66:
            p66 = True
        elif b == 0x67:
            p67 = True
        elif b in (0xF2, 0xF3):
            rep = b
        elif b in (0x64, 0x65):
            # 段覆盖：fs/gs 基址来自 MSR/OS，不能当成绝对地址展开（TLS/栈保护常用）
            seg = "fs" if b == 0x64 else "gs"
        elif b == 0xF0:
            raise LiftError("lock 前缀：原子语义未建模",
                            "带 lock 的内存序/原子性语义")
        i += 1
    rex = None
    if i < len(raw) and 0x40 <= raw[i] <= 0x4F:
        b = raw[i]
        rex = {"w": bool(b & 8), "r": bool(b & 4),
               "x": bool(b & 2), "b": bool(b & 1)}
        i += 1
    return i, {"p66": p66, "p67": p67, "rep": rep, "rex": rex, "seg": seg}


def _reg_name(idx, size, has_rex):
    if size == 64:
        return _REG64[idx]
    if size == 32:
        return _REG32[idx]
    if size == 16:
        return _REG16[idx]
    if has_rex or idx >= 8:
        return _REG8[idx]
    return _REG8_NO_REX[idx]


def _regop(idx, size, has_rex):
    return {"t": "reg", "idx": idx, "size": size,
            "name": _reg_name(idx, size, has_rex)}


def _signed(v):
    return "-0x%x" % (-v) if v < 0 else "0x%x" % v


class _Cursor:
    def __init__(self, ins, pref, start):
        self.raw = bytes.fromhex(ins["bytes"].replace(" ", ""))
        self.ins = ins
        self.pref = pref
        self.i = start
        self.has_rex = pref["rex"] is not None

    def need(self, n):
        if self.i + n > len(self.raw):
            _fail("操作数越过指令边界", "该 opcode 的操作数编码表")

    def u8(self):
        self.need(1)
        v = self.raw[self.i]
        self.i += 1
        return v

    def imm(self, n):
        self.need(n)
        v = int.from_bytes(self.raw[self.i:self.i + n], "little", signed=True)
        self.i += n
        return v

    def immu(self, n):
        self.need(n)
        v = int.from_bytes(self.raw[self.i:self.i + n], "little")
        self.i += n
        return v

    def modrm(self):
        m = self.u8()
        return m >> 6, ((m >> 3) & 7), (m & 7), m

    def reg_field(self, raw_reg, group=False):
        idx = raw_reg if group else raw_reg | (8 if self.pref["rex"]
                                               and self.pref["rex"]["r"] else 0)
        return idx

    def rm_operand(self, size, mod=None):
        """读 ModRM.rm 指向的操作数（reg 或 mem）。

        ModRM 字节已被调用方读走时传 mod：rm 从上一字节低 3 位取，
        保证"SIB/disp 只消费一次"。
        """
        if mod is None:
            mod, _reg, rm, _m = self.modrm()
        else:
            rm = self.raw[self.i - 1] & 7
        if mod == 3:
            idx = rm | (8 if self.has_rex and self.pref["rex"]["b"] else 0)
            return _regop(idx, size, self.has_rex)
        base = index = None
        scale, disp, rip = 1, 0, False
        # 编码顺序：ModRM → SIB → disp。先读 disp 会把 SIB 当成 disp 的低字节，
        # 总长度仍然对得上（自检抓不住），只有操作数结构断言能抓住。
        if rm == 4:
            sib = self.u8()
            scale = 1 << (sib >> 6)
            if ((sib >> 3) & 7) != 4:
                index = ((sib >> 3) & 7) | (8 if self.pref["rex"]
                                            and self.pref["rex"]["x"] else 0)
            b = sib & 7
            if b == 5 and mod == 0:
                disp = self.imm(4)
            else:
                base = b | (8 if self.has_rex and self.pref["rex"]["b"] else 0)
                if mod == 1:
                    disp = self.imm(1)
                elif mod == 2:
                    disp = self.imm(4)
        elif mod == 0 and rm == 5:
            disp = self.imm(4)
            rip = True
        else:
            base = rm | (8 if self.has_rex and self.pref["rex"]["b"] else 0)
            if mod == 1:
                disp = self.imm(1)
            elif mod == 2:
                disp = self.imm(4)
        target = None
        if rip:
            target = self.ins["addr"] + self.ins["length"] + disp
        return {"t": "mem", "size": size, "base": base, "index": index,
                "scale": scale, "disp": disp, "rip": rip,
                "rip_target": target, "seg": self.pref.get("seg")}

    def check_end(self):
        if self.i != len(self.raw):
            _fail("操作数解码长度与已解边界不一致（%d != %d）"
                  % (self.i, len(self.raw)),
                  "该 opcode 的操作数编码表；这是内部一致性问题，应先修表")


def _opsize(pref, byte_form=False):
    if byte_form:
        return 8
    if pref["rex"] and pref["rex"]["w"]:
        return 64
    return 16 if pref["p66"] else 32


def decode(ins):
    """把一条已解边界的指令解成语义记录；表外/语义未实现 → LiftError。"""
    if ins["opcode_map"] not in (1, 2):
        _fail("VEX/EVEX（SIMD）指令：表达式层不支持",
              "向量寄存器/浮点语义（本单元只做标量整数表达式）")
    raw = bytes.fromhex(ins["bytes"].replace(" ", ""))
    start, pref = _prefixes(raw)
    c = _Cursor(ins, pref, start)
    op = c.u8()
    base = {"addr": ins["addr"], "bytes": ins["bytes"], "size": None}

    if pref["rep"] and op in (0xC3, 0x90):
        c.check_end()
        return dict(base, family="ret" if op == 0xC3 else "nop")

    if op == 0x0F:
        op2 = c.u8()
        return _decode_0f(ins, c, pref, op2, base)
    if (op & 0xF8) in _ALU and (op & 0x07) in (4, 5):
        # AL/eAX 立即数形态（04/05/0C/0D/.../3C/3D）：没有 ModRM 字节
        mnem = _ALU[op & 0xF8]
        size = 8 if (op & 0x07) == 4 else _opsize(pref)
        n = 1 if size == 8 else (2 if pref["p66"] else 4)
        a = _regop(0, size, c.has_rex)
        b = {"t": "imm", "value": c.imm(n), "size": n * 8}
        c.check_end()
        if mnem == "cmp":
            return dict(base, family="cmp", a=a, b=b)
        return dict(base, family="binop", mnem=mnem, dst=a, src=b,
                    sets_flags=mnem in ("add", "sub", "and", "or", "xor"))
    if (op & 0xF8) in _ALU:
        return _decode_alu(c, pref, op, base)
    if op in (0x80, 0x81, 0x83):
        size = 8 if op == 0x80 else _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        dst = c.rm_operand(size, mod)
        mnem = _GROUP1.get(reg)
        if mnem is None:
            _fail("group1 /%d 未定义" % reg, "该 group 编码的语义")
        if op == 0x83:
            imm = c.imm(1)
            src = {"t": "imm", "value": imm, "size": 8, "signed": True}
        else:
            n = 2 if (op == 0x81 and pref["p66"]) else (1 if op == 0x80 else 4)
            src = {"t": "imm", "value": c.imm(n), "size": n * 8}
        c.check_end()
        if mnem == "cmp":
            return dict(base, family="cmp", a=dst, b=src)
        return dict(base, family="binop", mnem=mnem, dst=dst, src=src,
                    sets_flags=mnem in ("add", "sub", "and", "or", "xor"))
    if op in (0x84, 0x85, 0xA8, 0xA9):
        size = 8 if op in (0x84, 0xA8) else _opsize(pref)
        if op in (0xA8, 0xA9):
            n = 1 if op == 0xA8 else (2 if pref["p66"] else 4)
            a = _regop(0, size, c.has_rex)
            b = {"t": "imm", "value": c.imm(n), "size": n * 8}
        else:
            mod, _reg, _rm, _m = c.modrm()
            a = c.rm_operand(size, mod)
            b = _regop(c.reg_field(_reg), size, c.has_rex)
        c.check_end()
        return dict(base, family="test", a=a, b=b)
    if op in (0x88, 0x89, 0x8A, 0x8B):
        size = 8 if op in (0x88, 0x8A) else _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        rm = c.rm_operand(size, mod)
        rf = _regop(c.reg_field(reg), size, c.has_rex)
        c.check_end()
        if op in (0x88, 0x89):
            return dict(base, family="assign", dst=rm, src=rf)
        return dict(base, family="assign", dst=rf, src=rm)
    if op == 0x8D:
        mod, reg, _rm, _m = c.modrm()
        src = c.rm_operand(0, mod)          # lea 不读写内存
        dst = _regop(c.reg_field(reg), _opsize(pref), c.has_rex)
        c.check_end()
        return dict(base, family="lea", dst=dst, src=src)
    if op == 0x63:
        want = 64 if (pref["rex"] and pref["rex"]["w"]) else 32
        mod, reg, _rm, _m = c.modrm()
        src = c.rm_operand(32, mod)
        dst = _regop(c.reg_field(reg), want, c.has_rex)
        c.check_end()
        return dict(base, family="assign", dst=dst, src=src, mnem="movsxd")
    if op in (0x69, 0x6B):
        size = _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        b = c.rm_operand(size, mod)
        n = 1 if op == 0x6B else (2 if pref["p66"] else 4)
        imm = {"t": "imm", "value": c.imm(n), "size": n * 8}
        dst = _regop(c.reg_field(reg), size, c.has_rex)
        c.check_end()
        return dict(base, family="binop", mnem="imul", dst=dst, src=b,
                    src2=imm, ternary=True, sets_flags=True)
    if op in (0xC6, 0xC7):
        size = 8 if op == 0xC6 else _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        if reg != 0:
            _fail("C6/C7 /%d 未定义" % reg, "该 group 编码的语义")
        dst = c.rm_operand(size, mod)
        n = 1 if op == 0xC6 else (2 if pref["p66"] else 4)
        src = {"t": "imm", "value": c.imm(n), "size": n * 8}
        c.check_end()
        return dict(base, family="assign", dst=dst, src=src)
    if 0xB0 <= op <= 0xB7:
        idx = (op & 7) | (8 if c.has_rex and pref["rex"]["b"] else 0)
        dst = _regop(idx, 8, c.has_rex)
        src = {"t": "imm", "value": c.imm(1), "size": 8}
        c.check_end()
        return dict(base, family="assign", dst=dst, src=src)
    if 0xB8 <= op <= 0xBF:
        size = _opsize(pref)
        idx = (op & 7) | (8 if c.has_rex and pref["rex"]["b"] else 0)
        dst = _regop(idx, size, c.has_rex)
        n = 8 if size == 64 else (2 if size == 16 else 4)
        src = {"t": "imm", "value": c.imm(n), "size": n * 8}
        c.check_end()
        return dict(base, family="assign", dst=dst, src=src)
    if op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
        size = 8 if op in (0xC0, 0xD0, 0xD2) else _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        dst = c.rm_operand(size, mod)
        mnem = _GROUP2.get(reg)
        if mnem is None:
            _fail("group2 /%d 未定义" % reg, "该 group 编码的语义")
        if op in (0xC0, 0xC1):
            count = {"t": "imm", "value": c.imm(1), "size": 8}
        elif op in (0xD0, 0xD1):
            count = {"t": "imm", "value": 1, "size": 8}
        else:
            count = _regop(1, 8, c.has_rex)
        c.check_end()
        return dict(base, family="shift", mnem=mnem, dst=dst, count=count,
                    sets_flags=True)
    if op in (0xF6, 0xF7):
        size = 8 if op == 0xF6 else _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        rm = c.rm_operand(size, mod)
        if reg in (0, 1):
            n = 1 if op == 0xF6 else (2 if pref["p66"] else 4)
            imm = {"t": "imm", "value": c.imm(n), "size": n * 8}
            c.check_end()
            return dict(base, family="test", a=rm, b=imm)
        if reg in (2, 3):
            c.check_end()
            return dict(base, family="unop", mnem="not" if reg == 2 else "neg",
                        dst=rm, sets_flags=(reg == 3))
        if reg in (4, 5, 6, 7):
            _fail("mul/imul/div/idiv（隐式 rax/rdx 双寄存器结果）未建模",
                  "隐式操作数 rax/rdx 与商余数语义")
        _fail("group3 /%d 未定义" % reg, "该 group 编码的语义")
    if op == 0xFE:
        mod, reg, _rm, _m = c.modrm()
        dst = c.rm_operand(8, mod)
        if reg not in (0, 1):
            _fail("FE /%d 未定义" % reg, "该 group 编码的语义")
        c.check_end()
        return dict(base, family="unop", mnem="inc" if reg == 0 else "dec",
                    dst=dst, sets_flags=True)
    if op == 0xFF:
        return _decode_ff(c, pref, base)
    if 0x50 <= op <= 0x57:
        idx = (op & 7) | (8 if c.has_rex and pref["rex"]["b"] else 0)
        c.check_end()
        return dict(base, family="push", src=_regop(idx, 64, c.has_rex))
    if 0x58 <= op <= 0x5F:
        idx = (op & 7) | (8 if c.has_rex and pref["rex"]["b"] else 0)
        c.check_end()
        return dict(base, family="pop", dst=_regop(idx, 64, c.has_rex))
    if op in (0x68, 0x6A):
        n = 1 if op == 0x6A else (2 if pref["p66"] else 4)
        src = {"t": "imm", "value": c.imm(n), "size": n * 8}
        c.check_end()
        return dict(base, family="push", src=src)
    if op == 0x8F:
        mod, reg, _rm, _m = c.modrm()
        if reg != 0:
            _fail("8F /%d 未定义" % reg, "该 group 编码的语义")
        dst = c.rm_operand(64, mod)
        c.check_end()
        return dict(base, family="pop", dst=dst)
    if op == 0xC3:
        c.check_end()
        return dict(base, family="ret")
    if op == 0xC2:
        imm = c.imm(2)
        c.check_end()
        return dict(base, family="ret", stack_adjust=imm)
    if op == 0xC9:
        c.check_end()
        return dict(base, family="leave")
    if op == 0x98:
        c.check_end()
        return dict(base, family="conv",
                    mnem="cdqe" if (pref["rex"] and pref["rex"]["w"])
                    else ("cbw" if pref["p66"] else "cwde"))
    if op == 0x99:
        c.check_end()
        return dict(base, family="conv",
                    mnem="cqo" if (pref["rex"] and pref["rex"]["w"])
                    else ("cwd" if pref["p66"] else "cdq"))
    if op == 0xCD:
        n = c.u8()
        c.check_end()
        return dict(base, family="intrinsic", text="int(0x%x)" % n)
    if op in (0x86, 0x87):
        size = 8 if op == 0x86 else _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        a = c.rm_operand(size, mod)
        b = _regop(c.reg_field(reg), size, c.has_rex)
        c.check_end()
        return dict(base, family="xchg", a=a, b=b)
    if op == 0x90 and not (c.has_rex and pref["rex"]["b"]):
        c.check_end()
        return dict(base, family="nop")
    if op == 0xCC:
        c.check_end()
        return dict(base, family="trap")
    if op == 0xF4:
        c.check_end()
        return dict(base, family="hlt")
    if op in (0xE8, 0xE9):
        rel = c.imm(4)
        c.check_end()
        tgt = ins["addr"] + ins["length"] + rel
        return dict(base, family="call" if op == 0xE8 else "jmp", target=tgt)
    if op == 0xEB:
        rel = c.imm(1)
        c.check_end()
        return dict(base, family="jmp", target=ins["addr"] + ins["length"] + rel)
    if 0x70 <= op <= 0x7F:
        rel = c.imm(1)
        c.check_end()
        return dict(base, family="jcc", cc=op & 0x0F,
                    target=ins["addr"] + ins["length"] + rel)
    if op in (0xE0, 0xE1, 0xE2, 0xE3):
        rel = c.imm(1)
        c.check_end()
        return dict(base, family="loop", cc=op,
                    target=ins["addr"] + ins["length"] + rel)
    if 0xD8 <= op <= 0xDF:
        _fail("x87 浮点指令（opcode 0x%02x）未建模" % op,
              "x87 栈式浮点寄存器与舍入语义（M5-U1 只做标量整数表达式）")
    if op in (0xA4, 0xA5, 0xA6, 0xA7, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF):
        _fail("字符串指令（opcode 0x%02x）未建模" % op,
              "rep/隐式 rsi/rdi 更新与方向标志语义（M5-U1 白名单之外）")
    _fail("opcode 0x%02x 未在表达式白名单内" % op,
          "该 opcode 的操作数编码与算术语义（M5-U1 白名单之外）")


def _decode_alu(c, pref, op, base):
    base_op = op & 0xF8
    variant = op & 0x03
    mnem = _ALU[base_op]
    size = 8 if variant in (0, 2) else _opsize(pref)
    mod, reg, _rm, _m = c.modrm()
    rm = c.rm_operand(size, mod)
    rf = _regop(c.reg_field(reg), size, c.has_rex)
    c.check_end()
    if variant in (0, 1):
        dst, src = rm, rf
    else:
        dst, src = rf, rm
    if mnem == "cmp":
        return dict(base, family="cmp", a=dst, b=src)
    return dict(base, family="binop", mnem=mnem, dst=dst, src=src,
                sets_flags=mnem in ("add", "sub", "and", "or", "xor"))


def _decode_ff(c, pref, base):
    mod, reg, _rm, _m = c.modrm()
    if reg == 0 or reg == 1:
        m = "inc" if reg == 0 else "dec"
        dst = c.rm_operand(_opsize(pref), mod)
        c.check_end()
        return dict(base, family="unop", mnem=m, dst=dst, sets_flags=True)
    if reg == 2:
        tgt = c.rm_operand(64, mod)
        c.check_end()
        return dict(base, family="call", target=None, indirect=tgt)
    if reg == 4:
        tgt = c.rm_operand(64, mod)
        c.check_end()
        return dict(base, family="jmp", target=None, indirect=tgt)
    if reg == 6:
        src = c.rm_operand(64, mod)
        c.check_end()
        return dict(base, family="push", src=src)
    _fail("FF /%d（远调用/远跳转等）未建模" % reg, "far call/jmp 的选择子语义")


def _decode_0f(ins, c, pref, op2, base):
    if op2 == 0xAF:
        size = _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        src = c.rm_operand(size, mod)
        dst = _regop(c.reg_field(reg), size, c.has_rex)
        c.check_end()
        return dict(base, family="binop", mnem="imul", dst=dst, src=src,
                    two_operand_imul=True, sets_flags=True)
    if op2 in (0xB6, 0xB7, 0xBE, 0xBF):
        src_size = 8 if op2 in (0xB6, 0xBE) else 16
        signed = op2 in (0xBE, 0xBF)
        mod, reg, _rm, _m = c.modrm()
        src = c.rm_operand(src_size, mod)
        dst = _regop(c.reg_field(reg), _opsize(pref), c.has_rex)
        c.check_end()
        return dict(base, family="assign", dst=dst, src=src,
                    mnem="movsx" if signed else "movzx")
    if 0x40 <= op2 <= 0x4F:
        size = _opsize(pref)
        mod, reg, _rm, _m = c.modrm()
        src = c.rm_operand(size, mod)
        dst = _regop(c.reg_field(reg), size, c.has_rex)
        c.check_end()
        return dict(base, family="cmov", cc=op2 & 0x0F, dst=dst, src=src)
    if 0x90 <= op2 <= 0x9F:
        mod, _reg, _rm, _m = c.modrm()
        dst = c.rm_operand(8, mod)
        c.check_end()
        return dict(base, family="setcc", cc=op2 & 0x0F, dst=dst)
    if op2 == 0x1F or op2 == 0x1E:
        mod, _reg, _rm, _m = c.modrm()
        c.rm_operand(0, mod)
        c.check_end()
        return dict(base, family="nop")
    if op2 == 0x05:
        c.check_end()
        return dict(base, family="intrinsic", text="syscall()")
    if op2 == 0x0B:
        c.check_end()
        return dict(base, family="ud2")
    if op2 == 0x31:
        c.check_end()
        return dict(base, family="intrinsic", text="rdtsc()")
    if op2 == 0xA2:
        c.check_end()
        return dict(base, family="intrinsic", text="cpuid()")
    if 0xC8 <= op2 <= 0xCF:
        size = _opsize(pref)
        idx = (op2 & 7) | (8 if c.has_rex and pref["rex"]["b"] else 0)
        r = _regop(idx, size, c.has_rex)
        c.check_end()
        return dict(base, family="bswap", dst=r)
    if 0x80 <= op2 <= 0x8F:
        rel = c.imm(4)
        c.check_end()
        return dict(base, family="jcc", cc=op2 & 0x0F,
                    target=ins["addr"] + ins["length"] + rel)
    if op2 in _0F_BIT:
        _fail("0F %02x 位操作指令（bt/bts/btr/btc/bsf/bsr 组）未建模" % op2,
              "位测试/扫描语义与 CF 输出（M5-U1 白名单之外）")
    if op2 in _0F_SIMD:
        _fail("0F %02x SIMD/浮点指令未建模" % op2,
              "向量寄存器/浮点语义（M5-U1 只做标量整数表达式）")
    if op2 in _0F_SYS:
        _fail("0F %02x 系统/描述符指令未建模" % op2,
              "系统寄存器与描述符表语义（不在函数内表达式范围）")
    _fail("0F %02x 指令语义未实现" % op2,
          "该 0F 指令的操作数编码与语义（M5-U1 白名单之外）")


# ── 表达式渲染 ───────────────────────────────────────────────────────
def _slot_name(base, disp):
    """rbp/rsp 相对且无 index：按栈槽命名（负偏移 local_/sp_，正偏移 stk_）。"""
    if base == 5 and disp < 0:
        return "local_%x" % (-disp)
    if base == 5 and disp > 0:
        # rbp 正偏移不做 ABI 判定（可能是栈上传参，也可能是调用者帧）→ 中性命名
        return "stk_%x" % disp
    if base == 4 and disp < 0:
        return "sp_%x" % (-disp)
    return None


def _bits_word(size):
    return "u%d" % size if size else "u8"


def render_operand(op, imp=None):
    if op["t"] == "imm":
        v = op["value"]
        return "-0x%x" % (-v) if v < 0 else "0x%x" % v
    if op["t"] == "reg":
        return op["name"]
    if op["t"] == "mem":
        slot = (_slot_name(op["base"], op["disp"])
                if op["index"] is None and not op.get("seg") else None)
        if slot:
            return slot
        if op["rip"]:
            tgt = op["rip_target"]
            name = imp.get(tgt) if imp else None
            if name:
                return "*%s" % name
            return "*(%s *)data_0x%x" % (_bits_word(op["size"]), tgt)
        parts = []
        if op["base"] is not None:
            parts.append(_REG64[op["base"]])
        if op["index"] is not None:
            parts.append("%s * %d" % (_REG64[op["index"]], op["scale"]))
        if op["disp"] or not parts:
            parts.append(_signed(op["disp"]))
        addr_text = " + ".join(parts)
        if op.get("seg"):
            # 段基址未展开：fs:[0x28] 不是绝对地址 0x28，必须保留段前缀
            return "*(%s *)(%s:[%s])" % (_bits_word(op["size"]),
                                         op["seg"], addr_text)
        return "*(%s *)(%s)" % (_bits_word(op["size"]), addr_text)
    return "?"


def _flags_operand(fl):
    """把标志位来源压成一个可比较的左值表达式。"""
    if fl is None:
        return None
    fam = fl["family"]
    if fam == "cmp":
        return render_operand(fl["a"]), render_operand(fl["b"]), "cmp"
    if fam == "test":
        return render_operand(fl["a"]), render_operand(fl["b"]), "test"
    if fam == "binop" and fl["mnem"] in ("sub", "cmp"):
        return render_operand(fl["dst"]), render_operand(fl.get("src") or fl.get("b")), "cmp"
    if fam == "binop":
        return "(%s)" % _binop_text(fl), "0", "result"
    if fam == "unop":
        return "(%s)" % _unop_text(fl), "0", "result"
    if fam == "shift":
        return "(%s)" % _shift_text(fl), "0", "result"
    return None


def _binop_text(fl, imp=None):
    """二元运算的右值文本（左值由调用方负责）。"""
    op = _OP_TEXT.get(fl["mnem"], fl["mnem"])
    if fl.get("ternary"):                      # imul r, rm, imm
        return "%s %s %s" % (render_operand(fl["src"], imp), op,
                             render_operand(fl["src2"], imp))
    d, s = render_operand(fl["dst"], imp), render_operand(fl["src"], imp)
    if fl.get("two_operand_imul"):              # imul r, rm
        return "%s %s %s" % (d, op, s)
    return "%s %s %s" % (d, op, s)


def _unop_text(fl, imp=None):
    d = render_operand(fl["dst"], imp)
    if fl["mnem"] == "not":
        return "~%s" % d
    return "%s(%s)" % (fl["mnem"], d)


def _shift_text(fl, imp=None):
    return "%s(%s, %s)" % (fl["mnem"], render_operand(fl["dst"], imp),
                           render_operand(fl["count"], imp))


def _cond_text(fl, cc, imp=None):
    """条件文本；不可判 → LiftError。"""
    if cc in _CC_ABSTAIN:
        _fail(_CC_ABSTAIN[cc], "OF/PF 标志位的完整语义")
    got = _flags_operand(fl)
    if got is None:
        _fail("条件跳转前没有可跟踪的标志位来源（jcc 0x%02x）" % cc,
              "跨块标志数据流（本单元只跟踪同一基本块内的 cmp/test/算术）")
    a, b, kind = got
    if kind == "test":
        if cc in _CC_EQ:
            return "(%s & %s) %s 0" % (a, b, _CC_EQ[cc])
        if cc in _CC_SIGN:
            return "(%s & %s) %s" % (a, b, _CC_SIGN[cc])
        # test 保证 OF=CF=0，所以有符号比较等价于"结果与 0 比"，
        # 无符号的 jbe/ja 退化为 ZF（CF=0）
        if cc in _CC_SIGNED:
            return "(%s & %s) %s 0" % (a, b, _CC_SIGNED[cc])
        if cc in (0x06, 0x07):
            return "(%s & %s) %s 0" % (a, b,
                                       "==" if cc == 0x06 else "!=")
        _fail("test 后的条件 0x%02x 需要 CF/OF 语义" % cc,
              "CF/OF 标志位（test 只可靠推 ZF/SF）")
    if cc in _CC_EQ:
        return "%s %s %s" % (a, _CC_EQ[cc], b)
    if cc in _CC_SIGNED:
        if kind != "cmp":
            # add/inc 等算术后：结果与 0 比才是正确语义（见 SDM SF^OF 定义）
            return "%s %s %s" % (a, _CC_SIGNED[cc], b)
        return "%s %s %s" % (a, _CC_SIGNED[cc], b)
    if cc in _CC_UNSIGNED:
        if kind != "cmp":
            _fail("算术结果后的无符号条件 0x%02x 需要 CF 语义" % cc,
                  "CF（进位/借位）标志位")
        return "%s %s %s" % (a, _CC_UNSIGNED[cc], b)
    if cc in _CC_SIGN:
        return "%s %s" % (a, _CC_SIGN[cc])
    _fail("条件码 0x%02x 未建模" % cc, "该条件码的标志位定义")


# ── 函数提升 ─────────────────────────────────────────────────────────
def _declared(seed):
    return bool(seed and seed.get("end"))


def _authority(seed):
    return seed["authority"] if seed else recdesc.DERIVED


def _symbol_of(seed):
    if not seed:
        return None
    for d in seed.get("details") or []:
        if d and not d.startswith("range ") and not d.startswith("0x"):
            return d
    return None


def _import_names(path):
    """PE：IAT 槽 VA → "dll!name"（复用 M3 iat 解码；失败则空表，不算错误）。"""
    out = {}
    try:
        data = open(path, "rb").read()
        if data[:2] != b"MZ":
            return out
        h = pe.parse(path)
        from . import iat
        loc = iat.locate_bytes(data)
        for s in loc.get("slots") or []:
            if s.get("rva") is None:
                continue
            nm = s.get("name") or (("ord_%d" % s["ordinal"])
                                   if s.get("ordinal") else None)
            if nm:
                # 地址空间是 RVA（与 recdesc/disasm 一致），键也用槽 RVA
                out[s["rva"]] = "%s!%s" % (s.get("dll") or "?", nm)
    except Exception:
        return out
    return out


def list_functions(res):
    """按函数域聚合：{addr, end, boundary, authority, symbol, insns, blocks}。"""
    seeds = {s["addr"]: s for s in res["seeds"]}
    by_fn = {}
    for i in res["instructions"]:
        by_fn.setdefault(i.get("origin"), []).append(i)
    blocks = {}
    for b in res["blocks"]:
        blocks.setdefault(b["function"], []).append(b)
    out = []
    for fn in sorted(a for a in by_fn if a is not None):
        seed = seeds.get(fn)
        out.append({
            "addr": fn, "end": seed.get("end") if seed else None,
            "boundary": "declared" if _declared(seed) else "unknown",
            "authority": _authority(seed), "symbol": _symbol_of(seed),
            "insns": len(by_fn[fn]), "blocks": len(blocks.get(fn) or []),
        })
    return out


def lift_function(res, func_addr, imp=None):
    """提升一个函数：返回结构化结果（含伪 C 文本、abstain 明细）。"""
    seeds = {s["addr"]: s for s in res["seeds"]}
    seed = seeds.get(func_addr)
    insns = [i for i in res["instructions"] if i.get("origin") == func_addr]
    blks = [b for b in res["blocks"] if b["function"] == func_addr]
    if not insns:
        return {"function": func_addr, "skipped": "该函数没有已解出指令"}
    by_addr = {i["addr"]: i for i in insns}
    imp = imp or {}
    boundary = "declared" if _declared(seed) else "unknown"
    lo, hi = func_addr, seed.get("end") if seed else None
    out_blocks, abstains = [], []
    events = {"calls": [], "jumps": [], "branches": []}
    statements = 0
    lifted = 0
    stack = {}
    lines = []
    sym = _symbol_of(seed)
    head = "// FUNC %s  0x%x..%s  boundary=%s  authority=%s" % (
        (sym or "sub_0x%x" % func_addr), lo,
        ("0x%x" % hi) if hi else "?", boundary, _authority(seed))

    for b in blks:
        flags = None
        blines = []
        n_body = None            # 末条指令之前累计的行数（结构化层用）
        last_a = b["insns"][-1] if b["insns"] else None
        for a in b["insns"]:
            if n_body is None and a == last_a and b["terminator"] != "next":
                n_body = len(blines)
            ins = by_addr.get(a)
            if ins is None:
                continue
            try:
                rec = decode(ins)
                stmts = _statements(rec, flags, imp, stack)
            except LiftError as e:
                abstains.append({"addr": a, "bytes": ins["bytes"],
                                 "reason": e.reason, "missing": e.missing})
                blines.append("/* abstain @0x%x: %s（缺：%s） */"
                              % (a, e.reason, e.missing))
                statements += 1
                flags = None
                continue
            lifted += 1
            _record_event(events, a, rec)
            flags = _next_flags(rec, flags)
            for s in stmts:
                statements += 1
                blines.append(s)
        # 块终结符：用最后一条指令的条件/跳转渲染
        tail = _terminator_lines(b, insns, seeds, imp, abstains, flags)
        if n_body is None:
            n_body = len(blines)
        if tail:
            statements += len(tail)
            blines.extend(tail)
        out_blocks.append({"start": b["start"], "end": b["end"],
                           "terminator": b["terminator"], "lines": blines,
                           # 结构化层只读这两个切片：body 不含任何块间跳转，
                           # term 只含终结符语句 + fallthrough 说明（可回指边）
                           "body_lines": blines[:n_body],
                           "term_lines": blines[n_body:]})
        lines.append("L_0x%x:" % b["start"])
        lines.extend("  " + x for x in blines)

    legend = []
    for off in sorted(stack, key=lambda s: (s[0], s[1])):
        legend.append("// stack %s = [%s%+d]  宽度 %s"
                      % (stack[off][0], "rbp" if off[0] == 5 else "rsp",
                         off[1], "/".join(sorted(stack[off][1]))))
    abst_ratio = (len(abstains) / len(insns)) if insns else None
    text = "\n".join([head,
                      "// 约定: addr(x)=x 的地址（非解引用）；*(uN *)p 解引用；"
                      "local_/sp_ 为栈负偏移，stk_ 为 rbp 正偏移；flags 行为标志位快照；"
                      "fs:/gs: 为段基址未展开的段相对地址（不是绝对地址）",
                      "// 指令 %d / 已提升 %d / abstain %d（%.2f%%）/ 语句 %d"
                      % (len(insns), lifted, len(abstains),
                         100 * (abst_ratio or 0), statements)]
                     + legend + lines)
    return {
        "function": func_addr, "symbol": sym, "range": [lo, hi],
        "boundary": boundary, "authority": _authority(seed),
        "blocks": out_blocks,
        "stats": {"insns": len(insns), "lifted": lifted,
                  "abstained": len(abstains), "statements": statements,
                  "abstain_ratio": abst_ratio},
        "abstains": abstains, "stack_slots": len(stack), "text": text,
        "events": events,
        "verdict": ("complete" if not abstains else
                    ("partial" if boundary == "declared" else
                     "inferred-partial")),
    }


def _record_event(events, addr, rec):
    """结构化记录控制转移（供对读统计；文本只用于人读）。"""
    fam = rec["family"]
    if fam == "call":
        events["calls"].append({"addr": addr, "target": rec.get("target"),
                                "indirect": rec.get("indirect") is not None})
    elif fam == "jmp":
        events["jumps"].append({"addr": addr, "target": rec.get("target"),
                                "indirect": rec.get("indirect") is not None})
    elif fam in ("jcc", "loop"):
        events["branches"].append({"addr": addr, "target": rec["target"],
                                   "cc": rec["cc"]})


def _statements(rec, flags, imp, stack):
    fam = rec["family"]
    if fam == "nop":
        return []
    if fam == "assign":
        _note_mem(rec["dst"], stack, rec["dst"].get("size"))
        _note_mem(rec["src"], stack, rec["src"].get("size"))
        extra = ("  /* %s */" % rec["mnem"]) if rec.get("mnem") else ""
        return ["%s = %s;%s" % (render_operand(rec["dst"], imp),
                                render_operand(rec["src"], imp), extra)]
    if fam == "lea":
        if rec["src"]["t"] != "mem":
            _fail("lea 的操作数不是内存", "lea 的 ModRM 内存形式")
        # addr(x) 表示"x 的地址"（不是解引用）；寄存器在这里当数值参与地址算术
        return ["%s = addr(%s);" % (render_operand(rec["dst"], imp),
                                    _lea_text(rec["src"], imp))]
    if fam == "binop":
        _note_mem(rec["dst"], stack, rec["dst"].get("size"))
        d = render_operand(rec["dst"], imp)
        s = render_operand(rec["src"], imp)
        if rec.get("ternary"):                       # imul r, rm, imm
            return ["%s = %s * %s;" % (d, s,
                                       render_operand(rec["src2"], imp))]
        if rec.get("two_operand_imul"):              # imul r, rm
            return ["%s = %s * %s;" % (d, d, s)]
        compound = {"add": "+=", "sub": "-=", "or": "|=",
                    "and": "&=", "xor": "^="}
        if rec["mnem"] in compound:
            return ["%s %s %s;" % (d, compound[rec["mnem"]], s)]
        return ["%s = %s %s %s;" % (d, d, rec["mnem"], s)]
    if fam == "unop":
        d = render_operand(rec["dst"], imp)
        if rec["mnem"] == "inc":
            return ["%s += 1;" % d]
        if rec["mnem"] == "dec":
            return ["%s -= 1;" % d]
        if rec["mnem"] == "neg":
            return ["%s = -%s;" % (d, d)]
        return ["%s = ~%s;" % (d, d)]
    if fam == "shift":
        return ["%s = %s;" % (render_operand(rec["dst"], imp),
                              _shift_text(rec, imp))]
    if fam == "cmp":
        return ["flags = cmp(%s, %s);" % (render_operand(rec["a"], imp),
                                          render_operand(rec["b"], imp))]
    if fam == "test":
        return ["flags = test(%s, %s);" % (render_operand(rec["a"], imp),
                                           render_operand(rec["b"], imp))]
    if fam == "call":
        return [_call_text(rec, imp)]
    if fam == "jmp":
        if rec.get("target") is None:
            return ["/* jmp 间接：目标不可静态确定（不猜） */"]
        return ["goto L_0x%x;" % rec["target"]]
    if fam == "ret":
        adj = rec.get("stack_adjust")
        return ["return;" + ("  /* ret %d */" % adj if adj else "")]
    if fam == "leave":
        return ["rsp = rbp; rbp = pop();"]
    if fam == "push":
        return ["push(%s);" % render_operand(rec["src"], imp)]
    if fam == "pop":
        return ["%s = pop();" % render_operand(rec["dst"], imp)]
    if fam == "conv":
        return ["/* %s（隐式 rax/rdx 扩展） */" % rec["mnem"]]
    if fam == "setcc":
        if flags is None:
            _fail("setcc 前没有可跟踪的标志位来源", "跨块标志数据流")
        return ["%s = (%s);" % (render_operand(rec["dst"], imp),
                                _cond_text(flags, rec["cc"], imp))]
    if fam == "cmov":
        if flags is None:
            _fail("cmov 前没有可跟踪的标志位来源", "跨块标志数据流")
        return ["if (%s) %s = %s;" % (_cond_text(flags, rec["cc"], imp),
                                      render_operand(rec["dst"], imp),
                                      render_operand(rec["src"], imp))]
    if fam == "bswap":
        return ["%s = bswap(%s);" % (render_operand(rec["dst"], imp),
                                     render_operand(rec["dst"], imp))]
    if fam == "xchg":
        return ["swap(%s, %s);" % (render_operand(rec["a"], imp),
                                   render_operand(rec["b"], imp))]
    if fam == "intrinsic":
        return ["%s;" % rec["text"]]
    if fam == "trap":
        return ["__int3();"]
    if fam == "hlt":
        return ["__halt();"]
    if fam == "ud2":
        return ["__ud2();"]
    if fam == "jcc":
        if flags is None:
            _fail("条件跳转前没有可跟踪的标志位来源",
                  "跨块标志数据流")
        return ["if (%s) goto L_0x%x;" % (_cond_text(flags, rec["cc"], imp),
                                          rec["target"])]
    if fam == "loop":
        op = rec["cc"]
        if op == 0xE3:                        # jrcxz
            return ["if (rcx == 0) goto L_0x%x;" % rec["target"]]
        return ["if (--rcx != 0) goto L_0x%x;" % rec["target"]]
    _fail("表达式族 %s 未实现" % fam, "该族的语句模板")


def _lea_text(mem, imp):
    if mem["rip"]:
        return "data_0x%x" % mem["rip_target"]
    parts = []
    if mem["base"] is not None:
        parts.append(_REG64[mem["base"]])
    if mem["index"] is not None:
        parts.append("%s * %d" % (_REG64[mem["index"]], mem["scale"]))
    if mem["disp"] or not parts:
        parts.append(_signed(mem["disp"]))
    text = " + ".join(parts)
    return "%s:[%s]" % (mem["seg"], text) if mem.get("seg") else text


def _call_text(rec, imp):
    tgt = rec.get("target")
    if tgt is not None:
        nm = imp.get(tgt)
        return "%s();" % (nm or "sub_0x%x" % tgt)
    ind = rec.get("indirect")
    if ind is not None:
        if ind["t"] == "mem" and ind["rip"]:
            nm = imp.get(ind["rip_target"])
            if nm:
                return "%s();  /* 导入调用 IAT */" % nm
        return "(*%s)();  /* 间接调用：目标不可静态确定（不猜） */" \
            % render_operand(ind, imp)
    return "(*unknown)();  /* 间接调用：目标不可静态确定（不猜） */"


def _note_mem(op, stack, size):
    if op["t"] != "mem" or op["index"] is not None or op["rip"]:
        return
    slot = _slot_name(op["base"], op["disp"])
    if not slot:
        return
    key = (op["base"], op["disp"])
    ent = stack.setdefault(key, [slot, set()])
    if size:
        ent[1].add("u%d" % size)


def _next_flags(rec, flags):
    """标志位如何在指令间传递：算术类重设，搬移类保持，调用/终结类清空。"""
    fam = rec["family"]
    if fam in ("cmp", "test"):
        return rec
    if fam in ("binop", "unop", "shift"):
        # adc/sbb 依赖 CF 输入，本实现不建模 → 清空；add/sub/and/or/xor/inc/dec/neg 可跟踪
        return rec if rec.get("sets_flags") else None
    if fam in ("call", "intrinsic", "ret", "jmp", "trap", "hlt", "ud2", "leave"):
        return None
    return flags          # mov/lea/push/pop/nop/conv/bswap/setcc/cmov 不改标志


def _terminator_lines(block, insns, seeds, imp, abstains, flags):
    """块终结符的收尾语句（末条指令已在 _statements 里渲染过语义型语句）。

    jcc/loop 由末条指令的 _statements 输出 if-goto；fallthrough 这里补显式
    goto，保证伪 C 不依赖块排列顺序。
    """
    if not block["insns"]:
        return []
    last = None
    for i in insns:
        if i["addr"] == block["insns"][-1]:
            last = i
    if last is None:
        return []
    try:
        rec = decode(last)
    except LiftError:
        return []
    fam = rec["family"]
    if fam in ("jcc", "loop"):
        nxt = block["end"]
        # 显式 fallthrough：块不是函数末尾时补 goto
        return ["goto L_0x%x;  /* 未取分支 */" % nxt]
    return []


# ── 汇总 ─────────────────────────────────────────────────────────────
def lift_binary(path, section=".text", include_inferred=False, res=None):
    res = res if res is not None else recdesc.descend(path, section)
    imp = _import_names(path)
    funcs = list_functions(res)
    lifted = []
    skipped = []
    for f in funcs:
        if f["boundary"] != "declared" and not include_inferred:
            skipped.append({"function": f["addr"], "symbol": f["symbol"],
                            "reason": "函数边界未声明（无 .pdata/FDE/st_size）："
                                      "不能把推断域当函数域",
                            "insns": f["insns"]})
            continue
        lifted.append(lift_function(res, f["addr"], imp))
    # 汇总
    tot_ins = sum(r["stats"]["insns"] for r in lifted)
    tot_abs = sum(r["stats"]["abstained"] for r in lifted)
    verdict = {"complete": 0, "partial": 0, "inferred-partial": 0}
    for r in lifted:
        verdict[r["verdict"]] += 1
    reasons = {}
    for r in lifted:
        for a in r["abstains"]:
            reasons[a["reason"]] = reasons.get(a["reason"], 0) + 1
    return {
        "path": str(path), "section": section,
        "recdesc_stats": res["stats"],
        "functions_total": len(funcs),
        "functions_lifted": len(lifted),
        "functions_skipped": len(skipped),
        "skipped": skipped,
        "verdict": verdict,
        "stats": {
            "insns": tot_ins,
            "lifted": sum(r["stats"]["lifted"] for r in lifted),
            "abstained": tot_abs,
            "abstain_ratio": (tot_abs / tot_ins) if tot_ins else None,
            "statements": sum(r["stats"]["statements"] for r in lifted),
        },
        "abstain_reasons": reasons,
        "functions": [{"function": r["function"], "symbol": r["symbol"],
                       "range": r["range"], "boundary": r["boundary"],
                       "authority": r["authority"],
                       "verdict": r["verdict"],
                       "insns": r["stats"]["insns"],
                       "abstained": r["stats"]["abstained"],
                       "blocks": len(r["blocks"]),
                       "stack_slots": r["stack_slots"]}
                      for r in lifted],
        "caveats": list(CAVEATS),
    }


def render_summary(b):
    st = b["stats"]
    lines = [
        "EXPR: %s  section=%s" % (b["path"], b["section"]),
        "函数域: 共 %d 个 ｜ 已提升 %d ｜ 跳过 %d（边界未声明，--include-inferred 可强制）"
        % (b["functions_total"], b["functions_lifted"], b["functions_skipped"]),
        "函数级判定: 完整 %d ｜ 部分 %d ｜ 推断域部分 %d"
        % (b["verdict"]["complete"], b["verdict"]["partial"],
           b["verdict"]["inferred-partial"]),
        "指令级: 共 %d ｜ 已提升 %d ｜ abstain %d（%.2f%%）｜ 语句 %d"
        % (st["insns"], st["lifted"], st["abstained"],
           100 * (st["abstain_ratio"] or 0), st["statements"]),
    ]
    if b["abstain_reasons"]:
        lines.append("abstain 原因（互斥计数，按出现次数）:")
        for r, n in sorted(b["abstain_reasons"].items(), key=lambda kv: -kv[1]):
            lines.append("  · %d× %s" % (n, r))
    else:
        lines.append("abstain: 0（全部指令都在白名单内）")
    lines.append("caveats（表达式恢复的诚实边界）:")
    for c in b["caveats"]:
        lines.append("  ! %s" % c)
    return "\n".join(lines)


def render_function(r):
    if r.get("skipped"):
        return "// FUNC 0x%x 跳过：%s" % (r["function"], r["skipped"])
    return r["text"]


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="rekit expr",
        description="函数内表达式恢复（伪 C；不可恢复处显式 abstain）")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--func", type=lambda s: int(s, 0), default=None,
                    help="只输出该函数（地址，如 0x401000）")
    ap.add_argument("--include-inferred", action="store_true",
                    help="也提升边界未声明的函数（单独计数，不与声明域混算）")
    ap.add_argument("--switch-candidates", action="store_true",
                    help="额外输出跳转表候选（非确定；单列并标注证据等级，"
                         "不进入确定边/表达式/CFG 口径）")
    ap.add_argument("--structured", action="store_true",
                    help="输出控制流结构化（if/loop/switch；每处可回指块与边；"
                         "默认关闭，不改变既有输出）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        with open(args.file, "rb"):
            pass
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    try:
        if args.func is None:
            res = recdesc.descend(args.file, args.section) \
                if (args.switch_candidates or args.structured) else None
            out = lift_binary(args.file, args.section, args.include_inferred, res)
            if args.structured:
                from . import struct as cstruct, switchcand
                cand = switchcand.analyze_binary(args.file, args.section, res)
                out["structured"] = cstruct.structure_binary(
                    res, cand, args.include_inferred)
            if args.json:
                if args.switch_candidates:
                    from . import switchcand
                    out["switch_candidates"] = switchcand.analyze_binary(
                        args.file, args.section, res)
                print(json.dumps(out, ensure_ascii=False, indent=2))
            else:
                print(render_summary(out))
                if args.structured:
                    st = out["structured"]["stats"]
                    print("\n── 控制流结构化汇总（--structured；每函数明细用 --func）──")
                    print("函数 %d ｜ if %d / else %d / while %d / do-while %d / "
                          "for %d / switch %d（降级 %d）"
                          % (st["functions"], st["if"], st["else"], st["while"],
                             st["do_while"], st["for"], st["switch"],
                             st["switch_downgraded"]))
                    print("goto %d ｜ break %d ｜ continue %d ｜ 条件不可判 %d ｜ "
                          "goto 密集函数 %d" % (st["goto"], st["break"],
                                                st["continue"], st["cond_unknown"],
                                                st["goto_dense_functions"]))
                    print("不可约 %d 块（%d 个函数）｜ 不可达 %d 块 ｜ 可回溯违规 %d 项"
                          % (st["irreducible_blocks"], st["irreducible_functions"],
                             st["unreachable_blocks"], st["violations"]))
                if args.switch_candidates:
                    from . import switchcand
                    print(switchcand.render_candidates(
                        switchcand.analyze_binary(args.file, args.section, res)))
            return 0
        # 单函数模式
        res = recdesc.descend(args.file, args.section)
        sel = [f for f in list_functions(res) if f["addr"] == args.func]
        if not sel:
            print("rekit: %s: 函数 0x%x 不在已解范围内" % (args.file, args.func),
                  file=sys.stderr)
            return 2
        if sel[0]["boundary"] != "declared" and not args.include_inferred:
            print("rekit: %s: 函数 0x%x 边界未声明（无 .pdata/FDE/st_size）；"
                  "如确要提升请加 --include-inferred"
                  % (args.file, args.func), file=sys.stderr)
            return 2
        r = lift_function(res, args.func, _import_names(args.file))
        cand = None
        if args.switch_candidates:
            from . import switchcand
            cand = switchcand.analyze_function(res, args.func)
            r["switch_candidates"] = cand
        if args.structured:
            from . import struct as cstruct
            if cand is None:
                # switch 只在候选证据为 high 时才渲染，所以结构化必须能拿到候选；
                # 但候选报告本身仍只在 --switch-candidates 下单独输出（默认关闭语义不变）
                from . import switchcand
                cand = switchcand.analyze_function(res, args.func)
            r["structured"] = cstruct.structure_function(
                res, args.func, cand, lifted=r)
        print(json.dumps(r, ensure_ascii=False, indent=2) if args.json
              else render_function(r))
        if args.structured and not args.json:
            from . import struct as cstruct
            print("\n" + cstruct.render_function(r["structured"]))
        if args.switch_candidates and not args.json:
            from . import switchcand
            print(switchcand.render_candidates(r["switch_candidates"], single=True))
        return 0
    except ValueError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except (struct.error, IndexError) as e:
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
