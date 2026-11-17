#!/usr/bin/env python3
# rekit.recdesc — x86-64 递归下降 + 基本块划分（M4 第二单元）
#
# 与 disasm.py（线性扫描）的分工：
#   disasm 回答「从节首按字节规则能切出哪些边界」；
#   recdesc 回答「从工具链声明的入口出发，哪些边界真的会被执行到」。
#   两者结果必须分开报：线性扫描会跨过函数尾进入数据/填充，递归下降不会。
#
# 种子分级（本轮硬要求：权威与启发式不得混在同一个成功率里）：
#   权威 authoritative —— 由链接器/编译器写进文件的结构声明，不是我们猜的：
#     PE : 导出表 EAT、.pdata(RUNTIME_FUNCTION.BeginAddress)、AddressOfEntryPoint
#     ELF: ELF header e_entry、symtab/dynsym 的 STT_FUNC、.eh_frame 的 FDE
#          initial_location（CIE/FDE 解析见 _parse_eh_frame）
#          以及 Go 二进制的 .gopclntab 函数表（rekit.gopclntab，运行时必需表，
#          非调试信息；只覆盖 Go 函数，链接器标记另计）
#   启发式 heuristic —— 纯字节模式，可能落在指令中间/数据里：
#     函数序言模式（55 48 89 e5 / 55 48 8b ec）
#   派生 derived —— 递归下降过程中 call 直接目标（不是种子，是被发现的入口；
#     单独计数，既不混入权威成功率，也不混入启发式成功率）
#
# 下降规则（x86-64，只依赖 disasm._decode_any 的边界+opcode_map）：
#   jmp rel        → 只走向目标
#   jcc rel        → 目标 + 顺序后继
#   call rel       → 目标记为派生入口 + 顺序后继
#   ret/hlt/ud2/int3 → 当前路径结束
#   jmp/call 间接  → jmp 结束；call 继续顺序后继（目标不可静态确定，记为未解析）
#   其它           → 顺序后继
#   目标越界/落在另一条指令内部/解码失败（VEX/EVEX 等）→ 该路径 abstain 并记录，
#     绝不猜长度或强行对齐（abstain 的代价由 verify_recdesc 单独量化）。
#
# 基本块（M4 第三单元补全并写死规则）：
#   leader = 函数入口种子 ∪ 直接跳转/分支目标 ∪ 控制转移后的顺序地址
#            ∪ 指令所属函数（origin）变化处
#   终结符 = jmp_rel / jmp_ind / ret / hlt / trap / ud2（块末无顺序边）
#   call_rel / call_ind 不终结基本块：函数内 CFG 只保留顺序边，调用边单列
#   块只属于一个函数，绝不跨函数合并；函数边界来自权威声明的 end
#
# CFG 边分级（绝不把猜的边混进确定集）：
#   definite      确定边：函数有权威声明的 end，目标已解出且同属该函数
#   speculative   疑似边：目标/起点可解出，但该函数没有声明边界（分组是推断的），
#                 或该函数根来自启发式种子
#   cross_function 跨函数边：直接目标属于另一个函数（尾调用/跨函数分支），单列
#   undecoded     无法判定：直接目标未解出（数据/填充/VEX abstain）
#   unresolved    无法判定：间接 jmp/call，目标不可静态确定——目标写 None，不猜
#   调用边（call_rel/call_ind）单独放 calls，不混入函数内 CFG 边。
#
# R45 措辞（2026-11-15 裁决同步，只收敛口径、不放松判据）：
#   禁止的是「把猜测当已知」——候选目标不得写进 definite/speculative 计数、
#   不得当作确定边或表达式里的 case 目标；
#   不禁止「提出有证据的候选」——跳转表候选由 rekit.switchcand 在显式开关下
#   单列输出，标注证据等级与依据、列出被拒理由，且绝不修改本模块的任何输出。
#
# 已知盲区（也写进 CAVEATS，CLI 会打印）：
#   1) 只覆盖从种子可达的代码：无符号无 FDE 的函数、间接跳转目标、跳转表分支、
#      vtables/回调地址都不在种子里 → 不可达即不可见；
#   2) VEX/EVEX 未实现：命中即 abstain，当前路径停止（不是边界解错）；
#   3) 若权威种子本身有误（.pdata/FDE 指向数据），下降会把数据当指令，无法自证；
#   4) 不做数据/代码判别；函数范围只在符号/FDE/.pdata 有声明时可验证；
#   5) 不处理异常展开语义（.eh_frame 只取 FDE 起点，不解析 CFI 指令）；
#   6) 无声明边界的派生函数：其内部边只能记 speculated（无法证明没跨函数）。
import struct
from bisect import bisect_right

from . import disasm, elf, pe
from .errors import RekitError

CAVEATS = [
    "只覆盖从种子可达的代码：无符号/无 FDE 的函数、间接跳转目标、跳转表分支不可见",
    "VEX/EVEX（AVX/AVX-512）已解长度（M5 补表）；仅保留位非法的伪 AVX 编码会 "
    "abstain，不是边界解错",
    "权威种子本身若有误（.pdata/FDE 指向数据），下降会把数据当指令，无法自证",
    "不做数据/代码判别；函数范围仅在符号/FDE/.pdata 有声明时可验证",
    "不解析 .eh_frame 的 CFI 指令，只取 FDE 起点；异常处理路径不在覆盖内",
    "无声明边界的派生函数只能按已解出指令推断函数域，其内部边记为疑似边",
    "间接 jmp/call 目标不可静态确定：记为未解析（target=None），不猜目标；"
    "跳转表候选仅在 rekit.switchcand 单列（默认关闭），不进确定集（R45）",
    "Go 二进制：gopclntab 是链接器产出的运行时必需表（declared 级，非调试信息），"
    "提供函数入口/结束；只覆盖 Go 函数，go:buildid/textfips* 等链接器标记已排除并单列",
]

AUTH, HEUR, DERIVED = "authoritative", "heuristic", "derived"

# 函数序言字节模式（启发式；故意保留误报可能，成功率单独统计）
PROLOGUE_PATTERNS = [b"\x55\x48\x89\xe5", b"\x55\x48\x8b\xec"]   # 仅作文档参考

_TERMINATORS = {"ret", "hlt", "trap", "ud2", "jmp_rel", "jmp_ind"}
_COND = {"jcc_rel", "jcc_rel32", "loop_rel"}


# ── LEB128 / DWARF 编码读取（.eh_frame 专用） ─────────────────────────
def _uleb(b, p):
    r, s = 0, 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, p
        s += 7


def _sleb(b, p):
    r, s = 0, 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            if x & 0x40:
                r -= 1 << s
            return r, p


def _read_encoded(b, p, enc, field_va):
    """按 DW_EH_PE 编码读一个值。返回 (value, next_pos)。

    fmt = enc & 0x0f；application = enc & 0x70。
    只处理本机能见到的 absptr/uleb/sdata/udata + pcrel；其它编码抛 ValueError，
    由调用方记为「.eh_frame 不可解析」，不猜。
    """
    fmt = enc & 0x0F
    if fmt == 0x00:                       # absptr（ELF64 = 8 字节）
        v = struct.unpack_from("<Q", b, p)[0]
        p += 8
    elif fmt == 0x01:
        v, p = _uleb(b, p)
    elif fmt == 0x02:
        v = struct.unpack_from("<H", b, p)[0]
        p += 2
    elif fmt == 0x03:
        v = struct.unpack_from("<I", b, p)[0]
        p += 4
    elif fmt == 0x04:
        v = struct.unpack_from("<Q", b, p)[0]
        p += 8
    elif fmt == 0x09:
        v, p = _sleb(b, p)
    elif fmt == 0x0A:
        v = struct.unpack_from("<h", b, p)[0]
        p += 2
    elif fmt == 0x0B:
        v = struct.unpack_from("<i", b, p)[0]
        p += 4
    elif fmt == 0x0C:
        v = struct.unpack_from("<q", b, p)[0]
        p += 8
    else:
        raise ValueError("DW_EH_PE 格式 0x%x 未实现" % fmt)
    app = enc & 0x70
    if app == 0x10:                       # pcrel：相对编码字段本身的 VA
        v += field_va
    elif app == 0x00:
        pass
    else:
        raise ValueError("DW_EH_PE 应用 0x%x 未实现" % app)
    if enc & 0x80:
        # indirect：槽内存的是指针，需再解引用才能拿到目标。本实现只跳过这个
        # 字段（personality 指针），不解引用；对 FDE 起点（从不 indirect）无影响。
        pass
    return v, p


def _parse_eh_frame(data, sec):
    """.eh_frame → FDE 起点列表（函数入口）。

    结构：length(4) / CIE_pointer(4) / body；length==0 终止。
    CIE 的 augmentation 'zR' 给出 FDE 地址编码；FDE 的 initial_location 即函数起点。
    任何结构异常都停表并返回已解析部分 + error，不猜。
    """
    base_off, base_va, size = sec["offset"], sec["addr"], sec["size"]
    blob = data[base_off:base_off + size]
    cies = {}
    starts, err = [], None
    p = 0
    try:
        while p + 4 <= len(blob):
            field_va = base_va + p
            length = struct.unpack_from("<I", blob, p)[0]
            if length == 0:
                break
            hdr = 4
            if length == 0xFFFFFFFF:
                length = struct.unpack_from("<Q", blob, p + 4)[0]
                hdr = 12
            body = p + hdr
            end = body + length
            if end > len(blob):
                raise ValueError("记录越界 @0x%x" % p)
            cie_ptr = struct.unpack_from("<I", blob, body)[0]
            if cie_ptr == 0:
                # ---- CIE ----
                q = body + 4
                _version = blob[q]
                q += 1
                z = blob.index(b"\x00", q)
                aug = blob[q:z].decode("ascii", "replace")
                q = z + 1
                _ca, q = _uleb(blob, q)
                _da, q = _sleb(blob, q)
                _ret, q = _uleb(blob, q)
                fde_enc = 0x00
                if aug.startswith("z"):
                    aug_len, q = _uleb(blob, q)
                    aug_end = q + aug_len
                    for ch in aug[1:]:
                        if ch == "L":          # LSDA 编码
                            q += 1
                        elif ch == "R":        # FDE 指针编码
                            fde_enc = blob[q]
                            q += 1
                        elif ch == "P":        # personality：编码字节 + 指针
                            enc_p = blob[q]
                            q += 1
                            _v, q = _read_encoded(blob, q, enc_p, base_va + q)
                        elif ch in "SBG":
                            pass
                        else:
                            raise ValueError("CIE augmentation %r 未实现" % aug)
                    q = aug_end
                cies[field_va] = fde_enc
            else:
                # ---- FDE：cie_ptr 相对 [CIE_pointer 字段自身] 的 VA ----
                # 规范：cie_ptr = 本字段地址 - CIE 地址；不是相对 length 字段
                cie_va = (base_va + body) - cie_ptr
                if cie_va not in cies:
                    raise ValueError("FDE @0x%x 引用未知 CIE 0x%x"
                                     % (field_va, cie_va))
                enc = cies[cie_va]
                q = body + 4
                loc, q = _read_encoded(blob, q, enc, base_va + q)
                rng, q = _read_encoded(blob, q, enc & 0x0F, base_va + q)
                starts.append((loc, rng, "fde@0x%x" % field_va))
            p = end
    except (ValueError, IndexError, struct.error) as e:
        err = str(e)
    return starts, err


# ── 种子采集 ─────────────────────────────────────────────────────────
def _in_section(addr, sec):
    return sec["va"] <= addr < sec["va"] + sec["size"]


def _seed_add(bucket, addr, source, authority, detail="", end=None):
    ent = bucket.setdefault(addr, {"addr": addr, "sources": [], "authority": authority,
                                   "details": [], "end": None, "end_by_source": {}})
    ent["sources"].append(source)
    ent["details"].append(detail)
    if end and end > addr:
        # 函数结束地址：FDE range / symtab st_size / .pdata EndAddress / gopclntab
        # 下一入口，多源互证。取较大值避免某源 size 偏小把真实尾部截断；
        # 逐源留档（end_by_source），差异写进 details 供审计与归因。
        ent["end_by_source"][source] = end
        if ent["end"] is None:
            ent["end"] = end
        elif ent["end"] != end:
            ent["details"].append("end 冲突: 0x%x vs 0x%x（%s vs %s）"
                                  % (ent["end"], end,
                                     ",".join(k for k, v in ent["end_by_source"].items()
                                              if v == ent["end"]) or "?",
                                     source))
            ent["end"] = max(ent["end"], end)
    # 同一地址若同时被权威与启发式覆盖，按权威记（但 sources 保留两条，便于审计）
    if authority == AUTH:
        ent["authority"] = AUTH


def _add_gopclntab(seeds, notes, path, image_base, extra):
    """把 Go pclntab 的函数入口/结束作为 declared 级种子合入。

    与 entry/symtab_func/dynsym_func/eh_frame_fde/pdata/export 并列，source="gopclntab"：
    它是链接器产出的运行时必需表，不是调试信息，也不是字节模式猜测。
    只排除链接器标记（go:buildid / go:textfips*），它们不是函数代码，单列计数。
    """
    from . import gopclntab
    r = gopclntab.parse(path)
    summary = {"status": r["status"], "version": r.get("version"),
               "nfunc": r.get("nfunc", 0), "n_markers": r.get("n_markers", 0),
               "reason": r.get("reason"), "where": r.get("where"),
               "warnings": list(r.get("warnings") or [])}
    if extra is not None:
        extra["gopclntab"] = summary
    if r["status"] != "ok":
        notes.append("gopclntab: %s（%s）" % (r["status"], r.get("reason")))
        return
    added = 0
    for f in r["funcs"]:
        if f["is_marker"]:
            continue
        _seed_add(seeds, f["entry"] - image_base, "gopclntab", AUTH,
                  "%s [%s]" % (f["name"], r["version"]),
                  end=f["end"] - image_base)
        added += 1
    notes.append("gopclntab %s：%d 个函数入口（表内 %d 条，已排除链接器标记 %d 条）"
                 % (r["version"], added, r["nfunc"], r["n_markers"]))


def collect_seeds(path, section=".text", gopclntab=True, extra=None):
    """返回 (sec, seeds, rejected, notes, fmt)。seeds 已按地址去重。

    rejected: 落在节外/地址为 0 的种子（不静默丢弃，报告里可见）。
    gopclntab=False 可关闭 Go pclntab 种子（A/B 对照用，默认开启）。
    extra: 可选 dict，回填 {"gopclntab": 解析摘要}，避免调用方重复解析。
    """
    data = open(path, "rb").read()
    sec = disasm.find_section(path, section)
    if sec is None:
        raise ValueError("找不到可分析的节 %s" % section)
    seeds, rejected, notes = {}, [], []
    if data[:4] == b"\x7fELF":
        fmt = "elf"
        r = elf.parse(path)
        # 1) ELF header 入口（权威）
        _seed_add(seeds, r["entry"], "entry", AUTH, "e_entry")
        # 2) symtab/dynsym 的 STT_FUNC（权威；st_value 即 VA）
        for key in ("symtab", "dynsym"):
            for (nm, val, sz, _bd, ty, ndx) in (r["symbols"].get(key) or []):
                if ty != "FUNC" or not val:
                    continue
                _seed_add(seeds, val, "%s_func" % key, AUTH, nm or "(anon)",
                          end=val + sz if sz else None)
        # 3) .eh_frame FDE 起点（权威）
        eh = next((s for s in elf.section_headers(data) if s["name"] == ".eh_frame"
                   and s["size"] > 0), None)
        if eh is None:
            notes.append("没有 .eh_frame 节：缺少 FDE 种子")
        else:
            fdes, err = _parse_eh_frame(data, eh)
            for (va, rng, detail) in fdes:
                _seed_add(seeds, va, "eh_frame_fde", AUTH, detail,
                          end=va + rng if rng else None)
            notes.append(".eh_frame FDE 起点 %d 个%s"
                         % (len(fdes), "" if not err else "（解析中断：%s）" % err))
        # 4) Go pclntab（权威；VA 与 ELF 地址空间一致）
        if gopclntab:
            _add_gopclntab(seeds, notes, path, 0, extra)
    elif data[:2] == b"MZ":
        fmt = "pe"
        r = pe.parse(path)
        # 1) 入口点（权威，RVA）
        _seed_add(seeds, r["entry"], "entry", AUTH, "AddressOfEntryPoint")
        # 2) 导出表 EAT（权威，RVA）
        ex = r["exports"]
        if ex:
            for (nm, _ord, rva) in ex["exports"]:
                if rva:
                    _seed_add(seeds, rva, "export", AUTH, nm or "(ordinal)")
        # 3) .pdata RUNTIME_FUNCTION.BeginAddress（权威，RVA）
        pd = next((s for s in r["sections"] if s[4] == ".pdata" and s[3] > 0), None)
        if pd is None:
            notes.append("没有 .pdata 节：缺少异常表种子")
        else:
            vaddr, vsize, rawptr, rawsize, _nm = pd
            n = min(vsize or rawsize, rawsize) // 12
            for i in range(n):
                begin, end, _unwind = struct.unpack_from(
                    "<III", data, rawptr + i * 12)
                if begin:
                    _seed_add(seeds, begin, "pdata", AUTH,
                              "range 0x%x..0x%x" % (begin, end), end=end)
            notes.append(".pdata RUNTIME_FUNCTION %d 条" % n)
        # 4) Go pclntab（权威；表内是 VA，PE 种子地址空间是 RVA → 减去 image_base）
        if gopclntab:
            _add_gopclntab(seeds, notes, path, r["image_base"], extra)
    else:
        raise ValueError("无法识别的格式（非 ELF / 非 PE）")

    # 过滤到目标节；节外种子不参与下降，但必须可见
    kept = {}
    for addr, ent in seeds.items():
        if _in_section(addr, sec):
            kept[addr] = ent
        else:
            rejected.append({"addr": addr, "sources": ent["sources"],
                             "authority": ent["authority"], "reason": "不在节内"})
    return sec, kept, rejected, notes, fmt


def _prologue_len(blob, i):
    """i 处是否是「push rbp; mov rbp, rsp」序言起点；返回匹配字节数（0 = 不是）。

    按 opcode 判（M8-U0 / R71），不按字面字节：
      · push 必须是 0x55；REX 只允许 0x48（REX.R/X/B 会把它变成别的寄存器，
        `41 55` 是 push r13，不是序言）；
      · push 与 mov 之间允许 legacy 前缀（字面模式会在这里漏）；
      · mov 允许 0x89/0xE5 或 0x8B/0xEC，且必须带 REX.W。
    """
    n = len(blob)
    if i >= n or blob[i] != 0x55:
        return 0
    j = i + 1
    while j < n and blob[j] in disasm._LEGACY_PREFIX:
        j += 1
    if j < n and 0x40 <= blob[j] <= 0x4F:
        if blob[j] != 0x48:
            return 0
        j += 1
    if j + 1 >= n:
        return 0
    if (blob[j] == 0x89 and blob[j + 1] == 0xE5) or \
            (blob[j] == 0x8B and blob[j + 1] == 0xEC):
        return j + 2 - i
    return 0


def collect_heuristic_seeds(path, section=".text", cap=4096):
    """函数序言扫描 → 启发式种子（单独一组，不与权威混算）。

    判据见 _prologue_len（R71：跳前缀取 opcode）。实测三样本与字面字节模式
    命中数相同（1/1/25），差异只在判据正确性，不在样本数字。
    """
    data = open(path, "rb").read()
    sec = disasm.find_section(path, section)
    if sec is None:
        return {}
    blob = data[sec["off"]:sec["off"] + sec["size"]]
    out = {}
    for i in range(len(blob)):
        n = _prologue_len(blob, i)
        if n and len(out) < cap:
            _seed_add(out, sec["va"] + i, "prologue_scan", HEUR, blob[i:i + n].hex())
    return out


# ── 指令流分类 ───────────────────────────────────────────────────────
def _raw(ins):
    return bytes.fromhex(ins["bytes"].replace(" ", ""))


def _disp(ins, n):
    return int.from_bytes(_raw(ins)[-n:], "little", signed=True)


def _modrm_byte(ins):
    b = _raw(ins)
    i = 0
    while i < len(b) and b[i] in disasm._LEGACY_PREFIX:
        i += 1
    if i < len(b) and 0x40 <= b[i] <= 0x4F:
        i += 1
    if i >= len(b):
        return None
    op = b[i]
    i += 1
    if op == 0x0F:
        if i >= len(b):
            return None
        op2 = b[i]
        i += 1
        if op2 in (0x38, 0x3A):
            i += 1
    return b[i] if i < len(b) else None


def classify(ins):
    """返回 (kind, target_addr|None)。kind ∈ next/jmp_rel/jcc_rel/jcc_rel32/
    loop_rel/call_rel/ret/jmp_ind/call_ind/hlt/trap/ud2。"""
    op, m, addr, ln = ins["opcode"], ins["opcode_map"], ins["addr"], ins["length"]
    nxt = addr + ln
    if m == 1:
        if op == 0xE8:
            return "call_rel", nxt + _disp(ins, 4)
        if op == 0xE9:
            return "jmp_rel", nxt + _disp(ins, 4)
        if op == 0xEB:
            return "jmp_rel", nxt + _disp(ins, 1)
        if 0x70 <= op <= 0x7F:
            return "jcc_rel", nxt + _disp(ins, 1)
        if 0xE0 <= op <= 0xE3:
            return "loop_rel", nxt + _disp(ins, 1)
        if op in (0xC2, 0xC3, 0xCA, 0xCB, 0xCF):
            return "ret", None
        if op == 0xF4:
            return "hlt", None
        if op == 0xCC:
            return "trap", None
        if op == 0xFF:
            mb = _modrm_byte(ins)
            reg = (mb >> 3) & 7 if mb is not None else -1
            if reg in (4, 5):
                return "jmp_ind", None
            if reg in (2, 3):
                return "call_ind", None
    elif m == 2:
        if op == 0x0B:
            return "ud2", None
        if 0x80 <= op <= 0x8F:
            return "jcc_rel32", nxt + _disp(ins, 4)
    return "next", None


# ── 递归下降 ─────────────────────────────────────────────────────────
class _Decoder:
    def __init__(self, data, sec):
        self.data = data
        self.sec = sec
        self.start = sec["off"]
        self.end = sec["off"] + sec["size"]
        self.last_category = None      # 最近一次 decode 的弃权类别（M9 归因用）

    def decode(self, addr):
        """返回 (ins, None) 或 (None, reason)；类别留在 self.last_category。"""
        if not _in_section(addr, self.sec):
            self.last_category = "outside_section"
            return None, "目标不在节内"
        pos = self.start + (addr - self.sec["va"])
        try:
            ln, meta = disasm._decode_any(self.data, pos, self.end)
        except disasm.Unsupported as e:
            self.last_category = e.category
            return None, e.reason
        if pos + ln > self.end:
            self.last_category = "truncated"
            return None, "指令跨出节尾"
        self.last_category = None
        return {"addr": addr, "off": pos, "length": ln,
                "bytes": self.data[pos:pos + ln].hex(" "),
                "opcode": meta.get("opcode"),
                "opcode_map": meta.get("opcode_map")}, None


def descend(path, section=".text", include_heuristic=False, seed_cap=4096,
            gopclntab=True):
    extra = {}
    sec, auth_seeds, rejected, notes, fmt = collect_seeds(
        path, section, gopclntab=gopclntab, extra=extra)
    data = open(path, "rb").read()
    dec = _Decoder(data, sec)

    seeds = dict(auth_seeds)
    if include_heuristic:
        for addr, ent in collect_heuristic_seeds(path, section, seed_cap).items():
            if addr in seeds:
                seeds[addr]["sources"].extend(ent["sources"])
                seeds[addr]["details"].extend(ent["details"])
            else:
                seeds[addr] = ent

    # 权威函数范围（start,end）：CFG 的硬边界。只收有 end 的权威种子。
    ranges = sorted((e["addr"], e["end"]) for e in seeds.values()
                    if e["authority"] == AUTH and e.get("end"))
    range_starts = [r[0] for r in ranges]

    def range_of(addr):
        """addr 落在哪个权威声明函数范围内；没有声明则 None。"""
        i = bisect_right(range_starts, addr) - 1
        if i >= 0 and addr < ranges[i][1]:
            return ranges[i]
        return None

    # 种子按地址排序，队列用索引推进（BFS，确定性输出）
    queue = [{"addr": a, "authority": e["authority"],
              "sources": list(e["sources"]), "end": e.get("end"), "origin": a}
             for a, e in sorted(seeds.items())]
    insns = {}                    # addr -> ins（允许重叠起点，x86 合法）
    covered = bytearray(sec["size"])   # 字节联合覆盖（重叠只算一次）
    va0 = sec["va"]
    overlaps, abstains, outside = [], [], []
    seed_hits = {}

    def seed_end(addr):
        e = seeds.get(addr)
        return e.get("end") if e else None

    def enqueue(addr, authority, source, end=None, origin=None):
        queue.append({"addr": addr, "authority": authority,
                      "sources": [source], "end": end,
                      "origin": addr if origin is None else origin})

    qi = 0
    while qi < len(queue):
        root = queue[qi]
        qi += 1
        cur = root["addr"]
        limit = root.get("end")
        if cur in insns:
            # 已被别的路径解过：种子命中的一种（不算漏检）
            seed_hits.setdefault(cur, "ok")
            continue

        def tgt_limit(tgt):
            # 目标在当前函数范围内 → 继承函数结束界，防止顺序流外溢到填充/下一函数；
            # 跳出范围（尾调用/分支到别处）→ 用目标自身已知的函数范围（若有）。
            if limit is not None and root["addr"] <= tgt < limit:
                return limit
            return seed_end(tgt)

        while True:
            if limit is not None and cur >= limit:
                break                    # 已到声明函数范围末尾，不再顺序外溢
            r_here = range_of(cur)
            if (r_here is not None and limit is None
                    and not (r_here[0] <= root["origin"] < r_here[1])):
                # 无声明边界的函数顺序流入另一个已声明函数：函数边界交给
                # 该函数自己的种子，绝不把两个函数合成一段。
                break
            if cur in insns or not _in_section(cur, sec):
                break
            ins, err = dec.decode(cur)
            if err:
                bucket = abstains if ("VEX" in err or "EVEX" in err) else outside
                bucket.append({"addr": cur, "reason": err,
                               "category": dec.last_category,
                               "root": root["sources"][0]})
                if cur == root["addr"]:
                    seed_hits[root["addr"]] = err
                break
            end = cur + ins["length"]
            if limit is not None and end > limit:
                # 指令跨出声明范围：不截断指令，也不把它算进本函数
                outside.append({"addr": cur,
                                "reason": "越过函数声明范围 0x%x" % limit,
                                "root": root["sources"][0]})
                break
            o0, o1 = cur - va0, end - va0
            if any(covered[o0:o1]):
                # x86 允许重叠解码（典型：jcc 跳过 lock 前缀，目标落在前一条指令内部）
                overlaps.append({"addr": cur, "from": root["sources"][0],
                                 "bytes": ins["bytes"]})
            insns[cur] = ins
            ins["origin"] = root["origin"]
            covered[o0:o1] = b"\x01" * (o1 - o0)
            if cur in seeds and cur not in seed_hits:
                seed_hits[cur] = "ok"
            kind, tgt = classify(ins)
            if kind == "call_rel":
                r = range_of(tgt)
                if r is not None:
                    # 调用目标落在权威声明函数内：以该函数为 origin 和边界
                    enqueue(tgt, DERIVED, "call@0x%x" % cur, r[1], origin=r[0])
                else:
                    enqueue(tgt, DERIVED, "call@0x%x" % cur, tgt_limit(tgt))
            elif kind in _COND or kind == "jmp_rel":
                tag = ("branch@0x%x" if kind in _COND else "jmp@0x%x") % cur
                r = range_of(tgt)
                if limit is not None and root["addr"] <= tgt < limit:
                    enqueue(tgt, DERIVED, tag, limit, origin=root["origin"])
                elif r is not None:
                    # 目标落在另一个权威声明的函数里：边界以声明为准
                    # （尾调用/跨函数分支；CFG 里单列为 cross_function）
                    enqueue(tgt, DERIVED, tag, r[1], origin=r[0])
                else:
                    base = seeds.get(root["origin"]) or {}
                    if base.get("end"):
                        # 当前函数有声明边界，目标却不在任何声明范围内：
                        # 不得把界外代码算进本函数 → 另起边界未知的新根
                        enqueue(tgt, DERIVED, tag, None)
                    else:
                        # 当前函数本身没有声明边界：沿用函数身份，边记「疑似」
                        enqueue(tgt, DERIVED, tag, None, origin=root["origin"])
            if kind in _TERMINATORS:
                break
            # call_ind 的目标不可静态确定，但顺序流继续
            cur = end

    # ---- 种子逐类统计（权威/启发式/派生分开，绝不合并成功率） ----
    def rate(cls):
        total = [a for a, e in seeds.items() if e["authority"] == cls]
        ok = [a for a in total if seed_hits.get(a) == "ok"]
        return {"total": len(total), "hit": len(ok),
                "ratio": (len(ok) / len(total)) if total else None,
                "misses": [{"addr": a, "reason": seed_hits.get(a, "未被调度")}
                           for a in total if seed_hits.get(a) != "ok"]}

    derived_total = sum(1 for r in queue if r["authority"] == DERIVED)
    derived_hit = sum(1 for r in queue if r["authority"] == DERIVED
                      and seed_hits.get(r["addr"]) == "ok")
    # 声明级种子按来源逐项计数（R99：绝不把 entry/symtab/fde/pdata/gopclntab
    # 合并成一个不区分的「已声明」总数；一个种子可被多源声明，故给两种口径）
    by_source, only_source = {}, {}
    conf_seeds, conf_pairs, conf_deltas = 0, {}, []
    for e in seeds.values():
        if e["authority"] != AUTH:
            continue
        srcs = sorted(set(e["sources"]))
        for s in srcs:
            by_source[s] = by_source.get(s, 0) + 1
        if len(srcs) == 1:
            only_source[srcs[0]] = only_source.get(srcs[0], 0) + 1
        eb = {k: v for k, v in (e.get("end_by_source") or {}).items() if v}
        if len(eb) >= 2 and len(set(eb.values())) > 1:
            # 两源声明的函数结束不一致：按「哪一源更短」逐对归因，不静默取大值
            conf_seeds += 1
            lo = min(eb, key=eb.get)
            hi = max(eb, key=eb.get)
            pair = "%s <%s" % (lo, hi)
            conf_pairs[pair] = conf_pairs.get(pair, 0) + 1
            conf_deltas.append(eb[hi] - eb[lo])
    delta_hist = {}
    for d in conf_deltas:
        delta_hist[d] = delta_hist.get(d, 0) + 1
    seed_stats = {
        AUTH: rate(AUTH),
        HEUR: rate(HEUR),
        DERIVED: {"total": derived_total, "hit": derived_hit,
                  "ratio": (derived_hit / derived_total) if derived_total else None},
        "declared_by_source": by_source,
        "declared_only_by_source": only_source,
        "end_conflicts": {
            "seeds": conf_seeds,
            "by_pair": dict(sorted(conf_pairs.items(),
                                   key=lambda kv: -kv[1])[:8]),
            "pairs_total": len(conf_pairs),
            "delta_min": min(conf_deltas) if conf_deltas else None,
            "delta_max": max(conf_deltas) if conf_deltas else None,
            "delta_hist": dict(sorted(delta_hist.items(),
                                      key=lambda kv: -kv[1])[:8]),
        },
    }

    ins_list = [insns[a] for a in sorted(insns)]
    blocks = _build_blocks(ins_list, seeds)
    cfg = _build_cfg(blocks, ins_list, seeds)
    bytes_covered = sum(covered)
    return {
        "path": str(path), "format": fmt, "section": sec,
        "seeds": list(seeds.values()), "rejected_seeds": rejected,
        "seed_stats": seed_stats, "notes": notes,
        "gopclntab": extra.get("gopclntab"),
        "instructions": ins_list, "blocks": blocks, "cfg": cfg,
        "stats": {
            "instructions": len(ins_list),
            "instruction_bytes": sum(i["length"] for i in ins_list),
            "bytes_covered": bytes_covered,
            "section_size": sec["size"],
            "coverage": (bytes_covered / sec["size"]) if sec["size"] else None,
            "blocks": len(blocks),
            "abstains": len(abstains),
            "overlaps": len(overlaps),
            "outside": len(outside),
            "edges_definite": cfg["counts"]["definite"],
            "edges_speculative": cfg["counts"]["speculative"],
            "edges_unresolved": cfg["counts"]["unresolved"],
            "edges_cross_function": cfg["counts"]["cross_function"],
            "edges_undecoded": cfg["counts"]["undecoded"],
            "calls_definite": cfg["call_counts"]["definite"],
            "calls_unresolved": cfg["call_counts"]["unresolved"],
            "calls_undecoded": cfg["call_counts"]["undecoded"],
        },
        "abstains": abstains, "overlaps": overlaps, "outside": outside,
        "caveats": list(CAVEATS),
    }


def _build_blocks(ins_list, seeds):
    """按 leader 划分基本块（规则见文件头）。

    leader：函数入口种子 / 直接分支目标 / 非 call 转移后的顺序地址 /
            指令所属函数（origin）变化处。
    call 不终结块：函数内 CFG 只保留顺序边，调用目标单列到 cfg.calls。
    每块带 function/range/boundary：块只属于一个函数，绝不跨函数合并。
    """
    if not ins_list:
        return []
    by_addr = {i["addr"]: i for i in ins_list}
    leaders = set(a for a in seeds if a in by_addr)
    succ_map = {}
    for ins in ins_list:
        kind, tgt = classify(ins)
        succ_map[ins["addr"]] = (kind, tgt)
        if tgt is not None and tgt in by_addr:
            leaders.add(tgt)
        end = ins["addr"] + ins["length"]
        if kind != "next" and kind not in ("call_rel", "call_ind"):
            if end in by_addr:
                leaders.add(end)
    blocks = []
    cur = None
    prev_end = None
    for ins in ins_list:
        a = ins["addr"]
        kind, _tgt = succ_map[a]
        func = ins.get("origin")
        if (cur is None or a in leaders or prev_end != a
                or cur["function"] != func):
            if cur is not None:
                blocks.append(cur)
            ent = seeds.get(func) or {}
            cur = {"start": a, "end": a, "insns": [], "terminator": "next",
                   "successors": [], "function": func,
                   "range": [func, ent.get("end")],
                   "boundary": "declared" if ent.get("end") else "unknown",
                   "authority": ent.get("authority", DERIVED)}
        cur["insns"].append(a)
        cur["end"] = a + ins["length"]
        cur["terminator"] = kind
        prev_end = a + ins["length"]
    if cur is not None:
        blocks.append(cur)
    for b in blocks:
        term = b["terminator"]
        last = by_addr[b["insns"][-1]]
        _kind, tgt = succ_map[last["addr"]]
        succ = []
        if term in _COND:
            if tgt is not None:
                succ.append(tgt)
            if b["end"] in by_addr:
                succ.append(b["end"])
        elif term == "jmp_rel":
            if tgt is not None:
                succ.append(tgt)
        elif term in ("call_rel", "call_ind", "next"):
            if b["end"] in by_addr:
                succ.append(b["end"])
        # successors 只收本函数内的确定目标；跨函数/未解出在 cfg 单列
        b["successors"] = [s for s in succ
                           if s in by_addr
                           and by_addr[s].get("origin") == b["function"]]
    return blocks


_EDGE_CLASSES = ("definite", "speculative", "unresolved",
                 "cross_function", "undecoded")
_CALL_CLASSES = ("definite", "unresolved", "undecoded")


def _build_cfg(blocks, ins_list, seeds):
    """函数内 CFG：边按证据强度分级，调用边单列（不混入函数内图）。

    definite       源函数有权威声明 end、根非启发式；目标已解出且同函数
    speculative    目标已解出且同函数，但函数边界未声明或根来自启发式
    cross_function 直接目标属于另一个函数（按 origin 判定），单列
    undecoded      直接目标未解出（数据/填充/VEX abstain）
    unresolved     间接 jmp/call：target=None，不猜目标
    """
    by_addr = {i["addr"]: i for i in ins_list}
    block_of = {}
    for b in blocks:
        for a in b["insns"]:
            block_of[a] = b["start"]
    edges = {k: [] for k in _EDGE_CLASSES}
    calls = {k: [] for k in _CALL_CLASSES}

    def declared(func):
        e = seeds.get(func)
        return bool(e and e.get("end"))

    def authority(func):
        e = seeds.get(func)
        return e["authority"] if e else DERIVED

    def add(block, to, kind):
        rec = {"from": block["start"], "to": to, "kind": kind}
        if to is None:
            edges["unresolved"].append(dict(rec, reason="间接目标不可静态确定"))
            return
        t = by_addr.get(to)
        if t is None:
            edges["undecoded"].append(dict(
                rec, reason="目标未解出（数据/填充/abstain）"))
            return
        if t.get("origin") != block["function"]:
            tf = t.get("origin")
            tent = seeds.get(tf) or {}
            edges["cross_function"].append(dict(
                rec, to_function=tf, to_block=block_of.get(to),
                to_boundary="declared" if tent.get("end") else "unknown"))
            return
        conf = ("definite" if (declared(block["function"])
                              and authority(block["function"]) != HEUR)
                else "speculative")
        edges[conf].append(dict(rec, to_block=block_of.get(to)))

    for b in blocks:
        last = by_addr[b["insns"][-1]]
        kind, tgt = classify(last)
        # 函数末尾不是顺序边：块结束地址等于声明 end 时，后面的字节即使
        # 已被别的函数解出，也不得连成 fallthrough（那是函数边界，不是控制流）
        can_fall = (b["boundary"] != "declared"
                    or b["end"] < b["range"][1])
        if kind in ("next", "call_rel", "call_ind"):
            if can_fall and b["end"] in by_addr:
                add(b, b["end"], "fallthrough")
        elif kind in _COND:
            add(b, tgt, "taken")
            if can_fall and b["end"] in by_addr:
                add(b, b["end"], "fallthrough")
        elif kind == "jmp_rel":
            add(b, tgt, "taken")
        elif kind == "jmp_ind":
            add(b, None, "jmp_ind")
        # ret/hlt/trap/ud2：无出边
        if kind == "call_rel":
            if tgt is None:
                calls["unresolved"].append({"from": last["addr"], "to": None})
            elif tgt in by_addr:
                calls["definite"].append({"from": last["addr"], "to": tgt})
            else:
                calls["undecoded"].append({"from": last["addr"], "to": tgt,
                                           "reason": "调用目标未解出"})
        elif kind == "call_ind":
            calls["unresolved"].append({"from": last["addr"], "to": None,
                                        "reason": "间接调用目标不可静态确定"})

    funcs = sorted(set(i.get("origin") for i in ins_list
                       if i.get("origin") is not None))
    function_stats = {"declared": 0, "unknown": 0}
    for f in funcs:
        function_stats["declared" if declared(f) else "unknown"] += 1
    return {
        "edges": edges, "calls": calls,
        "counts": {k: len(v) for k, v in edges.items()},
        "call_counts": {k: len(v) for k, v in calls.items()},
        "function_stats": function_stats,
        "classes": list(_EDGE_CLASSES),
    }


# ── 渲染 / CLI ──────────────────────────────────────────────────────
def render_text(res):
    sec = res["section"]
    st = res["stats"]
    ss = res["seed_stats"]
    lines = [
        "RECDESC: %s  section=%s  VA=0x%x  off=0x%x  size=0x%x"
        % (res["path"], sec["name"], sec["va"], sec["off"], sec["size"]),
        "指令 %d 条 / 覆盖 %d 字节（%.2f%%）/ 基本块 %d 个"
        % (st["instructions"], st["bytes_covered"],
           100 * (st["coverage"] or 0), st["blocks"]),
        "种子成功率（分类单列，不合并）:",
    ]
    for cls, label in ((AUTH, "权威 authoritative"),
                       (HEUR, "启发式 heuristic"),
                       (DERIVED, "派生 derived")):
        r = ss[cls]
        lines.append("  %-20s %d/%d%s" % (
            label, r["hit"], r["total"],
            "" if r["ratio"] is None else "  = %.2f%%" % (100 * r["ratio"])))
    if res["abstains"]:
        lines.append("abstain %d 处（VEX/EVEX 等，当前路径停止）:" % len(res["abstains"]))
        for a in res["abstains"][:10]:
            lines.append("  ! addr=0x%x reason=%s root=%s"
                         % (a["addr"], a["reason"], a["root"]))
    if res["overlaps"]:
        lines.append("重叠解码 %d 处（x86 合法：例如 jcc 跳过 lock 前缀）:"
                     % len(res["overlaps"]))
        for c in res["overlaps"][:10]:
            lines.append("  ~ addr=0x%x from=%s bytes=%s"
                         % (c["addr"], c["from"], c["bytes"]))
    cfg = res.get("cfg") or {}
    cnt, cc = cfg.get("counts") or {}, cfg.get("call_counts") or {}
    if cnt:
        lines.append("CFG（函数内边分级，不合并；调用边单列）:")
        lines.append("  确定 %d ｜ 疑似 %d ｜ 跨函数 %d ｜ 目标未解出 %d ｜ 未解析 %d"
                     % (cnt.get("definite", 0), cnt.get("speculative", 0),
                        cnt.get("cross_function", 0), cnt.get("undecoded", 0),
                        cnt.get("unresolved", 0)))
        lines.append("  调用边：确定 %d ｜ 目标未解出 %d ｜ 未解析 %d（间接，不猜目标）"
                     % (cc.get("definite", 0), cc.get("undecoded", 0),
                        cc.get("unresolved", 0)))
        fs = cfg["function_stats"]
        lines.append("  函数：声明边界 %d 个 ｜ 边界未知 %d 个"
                     % (fs["declared"], fs["unknown"]))
        if cnt.get("definite", 0) == 0:
            total_edges = sum(cnt.values())
            if total_edges == 0:
                branchy = any((b.get("terminator") or "").startswith(("jcc", "jmp"))
                              for b in res["blocks"])
                if branchy:
                    lines.append("  ！确定边为 0：解出的 %d 个基本块里有跳转/分支指令，"
                                 "但目标全部未解出或不可静态确定，没有一条边能记为确定"
                                 "——不是‘没有控制流’，是目标不可达/不可判定"
                                 % len(res["blocks"]))
                else:
                    lines.append("  ！确定边为 0：解出的 %d 个基本块里没有任何跳转/分支"
                                 "指令（只有 ret 与顺序指令，例如单条 ret 桩函数）"
                                 "——本样本确实没有函数内控制流"
                                 % len(res["blocks"]))
            elif fs["declared"] == 0:
                lines.append("  ！确定边为 0：本样本没有权威声明的函数结束界"
                             "（.pdata/FDE/st_size），无法给边打‘确定’标签；"
                             "%d 条边只能记疑似/跨函数/未解析——不代表没有控制流"
                             % total_edges)
            else:
                lines.append("  ！确定边为 0：本样本仅 %d 个函数有声明结束界，"
                             "其余函数边界未知；%d 条边只能记疑似/跨函数/未解析"
                             "——不代表没有控制流" % (fs["declared"], total_edges))
        for e in cfg["edges"]["cross_function"][:5]:
            lines.append("  · 跨函数 %s 0x%x -> 0x%x（函数 0x%x）"
                         % (e["kind"], e["from"], e["to"],
                            e["to_function"] or 0))
        for e in cfg["edges"]["unresolved"][:5]:
            lines.append("  · 未解析 %s @0x%x（目标不猜）" % (e["kind"], e["from"]))
    lines.append("caveats（递归下降盲区，可达才可见）:")
    for c in res["caveats"]:
        lines.append("  ! %s" % c)
    for b in res["blocks"][:100]:
        lines.append("  block 0x%x..0x%x fn=0x%x %d insns  %-9s succ=%s"
                     % (b["start"], b["end"], b["function"] or 0,
                        len(b["insns"]), b["terminator"],
                        ",".join("0x%x" % s for s in b["successors"]) or "-"))
    if len(res["blocks"]) > 100:
        lines.append("  ...（共 %d 个基本块，仅显示前 100 个）" % len(res["blocks"]))
    return "\n".join(lines)


def main(argv=None):
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(
        prog="rekit recdesc",
        description="x86-64 递归下降 + 基本块划分（种子分权威/启发式/派生）")
    ap.add_argument("file")
    ap.add_argument("--section", default=".text")
    ap.add_argument("--heuristic", action="store_true",
                    help="额外加入函数序言模式种子（单独计数，不混入权威成功率）")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        with open(args.file, "rb"):
            pass
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    try:
        res = descend(args.file, args.section, args.heuristic)
    except ValueError as e:
        print("rekit: %s: %s" % (args.file, e), file=sys.stderr)
        return 2
    except (struct.error, IndexError, RekitError) as e:
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(render_text(res))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
