#!/usr/bin/env python3
# rekit.mcp — MCP (Model Context Protocol) stdio 服务器（M1.5，2026-11-15）
#
# 设计要点（防坑先行，参照 JSON-RPC 2.0 + MCP stdio 规范）：
#   1. 帧格式：每行一条 JSON，禁止内嵌换行；响应必须 flush（否则客户端死等——经典坑）
#   2. stdout 是协议通道：任何日志/错误信息只走 stderr
#   3. 通知（无 id 字段）不产生响应；带 id 的未知方法 → -32601
#   4. 工具执行错误（文件不存在/格式不识别/解析失败）→ isError:true 的正常响应，
#      协议层错误（未知方法/坏帧）才用 JSON-RPC error —— 两层错误语义分开
#   5. 段名采用 readelf 风格（GNU_EH_FRAME 而非 EH_FRAME），交叉验证可直接对拍
import json
import os
import sys

from . import elf, pe, fingerprint
from .cli import detect_format

# 支持的 MCP 协议版本（新→旧）；客户端版本在列表内则回显，否则回最新
SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
LATEST = SUPPORTED_VERSIONS[0]

# readelf 风格段名表（覆盖 elf.PT_TYPES 的非 GNU 前缀命名，仅 MCP 层使用）
PT_NAMES = dict(elf.PT_TYPES)
PT_NAMES.update({0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
                 0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY"})

MACHINE_ARCH = {62: "x86-64", 183: "AArch64", 40: "ARM", 3: "x86",
                8: "MIPS", 243: "RISC-V", 50: "IA-64"}
ET_NAMES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


class ToolError(Exception):
    """工具级错误 → isError:true 响应（连接存活，服务器不崩）"""


def _require_path(args):
    path = args.get("path")
    if not path:
        raise ToolError("缺少必需参数 path")
    if not os.path.exists(path):
        raise ToolError("文件不存在: %s" % path)
    return path


def _detect(path):
    fmt = detect_format(path)
    if fmt is None:
        raise ToolError("无法识别的格式（非 ELF / 非 PE）: %s" % path)
    return fmt


def pflags_str(f):
    """p_flags → readelf 风格：R / R E / RW / RW E"""
    return (("R" if f & 4 else "") + ("W" if f & 2 else "")
            + (" E" if f & 1 else "")).strip()


# ── 工具实现（纯函数，返回 dict；供 tools/call 与直接复用） ──────────

def tool_info(path):
    path = _require_path(path if isinstance(path, dict) else {"path": path})
    fmt = _detect(path)
    if fmt == "elf":
        r = elf.parse(path)
        data = open(path, "rb").read()
        interp = None
        for (t, _fl, off, _va, fsz) in r["phdrs"]:
            if t == elf.PT_INTERP:
                interp = data[off:off + fsz].rstrip(b"\x00").decode("ascii", "replace")
        sec = r["security"]
        return {
            "format": "ELF",
            "arch": MACHINE_ARCH.get(r["machine"], "machine_%d" % r["machine"]),
            "bits": 64 if data[4] == 2 else 32,
            "endian": "little" if data[5] == 1 else "big",
            "type": ET_NAMES.get(r["type"], r["type"]),
            "entry": "0x%x" % r["entry"],
            "phdrs": len(r["phdrs"]),
            "sections": len(r["sections"]),
            "security": {"nx": sec["nx"], "relro": sec["relro"], "pie": sec["pie"]},
            "wx_segments": sec["wx_segments"],
            "interpreter": interp,
            "needed": r["dynamic"]["needed"] if r["dynamic"] else [],
        }
    r = pe.parse(path)
    return {
        "format": "PE",
        "arch": r["machine"],
        "bits": 64 if r["magic"] == 0x20B else 32,
        "type": "DLL" if int(r["chars"], 16) & 0x2000 else "EXE",
        "entry_rva": "0x%X" % r["entry"],
        "image_base": "0x%X" % r["image_base"],
        "subsystem": r["subsystem"],
        "sections": r["nsect"],
        "imports": [{"dll": d, "count": len(fns)} for (d, fns) in r["imports"]],
        "exports": None if r["exports"] is None else {
            "dll": r["exports"]["dll"], "base": r["exports"]["base"],
            "nfuncs": r["exports"]["nfuncs"]},
        "rich": None if r["rich"] is None else {
            "key": "0x%08X" % r["rich"]["key"], "pairs": len(r["rich"]["pairs"])},
    }


def _int_arg(args, key):
    v = args.get(key)
    if v is None:
        return None
    if isinstance(v, bool):
        raise ToolError("%s 必须是整数，收到: %r" % (key, v))
    if isinstance(v, int):
        return v
    try:
        return int(str(v), 0)
    except ValueError:
        raise ToolError("%s 必须是整数或 0x 前缀十六进制，收到: %r" % (key, v))


def tool_map(path, kind="segments"):
    if not isinstance(path, dict):
        path = {"path": path}
    p = _require_path(path)
    kind = path.get("kind", kind)
    addr = _int_arg(path, "addr")
    off = _int_arg(path, "off")
    section = path.get("section")
    if section is not None and addr is None:
        raise ToolError("section 只能与 addr 一起使用（文件偏移没有节身份）")
    fmt = _detect(p)
    if fmt == "elf":
        r = elf.parse(p)
        if kind == "segments":
            entries = [{"index": i, "type": PT_NAMES.get(t, "PT_%x" % t),
                        "flags": pflags_str(fl), "vaddr": "0x%x" % va,
                        "offset": "0x%x" % off, "filesz": "0x%x" % fsz}
                       for i, (t, fl, off, va, fsz) in enumerate(r["phdrs"])]
        elif kind == "sections":
            entries = [{"index": i, "name": nm, "type": t, "addr": "0x%x" % a,
                        "offset": "0x%x" % o, "size": "0x%x" % s}
                       for i, (nm, t, a, o, s) in enumerate(r["sections"])]
        else:
            raise ToolError("kind 必须是 segments 或 sections，收到: %r" % kind)
        return _attach_query({"format": "ELF", "kind": kind, "count": len(entries),
                              "entries": entries}, p, addr, off, section)
    # PE：无 ELF 式段表，映射单元即节
    r = pe.parse(p)
    entries = [{"index": i, "name": nm, "rva": "0x%x" % va, "vsize": "0x%x" % vs,
                "rawptr": "0x%x" % rp, "rawsize": "0x%x" % rs}
               for i, (va, vs, rp, rs, nm) in enumerate(r["sections"])]
    return _attach_query({"format": "PE", "kind": "sections", "count": len(entries),
                          "note": "PE 无 ELF 式段表，map 统一返回节表",
                          "entries": entries}, p, addr, off, section)


def _attach_query(result, path, addr, off, section):
    """地址/偏移换算查询（与 CLI map 同一输出契约）。

    query_mode 区分两种问法：
      "addr"    裸地址，保守口径（NOBITS 重叠时优先 not_in_file）
      "section" 节身份，带 section 与 section_matched
      "offset"  文件偏移（无节身份）
    """
    if addr is None and off is None:
        return result
    from . import mapview
    model = mapview.build(path)
    q = {}
    if addr is not None:
        q["addr"] = dict(mapview.addr_to_off(model, addr, section=section),
                         query=addr)
    if off is not None:
        q["off"] = dict(mapview.off_to_addr(model, off), query=off)
    result["query"] = q
    return result


def tool_fingerprint(path):
    if not isinstance(path, dict):
        path = {"path": path}
    p = _require_path(path)
    fmt = _detect(p)
    return fingerprint.analyze(p, fmt)


def tool_iat(path):
    """IAT 定位/解码（只读）。可修复性随结果返回，不只给一堆 unresolved。"""
    if not isinstance(path, dict):
        path = {"path": path}
    p = _require_path(path)
    if _detect(p) != "pe":
        raise ToolError("IAT 只适用于 PE: %s" % p)
    from . import iat
    try:
        return iat.locate(p)
    except ValueError as e:
        raise ToolError(str(e))
    except Exception as e:
        raise ToolError("解析失败: %s: %s" % (type(e).__name__, e))


TOOLS = [
    {"name": "rekit_info",
     "description": "二进制分诊摘要。ELF：格式/架构/类型/入口/段节数/安全态"
                    "(NX·RELRO·PIE)/动态依赖/解释器；PE：架构/类型/入口RVA/"
                    "映像基址/节表数/导入导出摘要/Rich 头指纹。",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "待分析文件路径"}},
                     "required": ["path"]}},
    {"name": "rekit_map",
     "description": "内存映射视图与地址换算。ELF：段表(program headers，含 readelf "
                    "风格 GNU_* 段名)或节表；PE：节表(RVA/VSize/RawPtr/RawSize)。"
                    "可选 addr/off 做换算：返回 query.addr / query.off，"
                    "query_mode 区分 'addr'(裸地址，保守口径) / 'section'(节身份，"
                    "带 section 与 section_matched) / 'offset'(文件偏移)。"
                    "裸地址与节级回答不合并。",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "待分析文件路径"},
                                    "kind": {"type": "string",
                                             "enum": ["segments", "sections"],
                                             "description": "segments(默认) 或 sections"},
                                    "addr": {"type": ["integer", "string"],
                                             "description": "查询地址（ELF=vaddr / PE=RVA），"
                                                            "整数或 0x 前缀十六进制"},
                                    "off": {"type": ["integer", "string"],
                                            "description": "查询文件偏移，整数或 0x 前缀十六进制"},
                                    "section": {"type": "string",
                                                "description": "节身份，仅配合 addr；"
                                                               "地址不落在该节内则 "
                                                               "section_matched=false"}},
                     "required": ["path"]}},
    {"name": "rekit_fingerprint",
     "description": "指纹分诊（净室观察法，M2）：壳识别(packer，仅 UPX 强判+常见壳 hint)、"
                    "编译器指纹(gcc/msvc/go/rust，证据不足答 unknown)、"
                    "stripped/COFF 符号表、加固位(ELF NX·RELRO·PIE；PE NX·ASLR·CFG 等)。"
                    "每条结论附 evidence 数组，强结论至少两条独立证据。",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "待分析文件路径"}},
                     "required": ["path"]}},
    {"name": "rekit_iat",
     "description": "PE 导入地址表(IAT)定位与解码（只读，M3）：逐描述符给 dll/INT/IAT RVA 与"
                    "逐 slot 的 name|#ordinal、hint、RVA、文件偏移。"
                    "repairable 表示加载态能否回解：OriginalFirstThunk=0 的加壳/自解压镜像"
                    "名称源与 IAT 同址，加载后被覆盖 → repairable=false，caveats 给出原因；"
                    "此类样本修复会全部 unresolved，本工具不做脱壳。",
     "inputSchema": {"type": "object",
                     "properties": {"path": {"type": "string",
                                             "description": "待分析 PE 文件路径"}},
                     "required": ["path"]}},
]

_TOOL_FUNCS = {"rekit_info": tool_info, "rekit_map": tool_map,
               "rekit_fingerprint": tool_fingerprint, "rekit_iat": tool_iat}


# ── JSON-RPC 分发 ──────────────────────────────────────────────

def _ok(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _err(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": code, "message": message}}


def handle(msg):
    """处理一条已解析的请求 dict；返回响应 dict 或 None（通知）。"""
    if not isinstance(msg, dict):
        return None
    method = msg.get("method")
    msg_id = msg.get("id")   # None ⇒ 通知（MCP 规范：通知无 id）

    if method == "initialize":
        client_v = (msg.get("params") or {}).get("protocolVersion")
        version = client_v if client_v in SUPPORTED_VERSIONS else LATEST
        return _ok(msg_id, {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "rekit", "version": "0.1.0"}})
    if method == "ping":
        return _ok(msg_id, {})
    if method == "tools/list":
        return _ok(msg_id, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        args = params.get("arguments") or {}
        func = _TOOL_FUNCS.get(name)
        try:
            if func is None:
                raise ToolError("未知工具: %r" % name)
            result = func(args)
        except ToolError as e:
            return _ok(msg_id, {"content": [{"type": "text", "text": str(e)}],
                                "isError": True})
        except Exception as e:  # 解析崩溃也走 isError，连接存活
            return _ok(msg_id, {"content": [{"type": "text",
                                             "text": "%s: %s" % (type(e).__name__, e)}],
                                "isError": True})
        return _ok(msg_id, {"content": [{"type": "text",
                                         "text": json.dumps(result, ensure_ascii=False,
                                                            indent=2)}]})
    # notifications/* 与未知通知：静默忽略；未知方法且带 id：method not found
    if msg_id is None:
        return None
    return _err(msg_id, -32601, "Method not found: %r" % method)


def serve(stdin=None, stdout=None):
    """stdio 主循环。返回 0（客户端断开即结束）。"""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            print("rekit-mcp: 跳过无法解析的帧", file=sys.stderr)
            continue
        resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            stdout.flush()   # 不 flush 客户端会死等（协议层第一坑）
    return 0
