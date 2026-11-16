#!/usr/bin/env python3
# rekit.cli — 统一命令行入口（2026-11-14 M1 收口日）
#
# 分诊规则（magic 字节，两级校验）：
#   ELF: 前 4 字节 \x7fELF
#   PE : 前 2 字节 MZ **且** e_lfanew(0x3C) 处 4 字节 PE\0\0
#        —— 双重校验防"MZ 开头但非 PE"的文件误入 pe 通道
# 分发：elf/pe 渲染通道直接复用各模块 main([path])，输出与模块直调逐字节一致。
# 失败语义（分诊工具的崩溃路径必须可控，禁止 traceback 直面用户）：
#   退出码 2 = 分诊失败（不认识/读不了的格式）
#   退出码 3 = 分诊通过但解析失败（截断/损坏等，一行报告异常类型）
import argparse
import os
import struct
import sys

from . import elf, pe


def detect_format(path):
    """返回 'elf' / 'pe' / None。文件级 OSError 由调用方统一处理。"""
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


# U1（2026-11-17 交付批次）：`rekit info <file> [--json]` 分诊报告。
# 字段名已冻结（见 pack\03_路线图与章程\JSON_CONTRACT.md），改名按破坏性变更处理。
INFO_SCHEMA = 1
_ELF_EM = {0x03: "i386", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64",
           0xF3: "RISC-V"}
_ELF_ET = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}


def _dotnet_info(path):
    from . import dotnet
    try:
        r = dotnet.open_tables(path)
    except Exception as e:  # 元数据层失败不影响 info 其余字段
        return {"is_cli": None, "status": "error",
                "reason": "%s: %s" % (type(e).__name__, e)}
    status = r.get("status")
    if status == dotnet.STATUS_OK:
        return {"is_cli": True, "status": status, "reason": None}
    return {"is_cli": True if status != dotnet.STATUS_NOT_DOTNET else False,
            "status": status, "reason": r.get("reason")}


def build_info(path):
    """返回 info 的 JSON 对象；键集合即冻结契约（缺失写 null，不省略键）。"""
    from . import elf, pe
    fmt = detect_format(path)
    if fmt == "elf":
        r = elf.parse(path)
        with open(path, "rb") as f:
            head = f.read(5)
        secs = [{"name": s[0], "addr": s[2], "offset": s[3], "size": s[4]}
                for s in r["sections"]]
        return {"schema": INFO_SCHEMA, "path": str(path), "format": "ELF",
                "arch": _ELF_EM.get(r["machine"], "0x%x" % r["machine"]),
                "bits": 64 if head[4] == 2 else 32,
                "type": _ELF_ET.get(r["type"], "0x%x" % r["type"]),
                "entry": r["entry"], "image_base": None, "subsystem": None,
                "nsections": len(secs), "sections": secs,
                "security": r["security"], "imports": None, "exports": None,
                "dotnet": None}
    if fmt == "pe":
        r = pe.parse(path)
        secs = [{"name": s[4], "addr": s[0], "offset": s[2], "size": s[3]}
                for s in r["sections"]]
        exp = r.get("exports")
        return {"schema": INFO_SCHEMA, "path": str(path), "format": "PE",
                "arch": r["machine"],
                "bits": 64 if r["magic"] == 0x20B else 32,
                "type": "DLL" if int(r["chars"], 16) & 0x2000 else "EXE",
                "entry": r["entry"], "image_base": r["image_base"],
                "subsystem": r["subsystem"], "nsections": r["nsect"],
                "sections": secs, "security": None,
                "imports": sorted(r["imports"]) if r["imports"] else [],
                "exports": None if not exp else {"dll": exp["dll"],
                                                 "nfuncs": exp["nfuncs"]},
                "dotnet": _dotnet_info(path)}
    return None


def render_info(info):
    lines = ["file     : %s" % info["path"],
             "format   : %s (%s, %d-bit, %s)" % (info["format"], info["arch"],
                                                 info["bits"], info["type"]),
             "entry    : 0x%x" % info["entry"],
             "sections : %d" % info["nsections"]]
    if info["format"] == "ELF":
        s = info["security"]
        lines.append("security : NX %s (%s) | RELRO %s | PIE %s | W+X segs %d"
                     % (s["nx"], s["nx_reason"], s["relro"], s["pie"],
                        len(s["wx_segments"])))
    else:
        lines.append("imagebase: 0x%x  subsystem: %s"
                     % (info["image_base"], info["subsystem"]))
        lines.append("imports  : %d DLL" % len(info["imports"]))
        if info["exports"]:
            lines.append("exports  : %s (%d funcs)"
                         % (info["exports"]["dll"], info["exports"]["nfuncs"]))
    d = info["dotnet"]
    if d is not None:
        lines.append("dotnet   : cli=%s status=%s%s"
                     % (d["is_cli"], d["status"],
                        "" if not d["reason"] else " (%s)" % d["reason"]))
    return "\n".join(lines)


def _info_main(argv):
    import argparse
    import json
    ap = argparse.ArgumentParser(
        prog="rekit.cli info",
        description="一条命令输出分诊报告（格式/架构/入口/节/保护/导入导出/.NET）")
    ap.add_argument("file", help="待分析文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON（字段名已冻结）")
    args = ap.parse_args(argv)
    if not os.path.exists(args.file):
        print("rekit: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        info = build_info(args.file)
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    except Exception as e:
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3
    if info is None:
        print("rekit: %s: 无法识别的格式（非 ELF / 非 PE）" % args.file,
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2, default=str))
    else:
        print(render_info(info))
    return 0


def main(argv=None):
    # M1.5（2026-11-15）：`rekit mcp` 启动 MCP stdio 服务器（CLI+MCP 双身份）。
    # 手动短路而非 argparse subparsers——保持单文件位置参数行为与 58 断言逐字节兼容。
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] == "mcp":
        from . import mcp
        return mcp.serve()
    # U1（2026-11-17）：`rekit info <file> [--json]` 分诊报告（章程承诺的命令）。
    if argv and argv[0] == "info":
        return _info_main(argv[1:])
    # M2（2026-11-15 U1）：`rekit fingerprint <file> [--json]` 指纹层。
    # 同样走手动短路，保证既有单文件位置参数路径逐字节不变。
    if argv and argv[0] == "fingerprint":
        from . import fingerprint
        return fingerprint.main(argv[1:])
    # M3（2026-11-15 U1）：`rekit map <file> [--json] [--addr HEX] [--off HEX]`
    # 映射视图与地址换算；同样手动短路，保既有位置参数路径逐字节不变。
    if argv and argv[0] == "map":
        from . import mapview
        return mapview.main(argv[1:])
    # M3（2026-11-15 U3）：`rekit iat <pe> [--json] [--repair-out NEW]`
    # IAT 定位/解码/修复雏形；写回只产出新文件。
    if argv and argv[0] == "iat":
        from . import iat
        return iat.main(argv[1:])
    # M4（2026-11-15 首日）：`rekit disasm <file> [--section NAME] [--limit N] [--json]`
    # x86-64 线性扫描，只解指令边界；每条指令带 addr_to_off 文件落点。
    if argv and argv[0] == "disasm":
        from . import disasm
        return disasm.main(argv[1:])
    # M4（2026-11-15 第二单元）：`rekit recdesc <file> [--section NAME] [--heuristic] [--json]`
    # 从权威/启发式种子做递归下降 + 基本块划分；种子成功率分类单列。
    if argv and argv[0] == "recdesc":
        from . import recdesc
        return recdesc.main(argv[1:])
    # M9（2026-11-16 收敛线 C）：`rekit coverage <file> [--section NAME] [--json]`
    # 覆盖率报告：分子/分母/分母口径三件套；分母由外部 objdump 独立计数。
    if argv and argv[0] == "coverage":
        from . import coverage
        return coverage.main(argv[1:])
    # M5（2026-11-15 第一单元）：`rekit expr <file> [--func HEX] [--json]`
    # 函数内表达式恢复（伪 C）；不可恢复处显式 abstain 并写缺什么信息。
    if argv and argv[0] == "expr":
        from . import expr
        return expr.main(argv[1:])
    # M19（2026-11-17）：`rekit sigblob <file> [--json] [--limit N]`
    # .NET 签名语义层：MethodDef/MemberRef/StandAloneSig 的 #Blob 签名解码。
    if argv and argv[0] == "sigblob":
        from . import sigblob
        return sigblob.main(argv[1:])
    # M20（2026-11-17）：`rekit layout <file> [--json] [--limit N] [--runtime J]`
    # .NET 类型布局与字段 RVA：FieldLayout/ClassLayout/FieldRVA 的静态可证部分。
    if argv and argv[0] == "layout":
        from . import layout
        return layout.main(argv[1:])
    # M18（2026-11-16）：`rekit ilflow <file> [--json] [--limit N]`
    # .NET IL 控制流与调用关系：token 三态解析、分支目标落点、基本块/边、EH 结构。
    if argv and argv[0] == "ilflow":
        from . import ilflow
        return ilflow.main(argv[1:])
    # M17（2026-11-16）：`rekit dotnet <file> [--json]`
    # .NET 程序集结构层：类型/方法/方法体位置/IL 边界；只读声明，缺即报缺。
    if argv and argv[0] == "dotnet":
        from . import dotnet
        return dotnet.main(argv[1:])
    # M16（2026-11-16）：`rekit datarefs <file> [--json]`
    # 非字符串数据引用层：声明对象 ↔ 指令引用点；分母先行，缺失显式。
    if argv and argv[0] == "datarefs":
        from . import datarefs
        return datarefs.main(argv[1:])
    # M15（2026-11-16）：`rekit funcreport <file> [--func HEX] [--json]`
    # 单函数报告：合成六层既有结果，只呈现、不判断；缺失显式列出。
    if argv and argv[0] == "funcreport":
        from . import funcreport
        return funcreport.main(argv[1:])
    # M7（2026-11-16 第一单元）：`rekit sitejoin <file> [--json]`
    # 三层拼接：调用图 / 参数事实层 / 结构化文本按调用地址对齐；冲突单列、只读。
    if argv and argv[0] == "sitejoin":
        from . import sitejoin
        return sitejoin.main(argv[1:])
    # M6（2026-11-15 第二单元）：`rekit callfacts <file> [--json]`
    # 跨函数参数传递的事实层：证据分 declared/observed/derived，不做 ABI 推断；
    # 与调用图三态逐点比对，矛盾单列。
    if argv and argv[0] == "callfacts":
        from . import callfacts
        return callfacts.main(argv[1:])
    # M6（2026-11-15 第一单元）：`rekit callgraph <file> [--json]`
    # 调用图（三态占比）+ 保守跨过程观察；间接调用走候选层（默认关闭）。
    if argv and argv[0] == "callgraph":
        from . import callgraph
        return callgraph.main(argv[1:])
    ap = argparse.ArgumentParser(
        prog="rekit.cli",
        description="rekit 统一入口：自动识别 ELF/PE 并输出分诊解析报告")
    ap.add_argument("file", help="待分析的二进制文件")
    ap.add_argument("--format", choices=["auto", "elf", "pe"], default="auto",
                    help="强制指定格式（默认 auto：magic 字节自动识别）")
    args = ap.parse_args(argv)

    if not os.path.exists(args.file):
        print("rekit: %s: 文件不存在" % args.file, file=sys.stderr)
        return 2
    try:
        fmt = args.format if args.format != "auto" else detect_format(args.file)
    except OSError as e:
        print("rekit: %s: 读取失败(%s)" % (args.file, e), file=sys.stderr)
        return 2
    if fmt is None:
        print("rekit: %s: 无法识别的格式（非 ELF / 非 PE）" % args.file,
              file=sys.stderr)
        return 2
    mod = {"elf": elf, "pe": pe}[fmt]
    try:
        mod.main([args.file])
    except Exception as e:  # 解析失败也要一行可读报告，退出码与分诊失败区分
        print("rekit: %s: 解析失败(%s: %s)" % (args.file, type(e).__name__, e),
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
