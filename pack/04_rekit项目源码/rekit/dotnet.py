#!/usr/bin/env python3
# rekit.dotnet — M17 .NET 程序集结构层（CLI 头 / 元数据表 / 方法体 / IL 边界）
#
# 为什么单独一层：
#   rekit 既有各层全部建立在 x86 指令与 ELF/PE 原生结构上（recdesc/expr/disasm/
#   callgraph/strxref/datarefs…）。.NET 程序集的方法体是 CLI 字节码，不是 x86；
#   把它喂给这些层只会得到空或假结果。本层只回答结构问题：
#     有哪些类型、哪些方法、方法体在文件哪里、IL 指令边界在哪。
#
# 口径（与 outputs/m17_dotnet/spec.md 一一对应）：
#   1) 全部来自声明：PE DataDirectory[14] → CLI 头 → 元数据根(BSJB) → 流 →
#      #~ 表流 → TypeDef/MethodDef 行；MethodDef.RVA 是唯一的方法体指针。
#      任一步越界/缺失就记 missing_*，不按“常见布局”补，不跳字节猜。
#   2) 方法体：RVA 只用节表换算成文件偏移；tiny/fat 头按 ECMA 位域解析；
#      代码区与附加 EH 节逐段限界。
#   3) IL 边界：opcode 表按 ECMA-335 手写（单字节 + 0xFE 前缀），操作数尺寸按
#      操作数类型；未编码的 opcode 记 undecodable_at 并停止，不继续猜。
#   4) 分母先行：MethodDef 行数 = 有 RVA + 无 RVA；有 RVA = 可定位 + 不可定位；
#      可定位 = 体解析成功 + 头非法 + 代码截断；体成功 = IL 解出 + IL 不可解。
#      比例只在分母之后给；分母为 0 时写 None。
#   5) 与既有层的关系显式列出（CROSS_LAYER）：x86 各层对 IL 方法体不适用，
#      返回 not_applicable 而不是静默空。
#
# 不做的：反编译 C#、反混淆、壳/混淆器识别、NativeAOT、签名语义解码。
import argparse
import json
import sys

from . import pe

SCHEMA = 1
CLI_DIR = 14
TINY = 2
FAT = 3

STATUS_OK = "ok"
STATUS_NOT_DOTNET = "not_dotnet"
STATUS_CLI_UNMAPPED = "cli_rva_unmapped"
STATUS_META_UNMAPPED = "metadata_rva_unmapped"
STATUS_NO_META = "no_metadata_root"
STATUS_NO_TABLES = "no_table_stream"
STATUS_TRUNCATED = "truncated"
STATUS_ERROR = "error"

CALIBER = {
    "declaration_chain": (
        "PE DataDirectory[14] → CLI 头 → MetaData RVA/Size → BSJB 根 → 流头 → "
        "#~ 表流 → 行；每步越界/缺失即 missing_*，不补按常见布局"),
    "rva_to_offset": (
        "只用节表：vaddr <= rva < vaddr+vsize 且 delta < rawsize 且 "
        "delta < vsize；不假设节名/对齐"),
    "table_widths": (
        "堆索引宽度由 HeapSizes 位图决定；表索引 <65536 ? 2 : 4；"
        "coded index 按 max(目标表行数) < 1<<(16-tag_bits) ? 2 : 4"),
    "body": (
        "tiny=(byte0&3)==2, code_size=byte0>>2；fat=(u16&3)==3, "
        "header_size=(u16>>12)*4, code_size=u32@4；其它低两位 → body_bad_header"),
    "eh_sections": (
        "代码区末尾 4 字节对齐；节头 Kind(1)+DataSize(1 或 3)+Reserved(2)；"
        "Kind&0x3F==1 按 12/24 字节逐条读子句；Kind&0x80 表示还有下一节"),
    "il": (
        "opcode 表来自 ECMA-335：单字节有效项 + 0xFE 前缀有效项；"
        "操作数尺寸按 Inline* 类型；未知编码 → undecodable_at 并停止"),
    "denominator": (
        "MethodDef 行数 = 有 RVA + 无 RVA；再逐层二分到 体成功/IL 解出；"
        "比例在分母之后，分母为 0 写 None"),
}

CAVEATS = [
    "本层只读声明：CLI 头/元数据表/方法体 RVA。缺失或越界的部分记 missing_*，"
    "不用“常见布局”补齐，也不把缺失当成“没有类型/方法”",
    "受控样本由本机 csc 编译，只覆盖编译器实际生成的 IL 子集（无 mixed-mode、"
    "无 NativeAOT、无混淆器变形）；它不能代表真实世界程序集分布，真实样本同跑见报告",
    "方法体只解析头/代码区/异常处理节；异常子句的 catch token/filter 偏移按声明"
    "原值给出，不解析类型签名，不做控制流重建",
    "签名只给 #Blob 原始字节预览，不解码参数/返回类型；字段/属性/事件仅计数",
    "IL 边界按 opcode 表切分；无法编码的 opcode 在 undecodable_at 停止，"
    "该偏移之后不再猜。本层不判断“这段 IL 是否合法可执行”",
    "RVA=0 的方法体按声明原因分类（abstract/pinvoke/runtime/native/unclassified）；"
    "unclassified 是“声明里看不出原因”，不是“没有方法体”",
    "`<Module>` 是元数据伪类型（全局方法/字段的宿主），单列，不算用户类型",
    "NativeAOT/ReadyToRun 的原生代码不在本层范围：若 RVA 指向原生代码，"
    "本层按 body_bad_header 或 undecodable 如实报，不反解原生指令",
    "与 x86 各层的关系见 cross_layer：map/iat/disasm/recdesc/callgraph/strxref/"
    "datarefs 等对 IL 方法体不适用，本层显式标注而不是返回空",
]

# ── 表定义（ECMA-335 II.22）────────────────────────────────────────
# 列类型：("u", n) / ("str",) / ("guid",) / ("blob",) /
#         ("idx", table_id) / ("coded", coded_name)
CODED = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasCustomAttribute": (5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00,
                               0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23,
                               0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [None, None, 0x06, 0x0A, None]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}

# 45 张表（含 ptr/保留表需要行宽；只解析其中一部分）
TABLE_SCHEMAS = {
    0x00: ("Module", [("Generation", ("u", 2)), ("Name", ("str",)),
                      ("Mvid", ("guid",)), ("EncId", ("guid",)),
                      ("EncBaseId", ("guid",))]),
    0x01: ("TypeRef", [("ResolutionScope", ("coded", "ResolutionScope")),
                       ("TypeName", ("str",)), ("TypeNamespace", ("str",))]),
    0x02: ("TypeDef", [("Flags", ("u", 4)), ("TypeName", ("str",)),
                       ("TypeNamespace", ("str",)),
                       ("Extends", ("coded", "TypeDefOrRef")),
                       ("FieldList", ("idx", 0x04)),
                       ("MethodList", ("idx", 0x06))]),
    0x03: ("FieldPtr", [("Field", ("idx", 0x04))]),
    0x04: ("Field", [("Flags", ("u", 2)), ("Name", ("str",)),
                     ("Signature", ("blob",))]),
    0x05: ("MethodPtr", [("Method", ("idx", 0x06))]),
    0x06: ("MethodDef", [("RVA", ("u", 4)), ("ImplFlags", ("u", 2)),
                         ("Flags", ("u", 2)), ("Name", ("str",)),
                         ("Signature", ("blob",)), ("ParamList", ("idx", 0x08))]),
    0x07: ("ParamPtr", [("Param", ("idx", 0x08))]),
    0x08: ("Param", [("Flags", ("u", 2)), ("Sequence", ("u", 2)),
                     ("Name", ("str",))]),
    0x09: ("InterfaceImpl", [("Class", ("idx", 0x02)),
                             ("Interface", ("coded", "TypeDefOrRef"))]),
    0x0A: ("MemberRef", [("Class", ("coded", "MemberRefParent")),
                         ("Name", ("str",)), ("Signature", ("blob",))]),
    0x0B: ("Constant", [("Type", ("u", 2)),
                        ("Parent", ("coded", "HasConstant")),
                        ("Value", ("blob",))]),
    0x0C: ("CustomAttribute", [("Parent", ("coded", "HasCustomAttribute")),
                               ("Type", ("coded", "CustomAttributeType")),
                               ("Value", ("blob",))]),
    0x0D: ("FieldMarshal", [("Parent", ("coded", "HasFieldMarshal")),
                            ("NativeType", ("blob",))]),
    0x0E: ("DeclSecurity", [("Action", ("u", 2)),
                            ("Parent", ("coded", "HasDeclSecurity")),
                            ("PermissionSet", ("blob",))]),
    0x0F: ("ClassLayout", [("PackingSize", ("u", 2)), ("ClassSize", ("u", 4)),
                           ("Parent", ("idx", 0x02))]),
    0x10: ("FieldLayout", [("Offset", ("u", 4)), ("Field", ("idx", 0x04))]),
    0x11: ("StandAloneSig", [("Signature", ("blob",))]),
    0x12: ("EventMap", [("Parent", ("idx", 0x02)),
                        ("EventList", ("idx", 0x14))]),
    0x13: ("EventPtr", [("Event", ("idx", 0x14))]),
    0x14: ("Event", [("EventFlags", ("u", 2)), ("Name", ("str",)),
                     ("EventType", ("coded", "TypeDefOrRef"))]),
    0x15: ("PropertyMap", [("Parent", ("idx", 0x02)),
                           ("PropertyList", ("idx", 0x17))]),
    0x16: ("PropertyPtr", [("Property", ("idx", 0x17))]),
    0x17: ("Property", [("Flags", ("u", 2)), ("Name", ("str",)),
                        ("Type", ("blob",))]),
    0x18: ("MethodSemantics", [("Semantics", ("u", 2)),
                               ("Method", ("idx", 0x06)),
                               ("Association", ("coded", "HasSemantics"))]),
    0x19: ("MethodImpl", [("Class", ("idx", 0x02)),
                          ("MethodBody", ("coded", "MethodDefOrRef")),
                          ("MethodDeclaration", ("coded", "MethodDefOrRef"))]),
    0x1A: ("ModuleRef", [("Name", ("str",))]),
    0x1B: ("TypeSpec", [("Signature", ("blob",))]),
    0x1C: ("ImplMap", [("MappingFlags", ("u", 2)),
                       ("MemberForwarded", ("coded", "MemberForwarded")),
                       ("ImportName", ("str",)), ("ImportScope", ("idx", 0x1A))]),
    0x1D: ("FieldRVA", [("RVA", ("u", 4)), ("Field", ("idx", 0x04))]),
    0x1E: ("ENCLog", [("Token", ("u", 4)), ("FuncCode", ("u", 4))]),
    0x1F: ("ENCMap", [("Token", ("u", 4))]),
    0x20: ("Assembly", [("HashAlgId", ("u", 4)), ("Major", ("u", 2)),
                        ("Minor", ("u", 2)), ("Build", ("u", 2)),
                        ("Rev", ("u", 2)), ("Flags", ("u", 4)),
                        ("PublicKey", ("blob",)), ("Name", ("str",)),
                        ("Culture", ("str",))]),
    0x21: ("AssemblyProcessor", [("Processor", ("u", 4))]),
    0x22: ("AssemblyOS", [("OSPlatformID", ("u", 4)),
                          ("OSMajorVersion", ("u", 4)),
                          ("OSMinorVersion", ("u", 4))]),
    0x23: ("AssemblyRef", [("Major", ("u", 2)), ("Minor", ("u", 2)),
                           ("Build", ("u", 2)), ("Rev", ("u", 2)),
                           ("Flags", ("u", 4)),
                           ("PublicKeyOrToken", ("blob",)),
                           ("Name", ("str",)), ("Culture", ("str",)),
                           ("HashValue", ("blob",))]),
    0x24: ("AssemblyRefProcessor", [("Processor", ("u", 4)),
                                    ("AssemblyRef", ("idx", 0x23))]),
    0x25: ("AssemblyRefOS", [("OSPlatformID", ("u", 4)),
                             ("OSMajorVersion", ("u", 4)),
                             ("OSMinorVersion", ("u", 4)),
                             ("AssemblyRef", ("idx", 0x23))]),
    0x26: ("File", [("Flags", ("u", 4)), ("Name", ("str",)),
                    ("HashValue", ("blob",))]),
    0x27: ("ExportedType", [("Flags", ("u", 4)), ("TypeDefId", ("u", 4)),
                            ("TypeName", ("str",)),
                            ("TypeNamespace", ("str",)),
                            ("Implementation", ("coded", "Implementation"))]),
    0x28: ("ManifestResource", [("Offset", ("u", 4)), ("Flags", ("u", 4)),
                                ("Name", ("str",)),
                                ("Implementation", ("coded", "Implementation"))]),
    0x29: ("NestedClass", [("NestedClass", ("idx", 0x02)),
                           ("EnclosingClass", ("idx", 0x02))]),
    0x2A: ("GenericParam", [("Number", ("u", 2)), ("Flags", ("u", 2)),
                            ("Owner", ("coded", "TypeOrMethodDef")),
                            ("Name", ("str",))]),
    0x2B: ("MethodSpec", [("Method", ("coded", "MethodDefOrRef")),
                          ("Instantiation", ("blob",))]),
    0x2C: ("GenericParamConstraint", [("Owner", ("idx", 0x2A)),
                                      ("Constraint", ("coded", "TypeDefOrRef"))]),
}
TABLE_NAMES = {i: s[0] for i, s in TABLE_SCHEMAS.items()}

HEAP_STRING, HEAP_GUID, HEAP_BLOB = "string", "guid", "blob"

# ── IL opcode（ECMA-335 Partition III/VI；手写，独立于 dncil）──────
_N = "none"
OP1 = {
    0x00: ("nop", _N), 0x01: ("break", _N),
    0x02: ("ldarg.0", _N), 0x03: ("ldarg.1", _N), 0x04: ("ldarg.2", _N),
    0x05: ("ldarg.3", _N), 0x06: ("ldloc.0", _N), 0x07: ("ldloc.1", _N),
    0x08: ("ldloc.2", _N), 0x09: ("ldloc.3", _N), 0x0A: ("stloc.0", _N),
    0x0B: ("stloc.1", _N), 0x0C: ("stloc.2", _N), 0x0D: ("stloc.3", _N),
    0x0E: ("ldarg.s", "shortvar"), 0x0F: ("ldarga.s", "shortvar"),
    0x10: ("starg.s", "shortvar"), 0x11: ("ldloc.s", "shortvar"),
    0x12: ("ldloca.s", "shortvar"), 0x13: ("stloc.s", "shortvar"),
    0x14: ("ldnull", _N), 0x15: ("ldc.i4.m1", _N), 0x16: ("ldc.i4.0", _N),
    0x17: ("ldc.i4.1", _N), 0x18: ("ldc.i4.2", _N), 0x19: ("ldc.i4.3", _N),
    0x1A: ("ldc.i4.4", _N), 0x1B: ("ldc.i4.5", _N), 0x1C: ("ldc.i4.6", _N),
    0x1D: ("ldc.i4.7", _N), 0x1E: ("ldc.i4.8", _N),
    0x1F: ("ldc.i4.s", "shorti"), 0x20: ("ldc.i4", "i"), 0x21: ("ldc.i8", "i8"),
    0x22: ("ldc.r4", "shortr"), 0x23: ("ldc.r8", "r"),
    0x25: ("dup", _N), 0x26: ("pop", _N),
    0x27: ("jmp", "method"), 0x28: ("call", "method"), 0x29: ("calli", "sig"),
    0x2A: ("ret", _N),
    0x2B: ("br.s", "shortbr"), 0x2C: ("brfalse.s", "shortbr"),
    0x2D: ("brtrue.s", "shortbr"), 0x2E: ("beq.s", "shortbr"),
    0x2F: ("bge.s", "shortbr"), 0x30: ("bgt.s", "shortbr"),
    0x31: ("ble.s", "shortbr"), 0x32: ("blt.s", "shortbr"),
    0x33: ("bne.un.s", "shortbr"), 0x34: ("bge.un.s", "shortbr"),
    0x35: ("bgt.un.s", "shortbr"), 0x36: ("ble.un.s", "shortbr"),
    0x37: ("blt.un.s", "shortbr"),
    0x38: ("br", "br"), 0x39: ("brfalse", "br"), 0x3A: ("brtrue", "br"),
    0x3B: ("beq", "br"), 0x3C: ("bge", "br"), 0x3D: ("bgt", "br"),
    0x3E: ("ble", "br"), 0x3F: ("blt", "br"), 0x40: ("bne.un", "br"),
    0x41: ("bge.un", "br"), 0x42: ("bgt.un", "br"), 0x43: ("ble.un", "br"),
    0x44: ("blt.un", "br"), 0x45: ("switch", "switch"),
    0x46: ("ldind.i1", _N), 0x47: ("ldind.u1", _N), 0x48: ("ldind.i2", _N),
    0x49: ("ldind.u2", _N), 0x4A: ("ldind.i4", _N), 0x4B: ("ldind.u4", _N),
    0x4C: ("ldind.i8", _N), 0x4D: ("ldind.i", _N), 0x4E: ("ldind.r4", _N),
    0x4F: ("ldind.r8", _N), 0x50: ("ldind.ref", _N),
    0x51: ("stind.ref", _N), 0x52: ("stind.i1", _N), 0x53: ("stind.i2", _N),
    0x54: ("stind.i4", _N), 0x55: ("stind.i8", _N), 0x56: ("stind.r4", _N),
    0x57: ("stind.r8", _N),
    0x58: ("add", _N), 0x59: ("sub", _N), 0x5A: ("mul", _N), 0x5B: ("div", _N),
    0x5C: ("div.un", _N), 0x5D: ("rem", _N), 0x5E: ("rem.un", _N),
    0x5F: ("and", _N), 0x60: ("or", _N), 0x61: ("xor", _N), 0x62: ("shl", _N),
    0x63: ("shr", _N), 0x64: ("shr.un", _N), 0x65: ("neg", _N),
    0x66: ("not", _N), 0x67: ("conv.i1", _N), 0x68: ("conv.i2", _N),
    0x69: ("conv.i4", _N), 0x6A: ("conv.i8", _N), 0x6B: ("conv.r4", _N),
    0x6C: ("conv.r8", _N), 0x6D: ("conv.u4", _N), 0x6E: ("conv.u8", _N),
    0x6F: ("callvirt", "method"), 0x70: ("cpobj", "type"),
    0x71: ("ldobj", "type"), 0x72: ("ldstr", "string"),
    0x73: ("newobj", "method"), 0x74: ("castclass", "type"),
    0x75: ("isinst", "type"), 0x76: ("conv.r.un", _N),
    0x79: ("unbox", "type"), 0x7A: ("throw", _N),
    0x7B: ("ldfld", "field"), 0x7C: ("ldflda", "field"),
    0x7D: ("stfld", "field"), 0x7E: ("ldsfld", "field"),
    0x7F: ("ldsflda", "field"), 0x80: ("stsfld", "field"),
    0x81: ("stobj", "type"),
    0x82: ("conv.ovf.i1.un", _N), 0x83: ("conv.ovf.i2.un", _N),
    0x84: ("conv.ovf.i4.un", _N), 0x85: ("conv.ovf.i8.un", _N),
    0x86: ("conv.ovf.u1.un", _N), 0x87: ("conv.ovf.u2.un", _N),
    0x88: ("conv.ovf.u4.un", _N), 0x89: ("conv.ovf.u8.un", _N),
    0x8A: ("conv.ovf.i.un", _N), 0x8B: ("conv.ovf.u.un", _N),
    0x8C: ("box", "type"), 0x8D: ("newarr", "type"), 0x8E: ("ldlen", _N),
    0x8F: ("ldelema", "type"),
    0x90: ("ldelem.i1", _N), 0x91: ("ldelem.u1", _N), 0x92: ("ldelem.i2", _N),
    0x93: ("ldelem.u2", _N), 0x94: ("ldelem.i4", _N), 0x95: ("ldelem.u4", _N),
    0x96: ("ldelem.i8", _N), 0x97: ("ldelem.i", _N),
    0x98: ("ldelem.r4", _N), 0x99: ("ldelem.r8", _N),
    0x9A: ("ldelem.ref", _N),
    0x9B: ("stelem.i", _N), 0x9C: ("stelem.i1", _N),
    0x9D: ("stelem.i2", _N), 0x9E: ("stelem.i4", _N),
    0x9F: ("stelem.i8", _N), 0xA0: ("stelem.r4", _N),
    0xA1: ("stelem.r8", _N), 0xA2: ("stelem.ref", _N),
    0xA3: ("ldelem", "type"), 0xA4: ("stelem", "type"),
    0xA5: ("unbox.any", "type"),
    0xB3: ("conv.ovf.i1", _N), 0xB4: ("conv.ovf.u1", _N),
    0xB5: ("conv.ovf.i2", _N), 0xB6: ("conv.ovf.u2", _N),
    0xB7: ("conv.ovf.i4", _N), 0xB8: ("conv.ovf.u4", _N),
    0xB9: ("conv.ovf.i8", _N), 0xBA: ("conv.ovf.u8", _N),
    0xC2: ("refanyval", "type"), 0xC3: ("ckfinite", _N),
    0xC6: ("mkrefany", "type"), 0xD0: ("ldtoken", "tok"),
    0xD1: ("conv.u2", _N), 0xD2: ("conv.u1", _N), 0xD3: ("conv.i", _N),
    0xD4: ("conv.ovf.i", _N), 0xD5: ("conv.ovf.u", _N),
    0xD6: ("add.ovf", _N), 0xD7: ("add.ovf.un", _N),
    0xD8: ("mul.ovf", _N), 0xD9: ("mul.ovf.un", _N),
    0xDA: ("sub.ovf", _N), 0xDB: ("sub.ovf.un", _N),
    0xDC: ("endfinally", _N), 0xDD: ("leave", "br"),
    0xDE: ("leave.s", "shortbr"), 0xDF: ("stind.i", _N), 0xE0: ("conv.u", _N),
}
OP2 = {
    0x00: ("arglist", _N), 0x01: ("ceq", _N), 0x02: ("cgt", _N),
    0x03: ("cgt.un", _N), 0x04: ("clt", _N), 0x05: ("clt.un", _N),
    0x06: ("ldftn", "method"), 0x07: ("ldvirtftn", "method"),
    0x09: ("ldarg", "var"), 0x0A: ("ldarga", "var"), 0x0B: ("starg", "var"),
    0x0C: ("ldloc", "var"), 0x0D: ("ldloca", "var"), 0x0E: ("stloc", "var"),
    0x0F: ("localloc", _N), 0x11: ("endfilter", _N),
    0x12: ("unaligned.", "shorti"), 0x13: ("volatile.", _N),
    0x14: ("tail.", _N), 0x15: ("initobj", "type"),
    0x16: ("constrained.", "type"), 0x17: ("cpblk", _N),
    0x18: ("initblk", _N), 0x19: ("no.", "shorti"), 0x1A: ("rethrow", _N),
    0x1C: ("sizeof", "type"), 0x1D: ("refanytype", _N),
    0x1E: ("readonly.", _N),
}
OPERAND_SIZE = {"none": 0, "shortvar": 1, "var": 2, "shorti": 1, "i": 4,
                "i8": 8, "shortr": 4, "r": 8, "method": 4, "field": 4,
                "type": 4, "tok": 4, "sig": 4, "string": 4,
                "shortbr": 1, "br": 4}

EH_KINDS = {0: "catch", 1: "filter", 2: "finally", 4: "fault"}

CROSS_LAYER = [
    {"layer": "map", "status": "partially_applicable",
     "reason": "RVA↔文件偏移与节视图仍成立，并用于方法体定位；但 map 不解释 IL 指令"},
    {"layer": "iat", "status": "not_applicable",
     "reason": "IL 调用是元数据 token（MethodDef/MemberRef）；P/Invoke 走 ImplMap 表，"
               "不是 IAT thunk"},
    {"layer": "disasm", "status": "not_applicable",
     "reason": "方法体是 CLI 字节码，不是 x86 指令流；按 x86 解码会得到假指令"},
    {"layer": "recdesc", "status": "not_applicable",
     "reason": "递归下降以 x86 指令为输入；IL 的边界由 opcode 表给出（本层 il）"},
    {"layer": "expr", "status": "not_applicable",
     "reason": "表达式恢复建立在 x86 指令与操作数上，IL 方法体不适用"},
    {"layer": "callgraph", "status": "not_applicable",
     "reason": "call/callvirt 的目标是元数据 token，不是代码地址；本层不产出 x86 调用图"},
    {"layer": "callfacts", "status": "not_applicable",
     "reason": "跨函数参数传递事实来自 x86 调用点，IL 方法体不适用"},
    {"layer": "sitejoin", "status": "not_applicable",
     "reason": "拼接对象是 x86 调用图/参数层/文本引用，IL 方法体没有这些层"},
    {"layer": "strxref", "status": "not_applicable",
     "reason": "字符串字面量在 #US 元数据堆（ldstr 用 token 引用），不在数据节；"
               "本层 strings_us 给出字面量清单"},
    {"layer": "datarefs", "status": "not_applicable",
     "reason": "数据对象声明来自 ELF 符号/DWARF；IL 的字段/类型引用是 token，"
               "没有 x86 寻址形态"},
    {"layer": "coverage", "status": "not_applicable",
     "reason": "覆盖率分母是 x86 指令；IL 指令不是 x86"},
    {"layer": "switchcand", "status": "not_applicable",
     "reason": "switch 候选识别面向 x86 跳转表；IL 的 switch 自带边界（本层 il）"},
    {"layer": "vexaudit", "status": "not_applicable",
     "reason": "VEX 前缀是 x86 编码，IL 不适用"},
    {"layer": "paramdecl", "status": "not_applicable",
     "reason": "形参声明来自 DWARF；.NET 的参数声明在 MethodDef.Signature blob 里，"
               "本层只给原始字节不解码"},
    {"layer": "struct", "status": "not_applicable",
     "reason": "结构层面向 DWARF 类型；.NET 类型在 TypeDef/签名 blob 里"},
    {"layer": "gopclntab", "status": "not_applicable",
     "reason": "Go 专用；.NET 程序集没有 pclntab"},
    {"layer": "fingerprint", "status": "applicable",
     "reason": "文件级指纹/PE 头仍有效；与是否 .NET 无关"},
    {"layer": "pe", "status": "applicable",
     "reason": "PE 头/节/数据目录仍有效；本层在其上读 DataDirectory[14]"},
    {"layer": "funcreport", "status": "not_applicable",
     "reason": "六层 x86 合成入口；对 .NET 文件返回 not_applicable 并指向 "
               "`rekit dotnet`，不返回空报告"},
]


# ── 基础读取 ────────────────────────────────────────────────────────
def _u(b, off, n):
    if off < 0 or off + n > len(b):
        raise ValueError("越界读 %d@%d（文件 %d 字节）" % (n, off, len(b)))
    return int.from_bytes(b[off:off + n], "little")


def _u24(b, off):
    return _u(b, off, 3)


def _compressed(b, off):
    """ECMA 压缩无符号整数。返回 (value, next_off)；越界抛 ValueError。"""
    if off >= len(b):
        raise ValueError("压缩整数越界 @%d" % off)
    b0 = b[off]
    if b0 & 0x80 == 0:
        return b0, off + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | _u(b, off + 1, 1), off + 2
    if b0 & 0xE0 == 0xC0:
        return ((b0 & 0x1F) << 24) | _u(b, off + 1, 3), off + 4
    raise ValueError("非法压缩整数首字节 0x%02x @%d" % (b0, off))


def _cstr(b, off):
    end = b.find(b"\x00", off)
    if end < 0:
        raise ValueError("字符串无终止符 @%d" % off)
    return b[off:end].decode("utf-8", "replace")


# ── 表流 ────────────────────────────────────────────────────────────
def _row_width(table_id, row_counts, heap_sizes):
    width = 0
    for _name, kind in TABLE_SCHEMAS[table_id][1]:
        if kind[0] == "u":
            width += kind[1]
        elif kind[0] == "str":
            width += 4 if heap_sizes & 0x01 else 2
        elif kind[0] == "guid":
            width += 4 if heap_sizes & 0x02 else 2
        elif kind[0] == "blob":
            width += 4 if heap_sizes & 0x04 else 2
        elif kind[0] == "idx":
            width += 2 if row_counts.get(kind[1], 0) < 0x10000 else 4
        elif kind[0] == "coded":
            bits, tables = CODED[kind[1]]
            mx = max([row_counts.get(t, 0) for t in tables if t is not None] or [0])
            width += 2 if mx < (1 << (16 - bits)) else 4
    return width


class Tables:
    """#~ 表流：只按声明读行；越界/缺堆一律记 missing，不补。"""

    def __init__(self, data, stream_off, stream_size, heaps):
        self.data = data
        self.off = stream_off
        self.size = stream_size
        self.heaps = heaps
        self.errors = []
        self.row_counts = {}
        self.row_sizes = {}
        self.table_offsets = {}
        self.heap_sizes = 0
        self.valid = 0
        self.sorted = 0
        self.major = self.minor = None
        self.reserved = None
        try:
            self._parse()
        except Exception as e:
            self.errors.append("%s: %s" % (type(e).__name__, e))

    def _parse(self):
        d, o = self.data, self.off
        self.reserved = _u(d, o, 4)
        self.major = _u(d, o + 4, 1)
        self.minor = _u(d, o + 5, 1)
        self.heap_sizes = _u(d, o + 6, 1)
        self.valid = _u(d, o + 8, 8)
        self.sorted = _u(d, o + 16, 8)
        pos = o + 24
        for tid in range(64):
            if self.valid >> tid & 1:
                self.row_counts[tid] = _u(d, pos, 4)
                pos += 4
        for tid, n in self.row_counts.items():
            if tid not in TABLE_SCHEMAS:
                self.errors.append("表 0x%02x 有效但无列定义（行数 %d）" % (tid, n))
                continue
            self.row_sizes[tid] = _row_width(tid, self.row_counts,
                                             self.heap_sizes)
        cur = pos
        for tid in sorted(self.row_sizes):
            self.table_offsets[tid] = cur
            cur += self.row_sizes[tid] * self.row_counts[tid]
        self.table_data_off = pos
        self.table_data_end = cur
        if cur > self.off + self.size:
            self.errors.append(
                "表数据区超出流范围：需要到 0x%x，流结束 0x%x"
                % (cur, self.off + self.size))

    def _heap_range(self, kind):
        r = self.heaps.get(kind)
        if r is None:
            return None
        return r

    def string(self, idx):
        r = self._heap_range(HEAP_STRING)
        if r is None:
            return {"value": None, "missing": "no_string_heap"}
        base, size = r
        if idx == 0:
            return {"value": "", "missing": None}
        if idx >= size:
            return {"value": None, "missing": "string_index_out_of_range"}
        try:
            return {"value": _cstr(self.data, base + idx), "missing": None}
        except ValueError:
            return {"value": None, "missing": "string_unterminated"}

    def blob_span(self, idx):
        """#Blob 项的定位（不读内容）：文件偏移/长度/结束位置 + 缺失原因。

        idx==0 表示「没有 blob」而非缺失：off/end 为 None、len=0、missing=None。
        """
        r = self._heap_range(HEAP_BLOB)
        if r is None:
            return {"index": idx, "off": None, "len": None, "end": None,
                    "missing": "no_blob_heap"}
        base, size = r
        if idx == 0:
            return {"index": 0, "off": None, "len": 0, "end": None,
                    "missing": None}
        if idx >= size:
            return {"index": idx, "off": None, "len": None, "end": None,
                    "missing": "blob_index_out_of_range"}
        try:
            n, pos = _compressed(self.data, base + idx)
        except ValueError as e:
            return {"index": idx, "off": None, "len": None, "end": None,
                    "missing": "blob_length_invalid: %s" % e}
        end = pos + n
        if end > base + size or end > len(self.data):
            return {"index": idx, "off": pos, "len": n, "end": end,
                    "missing": "blob_truncated"}
        return {"index": idx, "off": pos, "len": n, "end": end,
                "missing": None}

    def blob(self, idx):
        s = self.blob_span(idx)
        if s["missing"] is not None:
            return {"value": None, "length": s["len"], "missing": s["missing"]}
        if s["off"] is None:                      # idx==0：空 blob
            return {"value": b"", "length": 0, "missing": None}
        return {"value": self.data[s["off"]:s["end"]], "length": s["len"],
                "missing": None}

    def guid(self, idx):
        r = self._heap_range(HEAP_GUID)
        if r is None:
            return {"value": None, "missing": "no_guid_heap"}
        base, size = r
        if idx == 0:
            return {"value": "", "missing": None}
        off = (idx - 1) * 16
        if off + 16 > size or base + off + 16 > len(self.data):
            return {"value": None, "missing": "guid_index_out_of_range"}
        return {"value": self.data[base + off:base + off + 16].hex(),
                "missing": None}

    def row(self, tid, idx):
        """idx 为 1 基行号；返回 dict 或 None（越界/表不存在）。"""
        if idx <= 0:
            return None
        n = self.row_counts.get(tid, 0)
        if idx > n or tid not in self.table_offsets:
            return None
        width = self.row_sizes[tid]
        if self.table_offsets[tid] + width * n > len(self.data):
            return None
        off = self.table_offsets[tid] + width * (idx - 1)
        out = {}
        pos = off
        for name, kind in TABLE_SCHEMAS[tid][1]:
            if kind[0] == "u":
                out[name] = _u(self.data, pos, kind[1])
                pos += kind[1]
            elif kind[0] == "str":
                w = 4 if self.heap_sizes & 0x01 else 2
                out[name] = _u(self.data, pos, w)
                pos += w
            elif kind[0] == "guid":
                w = 4 if self.heap_sizes & 0x02 else 2
                out[name] = _u(self.data, pos, w)
                pos += w
            elif kind[0] == "blob":
                w = 4 if self.heap_sizes & 0x04 else 2
                out[name] = _u(self.data, pos, w)
                pos += w
            elif kind[0] == "idx":
                w = 2 if self.row_counts.get(kind[1], 0) < 0x10000 else 4
                out[name] = _u(self.data, pos, w)
                pos += w
            else:
                bits, tables = CODED[kind[1]]
                mx = max([self.row_counts.get(t, 0) for t in tables
                          if t is not None] or [0])
                w = 2 if mx < (1 << (16 - bits)) else 4
                out[name] = _u(self.data, pos, w)
                pos += w
        return out

    def rows(self, tid):
        n = self.row_counts.get(tid, 0)
        for i in range(1, n + 1):
            r = self.row(tid, i)
            if r is None:
                break
            yield i, r


def _decode_coded(name, raw):
    if raw is None:
        return None
    bits, tables = CODED[name]
    tag = raw & ((1 << bits) - 1)
    idx = raw >> bits
    if tag >= len(tables) or tables[tag] is None:
        return {"kind": "invalid", "tag": tag, "row": idx}
    return {"kind": TABLE_NAMES[tables[tag]], "tag": tag, "row": idx}


# ── 元数据根 / 流 ──────────────────────────────────────────────────
def _read_metadata_root(data, off, size, file_len):
    if off < 0 or off + 16 > file_len:
        return {"status": STATUS_TRUNCATED,
                "reason": "元数据根 0x%x 超出文件（%d 字节）" % (off, file_len)}
    sig = _u(data, off, 4)
    if sig != 0x424A5342:
        return {"status": STATUS_NO_META,
                "reason": "元数据根签名 0x%08x != 0x424A5342(BSJB)" % sig}
    major = _u(data, off + 4, 2)
    minor = _u(data, off + 6, 2)
    vlen = _u(data, off + 12, 4)
    if off + 16 + vlen > file_len:
        return {"status": STATUS_TRUNCATED,
                "reason": "版本串长度 %d 超出文件" % vlen}
    version = data[off + 16:off + 16 + vlen].split(b"\x00")[0].decode(
        "utf-8", "replace")
    p = off + 16 + vlen
    flags = _u(data, p, 2)
    nstreams = _u(data, p + 2, 2)
    p += 4
    streams = []
    for _ in range(nstreams):
        if p + 8 > file_len:
            return {"status": STATUS_TRUNCATED,
                    "reason": "流头数组在第 %d 项截断" % (len(streams) + 1)}
        s_off = _u(data, p, 4)
        s_size = _u(data, p + 4, 4)
        p += 8
        end = data.find(b"\x00", p)
        if end < 0:
            return {"status": STATUS_TRUNCATED,
                    "reason": "流名无终止符 @%d" % p}
        name = data[p:end].decode("ascii", "replace")
        p = (end + 1 + 3) & ~3
        streams.append({"name": name, "offset": s_off, "size": s_size,
                        "file_off": off + s_off,
                        "end_off": off + s_off + s_size})
    for s in streams:
        if s["offset"] + s["size"] > max(size, 0) or s["file_off"] < off \
                or s["end_off"] > file_len:
            s["out_of_range"] = True
    return {"status": STATUS_OK, "signature": "BSJB", "major": major,
            "minor": minor, "version": version, "flags": flags,
            "streams": streams, "size": size}


def _stream(meta, name):
    for s in meta.get("streams") or []:
        if s["name"] == name:
            return s
    return None


def _heaps(data, meta):
    out = {}
    for kind, name in ((HEAP_STRING, "#Strings"), (HEAP_GUID, "#GUID"),
                       (HEAP_BLOB, "#Blob")):
        s = _stream(meta, name)
        if s is None or s.get("out_of_range"):
            continue
        out[kind] = (s["file_off"], s["size"])
    return out


# ── 方法体 ──────────────────────────────────────────────────────────
def _rva_to_off(rva, sections, file_len):
    for s in sections:
        va, vs, rp, rs = s["vaddr"], s["vsize"], s["rawptr"], s["rawsize"]
        if va <= rva < va + vs:
            delta = rva - va
            if delta >= rs:
                return None, "rva_in_uninitialized_tail"
            off = rp + delta
            if off >= file_len:
                return None, "file_offset_out_of_range"
            return off, None
    return None, "rva_not_in_any_section"


def _parse_eh_sections(data, start, file_len):
    sections, clauses = [], []
    pos = (start + 3) & ~3
    guard = 0
    while pos + 4 <= file_len and guard < 64:
        guard += 1
        kind = data[pos]
        fat = bool(kind & 0x40)
        more = bool(kind & 0x80)
        if fat:
            dsize = _u24(data, pos + 1)
            hdr = 4
        else:
            dsize = _u(data, pos + 1, 1)
            hdr = 4
        reserved = _u(data, pos + 2, 2)
        payload = pos + hdr
        sec = {"kind_byte": kind, "kind": kind & 0x3F, "fat": fat,
               "more": more, "data_size": dsize, "reserved": reserved,
               "data_off": payload, "truncated": False, "clauses": 0}
        if payload + dsize > file_len:
            sec["truncated"] = True
            sections.append(sec)
            break
        if (kind & 0x3F) == 1:                 # EHTable
            csize = 24 if fat else 12
            count = dsize // csize
            sec["clauses"] = count
            sec["leftover"] = dsize % csize
            for i in range(count):
                c = payload + i * csize
                if fat:
                    flags = _u(data, c, 4)
                    try_off = _u(data, c + 4, 4)
                    try_len = _u(data, c + 8, 4)
                    h_off = _u(data, c + 12, 4)
                    h_len = _u(data, c + 16, 4)
                    extra = _u(data, c + 20, 4)
                else:
                    flags = _u(data, c, 2)
                    try_off = _u(data, c + 2, 2)
                    try_len = _u(data, c + 4, 1)
                    h_off = _u(data, c + 5, 2)
                    h_len = _u(data, c + 7, 1)
                    extra = _u(data, c + 8, 4)
                clauses.append({
                    "flags": flags, "kind": EH_KINDS.get(flags & 7),
                    "try_offset": try_off, "try_length": try_len,
                    "handler_offset": h_off, "handler_length": h_len,
                    "class_token": (extra if (flags & 7) == 0 else None),
                    "filter_offset": (extra if (flags & 7) == 1 else None),
                    "fat": fat,
                })
        sections.append(sec)
        pos = payload + dsize
        if not more:
            break
    return sections, clauses


def _parse_body(data, body_off, file_len):
    """返回 (body, error_reason)。error_reason 为 None 表示头与代码区都合法。"""
    if body_off is None or body_off >= file_len:
        return None, "body_offset_out_of_range"
    b0 = data[body_off]
    if b0 & 3 == TINY:
        code_size = b0 >> 2
        if code_size == 0:
            return None, "tiny_code_size_zero"
        code_off = body_off + 1
        if code_off + code_size > file_len:
            return {"kind": "tiny", "header_off": body_off,
                    "header_size": 1, "code_off": code_off,
                    "code_size": code_size, "max_stack": 8,
                    "local_sig": None, "flags": b0, "sections": [],
                    "eh_clauses": []}, "body_code_truncated"
        return {"kind": "tiny", "header_off": body_off, "header_size": 1,
                "code_off": code_off, "code_size": code_size,
                "max_stack": 8, "local_sig": None, "flags": b0,
                "sections": [], "eh_clauses": []}, None
    if b0 & 3 == FAT:
        if body_off + 12 > file_len:
            return None, "fat_header_truncated"
        flags = _u(data, body_off, 2)
        header_size = ((flags >> 12) & 0xF) * 4
        code_size = _u(data, body_off + 4, 4)
        local_sig = _u(data, body_off + 8, 4)
        max_stack = _u(data, body_off + 2, 2)
        if header_size < 12:
            return None, "fat_header_size_invalid_%d" % header_size
        if body_off + header_size > file_len:
            return None, "fat_header_truncated"
        code_off = body_off + header_size
        if code_off + code_size > file_len:
            return {"kind": "fat", "header_off": body_off,
                    "header_size": header_size, "code_off": code_off,
                    "code_size": code_size, "max_stack": max_stack,
                    "local_sig": local_sig, "flags": flags,
                    "sections": [], "eh_clauses": []}, "body_code_truncated"
        sections, clauses = [], []
        if flags & 0x8:                        # MoreSects
            sections, clauses = _parse_eh_sections(
                data, code_off + code_size, file_len)
        return {"kind": "fat", "header_off": body_off,
                "header_size": header_size, "code_off": code_off,
                "code_size": code_size, "max_stack": max_stack,
                "local_sig": local_sig, "flags": flags,
                "sections": sections, "eh_clauses": clauses}, None
    return None, "body_header_low_bits_%d" % (b0 & 3)


# ── IL 解码 ─────────────────────────────────────────────────────────
def _decode_il(code):
    """返回 (instructions, error)。offset 相对代码区起点。"""
    insns = []
    i, n = 0, len(code)
    while i < n:
        b = code[i]
        if b == 0xFE:
            if i + 1 >= n:
                return insns, {"offset": i, "reason": "prefix_truncated",
                               "byte": "fe"}
            op = OP2.get(code[i + 1])
            if op is None:
                return insns, {"offset": i, "reason": "unknown_opcode",
                               "byte": "fe%02x" % code[i + 1]}
            name, ot = op
            prefix = 2
        else:
            op = OP1.get(b)
            if op is None:
                return insns, {"offset": i, "reason": "unknown_opcode",
                               "byte": "%02x" % b}
            name, ot = op
            prefix = 1
        if ot == "switch":
            if i + prefix + 4 > n:
                return insns, {"offset": i, "reason": "switch_count_truncated",
                               "opcode": name}
            cnt = _u(code, i + prefix, 4)
            size = prefix + 4 + 4 * cnt
        else:
            size = prefix + OPERAND_SIZE[ot]
        if i + size > n:
            return insns, {"offset": i, "reason": "operand_truncated",
                           "opcode": name}
        operand = code[i + prefix:i + size]
        insns.append({"offset": i, "size": size, "opcode": name,
                      "operand_type": ot,
                      "operand_len": len(operand),
                      "operand_hex": operand[:16].hex()})
        i += size
    return insns, None


# ── 入口探测（funcreport 用；只读头，不解析整文件）────────────────
def probe(path):
    """返回 {is_cli, cli_rva, reason}。读不了文件抛 OSError。"""
    with open(path, "rb") as f:
        head = f.read(0x40)
        if len(head) < 0x40 or head[:2] != b"MZ":
            return {"is_cli": False, "cli_rva": None,
                    "reason": "前 2 字节不是 MZ（非 PE）"}
        e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
        f.seek(e_lfanew)
        if f.read(4) != b"PE\x00\x00":
            return {"is_cli": False, "cli_rva": None, "reason": "无 PE 签名"}
        coff = f.read(20)
        if len(coff) < 20:
            return {"is_cli": False, "cli_rva": None, "reason": "COFF 头截断"}
        optsize = int.from_bytes(coff[16:18], "little")
        opt = f.read(optsize)
    if len(opt) < 2:
        return {"is_cli": False, "cli_rva": None, "reason": "可选头截断"}
    magic = int.from_bytes(opt[0:2], "little")
    if magic not in (0x10B, 0x20B):
        return {"is_cli": False, "cli_rva": None,
                "reason": "可选头 magic 0x%x 不是 PE32/PE32+" % magic}
    ndirs_off = 108 if magic == 0x20B else 92
    if len(opt) < ndirs_off + 4:
        return {"is_cli": False, "cli_rva": None, "reason": "数据目录截断"}
    ndirs = int.from_bytes(opt[ndirs_off:ndirs_off + 4], "little")
    if ndirs <= CLI_DIR:
        return {"is_cli": False, "cli_rva": None,
                "reason": "数据目录数 %d <= %d，没有 CLI 目录" % (ndirs, CLI_DIR)}
    p = ndirs_off + 4 + CLI_DIR * 8
    if len(opt) < p + 8:
        return {"is_cli": False, "cli_rva": None, "reason": "CLI 目录项截断"}
    rva = int.from_bytes(opt[p:p + 4], "little")
    size = int.from_bytes(opt[p + 4:p + 8], "little")
    if rva == 0 or size == 0:
        return {"is_cli": False, "cli_rva": 0,
                "reason": "DataDirectory[14] 为 0（无 CLI 头）"}
    return {"is_cli": True, "cli_rva": rva, "cli_size": size, "reason": None}


# ── 构建 ────────────────────────────────────────────────────────────
def _bad_path(path, status, reason):
    return {"schema": SCHEMA, "path": str(path), "status": status,
            "reason": reason, "caliber": CALIBER, "caveats": list(CAVEATS),
            "cross_layer": CROSS_LAYER}


def open_tables(path):
    """M18：给 ilflow 用的只读元数据打开（CLI → 元数据根 → 表流）。

    不解释方法体、不产生报告；返回 data/sections/cli/meta/tables。
    任何一步失败都返回 {status,reason}，不按“常见布局”补。
    """
    with open(path, "rb") as f:
        data = f.read()
    file_len = len(data)
    if file_len < 0x40 or data[:2] != b"MZ":
        return {"status": STATUS_NOT_DOTNET,
                "reason": "前 2 字节不是 MZ（非 PE 文件）"}
    try:
        r = pe.parse(path)
    except Exception as e:
        return {"status": STATUS_ERROR,
                "reason": "PE 解析失败：%s: %s" % (type(e).__name__, e)}
    dirs = r.get("dirs") or []
    if len(dirs) <= CLI_DIR or not dirs[CLI_DIR][0] or not dirs[CLI_DIR][1]:
        return {"status": STATUS_NOT_DOTNET,
                "reason": "PE 数据目录[14]（CLI Header）不存在或为 0"}
    cli_rva, cli_size = dirs[CLI_DIR]
    sections = [{"index": h["index"], "name": h["name"], "vaddr": h["vaddr"],
                 "vsize": h["vsize"], "rawptr": h["rawptr"],
                 "rawsize": h["rawsize"], "chars": h["chars"]}
                for h in r["section_headers"]]
    cli_off, why = _rva_to_off(cli_rva, sections, file_len)
    if cli_off is None:
        return {"status": STATUS_CLI_UNMAPPED,
                "reason": "CLI 头 RVA 0x%x 无法换算到文件（%s）"
                          % (cli_rva, why)}
    if cli_off + 0x48 > file_len:
        return {"status": STATUS_TRUNCATED,
                "reason": "CLI 头 0x%x..0x%x 超出文件（%d 字节）"
                          % (cli_off, cli_off + 0x48, file_len)}
    cli = {"metadata_rva": _u(data, cli_off + 8, 4),
           "metadata_size": _u(data, cli_off + 12, 4),
           "file_off": cli_off, "rva": cli_rva, "declared_size": cli_size}
    meta_off, why = _rva_to_off(cli["metadata_rva"], sections, file_len)
    if meta_off is None:
        return {"status": STATUS_META_UNMAPPED,
                "reason": "元数据根 RVA 0x%x 无法换算到文件（%s）"
                          % (cli["metadata_rva"], why)}
    meta = _read_metadata_root(data, meta_off, cli["metadata_size"], file_len)
    if meta.get("status") != STATUS_OK:
        return {"status": meta.get("status"), "reason": meta.get("reason")}
    tables_stream = _stream(meta, "#~") or _stream(meta, "#-")
    if tables_stream is None:
        return {"status": STATUS_NO_TABLES,
                "reason": "元数据流里既没有 #~ 也没有 #-（无表流）"}
    if tables_stream.get("out_of_range"):
        return {"status": STATUS_TRUNCATED,
                "reason": "表流 %s 声明范围越界" % tables_stream["name"]}
    heaps = _heaps(data, meta)
    tables = Tables(data, tables_stream["file_off"], tables_stream["size"],
                    heaps)
    if not tables.row_counts:
        return {"status": STATUS_TRUNCATED,
                "reason": "表流头不可解析：%s"
                          % ("；".join(tables.errors) or "Valid 位图为 0")}
    return {"status": STATUS_OK, "data": data, "sections": sections,
            "cli": cli, "meta": meta, "tables": tables}


def build(path, detail_methods=50, detail_insns=256):
    """构建 .NET 结构报告。detail_* 只影响存储的 IL 指令，不影响分母计数。"""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        raise
    file_len = len(data)
    if file_len < 0x40 or data[:2] != b"MZ":
        return _bad_path(path, STATUS_NOT_DOTNET, "前 2 字节不是 MZ（非 PE 文件）")
    try:
        r = pe.parse(path)
    except Exception as e:
        return _bad_path(path, STATUS_ERROR,
                         "PE 解析失败：%s: %s" % (type(e).__name__, e))
    dirs = r.get("dirs") or []
    if len(dirs) <= CLI_DIR or not dirs[CLI_DIR][0] or not dirs[CLI_DIR][1]:
        return _bad_path(path, STATUS_NOT_DOTNET,
                         "PE 数据目录[14]（CLI Header）不存在或为 0："
                         "这是原生 PE，不是 .NET 程序集")
    cli_rva, cli_size = dirs[CLI_DIR]
    sections = [{"index": h["index"], "name": h["name"], "vaddr": h["vaddr"],
                 "vsize": h["vsize"], "rawptr": h["rawptr"],
                 "rawsize": h["rawsize"], "chars": h["chars"]}
                for h in r["section_headers"]]
    cli_off, why = _rva_to_off(cli_rva, sections, file_len)
    if cli_off is None:
        return _bad_path(path, STATUS_CLI_UNMAPPED,
                         "CLI 头 RVA 0x%x 无法换算到文件（%s）"
                         % (cli_rva, why))
    if cli_off + 0x48 > file_len:
        return _bad_path(path, STATUS_TRUNCATED,
                         "CLI 头 0x%x..0x%x 超出文件（%d 字节）"
                         % (cli_off, cli_off + 0x48, file_len))
    cli_cb = _u(data, cli_off, 4)
    cli = {
        "cb": cli_cb,
        "major": _u(data, cli_off + 4, 2),
        "minor": _u(data, cli_off + 6, 2),
        "metadata_rva": _u(data, cli_off + 8, 4),
        "metadata_size": _u(data, cli_off + 12, 4),
        "flags": _u(data, cli_off + 16, 4),
        "entrypoint_token": _u(data, cli_off + 20, 4),
        "resources_rva": _u(data, cli_off + 24, 4),
        "resources_size": _u(data, cli_off + 28, 4),
        "strong_name_rva": _u(data, cli_off + 32, 4),
        "strong_name_size": _u(data, cli_off + 36, 4),
        "code_manager_table": _u(data, cli_off + 40, 4),
        "vtable_fixups": _u(data, cli_off + 44, 4),
        "export_address_table_jumps": _u(data, cli_off + 48, 4),
        "managed_native_header": _u(data, cli_off + 52, 4),
        "file_off": cli_off, "rva": cli_rva, "declared_size": cli_size,
    }
    if cli_cb < 0x48:
        return {"schema": SCHEMA, "path": str(path),
                "status": STATUS_TRUNCATED,
                "reason": "CLI 头 cb=%d < 0x48（声明长度不足）" % cli_cb,
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER,
                "file": {"format": "PE", "machine": r["machine"],
                         "image_base": r["image_base"],
                         "entry": r["entry"], "sections": sections},
                "cli_header": cli}

    meta_off, why = _rva_to_off(cli["metadata_rva"], sections, file_len)
    if meta_off is None:
        return {"schema": SCHEMA, "path": str(path),
                "status": STATUS_META_UNMAPPED,
                "reason": "元数据根 RVA 0x%x 无法换算到文件（%s）"
                          % (cli["metadata_rva"], why),
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER,
                "file": {"format": "PE", "machine": r["machine"],
                         "image_base": r["image_base"],
                         "entry": r["entry"], "sections": sections},
                "cli_header": cli}
    meta = _read_metadata_root(data, meta_off, cli["metadata_size"], file_len)
    if meta.get("status") != STATUS_OK:
        return {"schema": SCHEMA, "path": str(path),
                "status": meta.get("status"), "reason": meta.get("reason"),
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER,
                "file": {"format": "PE", "machine": r["machine"],
                         "image_base": r["image_base"],
                         "entry": r["entry"], "sections": sections},
                "cli_header": cli, "metadata": meta}
    tables_stream = _stream(meta, "#~") or _stream(meta, "#-")
    if tables_stream is None:
        return {"schema": SCHEMA, "path": str(path),
                "status": STATUS_NO_TABLES,
                "reason": "元数据流里既没有 #~ 也没有 #-（无表流）",
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER,
                "file": {"format": "PE", "machine": r["machine"],
                         "image_base": r["image_base"],
                         "entry": r["entry"], "sections": sections},
                "cli_header": cli, "metadata": meta}
    if tables_stream.get("out_of_range"):
        return {"schema": SCHEMA, "path": str(path),
                "status": STATUS_TRUNCATED,
                "reason": "表流 %s 声明范围越界" % tables_stream["name"],
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER,
                "file": {"format": "PE", "machine": r["machine"],
                         "image_base": r["image_base"],
                         "entry": r["entry"], "sections": sections},
                "cli_header": cli, "metadata": meta}
    heaps = _heaps(data, meta)
    tables = Tables(data, tables_stream["file_off"], tables_stream["size"],
                    heaps)
    if not tables.row_counts:
        return {"schema": SCHEMA, "path": str(path),
                "status": STATUS_TRUNCATED,
                "reason": "表流头不可解析：%s"
                          % ("；".join(tables.errors) or "Valid 位图为 0"),
                "caliber": CALIBER, "caveats": list(CAVEATS),
                "cross_layer": CROSS_LAYER,
                "file": {"format": "PE", "machine": r["machine"],
                         "image_base": r["image_base"],
                         "entry": r["entry"], "sections": sections},
                "cli_header": cli, "metadata": meta}

    # ── 类型 ────────────────────────────────────────────────────────
    nested = {}
    for _i, nr in tables.rows(0x29):
        nested[nr["NestedClass"]] = nr["EnclosingClass"]
    typedef_rows = tables.row_counts.get(0x02, 0)
    method_rows = tables.row_counts.get(0x06, 0)
    field_rows = tables.row_counts.get(0x04, 0)
    param_rows = tables.row_counts.get(0x08, 0)

    def _method_range(tid):
        raw = tables.row(0x02, tid)
        if raw is None or raw["MethodList"] == 0:
            return None, None
        start = raw["MethodList"]
        nxt = tables.row(0x02, tid + 1)
        end = nxt["MethodList"] if nxt is not None and nxt["MethodList"] else \
            method_rows + 1
        if end <= start:
            return start, start
        return start, end

    def _field_range(tid):
        raw = tables.row(0x02, tid)
        if raw is None or raw["FieldList"] == 0:
            return None, None
        start = raw["FieldList"]
        nxt = tables.row(0x02, tid + 1)
        end = nxt["FieldList"] if nxt is not None and nxt["FieldList"] else \
            field_rows + 1
        if end <= start:
            return start, start
        return start, end

    types = []
    owner_of = {}
    for tid, tr in tables.rows(0x02):
        nm = tables.string(tr["TypeName"])
        ns = tables.string(tr["TypeNamespace"])
        ms, me = _method_range(tid)
        fs, fe = _field_range(tid)
        mcount = 0 if ms is None else max(0, me - ms)
        for mi in range(ms or 0, me or 0):
            owner_of.setdefault(mi, tid)
        extends = _decode_coded("TypeDefOrRef", tr["Extends"])
        ext_txt = None
        if extends and extends.get("kind") == "TypeDef":
            er = tables.row(0x02, extends["row"])
            if er is not None:
                en = tables.string(er["TypeName"])["value"]
                ens = tables.string(er["TypeNamespace"])["value"]
                ext_txt = (ens + "." if ens else "") + (en or "")
        elif extends and extends.get("kind") == "TypeRef":
            er = tables.row(0x01, extends["row"])
            if er is not None:
                en = tables.string(er["TypeName"])["value"]
                ens = tables.string(er["TypeNamespace"])["value"]
                ext_txt = (ens + "." if ens else "") + (en or "")
        types.append({
            "row": tid, "token": "0x02%06x" % tid,
            "namespace": ns["value"], "name": nm["value"],
            "name_missing": nm["missing"] or ns["missing"],
            "flags": tr["Flags"], "flags_hex": "0x%08x" % tr["Flags"],
            "extends": extends, "extends_text": ext_txt,
            "field_range": [fs, fe] if fs is not None else None,
            "field_count": 0 if fs is None else max(0, fe - fs),
            "method_range": [ms, me] if ms is not None else None,
            "method_count": mcount,
            "nested": {"enclosing_row": nested.get(tid)},
            "kind": ("pseudo_module" if (nm["value"] == "<Module>" and
                                         not (ns["value"] or ""))
                     else ("nested" if tid in nested else "toplevel")),
        })

    # ── 方法 / 方法体 / IL ─────────────────────────────────────────
    methods = []
    den = {
        "methoddef_rows": method_rows,
        "methods_with_rva": 0, "methods_without_rva": 0,
        "without_rva_by_reason": {"abstract": 0, "pinvoke": 0, "runtime": 0,
                                  "native": 0, "unclassified": 0},
        "rva_mapped": 0, "rva_unmapped": 0,
        "body_ok": 0, "body_bad_header": 0, "body_code_truncated": 0,
        "tiny_bodies": 0, "fat_bodies": 0,
        "methods_with_eh": 0, "eh_clauses": 0,
        "il_decoded": 0, "il_undecodable": 0, "il_instructions": 0,
    }
    stored = 0
    for mid, mr in tables.rows(0x06):
        nm = tables.string(mr["Name"])
        rva = mr["RVA"]
        impl = mr["ImplFlags"]
        flags = mr["Flags"]
        sig = tables.blob(mr["Signature"])
        item = {
            "row": mid, "token": "0x06%06x" % mid,
            "owner_row": owner_of.get(mid), "name": nm["value"],
            "name_missing": nm["missing"],
            "rva": rva, "impl_flags": impl, "flags": flags,
            "impl_flags_hex": "0x%04x" % impl, "flags_hex": "0x%04x" % flags,
            "signature_len": sig["length"],
            "signature_hex": (sig["value"][:32].hex()
                              if sig["value"] is not None else None),
            "signature_missing": sig["missing"],
            "body": None, "body_status": None, "body_reason": None,
            "il": {"instruction_count": 0, "instructions": [],
                   "stored": False, "truncated": False,
                   "undecodable_at": None, "tail_bytes": None},
        }
        if rva == 0:
            den["methods_without_rva"] += 1
            if flags & 0x0400:
                reason = "abstract"
            elif flags & 0x2000:
                reason = "pinvoke"
            elif impl & 3 == 3:
                reason = "runtime"
            elif impl & 3 == 1:
                reason = "native"
            else:
                reason = "unclassified"
            den["without_rva_by_reason"][reason] += 1
            item["body_status"] = "no_body_rva_zero"
            item["body_reason"] = reason
            methods.append(item)
            continue
        den["methods_with_rva"] += 1
        off, why = _rva_to_off(rva, sections, file_len)
        if off is None:
            den["rva_unmapped"] += 1
            item["body_status"] = "rva_unmapped"
            item["body_reason"] = why
            methods.append(item)
            continue
        den["rva_mapped"] += 1
        body, err = _parse_body(data, off, file_len)
        if body is None:
            den["body_bad_header"] += 1
            item["body_status"] = "body_bad_header"
            item["body_reason"] = err
            methods.append(item)
            continue
        item["body"] = {
            "kind": body["kind"], "header_off": body["header_off"],
            "header_size": body["header_size"], "code_off": body["code_off"],
            "code_size": body["code_size"], "max_stack": body["max_stack"],
            "local_sig": body["local_sig"], "flags": body["flags"],
            "sections": body["sections"], "eh_clauses": body["eh_clauses"],
        }
        if err == "body_code_truncated":
            den["body_code_truncated"] += 1
            item["body_status"] = "body_code_truncated"
            item["body_reason"] = err
            methods.append(item)
            continue
        den["body_ok"] += 1
        if body["kind"] == "tiny":
            den["tiny_bodies"] += 1
        else:
            den["fat_bodies"] += 1
        if body["eh_clauses"]:
            den["methods_with_eh"] += 1
            den["eh_clauses"] += len(body["eh_clauses"])
        code = data[body["code_off"]:body["code_off"] + body["code_size"]]
        insns, il_err = _decode_il(code)
        den["il_instructions"] += len(insns)
        if il_err is None:
            den["il_decoded"] += 1
        else:
            den["il_undecodable"] += 1
        item["body_status"] = "ok"
        tail = (body["code_size"] - (insns[-1]["offset"] + insns[-1]["size"])
                if insns else body["code_size"])
        keep = (detail_methods is None or stored < detail_methods)
        stored_insns = []
        truncated = False
        if keep:
            stored += 1
            if detail_insns is not None and len(insns) > detail_insns:
                stored_insns = insns[:detail_insns]
                truncated = True
            else:
                stored_insns = insns
        item["il"] = {
            "instruction_count": len(insns),
            "instructions": stored_insns,
            "stored": bool(keep),
            "truncated": truncated,
            "undecodable_at": il_err,
            "tail_bytes": tail,
        }
        methods.append(item)

    # 恒等式
    d = den
    d["methods_identity_ok"] = (
        d["methods_with_rva"] + d["methods_without_rva"] == d["methoddef_rows"])
    d["rva_identity_ok"] = (
        d["rva_mapped"] + d["rva_unmapped"] == d["methods_with_rva"])
    d["body_identity_ok"] = (
        d["body_ok"] + d["body_bad_header"] + d["body_code_truncated"]
        == d["rva_mapped"])
    d["il_identity_ok"] = (
        d["il_decoded"] + d["il_undecodable"] == d["body_ok"])
    d["identity_ok"] = bool(
        d["methods_identity_ok"] and d["rva_identity_ok"]
        and d["body_identity_ok"] and d["il_identity_ok"])
    d["body_ratio"] = (d["body_ok"] / d["methoddef_rows"]
                       if d["methoddef_rows"] else None)
    d["il_boundary_ratio"] = (d["il_decoded"] / d["body_ok"]
                              if d["body_ok"] else None)
    d["types_typedef_rows"] = typedef_rows
    d["types_pseudo_module"] = sum(1 for t in types
                                   if t["kind"] == "pseudo_module")
    d["types_named"] = typedef_rows - d["types_pseudo_module"]
    d["types_nested"] = len(nested)
    d["types_with_methods"] = sum(1 for t in types if t["method_count"])
    d["fields_rows"] = field_rows
    d["params_rows"] = param_rows
    d["interface_impls"] = tables.row_counts.get(0x09, 0)
    d["nested_class_rows"] = tables.row_counts.get(0x29, 0)
    d["detail_methods_stored"] = stored

    # ── 泛型 / 字符串 / 程序集 ─────────────────────────────────────
    gparams = []
    for gi, gr in tables.rows(0x2A):
        owner = _decode_coded("TypeOrMethodDef", gr["Owner"])
        gparams.append({"row": gi, "number": gr["Number"],
                        "flags": gr["Flags"],
                        "owner": owner,
                        "name": tables.string(gr["Name"])["value"]})
    assembly = None
    ar = tables.row(0x20, 1)
    if ar is not None:
        assembly = {
            "name": tables.string(ar["Name"])["value"],
            "version": "%d.%d.%d.%d" % (ar["Major"], ar["Minor"],
                                       ar["Build"], ar["Rev"]),
            "culture": tables.string(ar["Culture"])["value"],
            "flags": ar["Flags"], "hash_alg": ar["HashAlgId"],
            "public_key_len": tables.blob(ar["PublicKey"])["length"],
        }
    us = _stream(meta, "#US")
    us_entries = _us_entries(data, us) if us and not us.get("out_of_range") \
        else {"entries": None, "reserved_empty": None, "non_empty": None,
              "items": [], "previews": [], "reason": "无 #US 流"}

    rep = {
        "schema": SCHEMA, "path": str(path), "status": STATUS_OK,
        "reason": None,
        "caliber": CALIBER,
        "file": {"format": "PE", "machine": r["machine"],
                 "image_base": r["image_base"], "entry": r["entry"],
                 "cli_rva": cli_rva, "cli_size": cli_size,
                 "sections": sections},
        "cli_header": cli,
        "metadata": {k: meta.get(k) for k in
                     ("signature", "major", "minor", "version", "flags",
                      "size", "streams")},
        "tables": {
            "major": tables.major, "minor": tables.minor,
            "heap_sizes": tables.heap_sizes,
            "valid_mask": "0x%016x" % tables.valid,
            "sorted_mask": "0x%016x" % tables.sorted,
            "row_counts": {TABLE_NAMES.get(t, "0x%02x" % t): n
                           for t, n in sorted(tables.row_counts.items())},
            "table_data_range": [tables.table_data_off,
                                 tables.table_data_end],
            "errors": tables.errors,
        },
        "assembly": assembly,
        "types": types,
        "methods": methods,
        "strings_us": us_entries,
        "generics": {
            "params": gparams,
            "generic_param_rows": len(gparams),
            "method_specs": tables.row_counts.get(0x2B, 0),
            "type_specs": tables.row_counts.get(0x1B, 0),
            "constraints": tables.row_counts.get(0x2C, 0),
        },
        "denominators": den,
        "cross_layer": CROSS_LAYER,
        "caveats": list(CAVEATS),
        "limit": 40,
    }
    return rep


def _us_entries(data, s):
    """#US 堆：偏移 0 是保留空串；堆尾可能有 1 字节对齐 0（不是字符串条目）。"""
    base, size = s["file_off"], s["size"]
    items, off = [], 0
    while off < size:
        try:
            n, pos = _compressed(data, base + off)
        except ValueError:
            break
        if n == 0:
            if off == 0:
                items.append({"offset": 0, "text": ""})
                off = pos - base
                continue
            break                              # 尾部对齐填充，不是条目
        if pos + n > base + size or pos + n > len(data):
            break
        raw = data[pos:pos + n - 1]
        items.append({"offset": off,
                      "text": raw.decode("utf-16-le", "replace")})
        off = pos - base + n
    non_empty = [i["text"] for i in items if i["text"]]
    return {"entries": len(items),
            "reserved_empty": 1 if items and items[0]["text"] == "" else 0,
            "non_empty": len(non_empty),
            "items": items,
            "previews": non_empty[:64],
            "note": "#US 字面量（ldstr 的 token 指向此处）；只给原文，"
                    "不解密/不还原拼接；offset 是 #US 堆内偏移（token 低 24 位）"}


# ── 渲染 / CLI ──────────────────────────────────────────────────────
def render(rep, limit=None):
    if rep.get("status") in (STATUS_ERROR,):
        return ("== dotnet ==\n路径：%s\n错误：%s"
                % (rep.get("path"), rep.get("reason")))
    limit = rep.get("limit", 40) if limit is None else limit
    out = ["== rekit dotnet ==", "路径：%s" % rep.get("path"),
           "状态：%s" % rep.get("status")]
    if rep.get("status") != STATUS_OK:
        out.append("原因：%s" % rep.get("reason"))
        out.append("（已读到的声明部分见 JSON；缺失即缺失，不按常见布局补）")
        return "\n".join(out)
    f = rep["file"]
    cli = rep["cli_header"]
    meta = rep["metadata"]
    out.append("PE：%s  ImageBase=0x%x  Entry=0x%x  节数=%d"
               % (f["machine"], f["image_base"], f["entry"], len(f["sections"])))
    out.append("CLI 头：RVA=0x%x file=0x%x cb=%d 版本=%d.%d "
               "EntryPointToken=0x%08x 元数据 RVA=0x%x size=%d"
               % (cli["rva"], cli["file_off"], cli["cb"], cli["major"],
                  cli["minor"], cli["entrypoint_token"],
                  cli["metadata_rva"], cli["metadata_size"]))
    out.append("元数据根：%s 版本=%r 流=%s"
               % (meta["signature"], meta["version"],
                  ", ".join("%s(0x%x)" % (s["name"], s["size"])
                            for s in meta["streams"])))
    asm = rep.get("assembly")
    out.append("程序集：%s" % (("%s %s culture=%r" %
                             (asm["name"], asm["version"], asm["culture"]))
                             if asm else "无 Assembly 表行"))
    out.append("")
    d = rep["denominators"]
    out.append("== 分母（先报分母）==")
    out.append("TypeDef 行 %d（<Module> 伪类型 %d；命名类型 %d；嵌套 %d）；"
               "接口实现 %d；字段 %d；参数 %d"
               % (d["types_typedef_rows"], d["types_pseudo_module"],
                  d["types_named"], d["types_nested"], d["interface_impls"],
                  d["fields_rows"], d["params_rows"]))
    out.append("MethodDef 行 %d = 有 RVA %d + 无 RVA %d（恒等式 %s）"
               % (d["methoddef_rows"], d["methods_with_rva"],
                  d["methods_without_rva"],
                  "成立" if d["methods_identity_ok"] else "不成立"))
    out.append("无 RVA 原因：" + "；".join(
        "%s=%d" % kv for kv in
        sorted(d["without_rva_by_reason"].items())))
    out.append("有 RVA：可定位到文件 %d；不可定位 %d（恒等式 %s）"
               % (d["rva_mapped"], d["rva_unmapped"],
                  "成立" if d["rva_identity_ok"] else "不成立"))
    out.append("可定位：方法体解析成功 %d；头非法 %d；代码区截断 %d"
               "（恒等式 %s）"
               % (d["body_ok"], d["body_bad_header"], d["body_code_truncated"],
                  "成立" if d["body_identity_ok"] else "不成立"))
    out.append("方法体：tiny=%d fat=%d；带 EH 的方法 %d，EH 子句 %d"
               % (d["tiny_bodies"], d["fat_bodies"], d["methods_with_eh"],
                  d["eh_clauses"]))
    out.append("IL：解出边界 %d 个方法；不可解 %d；指令总数 %d"
               "（恒等式 %s）"
               % (d["il_decoded"], d["il_undecodable"],
                  d["il_instructions"],
                  "成立" if d["il_identity_ok"] else "不成立"))
    out.append("比例：方法体成功/MethodDef = %s；IL 解出/有体 = %s"
               % (("-" if d["body_ratio"] is None else
                   "%.6f" % d["body_ratio"]),
                  ("-" if d["il_boundary_ratio"] is None else
                   "%.6f" % d["il_boundary_ratio"])))
    out.append("泛型：GenericParam %d；MethodSpec %d；TypeSpec %d；约束 %d"
               % (rep["generics"]["generic_param_rows"],
                  rep["generics"]["method_specs"],
                  rep["generics"]["type_specs"],
                  rep["generics"]["constraints"]))
    us = rep.get("strings_us") or {}
    out.append("#US 字符串字面量：条目 %s（空串 %s + 非空 %s）%s"
               % (us.get("entries"), us.get("reserved_empty"),
                  us.get("non_empty"),
                  ("（%s）" % us["reason"]) if us.get("reason") else ""))
    out.append("")
    out.append("== 类型（%d 个，显示前 %d）==" % (len(rep["types"]),
                                              min(limit, len(rep["types"]))))
    for t in rep["types"][:limit]:
        full = ((t["namespace"] + ".") if t["namespace"] else "") + \
            (t["name"] or "(缺名字)")
        out.append("%s %-40s 方法=%d 字段=%d extends=%s 嵌套于=%s"
                   % (t["token"], full, t["method_count"], t["field_count"],
                      t["extends_text"] or "-",
                      t["nested"]["enclosing_row"] or "-"))
    out.append("")
    out.append("== 方法（%d 个，显示前 %d）==" % (len(rep["methods"]),
                                              min(limit, len(rep["methods"]))))
    for m in rep["methods"][:limit]:
        body = m.get("body") or {}
        il = m.get("il") or {}
        if body:
            btxt = "%s code=0x%x@file0x%x insn=%d" % (
                body["kind"], body["code_size"], body["code_off"],
                il.get("instruction_count", 0))
        else:
            btxt = "%s(%s)" % (m.get("body_status"), m.get("body_reason"))
        out.append("%s %-32s RVA=0x%-6x %s"
                   % (m["token"], m["name"], m["rva"], btxt))
    out.append("")
    out.append("== 与既有层的关系（显式，不静默空）==")
    for c in rep.get("cross_layer") or []:
        out.append("%-12s %-20s %s" % (c["layer"], c["status"], c["reason"]))
    out.append("")
    out.append("== caveat ==")
    for c in rep.get("caveats") or []:
        out.append("- " + c)
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rekit dotnet",
        description=".NET 程序集结构层：类型/方法/方法体位置/IL 指令边界（只读声明）")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--detail-methods", type=int, default=50,
                    help="JSON 中存储 IL 指令的方法数（分母计数不受影响）")
    ap.add_argument("--detail-insns", type=int, default=256,
                    help="每个方法存储的 IL 指令上限")
    ap.add_argument("--il-token", help="打印指定方法 token（如 0x06000005）的逐条 IL")
    a = ap.parse_args(argv)
    try:
        rep = build(a.path, detail_methods=a.detail_methods,
                    detail_insns=a.detail_insns)
    except OSError as e:
        print("rekit: %s: %s" % (a.path, e), file=sys.stderr)
        return 2
    except Exception as e:
        rep = {"schema": SCHEMA, "path": str(a.path), "status": STATUS_ERROR,
               "reason": "%s: %s" % (type(e).__name__, e)}
    if a.il_token:
        try:
            tok = int(a.il_token, 0)
        except ValueError:
            print("rekit: --il-token %r: 不是合法 token" % a.il_token,
                  file=sys.stderr)
            return 2
        for m in rep.get("methods") or []:
            if int(m["token"], 16) == tok:
                print("== %s %s RVA=0x%x =="
                      % (m["token"], m["name"], m["rva"]))
                il = m.get("il") or {}
                if not il.get("instructions"):
                    print("IL 指令未存储（%s）"
                          % (il.get("undecodable_at") or "detail 限制"))
                for ins in il.get("instructions") or []:
                    print("  IL_%04x +%d %-16s %s"
                          % (ins["offset"], ins["size"], ins["opcode"],
                             ins["operand_hex"]))
                return 0
        print("rekit: 找不到 token %s 的方法" % a.il_token, file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(render(rep, a.limit))
    return 0 if rep.get("status") == STATUS_OK else 2


if __name__ == "__main__":
    sys.exit(main())
