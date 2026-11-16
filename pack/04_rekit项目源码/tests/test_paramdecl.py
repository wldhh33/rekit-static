# tests/test_paramdecl.py — M8-U2：参数绑定只认 declared 来源
#
# 断言按验收四条组织：
#   1) 判据先于实现：R76「暂态写」的可判定证据集合为空 → 该判据本轮不可判定，
#      只能算负向约束（call 的 rsp 写按持久写）。同一口径套到参数绑定上：
#      没有「文件哪一处、怎么读到的」就不许绑定；
#   2) 声明来源必须可定位：DWARF 报节头/sh_offset/sh_size/压缩头 + CU/DIE +
#      位置表达式字节；导出表/COFF/ELF 符号表/PDB 结构性不声明形参；
#   3) 分母先行：无声明来源时 available=false，sites 仍计入分母且全部 abstain，
#      不得报「0 个参数」；
#   4) 数字分列：bound / partial / abstained 分开计数，弃权写清缺什么。
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rekit import callfacts as CF, paramdecl as PD, recdesc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(WORK))
SAMPLES = os.path.join(ROOT, "m2-task-card", "work", "samples")
GO_LINUX = os.path.join(SAMPLES, "hello_go_linux")
GO_EXE = os.path.join(SAMPLES, "hello_go.exe")
RUST = os.path.join(SAMPLES, "hello_rust.exe")
CLI = os.path.join(HERE, "fixtures", "cli-64.exe")
BINLS = os.path.join(HERE, "fixtures", "bin_ls.elf")
MINIDLL = os.path.join(HERE, "fixtures", "minidll.dll")

_need = pytest.mark.skipif(not os.path.isfile(GO_LINUX), reason="缺 Go 样本")
_cache = {}


def _read(path):
    if path not in _cache:
        _cache[path] = PD.read(path)
    return _cache[path]


def _facts(path):
    if ("f", path) not in _cache:
        _cache[("f", path)] = CF.build(path, res=recdesc.descend(path))
    return _cache[("f", path)]


# ── 合成 DWARF：每个读取路径都能被单测钉住 ──────────────────────────
def _uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _abbrev_bytes():
    def spec(at, form):
        return _uleb(at) + _uleb(form)

    out = bytearray()
    # 1: compile_unit（有子节点），只读名字
    out += _uleb(1) + _uleb(PD.DW_TAG_compile_unit) + b"\x01"
    out += spec(PD.DW_AT_name, PD.DW_FORM_strp) + b"\x00\x00"
    # 2: subprogram（有子节点）：name / low_pc / high_pc(常量偏移)
    out += _uleb(2) + _uleb(PD.DW_TAG_subprogram) + b"\x01"
    out += spec(PD.DW_AT_name, PD.DW_FORM_strp)
    out += spec(PD.DW_AT_low_pc, PD.DW_FORM_addr)
    out += spec(PD.DW_AT_high_pc, PD.DW_FORM_data8) + b"\x00\x00"
    # 3: formal_parameter：name + exprloc
    out += _uleb(3) + _uleb(PD.DW_TAG_formal_parameter) + b"\x00"
    out += spec(PD.DW_AT_name, PD.DW_FORM_strp)
    out += spec(PD.DW_AT_location, PD.DW_FORM_exprloc) + b"\x00\x00"
    # 4: formal_parameter：name + 位置列表（sec_offset）
    out += _uleb(4) + _uleb(PD.DW_TAG_formal_parameter) + b"\x00"
    out += spec(PD.DW_AT_name, PD.DW_FORM_strp)
    out += spec(PD.DW_AT_location, PD.DW_FORM_sec_offset) + b"\x00\x00"
    out += b"\x00"
    return bytes(out)


def _synthetic():
    """CU v4：f@0x1000 三个形参（rdi / rsi+piece / loclist→rdx），g@0x2000 零形参。"""
    strsec = b"test.c\x00f\x00a\x00b\x00c\x00g\x00"
    loclists = (b"\x06" + struct.pack("<Q", 0x1000) +       # base_address
                b"\x04" + _uleb(0) + _uleb(0x100) + _uleb(1)
                + b"\x51" + b"\x00")                        # offset_pair → reg1(rdx)
    body = bytearray()
    body += _uleb(1) + struct.pack("<I", 0)                  # CU: name "test.c"
    body += _uleb(2) + struct.pack("<I", 7) + struct.pack("<Q", 0x1000) \
        + struct.pack("<Q", 0x100)                           # subprogram f
    body += _uleb(3) + struct.pack("<I", 9) + b"\x01\x55"    # a: reg5 = rdi
    body += _uleb(3) + struct.pack("<I", 11) \
        + b"\x06\x54\x93\x04\x55\x93\x04"                     # b: rsi(4)+rdi(4) 两段
    body += _uleb(4) + struct.pack("<I", 13) + struct.pack("<I", 0)  # c: loclist
    body += b"\x00"                                          # f 子节点结束
    body += _uleb(2) + struct.pack("<I", 15) + struct.pack("<Q", 0x2000) \
        + struct.pack("<Q", 0x50)                            # subprogram g
    body += b"\x00"                                          # g 子节点结束
    body += b"\x00"                                          # CU 子节点结束
    payload = struct.pack("<H", 4) + struct.pack("<I", 0) + b"\x08" + bytes(body)
    info = struct.pack("<I", len(payload)) + payload
    secs = {".debug_info": info, ".debug_abbrev": _abbrev_bytes(),
            ".debug_str": strsec, ".debug_loclists": loclists}
    meta = {"locator": {"format": "synthetic",
                        "sections": ["合成 .debug_info", "合成 .debug_loclists"]}}
    decls, metadata, ctx = PD._parse_dwarf(secs, meta)
    by_low = {d["low_pc"]: d for d in decls if d["low_pc"] is not None}
    dwarf = {"decls": decls, "meta": metadata, "ctx": ctx,
             "by_low_pc": by_low, "addr_base": 0}
    return secs, decls, metadata, ctx, dwarf


def _site(target, regs, call_kind="direct"):
    facts = [{
        "direction": "before", "kind": "reg", "operand": r,
        "at": 0x900 + i * 4, "bytes": "48 89 c7",
        "evidence": [{"level": "observed", "source": "instruction", "text": "字节"},
                     {"level": "derived", "source": "window", "text": "倒扫"}]}
        for i, r in enumerate(regs)]
    return {"call_kind": call_kind, "target": target, "facts": facts,
            "cross_facts": []}


# ── 1. 合成解析：abbrev / CU / DIE / loclist / 位置表达式 ─────────────
def test_synthetic_dwarf_counts_and_locations():
    _secs, decls, meta, _ctx, _dwarf = _synthetic()
    assert meta["cus"] == 1
    assert meta["declarations"] == 2
    assert meta["formal_parameters"] == 3
    f = next(d for d in decls if d["name"] == "f")
    assert f["low_pc"] == 0x1000 and f["high_pc"] == 0x1100
    assert [p["name"] for p in f["params"]] == ["a", "b", "c"]
    assert f["params"][0]["location"]["kind"] == "expr"
    assert f["params"][2]["location"]["kind"] == "loclist"


def test_synthetic_loclist_resolves_entry_reg():
    _secs, decls, _meta, ctx, _dwarf = _synthetic()
    f = next(d for d in decls if d["name"] == "f")
    expr, off, why = PD._param_entry_expr(f["params"][2], f, ctx)
    assert why is None and expr == b"\x51" and off is not None
    assert PD._entry_regs(expr) == {"kind": "regs", "regs": ["rdx"],
                                    "pieces": [{"reg": "rdx", "size": None}]}


def test_entry_regs_pieces_and_unknown_ops():
    assert PD._entry_regs(b"\x55")["regs"] == ["rdi"]
    assert PD._entry_regs(b"\x55\x93\x08")["pieces"] == [{"reg": "rdi", "size": 8}]
    assert PD._entry_regs(b"\x90\x05")["regs"] == ["rdi"]      # DW_OP_regx 5
    assert PD._entry_regs(b"\x91\x78")["kind"] == "stack"     # DW_OP_fbreg -8
    assert PD._entry_regs(b"\x92\x01\x00")["kind"] == "unknown"  # bregx 未解释


def test_canon_zdebug_name():
    assert PD._canon(".zdebug_info") == ".debug_info"
    assert PD._canon(".zdebug_abbrev") == ".debug_abbrev"
    assert PD._canon(".debug_info") == ".debug_info"


def test_dwarf2_cu_header_field_order():
    """DWARF 2–4 头顺序是 version、abbrev_offset、address_size（语料无 v2/v3）。"""
    body = bytearray()
    body += _uleb(1) + struct.pack("<I", 0) + b"\x00"
    payload = struct.pack("<H", 2) + struct.pack("<I", 0) + b"\x08" + bytes(body)
    info = struct.pack("<I", len(payload)) + payload
    decls, meta, _ctx = PD._parse_dwarf(
        {".debug_info": info, ".debug_abbrev": _abbrev_bytes()},
        {"locator": {"format": "synthetic", "sections": []}})
    assert decls == [] and meta["cus"] == 1


# ── 2. 绑定纪律：缺声明/缺位置一律 abstain ──────────────────────────
def test_bind_by_declared_only():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    r = PD.bind_site(_site(0x1000, ["rdi", "rsi", "rdx"]), dwarf)
    assert r["status"] == "bound"
    assert [b["name"] for b in r["bound"]] == ["a", "b", "c"]
    assert [b["regs"] for b in r["bound"]] == [["rdi"], ["rsi", "rdi"], ["rdx"]]
    for b in r["bound"]:
        decl = [e for e in b["evidence"] if e["level"] == "declared"]
        assert decl and decl[0]["source"] == "dwarf"
        assert "CU@0x" in decl[0]["text"] and "DIE@0x" in decl[0]["text"]
        assert "寄存器段" in decl[0]["text"] and "位置表达式" in decl[0]["text"]


def test_missing_def_is_partial_not_zero():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    r = PD.bind_site(_site(0x1000, ["rdi", "rsi"]), dwarf)
    assert r["status"] == "partial"          # 有绑定也有未绑定：不得报 bound
    assert len(r["bound"]) == 2 and len(r["partial"]) == 0
    assert len(r["abstains"]) == 1 and "rdx" in r["abstains"][0]["missing"]
    assert r["params_concluded"] == 2
    r2 = PD.bind_site(_site(0x1000, ["rsi"]), dwarf)
    assert r2["status"] == "partial"
    assert len(r2["bound"]) == 0 and len(r2["partial"]) == 1
    assert "rdi" in r2["partial"][0]["missing"]     # b 的第二段缺定义
    assert any("rdx" in a["missing"] for a in r2["abstains"])


def test_no_facts_abstains_without_abi_guess():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    r = PD.bind_site(_site(0x1000, []), dwarf)
    assert r["status"] == "abstained"
    assert r["bound"] == [] and r["params_concluded"] == 0
    assert len(r["abstains"]) == 3
    assert all("缺" in a["missing"] for a in r["abstains"])


def test_zero_params_is_declared_not_absent():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    r = PD.bind_site(_site(0x2000, []), dwarf)
    assert r["status"] == "zero_params" and r["zero_params"] is True
    assert r["bound"][0]["param"] is None
    assert "0 个" in r["bound"][0]["evidence"][0]["text"]


def test_no_declaration_and_no_dwarf_abstain():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    r = PD.bind_site(_site(0x3000, ["rdi"]), dwarf)
    assert r["status"] == "no_declaration"
    assert "缺" in r["abstains"][0]["missing"]
    assert "禁止按 ABI" in r["abstains"][0]["missing"]
    r2 = PD.bind_site(_site(0x3000, ["rdi"]), None)
    assert r2["status"] == "no_declaration"
    assert "禁止按 ABI" in r2["abstains"][0]["missing"]


def test_indirect_site_is_no_target():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    r = PD.bind_site(_site(None, ["rdi"], call_kind="indirect"), dwarf)
    assert r["status"] == "no_target"
    assert "间接调用" in r["abstains"][0]["missing"]


def test_pe_image_base_conversion_is_explicit():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    # PE 的 DW_AT_low_pc 已经是 ImageBase+RVA；这里模拟该事实，验证站点目标
    # （按 RVA）如何换算到声明地址空间。
    dwarf["addr_base"] = 0x140000000
    dwarf["by_low_pc"] = {k + 0x140000000: v for k, v in dwarf["by_low_pc"].items()}
    r = PD.bind_site(_site(0x1000, ["rdi", "rsi", "rdx"]), dwarf)
    assert r["status"] == "bound"
    assert r["lookup_addr"] == 0x140001000 and r["addr_base"] == 0x140000000
    r2 = PD.bind_site(_site(0x3000, ["rdi"]), dwarf)
    assert r2["status"] == "no_declaration"
    assert "ImageBase 0x140000000" in r2["abstains"][0]["missing"]


def test_summarize_keeps_categories_separate():
    _secs, _decls, _meta, _ctx, dwarf = _synthetic()
    bs = [PD.bind_site(_site(0x1000, ["rdi", "rsi", "rdx"]), dwarf),
          PD.bind_site(_site(0x1000, ["rdi"]), dwarf),
          PD.bind_site(_site(0x2000, []), dwarf),
          PD.bind_site(_site(0x3000, ["rdi"]), dwarf),
          PD.bind_site(_site(None, [], call_kind="indirect"), dwarf)]
    c = PD.summarize(bs)
    assert c["sites"] == 5
    assert c["site_status"] == {"bound": 1, "partial": 1, "zero_params": 1,
                                "no_declaration": 1, "no_target": 1}
    # 形参级分列：3 个全绑定 + 1 个（a）绑定；b 缺一段 → partial；c 缺定义、
    # 站点 4 缺声明、站点 5 间接调用 → 弃权 3 条。不合成净增量。
    assert (c["params_bound"], c["params_partial"], c["params_abstained"]) == (4, 1, 3)
    assert c["zero_params_sites"] == 1
    assert c["no_declaration_sites"] == 1 and c["no_target_sites"] == 1
    assert c["abstain_reasons"]["目标没有可读的形参声明"] == 1
    assert c["abstain_reasons"]["间接调用目标不可静态确定"] == 1


# ── 3. 声明来源可定位（真实样本） ───────────────────────────────────
@_need
def test_go_elf_dwarf_locator_and_counts():
    a = _read(GO_LINUX)["audit"]
    d = a["classes"]["dwarf"]
    assert d["present"] and d["readable"] and d["declares"] == "formal_parameters"
    assert d["param_decl_count"] == _read(GO_LINUX)["dwarf"]["meta"]["formal_parameters"]
    assert ("SHF_COMPRESSED" in d["locator"] or "ZLIB" in d["locator"])
    assert "sh_offset=0x" in d["locator"] and "sh_size=0x" in d["locator"]
    # 结构性别名来源：只声明函数身份，不声明形参
    assert a["classes"]["elf_symtab"]["declares"] == "function_identity_only"
    assert a["classes"]["elf_symtab"]["param_decl_count"] is None


@_need
def test_go_pe_dwarf_locator_and_counts():
    a = _read(GO_EXE)["audit"]
    d = a["classes"]["dwarf"]
    assert d["present"] and d["readable"]
    assert d["param_decl_count"] == _read(GO_EXE)["dwarf"]["meta"]["formal_parameters"]
    assert "raw_name=" in d["locator"] and "ZLIB" in d["locator"]
    assert a["classes"]["coff_symbols"]["declares"] == "function_identity_only"
    assert a["classes"]["coff_symbols"]["param_decl_count"] is None
    assert a["classes"]["pdata"]["declares"] == "function_range_only"


@_need
def test_pdb_export_structural_no_params():
    rust = _read(RUST)["audit"]["classes"]["pdb"]
    assert rust["present"] and rust["readable"] is False
    assert rust["declares"] == "types_only_undecoded"
    assert "abstain" in rust["note"]
    exp = _read(MINIDLL)["audit"]["classes"]["export_table"]
    assert exp["present"] and exp["declares"] == "function_identity_only"
    assert exp["param_decl_count"] is None
    gl = _read(BINLS)["audit"]["classes"]["gnu_debuglink"]
    assert gl["present"] and gl["readable"] is False      # 外部文件不存在
    assert "不作判据" in gl["note"]


@_need
def test_absent_sources_are_not_reported_readable():
    for p in (GO_LINUX, GO_EXE, CLI, MINIDLL):
        for k, v in _read(p)["audit"]["classes"].items():
            if not v["present"]:
                assert v["readable"] is False, (p, k)


# ── 4. 集成：分母、分列、禁止 ABI ────────────────────────────────────
@_need
def test_go_samples_bind_with_declared_evidence():
    for p, base in ((GO_LINUX, 0), (GO_EXE, 0x140000000)):
        r = _facts(p)
        pb = r["param_binding"]
        c = pb["counts"]
        assert pb["available"] is True
        assert c["sites"] == r["counts"]["sites"] > 0
        assert sum(c["site_status"].values()) == c["sites"]
        assert c["no_declaration_sites"] == 0
        assert c["params_bound"] > 0 and c["bound_pieces"] >= c["params_bound"]
        stored = [s for s in r["sites"] if s.get("param_binding")]
        assert len(stored) == c["sites"] - c["no_target_sites"]
        for s in stored:
            b = s["param_binding"]
            assert b["target"] == s["target"]
            assert b["addr_base"] == base
            assert b["lookup_addr"] == (s["target"] + base if base else s["target"])
            for item in b.get("bound") or []:
                if item["param"] is None:
                    continue
                decl = [e for e in item["evidence"]
                        if e["level"] == "declared" and e["source"] == "dwarf"]
                assert decl, "绑定必须带 declared 级 DWARF 证据"
                assert "DIE@0x" in decl[0]["text"] and "CU@0x" in decl[0]["text"]
                assert set(q["reg"] for q in item["binds"]) <= set(item["regs"])
                assert all(q["def_at"] < s["from"] for q in item["binds"])
        for item in (x for s in stored for x in
                     (s["param_binding"].get("abstains") or [])):
            assert "缺" in item["missing"]


@_need
def test_no_declaration_sample_keeps_denominator():
    r = _facts(CLI)
    pb = r["param_binding"]
    c = pb["counts"]
    assert pb["available"] is False
    assert c["sites"] == r["counts"]["sites"] > 0
    assert c["params_bound"] == 0 and c["params_partial"] == 0
    assert c["params_abstained"] == c["sites"]
    assert all(not s.get("param_binding") for s in r["sites"])
    assert "不是「0 个参数」" in pb["note"]
    assert pb["declared_source_audit"]["dwarf"]["present"] is False


@_need
def test_rule_text_forbids_abi_inference():
    r = _facts(CLI)
    rule = r["param_binding"]["rule"]
    assert "禁止按寄存器顺序" in rule and "abstain" in rule
    assert "PDB" in rule and "结构性缺失" in rule
