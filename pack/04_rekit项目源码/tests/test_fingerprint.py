#!/usr/bin/env python3
"""M2 断言：指纹层（对应任务卡 E1–E8）。

覆盖状态（2026-11-15 更新）：
  - E2 / E3 已解挂：UPX 5.3.0 官方包到位，PE/ELF 各有正样本（tests/samples/fingerprint/upx/）。
  - 正样本 ground truth 来自 upx 本体（upx -l / -t / -d 往返），非本工具自证。
  - 权威对拍局限（如实标注）：本机无 readelf/objdump/file，ELF 维度以 pyelftools
    与 2026-11-10 readelf 期望表为准，属「实现独立、非进程独立」。
"""
import json
import os
import subprocess
import sys

import pytest

from rekit import fingerprint, mcp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
FPFIX = os.path.join(ROOT, "tests", "samples", "fingerprint")

ELF_SAMPLES = ("dyn_pie", "dyn_nopie", "dyn_static", "dyn_execstack",
               "dyn_norelro", "bin_ls.elf")
PE_SAMPLES = ("cli-64.exe", "minipe.exe", "minidll.dll")
GO_PE = "hello_go.exe"
GO_ELF = "hello_go_linux"
RUST_PE = "hello_rust.exe"
BUSYBOX = "busybox-1.35.0-musl-x86_64"


def fp(name):
    return fingerprint.analyze(os.path.join(FIX, name))


def fpf(name):
    return fingerprint.analyze(os.path.join(FPFIX, name))


# ── E1 输出契约 ──────────────────────────────────────────────

def test_schema_has_six_top_level_keys():
    """E1：任意样本都含 6 个顶层键，packer 必备 name/confidence/evidence。"""
    targets = [(FIX, n) for n in ELF_SAMPLES + PE_SAMPLES]
    targets += [(FPFIX, n) for n in (GO_PE, GO_ELF, RUST_PE, BUSYBOX)]
    for base, n in targets:
        r = fingerprint.analyze(os.path.join(base, n))
        assert set(fingerprint.TOP_LEVEL_KEYS) <= set(r), n
        assert set(("name", "confidence", "evidence")) <= set(r["packer"]), n
        assert set(("family", "version", "confidence", "evidence")) <= set(r["compiler"]), n
        assert isinstance(r["evidence"], list) and r["evidence"], n


def test_cli_json_matches_module_and_exit_codes():
    """E1：CLI 的 JSON 与模块输出等价；退出码 2/3 分层不变。"""
    path = os.path.join(FIX, "dyn_pie")
    out = subprocess.run([sys.executable, "-m", "rekit.cli", "fingerprint", path,
                          "--json"], cwd=ROOT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == fingerprint.analyze(path)

    missing = subprocess.run([sys.executable, "-m", "rekit.cli", "fingerprint",
                              os.path.join(FIX, "no-such-file")],
                             cwd=ROOT, capture_output=True, text=True)
    assert missing.returncode == 2

    textfile = subprocess.run([sys.executable, "-m", "rekit.cli", "fingerprint",
                               os.path.abspath(__file__)],
                              cwd=ROOT, capture_output=True, text=True)
    assert textfile.returncode == 2


def test_mcp_tool_registered():
    """E1：MCP 暴露 rekit_fingerprint，且与 CLI 同源。"""
    names = {t["name"] for t in mcp.TOOLS}
    assert {"rekit_info", "rekit_map", "rekit_fingerprint"} <= names
    r = mcp.tool_fingerprint({"path": os.path.join(FIX, "dyn_pie")})
    assert r["compiler"]["family"] == "gcc"


# ── E2/E3（部分）：零误报；UPX 正判挂起 ───────────────────────

def test_packer_none_on_every_unpacked_sample():
    """E3 负控：全部未加壳样本必须判 none（含真实世界 PE：PuTTY）。"""
    targets = [os.path.join(FIX, n) for n in ELF_SAMPLES + PE_SAMPLES]
    targets += [os.path.join(FPFIX, n) for n in
                (GO_PE, GO_ELF, RUST_PE, BUSYBOX, "putty-64bit.exe")]
    for p in targets:
        r = fingerprint.analyze(p)
        assert r["packer"]["name"] == "none", p
        assert r["packer"]["confidence"] >= 0.8, p


# ── E2 UPX 正判（PE + ELF 双口径）─────────────────────────────

UPX_PE = os.path.join("upx", "upx_cli-64.exe")
UPX_PE_MIT = os.path.join("upx", "upx_putty-64bit.exe")
UPX_ELF = os.path.join("upx", "upx_dyn_pie")


def test_upx_detected_on_both_formats():
    """E2：PE 与 ELF 各 ≥1 正样本 → upx，且证据 ≥2 条（强判门槛）。"""
    for n in (UPX_PE, UPX_PE_MIT, UPX_ELF):
        r = fpf(n)
        assert r["packer"]["name"] == "upx", n
        assert len(r["packer"]["evidence"]) >= 2, n
        assert r["packer"]["confidence"] >= 0.9, n


def test_upx_pe_evidence_forms():
    """E2：PE 侧两条证据分别是打包节名与 UPX! 魔数偏移。"""
    ev = fpf(UPX_PE)["packer"]["evidence"]
    assert any("UPX0" in e for e in ev)
    assert any("UPX!" in e and "0x" in e for e in ev)


def test_upx_elf_degrades_honestly():
    """E2：UPX ELF 节表被移除 → 结构降级；编译器/stripped 必须 unknown。"""
    r = fpf(UPX_ELF)
    assert r["packer"]["name"] == "upx"
    assert any("节表被移除" in e for e in r["packer"]["evidence"])
    assert any("降级" in e for e in r["evidence"])
    assert r["compiler"]["family"] == "unknown"
    assert r["stripped"] == "unknown"


def test_unknown_single_evidence_never_strong():
    """E3 纪律：只有 1 条壳证据时必须是 unknown，不得直接报 upx。"""
    r = fingerprint.detect_packer(b"junk UPX! junk", ["UPX0"])
    assert r["name"] == "upx"                      # 2 条证据 → 强判
    r1 = fingerprint.detect_packer(b"junk UPX! junk", [".text"])
    assert r1["name"] == "unknown" and r1["confidence"] < 0.5
    r0 = fingerprint.detect_packer(b"pure", [".text"])
    assert r0["name"] == "none"


# ── E4 GCC ───────────────────────────────────────────────────

def test_gcc_version_from_comment():
    """E4：5 个 gcc 构造样本 → gcc 14.2.0；权威 = .comment 原文。"""
    for n in ELF_SAMPLES[:5]:
        r = fp(n)["compiler"]
        assert r["family"] == "gcc", n
        assert r["version"] == "14.2.0", n
        assert any("GCC:" in e for e in r["evidence"]), n


def test_gcc_absent_comment_must_be_unknown():
    """E4：无 .comment 的 stripped 样本必须 unknown（猜 gcc 即误报）。"""
    assert fp("bin_ls.elf")["compiler"]["family"] == "unknown"
    assert fpf(BUSYBOX)["compiler"]["family"] == "unknown"


# ── E5 MSVC（含 Rich 假阳性防线）──────────────────────────────

def test_msvc_rich_build_mapping():
    """E5：cli-64.exe → msvc 19.29（build 30729 在低 16 位）。"""
    r = fp("cli-64.exe")["compiler"]
    assert r["family"] == "msvc"
    assert r["version"] == "19.29"
    assert any("build=30729" in e for e in r["evidence"])


def test_rich_is_not_msvc_when_rust_evidence_present():
    """E5：带 Rich 的 rustc 产物必须判 rust —— 「有 Rich ⇒ MSVC」是错误规则。"""
    r = fpf(RUST_PE)
    assert r["compiler"]["family"] == "rust"
    assert r["compiler"]["version"] is None          # rustc 默认不嵌版本号
    assert any("rustc/<commit>" in e for e in r["compiler"]["evidence"])


def test_no_rich_and_no_marker_is_unknown():
    """E5：自构造 PE（无 Rich）→ unknown，不得猜 msvc。"""
    assert fp("minipe.exe")["compiler"]["family"] == "unknown"


# ── E6 Go / Rust ─────────────────────────────────────────────

def test_go_pe_and_elf_version():
    """E6：两种 Go 产物 → go，版本 1.27.3（权威 = go version -m）。"""
    assert fpf(GO_PE)["compiler"]["family"] == "go"
    assert fpf(GO_PE)["compiler"]["version"] == "1.27.3"
    assert fpf(GO_ELF)["compiler"]["family"] == "go"
    assert fpf(GO_ELF)["compiler"]["version"] == "1.27.3"


def test_compiler_family_is_single_valued():
    """E6：family 唯一，不允许并列（证据仲裁必须收敛）。"""
    for n in (GO_PE, RUST_PE):
        fam = fpf(n)["compiler"]["family"]
        assert isinstance(fam, str) and fam in ("go", "rust")


# ── E7 stripped ──────────────────────────────────────────────

def test_elf_stripped_by_symtab():
    """E7：ELF stripped ⇔ 无 .symtab；.dynsym 不作为依据。"""
    assert fp("bin_ls.elf")["stripped"] is True
    assert fpf(BUSYBOX)["stripped"] is True
    for n in ("dyn_pie", "dyn_static", GO_ELF):
        r = fingerprint.analyze(os.path.join(FPFIX if n == GO_ELF else FIX, n))
        assert r["stripped"] is False, n


def test_pe_reports_coff_symbols_not_stripped():
    """E7：PE 不做 stripped 语义，改报 COFF 符号表存在性。"""
    assert fp("cli-64.exe")["stripped"] == "n/a"
    assert fp("cli-64.exe")["coff_symbols"] == "absent"
    assert fpf(GO_PE)["coff_symbols"] == "present"


# ── E8 加固位 ─────────────────────────────────────────────────

def test_elf_mitigations_match_readelf_table():
    """E8：ELF 6 样本 × {NX,RELRO,PIE} 与 2026-11-10 readelf 期望表全等。"""
    expect = {
        "bin_ls.elf":   ("enabled", "full", "yes"),
        "dyn_pie":      ("enabled", "partial", "yes"),
        "dyn_nopie":    ("enabled", "partial", "no"),
        "dyn_static":   ("enabled", "partial", "no"),
        "dyn_norelro":  ("enabled", "none", "no"),
        "dyn_execstack": ("disabled", "partial", "yes"),
    }
    for n, (nx, relro, pie) in expect.items():
        m = fp(n)["mitigations"]
        assert (m["nx"], m["relro"], m["pie"]) == (nx, relro, pie), n


def test_pe_mitigation_bits():
    """E8：PE 位由图 vs pefile 实测 0x8160 全等（NX/ASLR/HEVA on，CFG off）。"""
    for n in ("cli-64.exe", "minidll.dll"):
        m = fp(n)["mitigations"]
        assert m["dll_characteristics"] == "0x8160", n
        assert m["nx"] and m["dynamicbase"] and m["high_entropy_va"], n
        assert m["cfg"] is False and m["no_seh"] is False, n
