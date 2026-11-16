#!/usr/bin/env python3
# rekit ELF 回归测试套件 — 2026-11-07 落地（craft-anything 基线审计借鉴）
# 快照期望值来自 2026-11-07 全量验收 PASS 的真实输出（readelf 交叉验证过）
# 纪律：每个白银任务的验收断言必须固化进本套件，跑全量回归后才能收工。
import os
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from rekit.elf import parse  # noqa: E402

FIX = os.path.join(HERE, "fixtures")

# 2026-11-07 快照：/bin/ls (Ubuntu 24.04, coreutils) 30 节名序列
BIN_LS_SECTIONS = [
    "", ".note.gnu.property", ".note.gnu.build-id", ".interp", ".gnu.hash",
    ".dynsym", ".dynstr", ".gnu.version", ".gnu.version_r", ".rela.dyn",
    ".rela.plt", ".init", ".plt", ".plt.got", ".text", ".fini", ".rodata",
    ".eh_frame_hdr", ".eh_frame", ".note.ABI-tag", ".init_array",
    ".fini_array", ".data.rel.ro", ".dynamic", ".got", ".data", ".bss",
    ".gnu_debugaltlink", ".gnu_debuglink", ".shstrtab",
]
BIN_LS_NEEDED = ["libselinux.so.1", "libcap.so.2", "libc.so.6"]
BIN_LS_DYNAMIC = {"offset": 0x259f8, "vaddr": 0x269f8, "filesz": 0x210}


@pytest.fixture(scope="module")
def ls():
    return parse(f"{FIX}/bin_ls.elf")


@pytest.fixture(scope="module")
def pie():
    return parse(f"{FIX}/dyn_pie")


# ── 符号表回归（2026-11-08 白银任务，快照值 readelf -sW 交叉验证过）──

def test_dynsym_count_and_null_symbol(ls):
    # readelf: Symbol table '.dynsym' contains 138 entries（含第 0 号 null 符号）
    assert len(ls["symbols"]["dynsym"]) == 138
    assert ls["symbols"]["dynsym"][0] == ("", 0, 0, "LOCAL", "NOTYPE", 0)


def test_dynsym_imports_value_zero(ls):
    # SHN_UNDEF(ndx==0) 导入符号 st_value 恒为 0（bin_ls 122 个）
    imports = [s for s in ls["symbols"]["dynsym"] if s[5] == 0 and s[0]]
    assert len(imports) == 122
    assert all(s[1] == 0 for s in imports)
    assert "getenv" in {s[0] for s in imports}


def test_stripped_binary_has_no_symtab(ls):
    # bin_ls.elf 无 .symtab（stripped），必须优雅返回 None
    assert ls["symbols"]["symtab"] is None


def test_symtab_key_symbols_snapshot(pie):
    # dyn_pie .symtab 35 项；main=0x1129/11B、_start=0x1040/34B（readelf 对齐）
    assert len(pie["symbols"]["symtab"]) == 35
    syms = {s[0]: s for s in pie["symbols"]["symtab"]}
    assert syms["main"][1] == 0x1129 and syms["main"][2] == 11
    assert syms["main"][4] == "FUNC" and syms["main"][3] == "GLOBAL"
    assert syms["_start"][1] == 0x1040 and syms["_start"][2] == 34


def test_dynsym_vaddr_passthrough(pie):
    # st_value 是链接视图 vaddr，直接透传不换算：__libc_start_main UND=0
    d = {s[0]: s for s in pie["symbols"]["dynsym"]}
    assert d["__libc_start_main"][1] == 0 and d["__libc_start_main"][5] == 0
    assert len(pie["symbols"]["dynsym"]) == 6


def test_static_binary_symtab_no_dynsym():
    # dyn_static（无动态段）从节表路径仍解析 .symtab，且无 .dynsym
    r = parse(f"{FIX}/dyn_static")
    assert r["symbols"]["dynsym"] is None
    assert len(r["symbols"]["symtab"]) == 2084


# ── ELF 快照回归（自包含，不依赖外部工具）──────────────────────

def test_elf_header(ls):
    assert ls["entry"] == 0x6760
    assert len(ls["sections"]) == 30
    assert len(ls["phdrs"]) == 14


def test_section_names_snapshot(ls):
    got = [nm for (nm, *_rest) in ls["sections"]]
    assert got == BIN_LS_SECTIONS


def test_dynamic_needed_snapshot(ls):
    assert ls["dynamic"]["needed"] == BIN_LS_NEEDED


def test_dynamic_segment_fields_snapshot(ls):
    d = ls["dynamic"]
    assert (d["offset"], d["vaddr"], d["filesz"]) == (
        BIN_LS_DYNAMIC["offset"], BIN_LS_DYNAMIC["vaddr"],
        BIN_LS_DYNAMIC["filesz"])


def test_dyn_pie():
    r = parse(f"{FIX}/dyn_pie")
    assert r["dynamic"]["needed"] == ["libc.so.6"]


def test_dyn_nopie_vaddr_conversion():
    # 非 PIE：ImageBase 0x400000 剥离，0x400418 → 0x418
    d = parse(f"{FIX}/dyn_nopie")["dynamic"]
    assert d["strtab_vaddr"] == 0x400418
    assert d["strtab_off"] == 0x418
    assert d["needed"] == ["libc.so.6"]


def test_static_elf_no_dynamic():
    assert parse(f"{FIX}/dyn_static")["dynamic"] is None


# ── readelf 权威交叉验证（环境有 binutils 才跑）─────────────────

@pytest.mark.skipif(not shutil.which("readelf"), reason="readelf not available")
def test_cross_validate_with_readelf(ls):
    out = subprocess.run(
        ["readelf", "-d", f"{FIX}/bin_ls.elf"],
        capture_output=True, text=True).stdout
    ref = [ln.split("[")[1].rstrip("]") for ln in out.splitlines()
           if "Shared library:" in ln]
    assert ls["dynamic"]["needed"] == ref


# ── 重定位回归（2026-11-09 白银任务，快照值 readelf -rW 交叉验证过）──


def test_reloc_counts_snapshot(ls):
    # readelf: .rela.dyn contains 215 entries / .rela.plt contains 110 entries
    got = {nm: len(e) for (nm, _off, e) in ls["relocations"]}
    assert got == {".rela.dyn": 215, ".rela.plt": 110}


def test_reloc_type_distribution(ls):
    # readelf 统计：197 RELATIVE + 12 GLOB_DAT + 6 COPY（.rela.dyn）；110 JUMP_SLOT（.rela.plt）
    ents = {nm: e for (nm, _off, e) in ls["relocations"]}
    dist = {}
    for e in ents[".rela.dyn"]:
        dist[e[2]] = dist.get(e[2], 0) + 1
    assert dist == {8: 197, 6: 12, 5: 6}  # 8=RELATIVE 6=GLOB_DAT 5=COPY
    assert all(e[2] == 7 for e in ents[".rela.plt"])  # 全 JUMP_SLOT


def test_reloc_jumpslot_globdat_in_got(ls):
    # 110 JUMP_SLOT + 12 GLOB_DAT 的 r_offset 全落 .got [0x26c08, 0x26ff0)
    # （bin_ls 为 full RELRO 布局，.got.plt 已并入 .got）
    got = next(s for s in ls["sections"] if s[0] == ".got")
    lo, hi = got[2], got[2] + got[4]
    ents = [e for (_n, _o, es) in ls["relocations"] for e in es]
    for e in ents:
        if e[2] in (6, 7):
            assert lo <= e[0] < hi, "0x%x 越出 .got" % e[0]


def test_reloc_copy_bss_stvalue(ls):
    # 6 条 COPY 落 .bss 且 .dynsym 的 st_value == r_offset（复制语义：libc 数据 → 本模块 .bss）
    bss = next(s for s in ls["sections"] if s[0] == ".bss")
    lo, hi = bss[2], bss[2] + bss[4]
    copies = [e for (_n, _o, es) in ls["relocations"] for e in es if e[2] == 5]
    assert len(copies) == 6
    for e in copies:
        assert lo <= e[0] < hi
        assert e[6] == e[0]  # sym st_value == r_offset
    assert {e[5] for e in copies} == {"__progname", "stdout", "optind",
                                      "optarg", "__progname_full", "stderr"}


def test_reloc_static_irelative():
    # dyn_static：静态链接但 .rela.plt 有 22 条 R_X86_64_IRELATIVE(0x25)——ifunc 运行时修正
    # sym_idx 全 0（解析器内部选择器，非导入符号）
    r = parse(f"{FIX}/dyn_static")
    ents = [e for (_n, _o, es) in r["relocations"] for e in es]
    assert len(ents) == 22
    assert all(e[2] == 0x25 and e[4] == 0 and e[5] == "" for e in ents)


def test_reloc_dynamic_pie_snapshot():
    # dyn_pie：3 RELATIVE + 5 GLOB_DAT，无 .rela.plt；addend 联动语义抽样
    r = parse(f"{FIX}/dyn_pie")
    ents = [e for (_n, _o, es) in r["relocations"] for e in es]
    assert len(ents) == 8
    by_name = {e[5]: e for e in ents}
    assert by_name["__libc_start_main"][2] == 6  # GLOB_DAT
    assert by_name["__libc_start_main"][4] == 1  # .dynsym 序号 1（r_info>>32）
    assert by_name["__cxa_finalize"][2] == 6 and by_name["__cxa_finalize"][7] == 0


# ── readelf 重定位权威交叉验证（2026-11-09，环境有 binutils 才跑）──

@pytest.mark.skipif(not shutil.which("readelf"), reason="readelf not available")
def test_cross_validate_relocs_with_readelf(ls):
    """bin_ls.elf 全量 325 条 (offset,type,name[剥@GLIBC_*],addend) 逐行比对 readelf -rW。
    readelf 显示怪癖：无符号行（RELATIVE）addend 为裸十六进制，带符号行为 '+ 十进制'。"""
    import re
    out = subprocess.run(
        ["readelf", "-rW", f"{FIX}/bin_ls.elf"],
        capture_output=True, text=True).stdout
    ref = []
    for ln in out.splitlines():
        m = re.match(r"([0-9a-f]{16})\s+([0-9a-f]{16})\s+(R_X86_64_\S+)\s*(.*)", ln)
        if not m:
            continue
        tail = m.group(4).strip()
        if " + " in tail:
            head, _, add = tail.rpartition(" + ")
            nm = head.split()[-1].split("@")[0] if head.split() else ""
            ref.append((int(m.group(1), 16), m.group(3), nm, int(add)))
        else:
            ref.append((int(m.group(1), 16), m.group(3), "", int(tail, 16)))
    mine = [(o, tn, sn, ad)
            for (_n, _o, es) in ls["relocations"]
            for (o, _i, _t2, tn, _si, sn, _sv, ad) in es]
    assert mine == ref  # 325 条含 197 条无符号 RELATIVE 全一致


# ── readelf 符号表权威交叉验证（2026-11-08，环境有 binutils 才跑）──

@pytest.mark.skipif(not shutil.which("readelf"), reason="readelf not available")
def test_cross_validate_dynsym_with_readelf(ls):
    """bin_ls.elf .dynsym 全量 (name,value) 逐行比对 readelf -sW。
    注意 readelf 显示的符号名带 @GLIBC 后缀（来自 .gnu.version 节），
    原始 st_name 不含——比对前必须剥掉。"""
    import re
    out = subprocess.run(
        ["readelf", "-sW", f"{FIX}/bin_ls.elf"],
        capture_output=True, text=True).stdout
    ref, grab = [], False
    for ln in out.splitlines():
        if "Symbol table" in ln and "'.dynsym'" in ln:
            grab = True
            continue
        if grab:
            if not ln.strip():
                break
            m = re.match(
                r"\s*(\d+):\s+([0-9a-f]+)\s+\d+\s+\w+\s+\w+\s+\w+\s+\S+\s*(.*)", ln)
            if m:
                ref.append((m.group(3).split("@")[0].strip(), int(m.group(2), 16)))
    mine = [(nm, val) for (nm, val, *_t) in ls["symbols"]["dynsym"]]
    assert mine == ref  # 138 行含第 0 号 null 符号全一致


# ══ 2026-11-10 白银任务：checksec 三态（NX/RELRO/PIE）断言 ══
# 权威期望值来源：readelf -hW/-lW/-d 实测推导
# （artifacts/2026-11-10/evidence_readelf_authority.log）


@pytest.fixture(scope="module")
def sec():
    def _get(fn):
        return parse(f"{FIX}/{fn}")["security"]
    return _get


def test_checksec_bin_ls_full_relro_pie(sec):
    """/bin/ls：FLAGS BIND_NOW + FLAGS_1 NOW → Full RELRO；DYN+INTERP → PIE。"""
    s = sec("bin_ls.elf")
    assert s["nx"] == "enabled" and s["relro"] == "full" and s["pie"] == "yes"
    assert s["bind_now"] is True          # DT_FLAGS(30)&0x8 ∨ FLAGS_1&0x1 双路径命中
    assert s["relro_filesz"] > 0          # PT_GNU_RELRO 覆盖区间非空


def test_checksec_dyn_pie_partial(sec):
    """gcc 默认：-z relro 但无 now → Partial RELRO + PIE。"""
    s = sec("dyn_pie")
    assert s["nx"] == "enabled" and s["relro"] == "partial" and s["pie"] == "yes"
    assert s["bind_now"] is False


def test_checksec_dyn_nopie(sec):
    """ET_EXEC → no PIE；有 RELRO 无 now → partial。"""
    s = sec("dyn_nopie")
    assert s["pie"] == "no" and s["relro"] == "partial" and s["nx"] == "enabled"


def test_checksec_dyn_static(sec):
    """静态链接：有 PT_GNU_RELRO 无立即绑定 → partial（与 checksec 语义一致）。"""
    s = sec("dyn_static")
    assert s["pie"] == "no" and s["relro"] == "partial"


def test_checksec_dyn_norelro_none(sec):
    """-z norelro 构造：无 PT_GNU_RELRO → RELRO none。"""
    s = sec("dyn_norelro")
    assert s["relro"] == "none" and s["relro_filesz"] == 0
    assert s["pie"] == "no" and s["nx"] == "enabled"


def test_checksec_dyn_execstack_nx_disabled(sec):
    """-z execstack 构造：GNU_STACK flags=0x7(RWE) 含 X 位 → NX disabled。"""
    s = sec("dyn_execstack")
    assert s["nx"] == "disabled" and s["gnu_stack_flags"] == 0x7
    assert s["gnu_stack_flags"] & 0x1  # X 位真实置位
    assert s["relro"] == "partial" and s["pie"] == "yes"


def test_checksec_gnu_stack_flags_rw_standard(sec):
    """标准构建 5 样本 GNU_STACK flags 全为 0x6(RW)，X 位清零 → NX enabled。"""
    for fn in ("bin_ls.elf", "dyn_pie", "dyn_nopie", "dyn_static", "dyn_norelro"):
        s = sec(fn)
        assert s["gnu_stack_flags"] == 0x6, fn
        assert not s["gnu_stack_flags"] & 0x1, fn


def test_checksec_no_wx_load_segments(sec):
    """全部 6 样本无 W+X 并存的 PT_LOAD（正常编译器产物）；扫描器输出应为空。"""
    for fn in ("bin_ls.elf", "dyn_pie", "dyn_nopie", "dyn_static",
               "dyn_norelro", "dyn_execstack"):
        assert sec(fn)["wx_segments"] == [], fn


@pytest.mark.skipif(not shutil.which("readelf"), reason="readelf not available")
def test_checksec_cross_validate_execstack_with_readelf(sec):
    """dyn_execstack 的 GNU_STACK 行与 readelf -lW 权威输出交叉验证：
    readelf 显示 RWE ⟺ flags 含 X 位 ⟺ NX disabled。"""
    out = subprocess.run(["readelf", "-lW", f"{FIX}/dyn_execstack"],
                         capture_output=True, text=True).stdout
    line = next(l for l in out.splitlines() if "GNU_STACK" in l)
    flags = line.split()[6]  # GNU_STACK 0x0 0x0 0x0 0x0 0x0 RWE 0x10 → 第 7 列
    s = sec("dyn_execstack")
    assert ("E" in flags) == bool(s["gnu_stack_flags"] & 0x1) == (s["nx"] == "disabled")
