#!/usr/bin/env python3
# 2026-11-10 A1 验收：rekit checksec 三态 vs readelf 权威期望表（18 格全等比对）
# 权威值来源：evidence_readelf_authority.log（readelf -hW/-lW/-d 实测推导）
# 推导规则（与 readelf/checksec 语义一致）：
#   NX     = GNU_STACK 含 X ? disabled : enabled
#   RELRO  = 无 GNU_RELRO ? none : (BIND_NOW∨FLAGS&0x8∨FLAGS_1&0x1 ? full : partial)
#   PIE    = EXEC ? no : (INTERP ? yes : dso)
import sys

sys.path.insert(0, "<旧仓库根>")
from rekit.elf import parse  # noqa: E402

FIX = "<旧仓库根>/tests/fixtures"
# (样本, NX, RELRO, PIE) — 全部来自 evidence_readelf_authority.log 实测
EXPECT = [
    ("bin_ls.elf",    "enabled",  "full",    "yes"),   # FLAGS BIND_NOW + FLAGS_1 NOW
    ("dyn_pie",       "enabled",  "partial", "yes"),   # 仅 FLAGS_1 PIE
    ("dyn_nopie",     "enabled",  "partial", "no"),
    ("dyn_static",    "enabled",  "partial", "no"),    # 静态：有 RELRO 段无立即绑定
    ("dyn_norelro",   "enabled",  "none",    "no"),    # -z norelro 构造
    ("dyn_execstack", "disabled", "partial", "yes"),   # -z execstack：GNU_STACK RWE
]

fails = 0
print("%-16s %-9s %-9s %-9s %-6s %-9s %-9s %-6s %s" %
      ("fixture", "NX*", "RELRO*", "PIE*", "ok?", "NX", "RELRO", "PIE", "extra"))
for name, e_nx, e_relro, e_pie in EXPECT:
    s = parse(f"{FIX}/{name}")["security"]
    cells = [(s["nx"], e_nx), (s["relro"], e_relro), (s["pie"], e_pie)]
    ok = all(m == e for m, e in cells)
    fails += 0 if ok else 1
    extra = ("stackflags=0x%x bind_now=%s wx=%s" %
             (s["gnu_stack_flags"] or 0, s["bind_now"],
              ",".join(s["wx_segments"]) or "-"))
    print("%-16s %-9s %-9s %-9s %-6s %-9s %-9s %-6s %s" %
          (name, e_nx, e_relro, e_pie, "PASS" if ok else "FAIL",
           s["nx"], s["relro"], s["pie"], extra))

total = len(EXPECT) * 3
print("\n%d/%d cells equal (expect 18/18) -> %s" %
      (total - fails * 3, total, "A1 PASS" if fails == 0 else "A1 FAIL"))
sys.exit(1 if fails else 0)
