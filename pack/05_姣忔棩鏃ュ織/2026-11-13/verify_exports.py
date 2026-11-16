#!/usr/bin/env python3
# verify_exports.py — B2 三方逐项全等比对：rekit ↔ objdump -p（构造参数为公共参照）
# 用法：python3 verify_exports.py [dll路径]  → 输出 PASS/FAIL 明细
import re
import subprocess
import sys

sys.path.insert(0, "<旧仓库根>")
from rekit.pe import parse  # noqa: E402

DLL = sys.argv[1] if len(sys.argv) > 1 else \
    "<旧仓库根>/tests/minidll.dll"

# ---- rekit 侧：(name|None, ordinal, rva) ----
r = parse(DLL)
rekit_set = set()
for (nm, ordinal, rva) in r["exports"]["exports"]:
    rekit_set.add((nm, ordinal, rva))
rekit_named = {nm: (ordinal, rva) for (nm, ordinal, rva) in rekit_set if nm}

# ---- objdump 侧：EAT 段 (ordinal, rva) + Ordinal/Name 段 (name, ordinal) ----
# 返工#1 修正：必须按段落切分——EAT 行尾 "Export RVA" 会被裸正则误吃成函数名
out = subprocess.run(["objdump", "-p", DLL], capture_output=True, text=True,
                     check=True).stdout
eat_part = out.split("Export Address Table -- Ordinal Base")[1].split("[Ordinal/Name Pointer] Table")[0]
name_part = out.split("[Ordinal/Name Pointer] Table")[1]
eat = {}      # ordinal -> rva
for m in re.finditer(r"\[\s*\d+\] \+base\[\s*(\d+)\] ([0-9a-f]{8}) Export RVA", eat_part):
    eat[int(m.group(1))] = int(m.group(2), 16)
objdump_named = {}
for m in re.finditer(r"\[\s*\d+\] \+base\[\s*(\d+)\]\s+[0-9a-f]{4} (\w+)", name_part):
    objdump_named[m.group(2)] = int(m.group(1))

fails = []
def chk(cond, msg):
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        fails.append(msg)

# 1) EAT 全表（含纯序号项）逐项：ordinal→rva
chk(set(eat.items()) == {(o, v) for (_, o, v) in rekit_set},
    "EAT 全表 ordinal→RVA 逐项全等（%d 项，含纯序号）" % len(eat))
# 2) 名字导出：name→ordinal 映射（经 AddressOfNameOrdinals 换算的正确性）
chk(objdump_named == {nm: o for (nm, o, _) in rekit_set if nm},
    "名字→ordinal 映射全等（%s）" % objdump_named)
# 3) 关键反陷阱点：名字表顺序 ≠ EAT 顺序
chk(rekit_named.get("Mul") == (3, 0x1030) and rekit_named.get("Sub") == (2, 0x1020),
    "Mul→ord3@0x1030 / Sub→ord2@0x1020（顺序≠EAT序陷阱防住）")
# 4) 纯序号项
chk((None, 4, 0x1040) in rekit_set, "纯序号导出以 (None, ord4, 0x1040) 呈现")
# 5) DLL 名与目录
chk(r["exports"]["dll"] == "minidll.dll" and r["exports"]["base"] == 1,
    "DLL 名 minidll.dll / Base=1")

print("\n%s (%d FAIL)" % ("ALL PASS" if not fails else "HAS FAILURES", len(fails)))
sys.exit(1 if fails else 0)
