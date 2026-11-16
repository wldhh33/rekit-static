# 2026-11-16 第二轮：按总账权威变更修正 R102/R103（只改这两条的 canonical 字段）。
import json
import os

ROOT = r"D:\数据\下载\逆向学习工作体系_2026-11-15"
REG = os.path.join(ROOT, "pack", "rules.json")

PATCH = {
    "R102": {
        "check_method": "总账文件只收实测；「唯一权威」指针由总账链路硬校验。现行权威是 `evidence_numbers_ledger.json`（生效范围 M13-patch 至 M18 收口），`pack\\tools\\ledger_check.py --check` 在任一命中时 exit 1：小节缺失、登记数字在人读镜像中漂移、证据文件 sha256 变化、证据 mtime 晚于权威 JSON。`evidence_m13_ledger.json` 已降级为「M13 历史权威快照」，在 `sources` 里以 sha256 固定，仍被引用但不代表现行范围；M12 及更早见 `evidence_m12_ledger.json`。M12 实例：25/25 全量重跑，实测 12,307,603/15,313,023=80.3734% 与推算差 0。",
        "enforced_at": "`work\\evidence_numbers_ledger.json`（现行权威，M13–M18）；`work\\outputs\\NUMBERS_LEDGER.md`（人读镜像）；`pack\\tools\\ledger_check.py`（硬校验，exit 1）；`work\\evidence_m13_ledger.json`（M13 历史快照，仅作 `sources` 引用）；`work\\evidence_m12_ledger.json`（M12 及更早）。",
        "basis": "`CHANGELOG.md:96`（完整版）；`PROGRESS.md:264`（摘要）；`evidence_numbers_ledger.json` 的 `authority` / `scope` / `sections` / `sources`；`pack\\tools\\ledger_check.py` 的六项检查",
        "canonical_status": "`规范`（现行权威链：`evidence_numbers_ledger.json` > `evidence_m13_ledger.json`（M13 历史快照）> `evidence_m12_ledger.json`（更早）；区分方法见规则库附录 C）",
        "confidence": "high",
    },
    "R103": {
        "check_method": "数字来自 `evidence_m13_ledger.json` 的 `pe_gap` 段（该文件现为 `sources` 中的 M13 历史快照），经人工核对 + `ledger_check.py --check` 的引用链校验。M13 复算：缝隙 113,731 B = `.text` 3.2262%，换 `.pdata` 口径 -0.0402pp；缝隙内 objdump 指令 113,731 条全为 `cc/90`，我方解出 372 条全为 `int3`，跨 pdata end 的指令 0、CFG 边 0。注意：这三个数字**未逐字登记**在新权威的 M13 小节（该节只登记 §6 下界结论的 6 个数字），故不受数字漂移检查保护——属显式缺口，见附录 C。",
        "enforced_at": "`work\\evidence_numbers_ledger.json`（现行权威，M13 小节）；`work\\outputs\\NUMBERS_LEDGER.md` §5；`pack\\tools\\ledger_check.py`（对已登记小节/数字与 `sources` sha256 硬校验）。",
        "basis": "`CHANGELOG.md:97`；`PROGRESS.md:264`；`evidence_m13_ledger.json` 的 `pe_gap`；`evidence_numbers_ledger.json` 的 `sources` 条目",
        "canonical_status": "`规范`（引用链改指现行权威；`pe_gap` 三个数字尚未被新权威登记，见附录 C）",
        "confidence": "high",
    },
}


def main():
    reg = json.load(open(REG, encoding="utf-8"))
    ids = {r["id"] for r in reg["rules"]}
    for k in PATCH:
        if k not in ids:
            raise SystemExit("missing id: %s" % k)
    changed = 0
    for r in reg["rules"]:
        p = PATCH.get(r["id"])
        if not p:
            continue
        for k, v in p.items():
            if r.get(k) != v:
                r[k] = v
                changed += 1
    cc = reg.setdefault("canonical_coverage", {})
    cc["authority_update"] = "2026-11-16：现行权威改为 evidence_numbers_ledger.json（M13–M18），evidence_m13_ledger.json 降为历史快照"
    with open(REG, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("changed =", changed)


if __name__ == "__main__":
    main()
