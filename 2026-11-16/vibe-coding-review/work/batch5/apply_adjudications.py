# 把 8 项存疑的定案写回 pack/rules.json（只改 canonical 区字段，不动 mined 字段）。
# 幂等：重复运行结果相同。运行后用 batch4/verify_merge.py 校验 mined 字段零改动。
import json
import os

ROOT = r"D:\数据\下载\逆向学习工作体系_2026-11-15"
REG = os.path.join(ROOT, "pack", "rules.json")

PATCH = {
    "R33": {
        "check_method": "用权威工具（readelf / pefile / `upx -t`）逐条复核标注，修正须写入 manifest 的 `e9_ground_truth.corrections_before_freeze`。M2 实例两条：S5 `hello_go_linux` 的 `nx`（`?`→`enabled`）、S7 `busybox` 的 `relro`（`none(静态)`→`partial`），均由 `readelf -lW` 复核发现，属标注修正而非判据改动。",
        "enforced_at": "`2026-11-15\\m2-task-card\\work\\sample_manifest.json` 的 `e9_ground_truth.corrections_before_freeze`（两条修正记录）；受其保护的验收器为 `tests\\verify_fingerprint.py`（E9）。执行方式为人工复核流程，无专门脚本。",
        "basis": "`PROGRESS.md:58`（规则句与实例）；`sample_manifest.json` 的 `e9_ground_truth.corrections_before_freeze`",
        "canonical_status": "`规范`（原文为一行摘要；判定方式与实例由 manifest 的冻结前修正记录确证，非反推）",
        "confidence": "high",
    },
    "R34": {
        "check_method": "`tests\\verify_fingerprint.py:6-10` 写死「四个维度分别出混淆矩阵；分母为该维度可判定格数，弃权格单列，不并入命中率」；`:187-194` 的 `confusion()` 只统计可判定格。M2 曾因 `verify_e3` 列索引与 E9 矩阵混表而重跑。",
        "enforced_at": "`tests\\verify_fingerprint.py:6-10,187-194`（`--all --matrix`，E9 载体）。",
        "basis": "`PROGRESS.md:58`；`tests\\verify_fingerprint.py:6-10,187-194`",
        "canonical_status": "`规范`（判定方式由 E9 载体源码确证）",
        "confidence": "high",
    },
    "R35": {
        "check_method": "`tests\\verify_fingerprint.py:6-8` 写死三态纪律——unknown 只在 GT 为 `undeterminable` 时算命中；可判定格答 unknown 记 miss；不可判定格给确定结论记误报（FP）。M2 实测 132 可判定格全中、12 不可判定格全部正确弃权、误报 0。",
        "enforced_at": "`tests\\verify_fingerprint.py:6-8,73-81`。",
        "basis": "`PROGRESS.md:58`；`tests\\verify_fingerprint.py:6-8`",
        "canonical_status": "`规范`（判定方式由 E9 载体源码确证）",
        "confidence": "high",
    },
    "R49": {
        "canonical": "抽样规则必须在使用前写定：按指令数分层（S1 ≤10、S2 11–30、S3 31–100、S4 >100），层内按地址升序等距取 min(4,n)；另加 5 类强制覆盖——①含导入调用（IAT/GOT 槽间接 call）②含回边（循环）③含间接 jmp（switch/跳转表形态）④含 SIMD abstain（VEX/EVEX 或 SSE）⑤该二进制最大函数；无随机数。",
        "check_method": "抽样脚本先写死规则再抽；五类的判定函数与「该二进制无此类」的显式记录见 `tests\\verify_expr.py:12-17,48,92-104`。",
        "enforced_at": "`tests\\verify_expr.py:12-17,48`（M5 Ghidra 弱参照 57 函数抽样）。",
        "basis": "`CHANGELOG.md:28,29`（规则句）；`tests\\verify_expr.py:12-17,48`（五类枚举）",
        "canonical_status": "`规范`（五类清单由抽样脚本的写死规则确证）",
        "confidence": "high",
    },
    "R67": {
        "check_method": "人工检查 `CHARTER.md` 的「运行环境记录（回归前置）」节：须含 Python 版本、`PYTHONIOENCODING=utf-8`、objdump 路径、中文路径需 `LC_ALL=C`。已核实该节存在且节内自引 R67（2026-11-16 M6 收口新增）。",
        "enforced_at": "`pack\\03_…\\CHARTER.md` §运行环境记录。",
        "canonical_status": "`规范·判定方式为文档级`（2026-11-16 定案：保留为强制回归前置；换机器/工具链须同步更新，否则不得与旧结果对比）",
        "confidence": "documented",
    },
    "R72": {
        "canonical_status": "`规范·判定方式为文档级`（2026-11-16 定案：不引入自动检查；理由见规则库附录 C——正则只能查形式，查不了结论是否成立）",
        "confidence": "documented",
    },
    "R87": {
        "enforced_at": "`2026-11-15\\m3-task-card\\outputs\\TASK_m8_closeout.md`。",
        "canonical_status": "`规范·判定方式为文档级`（2026-11-16 定案：不引入自动检查；理由见附录 C）",
        "confidence": "documented",
    },
    "R88": {
        "enforced_at": "`2026-11-15\\m3-task-card\\outputs\\TASK_m8_closeout.md` §3。",
        "canonical_status": "`规范·判定方式为文档级`（2026-11-16 定案：不引入自动检查；理由见附录 C）",
        "confidence": "documented",
    },
    "R89": {
        "enforced_at": "`2026-11-15\\m3-task-card\\outputs\\TASK_m8_closeout.md` §2。",
        "canonical_status": "`规范·判定方式为文档级`（2026-11-16 定案：不引入自动检查；理由见附录 C）",
        "confidence": "documented",
    },
    "R93": {
        "canonical": "跳转表候选升格只能以外部 objdump 的指令起点集合为边界判据，`recdesc` 自身解码结果不得参与；5 项检查全过才升格——①`guard_proven`（表长由 `cmp idx,imm` + `ja/jae` 证明）②`table_complete`（无被拒项、未触发扫描截断）③`min_targets`（有效目标 ≥4）④`function_domain`（全部目标在声明函数域内）⑤`external_boundary`（全部目标出现在外部 objdump 指令起点集合）；升格仍不进确定边（R45）；空边界负控必须 0 升格。",
        "check_method": "`rekit\\switchcand.py:486-505` 逐项计算 `checks`，未过项写进 `reasons` 并把状态置 `blocked`；`tests\\verify_switchcand.py` 用外部边界独立复算 + 空边界负控 + `res` 深比较。",
        "enforced_at": "`rekit\\switchcand.py:481-521`；`tests\\verify_switchcand.py`。",
        "basis": "`CHANGELOG.md:87`（规则句）；`rekit\\switchcand.py:486-492`（五项具名检查）",
        "canonical_status": "`规范`（五项具名检查由实现源码确证）",
        "confidence": "high",
    },
    "R95": {
        "check_method": "逐样本核对登记表三栏（sha256 / 许可 / 可再分发或仅本地），并核 `selection_rules.violations` 为空。2026-11-16 实测：M2 `sample_manifest.json` 11/11、M9 `m9_sample_manifest.json` 7/7 三栏齐全且 `violations=[]`；但总账 25 个样本中有 7 个 `tests/fixtures` 未登记（`dyn_nopie`/`dyn_static`/`dyn_execstack`/`dyn_norelro`/`minipe.exe`/`minidll.dll`/`minipe_fakerich.exe`），登记覆盖为 18/25。",
        "enforced_at": "`2026-11-15\\m2-task-card\\work\\sample_manifest.json`；`2026-11-15\\m3-task-card\\work\\m9_sample_manifest.json`；核对脚本 `2026-11-16\\vibe-coding-review\\work\\batch5\\check_r95_manifest.py`。",
        "basis": "`CHANGELOG.md:89`；两份 manifest 的 2026-11-16 实测结果",
        "canonical_status": "`规范`（规则成立）；**落地 18/25**：7 个 fixture 缺登记行，使用限制见规则库附录 C",
        "confidence": "high",
    },
    "R102": {
        "check_method": "总账 `NUMBERS_LEDGER.md` 明写唯一权威为 `evidence_m13_ledger.json`；M13 meta 自述「M13 起唯一权威」，M12 meta 的「唯一权威」自述已被取代，但其覆盖率数字经 M13 回归原样引用。M12 实例：25/25 全量重跑，实测 12,307,603/15,313,023=80.3734% 与推算差 0。",
        "enforced_at": "`work\\outputs\\NUMBERS_LEDGER.md`；`work\\evidence_m13_ledger.json`（现行权威）；`work\\evidence_m12_ledger.json`（历史快照，仅作对照）",
        "basis": "`CHANGELOG.md:96`（完整版）；`PROGRESS.md:264`（摘要）；两份 ledger 的 `meta.note`",
        "canonical_status": "`规范`（权威链已定：M13 > M12，见附录 C）",
        "confidence": "high",
    },
    "R103": {
        "check_method": "`evidence_m13_ledger.json` 的 `pe_gap` 段 + 人工核对。M13 复算：缝隙 113,731 B = `.text` 的 3.2262%，换 `.pdata` 口径 -0.0402pp；缝隙内 objdump 指令 113,731 条全为 `cc/90`，我方解出 372 条全为 `int3`，跨 pdata end 的指令 0、CFG 边 0。",
        "enforced_at": "`work\\evidence_m13_ledger.json`（`pe_gap` 段）；`work\\outputs\\NUMBERS_LEDGER.md` §5。",
        "basis": "`CHANGELOG.md:97`；`PROGRESS.md:264`；`evidence_m13_ledger.json` 的 `pe_gap`",
        "canonical_status": "`规范`（数字以 M13 复算为准，见附录 C）",
        "confidence": "high",
    },
    "R110": {
        "canonical": "引用点归因三档（首地址 / 对象内部 / 对象之后窗口）不得合并；`inside_object` 必须带 `offset`，`after_object` 必须带 `delta` 且只表示邻接；当前口径为对象末尾后 **0<Δ≤64 字节**（`AFTER_WINDOW=64`），超窗一律不归因。",
        "check_method": "`tests\\verify_datarefs.py` 三档分列核对；`rekit\\datarefs.py:38,503-504` 的 `AFTER_WINDOW` 决定 `after_object` 边界，`CALIBER` 行明写「这个窗口是口径，不是『紧邻对象』的推断」；`tests\\test_datarefs.py`。",
        "enforced_at": "`rekit\\datarefs.py:38,63,77,503-504`；`tests\\verify_datarefs.py`。",
        "basis": "`CHANGELOG.md:103`（完整版）；`PROGRESS.md:306`（摘要）；`rekit\\datarefs.py:38`（窗口常量）",
        "canonical_status": "`规范`（窗口值 64 属实现口径常量并写入模块 CALIBER；改值即口径变更，须同步 CALIBER、verify_datarefs 与总账的 after_object 计数）",
        "confidence": "high",
    },
}

COVERAGE_EXTRA = {
    "adjudication_record": "2026-11-16\\vibe-coding-review\\work\\batch5\\RULE_ADJUDICATIONS.md",
    "adjudicated_items": 8,
    "adjudicated_rule_ids": 14,
    "material_insufficient": 0,
    "r95_registration_gap": "18/25（7 个 tests/fixtures 未登记三栏）",
}


def main():
    with open(REG, encoding="utf-8") as f:
        reg = json.load(f)
    ids = {r["id"] for r in reg["rules"]}
    missing = [k for k in PATCH if k not in ids]
    if missing:
        raise SystemExit("missing ids: %s" % missing)
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
    for k, v in COVERAGE_EXTRA.items():
        if cc.get(k) != v:
            cc[k] = v
            changed += 1
    cc["updated_at"] = "2026-11-16（8 项存疑裁决后）"
    with open(REG, "w", encoding="utf-8") as f:
        json.dump(reg, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("changed fields =", changed)
    print("rules =", len(reg["rules"]))


if __name__ == "__main__":
    main()
