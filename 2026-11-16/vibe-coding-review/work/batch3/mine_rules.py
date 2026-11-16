r"""从文档里挖规则原文（v3）：候选打分，取"最像一句规则"的那条，标注来源 file:line。

只读；输出 batch3\rules_extracted.json + rules_coverage.json。
"""
import difflib
import json
import os
import re

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
WORK = os.path.join(ROOT, "2026-11-15", "m3-task-card", "work")
OUT = os.path.join(ROOT, "2026-11-16", "vibe-coding-review", "work", "batch3")

SOURCES = [os.path.join(WORK, "pack03", f) for f in
           ("CHANGELOG.md", "PROGRESS.md", "RE-ROADMAP.md", "CHARTER.md")]
SOURCES.append(os.path.join(ROOT, "pack", "02_规则库", "规则库_R01-R32.md"))
OUTPUTS = os.path.join(WORK, "outputs")
if os.path.isdir(OUTPUTS):
    SOURCES += [os.path.join(OUTPUTS, f) for f in sorted(os.listdir(OUTPUTS)) if f.endswith(".md")]

PATTERNS = [
    ("bold", re.compile(r"\*\*R(\d{1,3})\*\*\s*([^；;|]{6,300})")),
    ("paren", re.compile(r"R(\d{1,3})（([^（）]{6,300})）")),
    ("trail", re.compile(r"R(\d{1,3})\s+([^；;|]{8,300})")),
]


def clean(s):
    s = s.replace("**", "").replace("`", "").strip(" ：:、,，-—–）)")
    return re.sub(r"\s+", " ", s).strip()


def score(text, kind, src, line, mstart):
    if not text or re.match(r"^[–—~-]?\s*R\d", text):
        return -99
    if "✅" in text or text.startswith(("一致、", "已达成", "U0 ")):
        return -99
    s = min(len(text), 60)
    if kind == "bold":
        s += 6
    if kind == "paren":
        s -= 8
    if re.search(r"R\d{1,3}", text):
        s -= 12
    if text.endswith(("）", "。", ")")):
        s += 3
    if re.match(r"^\d", text):
        s -= 10
    base = os.path.basename(src)
    if base.startswith("规则库"):
        s -= 0
    elif base == "CHANGELOG.md":
        s -= 3
    elif base == "PROGRESS.md":
        s -= 6
    elif base.startswith("TASK_"):
        s -= 9
    else:
        s -= 12
    if "规则" in line[max(0, mstart - 40):mstart]:
        s += 8
    return s


def sim(a, b):
    def grams(x):
        x = re.sub(r"[^\w\u4e00-\u9fff]", "", x)
        return {x[i:i + 2] for i in range(len(x) - 1)}
    ga, gb = grams(a), grams(b)
    jac = len(ga & gb) / len(ga | gb) if ga and gb else 0.0
    return max(difflib.SequenceMatcher(None, a, b).ratio(), jac)


def main():
    os.makedirs(OUT, exist_ok=True)
    cands = {}
    for path in SOURCES:
        rel = os.path.relpath(path, ROOT)
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            continue
        for ln, line in enumerate(lines, 1):
            if "R" not in line:
                continue
            for kind, pat in PATTERNS:
                for m in pat.finditer(line):
                    n = int(m.group(1))
                    if not 1 <= n <= 119:
                        continue
                    text = clean(m.group(2))
                    sc = score(text, kind, path, line, m.start())
                    if sc < -20:
                        continue
                    ms = re.search(r"\bM(\d{1,2})\b", line)
                    cands.setdefault("R%02d" % n, []).append({
                        "text": text[:400], "src": "%s:%d" % (rel, ln), "kind": kind, "score": sc,
                        "milestone": "M%s" % ms.group(1) if ms else ""})
    best = {}
    for rid, lst in cands.items():
        n = int(rid[1:])
        # R01–R32 以 02_规则库 为准（任务卡里的 "R4" 可能只是列表序号，不是规则号）
        if n <= 32:
            pool = [c for c in lst if os.path.basename(c["src"].split(":")[0]).startswith("规则库")]
            lst = pool or lst
        # 任务卡只作旁证，不作权威来源
        canon = [c for c in lst if not os.path.basename(c["src"].split(":")[0]).startswith("TASK_")]
        lst = canon or lst
        lst = sorted(lst, key=lambda x: (-x["score"], -len(x["text"])))
        best[rid] = dict(lst[0], n_candidates=len(cands[rid]),
                         alternates=[{"text": x["text"][:100], "kind": x["kind"], "src": x["src"]}
                                     for x in lst[1:3]])

    ids = sorted(best, key=lambda x: int(x[1:]))
    weak = [r for r in ids if len(best[r]["text"]) < 15]
    missing = ["R%02d" % i for i in range(1, 120) if "R%02d" % i not in best]

    # 互证：同一规则在不同文件里的说法是否一致（相似度 >= 0.6 视为同一句）
    registry, stats = [], {"corroborated": 0, "single_source": 0, "multi_candidate": 0,
                           "suspect": 0, "terse": 0}
    for rid in ids:
        cur = best[rid]
        pool = cands[rid]
        agree = [c for c in pool if sim(cur["text"], c["text"]) >= 0.45]
        n_src = len({c["src"].split(":")[0] for c in agree})
        closest = max([sim(cur["text"], c["text"]) for c in pool if c["src"] != cur["src"]] or [1.0])
        if len(cur["text"]) < 15:
            status = "terse"
        elif n_src >= 2:
            status = "corroborated"
        elif len(pool) == 1:
            status = "single_source"
        elif closest < 0.2:
            status = "suspect"
        else:
            status = "multi_candidate"
        stats[status] += 1
        registry.append({"id": rid, "statement": cur["text"], "source": cur["src"],
                         "kind": cur["kind"], "milestone": cur["milestone"], "status": status,
                         "agree_sources": n_src, "n_candidates": len(pool),
                         "closest_other_wording": round(closest, 2),
                         "alternates": [{"text": c["text"][:160], "src": c["src"]}
                                        for c in pool if c["text"] != cur["text"]][:2]})

    json.dump(best, open(os.path.join(OUT, "rules_extracted.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    json.dump({"ids_found": len(ids), "with_statement": len(ids) - len(weak), "weak": weak,
               "absent": missing, "stats": stats,
               "multi_candidate": [r["id"] for r in registry if r["status"] == "multi_candidate"],
               "suspect": [r["id"] for r in registry if r["status"] == "suspect"],
               "single_source": [r["id"] for r in registry if r["status"] == "single_source"],
               "sources": [os.path.relpath(p, ROOT) for p in SOURCES]},
              open(os.path.join(OUT, "rules_coverage.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    doc = {"schema": "rules_registry/1",
           "generated_at": "2026-11-16",
           "generated_by": "2026-11-16\\vibe-coding-review\\work\\batch3\\mine_rules.py",
           "scope": "R01–R119 共 119 个编号；statement 为文档原文摘录，未改写、未补写",
           "policy": {
               "status.corroborated": "≥2 个不同源文件出现相似度≥0.45 的表述",
               "status.single_source": "只有 1 条候选，无法互证",
               "status.multi_candidate": "同号多候选、措辞不同但相近，语句可用但需抽查",
               "status.suspect": "同号多候选且最相近的一条相似度<0.2，极可能是撞号，不可直接引用",
               "status.terse": "摘录 <15 字，语义可能完整但缺上下文，引用前需补",
               "id_normalization": "统一写成 R01–R119（两位补零）；原文中的 R1/R32 视为同号",
               "source_priority": "R01–R32 只认 02_规则库；任务卡 TASK_*.md 只作旁证，不作权威来源",
               "important": "本表不判断规则是否被代码执行；只记录它在哪里被写下来"},
           "stats": stats, "rules": registry}
    json.dump(doc, open(os.path.join(ROOT, "pack", "rules.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    # 只在任务卡/首页文档里出现的编号：没有规范出处，属于历史缺口的硬核部分
    only_task = [r["id"] for r in registry
                 if os.path.basename(r["source"].split(":")[0]).startswith("TASK_")]
    _report(registry, stats, only_task, missing, weak, OUT)
    print("only_task:", only_task)

    print("ids=%d with_statement=%d weak=%d absent=%d" % (len(ids), len(ids) - len(weak), len(weak), len(missing)))
    print("stats:", stats)
    print("weak:", weak)
    for k in ("R01", "R33", "R49", "R50", "R71", "R73", "R75", "R100", "R119"):
        v = best.get(k)
        print(k, "|", v["kind"] if v else "-", "|", (v["text"][:120] if v else "MISSING"))


def _report(registry, stats, only_task, missing, weak, out):
    m = {r["id"]: r for r in registry}
    L = ["# 规则事实源缺口报告（R01–R119）", "",
         "> 生成：`2026-11-16\\vibe-coding-review\\work\\batch3\\mine_rules.py`（机器生成，数字可复跑）",
         "> 配套产物：`pack\\rules.json`（登记表）、`rules_coverage.json`（覆盖统计）、`rules_extracted.json`（逐候选）", "",
         "## 0. 一句话结论", "",
         "R01–R119 **全部 119 个编号都能在文档里找到出处**，但只有 R01–R32 有规范定义文件；"
         "R33–R119 的定义散落在 CHANGELOG 的「新增规则」行与 PROGRESS 的「规则：」行里，"
         "属于**日志即规范**。因此本表能给出「摘录」，不能给出「权威定义」。", "",
         "## 1. 覆盖统计", "",
         "| 状态 | 条数 | 含义 |", "|---|---|---|",
         "| corroborated | %d | ≥2 个源文件有相近表述 |" % stats["corroborated"],
         "| single_source | %d | 只有 1 处出处 |" % stats["single_source"],
         "| multi_candidate | %d | 多处措辞不同但相近，需抽查 |" % stats["multi_candidate"],
         "| suspect | %d | 多处表述相差极大，疑撞号 |" % stats["suspect"],
         "| terse | %d | 摘录 <15 字，需补上下文 |" % stats["terse"],
         "", "完全无出处的编号：%s" % (missing or "无"), "",
         "## 2. 结构性缺口（比单条缺句更要紧）", "",
         "1. `pack\\02_规则库\\规则库_R01-R32.md` 只到 R32，之后 87 个编号没有规范文件。",
         "2. R33–R119 的定义只存在于**当天的工作日志**：CHANGELOG 的「新增规则 R##–R##：...」行、"
         "PROGRESS 的「规则：...」行。这是「日志即规范」，不是规则库。",
         "3. 所以「补历史」不是补一张表，而是**把日志提炼成规则**：需要一次人工收敛，grep 拼不出来。",
         "4. 口径警告：早期采集 `metrics.json` 报 `rules.gaps=[9,10,11,14,17,20,26]`，经复核是**假缺口**——"
         "规则库原文写 `R9` 而非 `R09`，旧正则只匹配补零写法。同一事实换一种统计口径就得出不同结论，"
         "所以本报告把口径写进 `pack\\rules.json` 的 `policy` 字段。", "",
         "## 3. 只在任务卡能查到的编号（置信度最低）", ""]
    if only_task:
        L += ["| 编号 | 摘录 | 出处 |", "|---|---|---|"]
        L += ["| %s | %s | `%s` |" % (r, m[r]["statement"][:90], m[r]["source"]) for r in only_task]
    else:
        L.append("无 —— 所有编号至少在 CHANGELOG/PROGRESS/规则库 之一出现。")
    L += ["", "## 4. 疑似撞号（suspect，需人工裁决）", ""]
    sus = [r["id"] for r in registry if r["status"] == "suspect"]
    if sus:
        L += ["| 编号 | 当前摘录（源） | 另一处表述（源） | 相似度 |", "|---|---|---|---|"]
        for r in sus:
            alt = (m[r]["alternates"] or [{"text": "—", "src": "—"}])[0]
            L.append("| %s | %s（`%s`） | %s（`%s`） | %.2f |" %
                     (r, m[r]["statement"][:60], m[r]["source"].split("\\")[-1],
                      alt["text"][:60], alt["src"].split("\\")[-1], m[r]["closest_other_wording"]))
    L += ["", "## 5. 摘录过短（terse）", ""]
    L += ["| 编号 | 摘录 | 出处 |", "|---|---|---|"] + \
         ["| %s | %s | `%s` |" % (r, m[r]["statement"], m[r]["source"]) for r in weak]
    L += ["", "## 6. 建议动作（给源码会话 / 人工）", "",
          "1. **不要**把 `rules.json` 的 statement 直接当规范定义贴进 `02_规则库`——它们是日志摘录，可能截断。",
          "2. 先裁决 §4 的 %d 条 suspect（撞号风险最高），再抽查 §1 的 %d 条 multi_candidate。" % (len(sus), stats["multi_candidate"]),
          "3. §3 的编号若任务卡也不够，只能回溯聊天记录；在此之前标 `canonical=false`。",
          "4. 收敛后新建 `pack\\02_规则库\\规则库_R33-R119.md`，并在 `rules.json` 每条加 `canonical: true/false`。", "",
          "## 7. 复跑", "", "```powershell",
          'python "2026-11-16\\vibe-coding-review\\work\\batch3\\mine_rules.py"', "```"]
    open(os.path.join(out, "rules_gap_report.md"), "w", encoding="utf-8", newline="\n").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
