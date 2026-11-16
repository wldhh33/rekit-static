# -*- coding: utf-8 -*-
"""2026-11-17 补录 R120–R126 到 rules.json（附录 E 五字段定义）。

原则：
- 只新增 7 条，不改 R01–R119 的任何字段（verify_merge.py 逐条比对 mined 字段）。
- mined 字段不是 miner 产物，本次按 CHANGELOG 规则句原文摘录，source 指向 CHANGELOG 行。
- stats 保持原样（它统计的是 R01–R119 的挖掘结果）。
- 每条带 evidence_boundary，写明"确定"与"推断/缺口"的分界。
"""
import json
import os

ROOT = r"d:\数据\下载\逆向学习工作体系_2026-11-15"
P = os.path.join(ROOT, r"pack\rules.json")

NEW = [
    {
        "id": "R120",
        "statement": "方法签名解码必须把 blob 消耗到恰好结束（`consumed == blob_len`），剩余字节记 `trailing_bytes` 并计 undecoded",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:111",
        "kind": "bold",
        "milestone": "M19",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "签名 blob 必须恰好耗尽",
        "canonical": "方法签名解码必须把 blob 消耗到恰好结束（`consumed == blob_len`）才算 decoded；剩余字节记 `trailing_bytes` 并计为 undecoded，不得「前缀解出即判成功」。",
        "constraint_object": "实现（`rekit.sigblob`）+ 输出计数。",
        "check_method": "`rekit\\sigblob.py:107-108` 写死判据、`:482` 抛 `trailing_bytes`；`tests\\verify_sigblob.py:724-738` 以长度前缀 +1 字节注入，断言 reason ∈ {`trailing_bytes`,`truncated_signature`}。",
        "enforced_at": "`rekit\\sigblob.py:482,494`；`tests\\verify_sigblob.py:724-738`。",
        "basis": "`CHANGELOG.md:111`；`PROGRESS.md:355`。",
        "canonical_status": "`规范`",
        "confidence": "high",
        "evidence_boundary": "确定：规则句、实现分支（`:482`）、注入自证（`:724-738`）三者齐备。推断：无。"
    },
    {
        "id": "R121",
        "statement": "`unknown`（结构已解、类型节点未知，计 `decoded_with_unknown`，不并入 undecoded）与 `undecoded`（字节没解完）分开计数，两者都不得按名称/邻近字节猜",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:111",
        "kind": "bold",
        "milestone": "M19",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "unknown 与 undecoded 分计",
        "canonical": "`unknown`（结构已解、类型节点未知，计 `decoded_with_unknown`）与 `undecoded`（字节未解完）必须分开计数；两者都不得按名称或邻近字节猜测后计入 decoded。",
        "constraint_object": "实现 + 输出分母（恒等式）。",
        "check_method": "`rekit\\sigblob.py:11,92` 的 CALIBER 定义恒等式 `has = readable + unreadable`、`readable = decoded + undecoded`；`tests\\verify_sigblob.py:648-649` 断言 `decoded_with_unknown` 分母符合预期，`unknown_policy` 项以 `UnknownCodedTag.dll`（coded tag=3）与 `UnknownElemType.dll`（0x6F）两个负样本钉住两分支。",
        "enforced_at": "`rekit\\sigblob.py:11,92`；`tests\\verify_sigblob.py:602-678`；负样本 `work\\samples\\m19_sigblob\\_neg\\UnknownCodedTag.dll`、`UnknownElemType.dll`。",
        "basis": "`CHANGELOG.md:111`；`PROGRESS.md:355`；两分支补证 `PROGRESS.md:375`。",
        "canonical_status": "`规范`",
        "confidence": "high",
        "evidence_boundary": "确定：字段名、恒等式、两分支负样本齐备。推断：「不得按名称猜」是实现纪律（代码中无按名回填分支），没有单独断言。"
    },
    {
        "id": "R122",
        "statement": "参考实现与 spec 的 canonical 文本冲突时按 spec 归一，但必须披露冲突点与处理方式，不得改被测实现或比较判据",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:111",
        "kind": "bold",
        "milestone": "M19",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "参考实现与 spec 冲突按 spec 归一且必须披露",
        "canonical": "参考实现与 spec 的 canonical 文本冲突时按 spec 归一（在被测实现之外修正参考侧 formatter），但必须在文档披露冲突点与处理方式；不得改被测实现或比较判据来消解冲突。",
        "constraint_object": "验收方法 + 文档披露。",
        "check_method": "spec 侧 canonical 文本表写死在 `work\\outputs\\m19_sigblob\\spec.md:89-104`（`modreq`/`modopt` 渲染）；冲突实例与归一位置记录在 `PROGRESS.md:351`（3 处 `modreq` 渲染差异：SRM 原生带 `class` 前缀，spec 写死 `modreq([TR]X)`，在参考侧 formatter 归一，未改被测实现与判据）。**「已披露」本身无脚本断言。**",
        "enforced_at": "`2026-11-15\\m3-task-card\\work\\outputs\\m19_sigblob\\spec.md:89-104`（口径）；`pack\\04_rekit项目源码\\tests\\sigref.ps1`（参考侧 formatter）。",
        "basis": "`CHANGELOG.md:111`；`PROGRESS.md:351,355`。",
        "canonical_status": "`规范·判定方式为文档级`",
        "confidence": "medium",
        "evidence_boundary": "确定：「按 spec 归一」的载体（spec §3 表格 + 参考侧 formatter）与 3 处实例有据。缺口：披露义务没有自动检查——若再遇冲突只改 formatter 而不写文档，门禁不会红。"
    },
    {
        "id": "R123",
        "statement": "类型布局的静态结论只到元数据写明的值（`FieldLayout.Offset`、`ClassLayout.PackingSize/ClassSize`、`FieldRVA` 的 RVA 与字节）；sequential/auto 偏移是运行期推导，必须标 `static_conclusion=false` 且不进静态分母",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:112",
        "kind": "bold",
        "milestone": "M20",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "类型布局静态结论只到元数据写明值",
        "canonical": "类型布局的静态结论只到元数据写明的值（`FieldLayout.Offset`、`ClassLayout.PackingSize/ClassSize`、`FieldRVA` 的 RVA 与数据字节）；sequential/auto 偏移属于运行期推导，必须标 `static_conclusion=false` 且不进静态分母。",
        "constraint_object": "实现（`rekit.layout`）+ 报告分栏。",
        "check_method": "`rekit\\layout.py:15,76-77,101` 写死口径；`tests\\verify_layout.py:587-589` 断言 `static_conclusion.excludes` 含运行期推导类型；`:439-448` 断言 `runtime_derived.static_conclusion` 必为 `False`。",
        "enforced_at": "`rekit\\layout.py:15,76-77,101,560`；`tests\\verify_layout.py:439-448,587-589`。",
        "basis": "`CHANGELOG.md:112`；`PROGRESS.md:360,369`。",
        "canonical_status": "`规范`",
        "confidence": "high",
        "evidence_boundary": "确定：分栏字段与两处断言齐备。推断：「不进静态分母」由 `excludes` 列表承担，未见对分母数值的独立复算断言（分母恒等式由 `m20-den` 项兜底）。"
    },
    {
        "id": "R124",
        "statement": "`FieldRVA` 数据长度不是元数据字段，按「valuetype `ClassSize` → 基元 → `unknown`」分源并逐类计数；推不出就记 `unknown` 并写缺什么，不得用 `.data` 字面量长度反推",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:112",
        "kind": "bold",
        "milestone": "M20",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "FieldRVA 数据长度分源计数",
        "canonical": "`FieldRVA` 的数据长度不是元数据字段，必须按「valuetype 的 `ClassSize` → 基元类型 → `unknown`」分源并逐类计数；推不出就记 `unknown` 并写缺什么，不得用 `.data` 字面量长度或数据段字节数反推。",
        "constraint_object": "实现 + 输出分源计数。",
        "check_method": "`rekit\\layout.py:217` 返回 `valuetype_not_typedef`（唯一 unknown 来源）；`tests\\verify_layout.py:298,354,471` 断言 ClassSize/推导长度与源码真值（`__StaticArrayInitTypeSize=N`、`.il` 的 `.data`/`.size`）121 行 0 不一致；`:298` 为 `m20-cs-extra` 负例。",
        "enforced_at": "`rekit\\layout.py:217`；`tests\\verify_layout.py:298,354,471`；源码真值 `work\\outputs\\m20_layout\\spec.md` 与 `.il`/`.cs` 受控样本。",
        "basis": "`CHANGELOG.md:112`；`PROGRESS.md:361-362,369`。",
        "canonical_status": "`规范`",
        "confidence": "high",
        "evidence_boundary": "确定：三源分支、逐类计数（122/9/1）、unknown 1（`System.DateTime`，`valuetype_not_typedef`）均有实测数。推断：「不得反推」属实现纪律，没有「若改用 .data 长度会怎样」的对照负例。"
    },
    {
        "id": "R125",
        "statement": "静态结论与运行期推导必须分栏（`static_conclusion.includes/excludes` + `runtime_derived`），交叉印证（静态偏移 == `Marshal.OffsetOf`）不得反写成静态来源",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:112",
        "kind": "bold",
        "milestone": "M20",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "静态结论与运行期推导分栏",
        "canonical": "静态结论与运行期推导必须分栏输出（`static_conclusion.includes/excludes` + `runtime_derived` 段）；交叉印证（静态偏移 == `Marshal.OffsetOf`）只能作为印证，不得反写成静态来源。",
        "constraint_object": "输出契约（JSON 分栏）。",
        "check_method": "`tests\\verify_layout.py:439-448` 断言 `runtime_derived.static_conclusion is False`；`:587-589` 断言 `static_conclusion` 排除运行期类型；`tests\\layoutauto.ps1` 量出的 10 个 auto 偏移只进 `auto_runtime` 段且标 `static_conclusion=false`。",
        "enforced_at": "`tests\\verify_layout.py:439-448,587-589`；`pack\\04_rekit项目源码\\tests\\layoutauto.ps1`。",
        "basis": "`CHANGELOG.md:112`；`PROGRESS.md:363-364,369,377`。",
        "canonical_status": "`规范`",
        "confidence": "high",
        "evidence_boundary": "确定：分栏字段与「runtime 段必为 False」有断言。推断：「不得反写」只在字段层断言（类型是否出现在 `includes`），对来源转述没有检查，靠人工审阅报告。"
    },
    {
        "id": "R126",
        "statement": "测试与门禁不得依赖机器上残留的安装或旧产物；凡「模块可执行 / 入口存在」类断言，必须在干净安装（`pip install -e .` 覆盖后新进程）里验证，或在测试内显式断言目标入口存在",
        "source": "pack\\03_路线图与章程\\CHANGELOG.md:117",
        "kind": "bold",
        "milestone": "U1",
        "status": "single_source",
        "agree_sources": 2,
        "n_candidates": 1,
        "closest_other_wording": None,
        "alternates": [],
        "title": "干净环境可执行性（环境脏导致的假通过）",
        "canonical": "测试与门禁不得依赖机器上残留的安装、旧产物或历史缓存；凡「模块可执行 / 入口存在 / 命令可用」类断言，必须在干净安装（`pip install -e .` 覆盖旧安装、新进程）后验证，或在测试内显式断言目标入口存在（`import rekit.__main__` / `python -m rekit --help` 退出码 0）。「本机一直是绿的」不构成证据。",
        "constraint_object": "测试 / 门禁。",
        "check_method": "`tests\\test_ilflow.py:410,417` 以子进程调 `python -m rekit`；`rekit\\__main__.py`（2026-11-17 新增）存在；`pack\\tools\\gate.ps1:107-123` 的 preflight 把「环境是否具备」与「代码是否正确」分开报（缺样本/清单不一致一律 exit 2）。",
        "enforced_at": "`pack\\04_rekit项目源码\\rekit\\__main__.py`；`tests\\test_ilflow.py:410,417`；`pack\\tools\\gate.ps1:107-123`。",
        "basis": "`CHANGELOG.md:117`；`PROGRESS.md:408`；依赖边界复核 `CHANGELOG.md:120`、`PROGRESS.md:380`。",
        "canonical_status": "`规范`",
        "confidence": "high",
        "evidence_boundary": "确定：触发实例（`No module named rekit.__main__`）、入口文件、preflight 位置均有据。推断/缺口：「干净安装后跑全量」是 `pack\\README.md` 的流程要求，无脚本强制（gate.ps1 不自动 `pip install -e .`）。"
    },
]

d = json.load(open(P, encoding="utf-8"))
have = {r["id"] for r in d["rules"]}
assert not (set(x["id"] for x in NEW) & have), "R120–R126 已存在，拒绝重复写入"
d["rules"].extend(NEW)
d["scope"] = ("R01–R126 共 126 个编号；R01–R119 为 mine_rules.py 摘录（statement 未改写），"
              "R120–R126 为 2026-11-17 补录（定义见 02_规则库\\规则库_R33-R119.md 附录 E，"
              "source 指向 CHANGELOG 规则句原文）")
cov = d.setdefault("canonical_coverage", {})
cov["appendix_e_rules"] = 7
cov["appendix_e_range"] = "R120–R126"
cov["appendix_e_updated_at"] = "2026-11-17"
cov["appendix_e_doc_level"] = ["R122"]
cov["appendix_e_note"] = "R120–R126 的五字段定义写在 规则库_R33-R119.md 附录 E；R122 的披露义务为文档级判定，无脚本断言。"
s = json.dumps(d, ensure_ascii=False, indent=1) + "\n"
# 原文件为 CRLF（LF=2786 / CRLF=2786），保持字节风格，避免整文件 diff
with open(P, "wb") as f:
    f.write(s.replace("\n", "\r\n").encode("utf-8"))
print("rules:", len(d["rules"]), "| appended:", len(NEW))
