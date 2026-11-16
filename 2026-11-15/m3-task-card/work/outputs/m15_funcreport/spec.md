# Spec — M15 单函数面向人报告层（rekit funcreport）

## 0. 目标与边界

**目标**：把已存在的六层结果（recdesc / expr / callgraph / callfacts / strxref /
paramdecl）按**函数地址**合成一份报告，让 rekit 能回答“这一个函数是什么样”，
而不是让人自己串子命令。

**硬边界（用户约束 → 实现落点）**：

| 用户约束 | 实现落点 |
|---|---|
| 只呈现、不判断；结论带来源（层 + 证据） | 每个可证伪条目带 `source={layer,field,text}`；模块内不新增目标/参数/语义推断 |
| 缺失要写缺失 | 每个 section 带 `evidence_state` + `scope` + `reason`；`absence_summary` 逐条列全 |
| 报告七项齐全 | identity / boundary / blocks_and_edges / expressions / calls / strings_and_data / parameters + caveats + absence_summary |
| 三类函数验收 + 外部工具抽查 | `tests/verify_funcreport.py` 用 objdump 对每类样本抽查可证伪项 |
| 人读 + 机器可读同源 | `main()` 只构建一次 report；`--json` 输出 `json.dumps(report)`，人读走 `render(report)`（纯函数，只读 dict） |
| 全量回归再汇报 | pytest + 全部 `tests/verify_*.py`，日志 `evidence_m15_*` |

**不做**：不修改任何既有层判据/数字；不重算 R91/R102–R107 口径；不新增反汇编；
不推断 ABI / 参数个数 / 参数名 / C 类型；不输出“建议”“结论性判断”“置信度评分”。

---

## 1. 文件清单

| 文件 | 类型 | 作用 |
|---|---|---|
| `rekit/funcreport.py` | 新增 | 报告层主体 |
| `tests/make_funcreport_full.py` | 新增 | 生成完整声明样本（内联 C），产物落 `tests/m15_fixtures/`（不污染既有 `tests/fixtures/` 的 10 样本计数） |
| `tests/test_funcreport.py` | 新增 | 结构/同源/只读/缺失语义单测 |
| `tests/verify_funcreport.py` | 新增 | 三类样本 + objdump 外部抽查（exit 0/1） |
| `outputs/TASK_m15_funcreport.md` | 新增 | 交付说明 |
| `rekit/cli.py` | **修改（唯一）** | 增加 `funcreport` 手动短路分支 |

`cli.py` 插入点：`expr` 分支之后、`sitejoin` 分支之前：
```python
if argv and argv[0] == "funcreport":
    from . import funcreport
    return funcreport.main(argv[1:])
```

**禁止**：改 `recdesc.py` / `expr.py` / `callgraph.py` / `callfacts.py` /
`strxref.py` / `paramdecl.py` / `coverage.py` 任何一行（coverage 只在 verify 中
作为外部校验工具使用，不进报告、不被 funcreport import）。

---

## 2. 数据契约（测试逐项断言）

### 2.1 证据状态枚举

```python
SCHEMA = 1
EVIDENCE_STATES = ("present", "absent_measured", "missing_source",
                   "missing_declaration", "missing_decode", "abstained",
                   "not_applicable")
```

| 状态 | 精确定义 | 归类 |
|---|---|---|
| `present` | 该段至少一条带来源条目 | 有证据 |
| `absent_measured` | 测量范围明确且范围内确实为 0 | **确实没有** |
| `missing_source` | 该类来源整体不存在于本样本 | **缺证据** |
| `missing_declaration` | 来源存在，但该函数无对应声明 | **缺证据** |
| `missing_decode` | 该函数无已解出指令，函数域内不可测量 | **缺证据** |
| `abstained` | 有来源但本层判据不足，已显式弃权并写缺什么 | **缺证据** |
| `not_applicable` | 该项对该函数类别不适用（仅用于占位，禁止滥用） | 不适用 |

每个 section 必须同时给 `evidence_state`、`scope`（测量/观察范围文字）、
`reason`（非 `present` 必填，`present` 时为 `None`）。

### 2.2 来源标注

```python
def _src(layer, field, text):  # layer ∈ 六个允许层
    return {"layer": layer, "field": field, "text": text}
```
允许层：`"recdesc" | "expr" | "callgraph" | "callfacts" | "strxref" | "paramdecl"`。

### 2.3 顶层结构（键集合固定）

```python
{
  "schema": 1,
  "status": "ok" | "function_not_found" | "not_a_function_start"
            | "no_decoded_instructions" | "function_not_specified",
  "path": str, "section": str,
  "function": {"addr": int, "symbol": str|None},
  "sections": {identity, boundary, blocks_and_edges, expressions,
               calls, strings_and_data, parameters},
  "caveats": [{"layer": str, "text": str}, ...],
  "absence_summary": [{"section","field","evidence_state","scope","reason"}, ...],
  "layer_caveats": {六层名: [str, ...]},
  "layer_errors": [{"layer","stage","reason"}, ...],   # 空表 = 无层失败
  "read_only": {"layers": [...], "note": "本模块不写回任何一层；有副作用即违约"}
}
```

`status != "ok"` 时**仍保留完整键结构**，各段为 `missing_decode` /
`missing_source` 并写 `reason`；`absence_summary` 必须同时列出这些段。

### 2.4 层失败语义（防止静默吞错）

每个层调用点包一层：
```python
try:
    ...
except Exception as e:
    note = {"layer": "<层名>", "stage": "<哪次调用>",
            "reason": "%s: %s" % (type(e).__name__, e)}
    layer_errors.append(note)
    section = _section("missing_source", scope, "层调用失败：" + note["reason"])
```
规则：
- 任何异常都进 `layer_errors`，**绝不静默**；
- 一个层失败不阻断其他层（报告仍产出）；
- `read_only` 校验：被复用的 `res/graph/facts/sxref` 对象在 build 前后
  `json.dumps` 哈希一致（测试断言，证明无写回）。

### 2.5 section 字段清单（测试据此断言“键齐全”）

| section | 必含键 |
|---|---|
| identity | `addr, symbol, insns, blocks, sources` |
| boundary | `boundary, authority, end, sources, end_by_source, conflicts` |
| blocks_and_edges | `blocks[]（含 insn_addrs 供外部抽查）, edges{definite,speculative,cross_function,undecoded,unresolved}, cfg_calls, note` |
| expressions | `stats, verdict, abstains[], blocks[], stack_slots, text` |
| calls | `direct[], indirect[], counts{decoded,plt_or_import,unresolved}, note` |
| strings_and_data | `strings[], data_refs{evidence_state,scope,reason}, scope_note` |
| parameters | `own_declaration{...}, caller_bindings[], counts, note` |

每个 `*[]` 内条目至少含 `addr` 与 `source`（或 `sources`）。

---

## 3. 各 section 的精确取数（只读既有层）

### 3.1 identity
- 一次 `recdesc.descend(path, section)`，全流程复用 `res`。
- 三种非 ok 状态判定：
  - `addr` 在 `res["instructions"]` 的 `origin` 集合 → ok；
  - `addr` 在 `seeds` 但无指令 → `no_decoded_instructions`；
  - `addr` 是已解出指令地址但不是任何函数起点 → `not_a_function_start`，
    `reason` 写“该地址是函数 0x… 内部指令（块 0x…）；本层只报告函数起点，
    不把内部地址当函数”；
  - 都不在 → `function_not_found`，`reason` 写节范围（va/size）与函数总数。
- ok 时条目：`addr/symbol/insns/blocks/sources`，来源 `_src("expr","list_functions",…)`。

### 3.2 boundary
- `seeds[addr]`：`authority/sources/details/end/end_by_source`；
  `seed` 缺失（derived 函数）→ `authority="derived"` 并显式说明“无种子记录”。
- 逐源结束地址表；`details` 原文中的 end 冲突条目原样引用（不重算）。
- 状态：有 `end` → `present`；无 `end` → `missing_source`，`reason` 写
  “无权威结束声明（.pdata/FDE/st_size/gopclntab 均未给出）”，并列出实际
  `sources`。绝不把“未声明”说成“没有边界”或“边界错误”。

### 3.3 blocks_and_edges
- 块：`b["function"] == addr`，输出 `start/end/insns_count/terminator/
  boundary/authority/range`。
- 边：`res["cfg"]["edges"]` 中 `from` ∈ 该函数块起点集合，按五类分组，
  每条保留 `from/to/kind` 与层原文 `reason`（若有）。
- `res["cfg"]["calls"]` 单列为 `cfg_calls`；`note` 引用 `callgraph`
  的 `cfg_call_note`（块末调用 vs 全量调用，口径不同不合并）。
- 状态：有块 → `present`；无块 → `missing_decode`。

### 3.4 expressions
- `expr.lift_function(res, addr, imp)`；`imp` 取自 `expr._import_names(path)`
  （PE 才有，失败为空表，不算错误）。
- 字段：`stats/verdict/abstains[{addr,bytes,reason,missing}]/stack_slots/
  blocks[{start,end,terminator,body_lines,term_lines}]/text`。
- 状态：`stats["insns"]==0` → `missing_decode`；`abstained==0` → `present`；
  否则 `abstained`，`reason` 引用第一条 abstain 的 `missing`。
- `body_lines` 与 `term_lines` 分开保留，不重排、不合并。

### 3.5 calls
- `callgraph.build(path, section, res=res)` 一次。
- 直接：`edges` 中 `from_fn==addr`，按 `state` 三态计数；`unresolved` 仅在
  间接候选层（默认关闭，报告写“候选层未开启”）。
- 间接：`facts["sites"]` 中 `function==addr and call_kind=="indirect"`，
  状态记 `unresolved`，`reason` 取该站点 `abstains[0].missing`。
- 状态：无已解出指令 → `missing_decode`；函数内全量已解出指令中
  `cfg.calls` 与 facts 站点均为 0 → `absent_measured`
  （`scope` 写明“函数内全部 N 条已解出指令”）；否则 `present`。

### 3.6 strings_and_data
- `strxref.build(path, section, res=res, facts=facts, graph=graph)` 一次。
- 字符串引用点：`sites` 中 `function==addr`，按 `target` 去重，文本取
  `strings_detail` 同 `addr` 的 `text`（`truncated` 原样保留）。
- 非字符串数据引用：本层无来源，`data_refs` 固定
  `missing_source` + 具体 `reason`（只覆盖字符串白名单，全局变量/表/常量池无层）。
- 状态：无指令 → `missing_decode`；有指令且无字符串引用点 → `absent_measured`
  （`scope` 写明“函数内 N 条已解出指令覆盖的字符串白名单引用点”）；
  否则 `present`。
- 不得把“没有字符串引用”说成“不使用字符串”。

### 3.7 parameters
- `paramdecl.read(path)` → `{"audit","dwarf"}`。
- 自身声明：`dwarf["by_low_pc"]` 按 `lookup` 命中；PE 换算
  `lookup = addr + addr_base if addr_base and addr < addr_base else addr`
  （与 `bind_site` 同规则，报告写换算依据）。
  - `dwarf is None` → `missing_source`，`reason` 必含“这不是 0 个参数”；
  - 有 DWARF 无该 DIE → `missing_declaration`；
  - `params==0` → `absent_measured`（DWARF 明示 0 个 formal_parameter）；
  - 有形参 → `present`，逐形参 `name/type_off/die_off/locator`。
- 调用点绑定：`facts["sites"]` 中 `call_kind=="direct" and target==addr`，
  逐个 `bind_site(site, dwarf)`；给 `status/bound/partial/abstains` 计数与明细
  （显示受 `--limit`，计数完整）。
- 无调用者 → `missing_source`，`reason="全量调用点中没有以该函数为目标的直接调用"`。
- 绝不 ABI 补齐、绝不按常见签名推断。

### 3.8 caveats
- 六层 `CAVEATS` 原文逐层分组（同层内去重，不跨层去重）；
- 本层两条：“只呈现、不判断”“缺失显式列出，见 absence_summary”。

### 3.9 absence_summary
- 遍历七段，每个非 `present` 的 (section, field) 收一条；
- 排序：section 固定顺序 → field 字典序；
- 测试断言：所有非 `present` 段至少一条，且不存在 `present` 段混入。

---

## 4. CLI

```
rekit funcreport <file> [--func HEX] [--section NAME] [--json] [--limit N]
```

- `--func`：`int(v, 0)`；解析失败 → stderr 一行，退出 2。
- 未给 `--func`：`status="function_not_specified"`，列
  `expr.list_functions(res)` 前 `--limit` 个候选（addr/symbol/boundary/authority），
  并写“请用 --func 指定”。**不猜默认函数**。
- `--json`：`json.dumps(report, ensure_ascii=False, indent=1, sort_keys=False)`。
- 人读：`print(render(report, limit))`。
- 文件不存在 → 2；解析异常 → 3。

---

## 5. 人读渲染规则

- 每段首行 `== 名称 ==  状态=<state>  范围=<scope>`；
  - `absent_measured` 次行 `确实没有：<测量结论>`（`reason` 写“范围内为 0”）；
  - 其余非 `present` 次行 `缺：<reason>`（字面“缺：”）。
  - 两种措辞严格分离，不把“确实没有”写成“缺”，也不反过来。
- 每条可证伪行尾 `[层:字段]`。
- 截断写 `显示 N / 共 M`；**禁止**用 `…` 代替数量或缺失。
  （层原文 caveats 中自带的 `…` 属引用，豁免；测试只检查本层生成的计数行。）
- 禁止“疑似/大概/应该是/可能”等推断措辞（测试对 render 做词表断言，
  引用层原文的 caveats 行豁免）。

---

## 6. 验收状态矩阵（三类函数，verify 必须逐项核对并落盘）

| section | 完整声明 `funcreport_full` / `add3` | 部分证据 Go `0x401320` | 严重不足 `minidll.dll` |
|---|---|---|---|
| identity | present | present | present |
| boundary | present（symtab/FDE end） | present（gopclntab end） | missing_source（无结束声明） |
| blocks_and_edges | present | present | present |
| expressions | present 或 abstained | present 或 abstained | present 或 abstained |
| calls | absent_measured（add3 无 call） | present 或 absent_measured | present 或 absent_measured |
| strings_and_data | absent_measured | present 或 absent_measured | present 或 absent_measured |
| parameters | present（3 个形参） | missing_source（无 DWARF） | missing_source（无 DWARF） |

- verify 将实测状态写入 `evidence_m15_funcreport.json`；任何与上表冲突即 FAIL，
  并打印冲突字段（不改成“通过”）。
- 若样本缺失（如 gcc 不可用导致 `funcreport_full` 不存在），该项记 `SKIP`
  并在汇总里单列，不得算 PASS。

---

## 7. 测试与抽查

### 7.1 `tests/test_funcreport.py`
1. `SCHEMA==1`；七段齐全；每段 `evidence_state ∈ EVIDENCE_STATES` 且 `scope` 非空；
   非 `present` 时 `reason` 非空。
2. 递归扫描所有来源字典，`layer` ∈ 六个允许层。
3. AST 导入检查：仅 `argparse/json/sys` + 六个允许层；不得 import
   `disasm/coverage/struct`；不得出现 `subprocess`。
4. `minidll.dll`：`parameters.evidence_state=="missing_source"`，`reason` 含
   “不是 0 个参数”；`absence_summary` 含该条。
5. 同源：`json.loads(json.dumps(report))==report`，且
   `render(report)==render(json.loads(json.dumps(report)))`。
6. `--func 0xdeadbeef` → `function_not_found` + `reason`；
   传函数内部指令地址 → `not_a_function_start` + 内部函数地址。
7. 确定性：`build()` 两次结果相等。
8. CLI：`main(["funcreport", path, "--func", hex])==0`；无 `--func` →
   `function_not_specified` + 候选。
9. 层失败语义：monkeypatch 某层抛异常 → `layer_errors` 非空、对应段
   `missing_source`、其余段仍产出。
10. 只读：`res/graph/facts/sxref` 在 build 前后哈希一致。

### 7.2 `tests/make_funcreport_full.py`
- C：`int add3(int a,int b,int c){return a+b*c;}`、`int twice(int x){return x*2;}`、
  `int main(void){return add3(1,2,3)+twice(4);}`
- `gcc -g -O0 -fno-pie -no-pie -o tests/m15_fixtures/funcreport_full`；
- gcc 缺失 → `SKIP`，退出 0。

### 7.3 `tests/verify_funcreport.py`（objdump 抽查，exit 0/1）
- (a) 每个块 `start` 与每个 `calls.direct[].target`（state=decoded）都是
  `objdump_instructions` 指令起点。
- (b) 报告列出的指令地址都落在其块 `[start,end)` 内且在 objdump 起点集合。
- (c) `funcreport_full`：`boundary.end - addr` == 外部 size。PE 的 COFF 符号值
  不是 size（aux 记录才有），故优先用 `objdump --dwarf=info` 的
  `DW_AT_low_pc/high_pc`；仅当输出是 ELF 的 6 列 `objdump -t` 行时才用符号 size。
- (d) `funcreport_full`：`parameters.own_declaration.params` 数 ==
  `objdump --dwarf=info` 中该 subprogram 的 `DW_TAG_formal_parameter` 数。
- (e) Go：报告指令地址数 ≤ objdump 在 `[addr, boundary.end 或节末)` 的指令数。
- (f) `minidll.dll`：`parameters.evidence_state ∈ {missing_source,
  missing_declaration}` 且人读含“缺：”。
- 写 `evidence_m15_funcreport.json`；逐项 PASS/FAIL/SKIP。

### 7.4 数字口径
本层不产生新数字：所有计数为既有层字段直读（每条带 `source`）。
`NUMBERS_LEDGER.md` 追加“M15 报告层不产生新数字”，说明不重算、不新增分母、
不改 R91/R102–R107。

---

## 8. 文档

- `outputs/TASK_m15_funcreport.md`：规格摘要、三类报告摘要、
  **“缺证据” vs “确实没有”逐字段清单**、抽查结果、回归结果。
- `outputs/NUMBERS_LEDGER.md`：追加 §“M15 报告层不产生新数字”。
- `CHARTER.md` / `PROGRESS.md` / `CHANGELOG.md`：各追加一行 M15 里程碑。
  写前用 `Get-ChildItem` 确认唯一目标目录（Windows 上可能出现乱码名
  `03_璺嚎鍥句笌绔嬬▼`），不新建目录。

---

## 9. 回归

环境前缀（每次命令）：
```
$env:PATH = "D:\msys64\ucrt64\bin;" + $env:PATH
$env:LC_ALL = "C"; $env:PYTHONIOENCODING = "utf-8"
```
1. `python tests/make_funcreport_full.py`
2. `python -m pytest tests -q` → `evidence_m15_pytest.log`
3. 全部 `tests/verify_*.py`（Python subprocess 驱动）→ `evidence_m15_verify.log`
4. `python tests/verify_funcreport.py` → `evidence_m15_funcreport.json`

任一非 0 如实汇报，不美化。

---

## 10. 完成定义（DoD）

- [ ] 三类样本各出一份报告，状态与 §6 矩阵一致或差异被逐条解释
- [ ] `absence_summary` 覆盖所有非 present 字段
- [ ] 单测 10 项全绿
- [ ] 抽查 (a)–(f) 全 PASS 或 SKIP 有据
- [ ] 全量回归与 M14 一致（差异逐条归因）
- [ ] 文档三件套 + TASK_m15 完成
- [ ] 汇报含“缺证据 / 确实没有”两张清单

## 11. 风险与决策（已定，不再询问）

| 风险 | 决策 |
|---|---|
| Go 样本调用点多导致报告巨大 | 计数完整、显示受 `--limit`；写“显示 N / 共 M” |
| PE ImageBase 地址空间 | 复用 `bind_site` 换算规则并在报告写明 |
| `minidll.dll` 无种子 | verify 记 SKIP 并说明，不假装 PASS |
| 报告层被误当“新判断层” | AST 白名单 + 每条 `source` + 文档边界声明 |
| 层崩溃被静默吞 | §2.4：`layer_errors` + 对应段 `missing_source` |
| 非函数起点地址 | §3.1：`not_a_function_start`，不静默取包含函数 |
