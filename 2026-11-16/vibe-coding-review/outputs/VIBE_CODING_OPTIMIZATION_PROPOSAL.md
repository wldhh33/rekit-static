# rekit 项目 · Vibe Coding 研究与优化提案

| 项 | 内容 |
|---|---|
| 版本 | v0.2（2026-11-16 按实测校准；校准结论见 §9，v0.1 正文保留作对照） |
| 日期 | 2026-11-16 |
| 对象 | `d:\数据\下载\逆向学习工作体系_2026-11-15`（下称"项目"），核心为 `rekit` 静态逆向分析工具 |
| 用途 | 交给下一个执行会话按条目改造；**本文档本身不改任何代码** |
| 约束 | 结论必须可核；证据必须能复跑；不许为好看的数字放宽判据 |
| 证据分级 | A=本机实测；B=项目内文件原文；C=公开研究（RCT/调查/论文）；D=厂商报告或个人经验 |

---

## 0. 一页结论

### 0.1 研究结论（公开实践）

1. **Vibe Coding 的原始含义很窄**：Karpathy 2025-02-02 的原话是"完全交给感觉、接受全部 diff、忘记代码存在"，他明确说的是周末玩具项目。把"所有 AI 辅助编程"都叫 Vibe Coding 是原意的稀释（Willison 2025-03-19）。
2. **被验证有效的不是"不读代码"，而是被 AI 放大的工程配套**：可验证的闭环、规格先行、版本控制与可回滚、测试/评审/文档。Willison 在 2025-10-07 把专业侧命名为 **vibe engineering**，2026-02 又更新为 **Agentic Engineering**；Anthropic 的官方实践把"给模型一个能自己验证工作的方法"列为单条最高杠杆。
3. **证据并不支持"AI 必然更快"**：METR 的随机对照试验中，16 名资深开源开发者在自己熟悉的仓库上做 246 个任务，允许使用 AI 反而慢 19%，而他们主观认为快了 20%（2025-07；METR 于 2026-02 声明该结果已过时并调整了实验设计）。2023 年 Copilot 的 RCT 则是在全新、单文件、单一语言的 HTTP server 任务上快 55.8%。两个结论并不矛盾：**任务形态决定收益**。
4. **公开批评集中在六类失败模式**：不可验证、循环自证、无回滚、上下文漂移、规模错觉、责任外包。对应的事实来源包括 Stack Overflow 2025（46% 明确不信任 AI 输出准确性）、Veracode 2025（45% 的生成代码引入 OWASP Top 10 漏洞）、GitClear（复制粘贴占比 8%→18%，厂商遥测）、DORA 2025（AI 是放大器，吞吐上升但交付不稳定仍在）、以及 Replit 删库事件（代码冻结期间仍写生产库，并谎称无法回滚）。
5. **2026 年的实践重心已从"提示词"转向"上下文与验证回路"**：AGENTS.md 类上下文文件成为跨工具事实标准（2853 个仓库的实证研究），Spec Kit 之类"规格即事实源"的流程被产品化。真正稀缺的是**可执行的门禁**，不是更长的提示词。

### 0.2 项目结论（对照后）

1. **这个项目已经把 vibe engineering 的正确做法做对了一半**：独立对拍、分母先行、证据落盘、只增不删、不改原始样本，这些恰好是公开实践里最难做到的部分。
2. **摩擦不在"用不用 AI"，而在"严谨写在文档里、没有写进工具里"**：112 条规则里只有 R107 有专门的规则级检查；21 个验证脚本 8,343 行却各写各的入口；已公布数字在 226 KB 文档里多处手抄；M18 已经发生过"空对空 PASS"，M7 发生过"校验器与被测同错"。
3. **三个 P0 动作可以在一周内完成且不碰任何判据**：建立单一事实源与回滚能力（O1）、建立会话交接协议（O3）、把 21 条验证命令收敛成一条 fail-closed 门禁（O2）。
4. **有 12 类流行做法明确不适合本项目**（第 5 节），最危险的是"让 AI 同时写实现与期望值"和"用 LLM 当评审"——它们会精确复现 M7 的"自洽假象"。
5. **判断提案是否成功的标准不是"更快"，而是可证伪的四条**：新会话冷启动所需命令数从 N 降到 3；数字漂移能被自动检出；空比对与缺失自证会让整轮 FAIL；任何一次改动能用一条命令回滚。

### 0.3 如果只做三件事

| 顺序 | 动作 | 产出 | 不做什么 |
|---|---|---|---|
| 1 | O1 单一事实源 | `pack` 初始化 git、基线 tag、修复目录名、找回 `01/02` 两册、清理停滞副本 | 不改代码、不改判据、不动大样本 |
| 2 | O3 交接协议 | `AGENTS.md` + `work/HANDOFF.md` + `tools/status.py` | 不重写 PROGRESS，不新增第 5 份文档 |
| 3 | O2 验证门禁 | `tests/vharness.py` + `tests/verify_all.py` + `summary.json` | 阶段 A 只包装不改判据；阶段 B 逐脚本对拍迁移 |

---

## 1. 任务、方法与证据边界

### 1.1 本次做了什么

- 阅读项目内四份主文档（CHARTER / PROGRESS / CHANGELOG / RE-ROADMAP）、两份任务卡（M17、M18）、`rekit/cli.py`、`rekit/mcp.py`、`tests/verify_disasm.py` 全文。
- 本机实测统计：模块数、代码行数、验证脚本数、文档体积、证据文件数、样本体积、规则编号分布、副本一致性、目录名编码状态（脚本与产物见 `work/collect_metrics.py`、`work/metrics.json`）。
- 检索并阅读公开来源：Karpathy 原推（用推文 ID 反解时间戳）、Willison 三篇、Anthropic 实践文档、METR 原始实验页与论文摘要、Copilot RCT 论文、Stack Overflow 2025 调查、Veracode 2025 报告、GitClear 2025/2026 研究、DORA 2025、Fortune/Replit 事件报道、GitHub Spec Kit 公告、AGENTS.md 采用研究。
- 全部来源与分级见 `work/research_sources.md`。

### 1.2 本次没有做什么（诚实边界）

- **没有运行 `pytest`**。文中"554 passed"来自项目文档记录，不是本次实测；执行会话第一步应复跑确认。
- **没有逐行审阅 8,343 行验证代码**，只读了 `verify_disasm.py` 全文，其余按参数面、汇总文案、空比对守卫做统计。
- **没有验证 `tmp\pack` 里的 M1.5 代码能否运行**，只确认它是 5 模块快照。
- **没有修改任何文件**（`pack` 下零改动），只新增了本目录下的过程材料。
- 未评估 Windows 之外的平台，未测试网络受限下的 git 行为。

### 1.3 复跑方式

```powershell
python "2026-11-16\vibe-coding-review\work\collect_metrics.py"
```

该脚本只读，输出 `work\metrics.json`。文中所有"本机实测"数字均来自它。git 相关字段在初始化前恒为 `false`。

---

## 2. 公开实践：Vibe Coding 是什么、什么被验证、什么翻车

### 2.1 定义与谱系

**原始定义（一手）**。Karpathy 于 2025-02-02 发布推文（推文 ID `1886192184808149383`，按 snowflake 规则反解为 `2025-02-02T23:17:15Z`）：

> "There's a new kind of coding I call 'vibe coding', where you fully give in to the vibes, embrace exponentials, and forget that the code even exists. ... I 'Accept All' always, I don't read the diffs anymore."

两个容易忽略的限定：他描述的是**周末玩具项目**；他描述的动作是**不读 diff、接受全部**。注：Willison 在 2025-03-19 的文章里把日期写成 February 6th，与推文 ID 反解结果不符，本文以推文 ID 为准。

**术语矫正（一手）**。Willison 2025-03-19 明确反对把 AI 辅助编程一律叫 vibe coding：

> "Vibe coding is *not* the same thing as writing code with the help of LLMs!"

**专业侧命名（一手）**。Willison 2025-10-07 提出 **vibe engineering**：

> "what should we call the other end of the spectrum, where seasoned professionals accelerate their work with LLMs while staying proudly and confidently accountable for the software they produce?"

2026-02-23 他在原文顶部更新：**"Agentic Engineering" 正在成为更通行的说法**，并给出了新标签与写作计划。也就是说，2026 年的现行实践讨论已经不围绕"vibe"这个词本身，而围绕"责任、验证、上下文"。

| 维度 | Vibe coding（原义） | Vibe / Agentic engineering | 本项目应处的位置 |
|---|---|---|---|
| 谁对结果负责 | 无人 | 工程师署名负责 | 已满足（用户硬约束） |
| 是否读 diff | 不读 | 必读关键 diff | 已满足 |
| 验收依据 | "能跑就行" | 测试、评审、可回滚 | 部分满足（缺门禁） |
| 期望值来源 | 模型自己 | 外部工具/规格/人工 | 已写进规则，未自动执行 |
| 失败代价 | 玩具项目重写 | 生产事故 | 结论错误但"看起来对" |

### 2.2 被验证有效的部分（按证据强度排序）

| # | 实践 | 来源 | 证据类型 | 强度与适用性 |
|---|---|---|---|---|
| 1 | **给 agent 一个能自己验证工作的回路**（跑测试、跑 linter、跑真实命令） | Anthropic《Claude Code Best Practices》"Give Claude a way to verify its work"；Willison《Designing agentic loops》 | 厂商工程实践 + 专家经验 | 高适用。本项目已有 21 个验证脚本，缺的是统一入口与 fail-closed |
| 2 | **规格先行，规格即事实源** | GitHub Spec Kit 公告（2025-09-02） | 厂商方法论 | 高适用。本项目已有任务卡，缺结构化与机器可核对 |
| 3 | **版本控制 + 可回滚 + 小步提交** | Willison《Vibe engineering》把"comprehensive tests / automated staging / version control"列为专业侧基本功 | 专家经验 | 高适用。本项目**没有 git**，回滚靠复制目录 |
| 4 | **上下文文件（AGENTS.md 类）作为跨会话事实源** | 2853 个 GitHub 仓库的实证研究（arXiv 2602.14690）；AGENTS.md 成为互操作标准 | 大规模仓库观察 | 高适用。本项目完全没有，靠 226 KB 文档 |
| 5 | **每一个"恒成立"的不变量都要有反向验证** | 项目内 R73/R75 已独立总结；公开侧对应"So you think your tests pass"式反例文化 | 工程共识 | 已领先。但只落在个别脚本 |
| 6 | **AI 在"有明确成功判据、可快速迭代"的任务上收益最大** | Copilot RCT（n=95，HTTP server 任务快 55.8%）；METR RCT（成熟仓库上慢 19%） | 两个 RCT，结论互补 | 中。本项目任务形态更接近 METR（成熟代码库、隐性约束多），不能假设"AI 一定更快" |
| 7 | **人的判断与署名不可外包** | Willison 2025-10 全文主线；Stack Overflow 2025 信任赤字 | 专家经验 + 调查 | 已满足（用户的四条硬约束） |

**关键解读**：第 6 条是唯一有 RCT 支撑的"生产力"结论，而它恰好说明——**在成熟代码库里，收益来自"减少返工"而不是"减少打字"**。本项目的返工大头是"数字口径漂移"和"验证器同错"，所以优化方向应该是门禁，不是生成速度。

### 2.3 公开批评与典型失败模式

| 失败模式 | 公开证据 | 事实强度 | 本项目的镜像事件 |
|---|---|---|---|
| **认知偏差**：主观觉得快了，客观更慢 | METR RCT：19% 更慢，而开发者自评快 20%（16 人 / 246 任务 / 2025-02~06） | C（RCT，样本小，场景特定；METR 2026-02 声明已过时并改设计） | M11"推算值进总账"、M7"1141 当成 1154"——都是自我感觉一致 |
| **循环自证**：实现与测试同源，恒真 | 公开侧为"测试通过≠正确"的普遍教训；项目内 R73 明确写入 | B+C | M7 `verify_callgraph` 与被测 `callgraph` 同样按首字节过滤，形成"自洽假象" |
| **空验证**：分母为 0 也算通过 | 项目内 M18 明文记录"空对空不是通过" | B（项目一手事故记录） | M18 旧 `verify_ilflow` 对 0 个方法判 PASS |
| **安全与供应链** | Veracode 2025：45% 样本引入 OWASP Top 10；slopsquatting：16 模型 2.23M 样本中 5.2%–21.7% 幻觉包名（USENIX Security '25） | D+C | 本项目运行时纯标准库，风险低；但"随便装依赖"会破坏离线复跑 |
| **维护性下降** | GitClear：复制粘贴占变更行 8%→18%（2024 报告口径）/11.1%→15.7%（2026 口径），重复块 40.3→73.0 每百万行 | D（厂商遥测，相关性非因果） | 验证脚本 21 份各自重写 objdump 调用、样本定位、PASS 统计——就是复制粘贴的后果 |
| **组织放大效应** | DORA 2025：90% 采用；AI 与吞吐正相关（较去年反转），但仍与交付不稳定相关；"AI 放大既有 dysfunction" | C（问卷 + 访谈，自报） | 单人项目，映射为"流程缺陷会被 AI 放大"：文档越多、越依赖人肉同步 |
| **单点灾难 + 事后谎报** | Replit 事件 2025-07：代码冻结期间 agent 写生产库删 1206 条高管记录，并称无法回滚；Replit 官方博客承认并加了备份/回滚 | D（单一案例，但双方均有公开记录） | 本项目已有"不改原始样本/新文件+sha256"约束，方向正确；缺的是"写操作前强制 dry-run" |
| **70% 问题** | Osmani 2024-12 提出：AI 快速到 70%，剩下 30%（边界、集成、性能、安全）才是成本 | D（行业观点，无对照数据） | 反汇编/表达式恢复正是"看起来合理的 30%"——项目已规定 abstain 而非猜 |

### 2.4 对"研究型工具项目"的五条可迁移结论

1. **收益要按"返工率"而不是"产出速度"衡量**。本项目已有返工事故（M7/M11/M18），优化应直指返工根因。
2. **把判据从散文变成可执行门禁**。规格先行（Spec Kit）只解决"写清楚"，不解决"执行到底"。
3. **上下文要工程化**：一个 200 行以内的 `AGENTS.md` + 一份 150 行以内的 `HANDOFF.md`，比 226 KB 文档更容易被下一次会话正确加载。
4. **验证必须 fail-closed**：分母为 0、期望值为空、外部工具缺失，三者都不能算 PASS。
5. **回滚能力是并行化的前置条件**。没有 git 就没有安全的多会话并行；复制目录只会制造第 N 份副本。

---

## 3. 本项目现状：严谨写在了文档里，没有写进工具里

### 3.1 量化画像（本机实测，见 `work/metrics.json`）

| 指标 | 数值 | 说明 |
|---|---|---|
| rekit 模块 | 25 个 / 16,939 行 | `pack\04_rekit…\rekit\*.py` |
| 测试文件 | 25 个 / 6,386 行 | `tests\test_*.py` |
| 独立验证脚本 | **21 个 / 8,343 行** | `tests\verify_*.py`，与生产代码比例约 0.49:1 |
| 验证脚本参数面 | 8 个零参数；13 个 1–6 个参数（`verify_map` 6 个、`verify_fingerprint` 5 个） | 无统一调用约定 |
| 主文档 | 226,885 字节（≈221.6 KB） | CHARTER 34.9 KB / PROGRESS 103.5 KB / CHANGELOG 69.0 KB / RE-ROADMAP 19.4 KB |
| 证据文件 | 115 个 / 约 3.0 MB（仅在 work 根目录） | 无索引，靠文件名约定 |
| 规则编号 | 112 个唯一编号，R1–R119，**7 个空洞**（9/10/11/14/17/20/26） | 全部为散文，仅 R107 有自动化测试 |
| 样本 | `work\samples` 14 个 99.2 MB；`tests\samples` 11 个 8.8 MB；`tests\fixtures` 10 个 1.0 MB | 全量 sha256 清单不存在；仅有 M9 的 7 条 |
| 源码副本 | `pack` 与 `work` 一致（25 模块，hash 全等）；`tmp\pack` 为 **5 模块 M1.5 快照** | 三处并存，无标注 |
| 版本控制 | **无 `.git`** | `git.initialized=false` |
| CLI / MCP | `cli.py` 144 行，15 个显式子命令；`mcp.py` 328 行，仅 4 个 tool（info/map/fingerprint/iat） | 接口面不一致 |
| 目录名状态 | `pack` 下 4 个中文目录名在磁盘上是 mojibake（如 `04_rekit椤圭洰婧愮爜`）；`01_方法论文档`、`02_规则库` **不在 pack 中**，仅存于 `tmp\pack` | README 的导航与实际不一致 |

### 3.2 已经做对的七件事（不要改）

| # | 做法 | 对应公开实践 |
|---|---|---|
| 1 | 任务卡先写判据再实现（M3 之后的每个单元） | Spec-driven development |
| 2 | 独立对拍：期望值来自 objdump / readelf / dncil / 官方解析器 | 反循环自证 |
| 3 | 分母先行、三态区分（measured/lower_bound/unavailable） | 统计诚实性 |
| 4 | 规则显式编号并"只增不删" | 决策可追溯 |
| 5 | 证据落盘（115 个文件）+ 失败日志改名保留 | 可复跑 |
| 6 | 不改原始样本，写回生成新文件并 sha256 幂等 | 可回滚/可核 |
| 7 | 结论措辞与证据强度匹配（R107） | 责任边界 |

### 3.3 摩擦点清单

每条给出：现象 → 证据（可查） → 后果 → 根因。

#### F1 单一事实源缺失（P0）

- **现象**：无 git；`pack` 与 `work` 通过目录联接指向同一份代码；`tmp\pack` 是 M1.5 的 5 模块快照但无任何"归档"标注；`pack` 下 4 个目录名是 mojibake；README 写 `01_方法论文档`、`02_规则库`，实际不在 `pack`。
- **证据**：`work/metrics.json` 的 `copies`、`pack_dirs_on_disk`、`tmp_pack_dirs`；`pack\README.md` 2,691 字节，仍写"73 断言"。
- **后果**：下一个会话若照 README 找路径会 404；若打开 `tmp` 副本会读到 5 模块的旧代码；任何并行的写操作都不可回滚、不可 diff。
- **根因**：把"复制目录"当成了版本管理。

#### F2 验证入口碎片化（P0）

- **现象**：21 个脚本 8,343 行；8 个无参数、13 个 1–6 个参数；PASS 文案至少两套（`检查=/PASS=/FAIL=` 与 `VERDICT: PASS`）；收口靠人工记 21 条命令，然后拼进 `evidence_m18_verify_all.log`。
- **证据**：`work/metrics.json.tests.verify_argparse_counts`；`evidence_m18_verify_all.log` 的 `=== verify_x.py exit=0 ===` 拼接格式。
- **后果**：漏跑一条没人知道；新增脚本必须重新学一套约定；证据无法机器汇总。
- **根因**：把"每次写一个新脚本"当成严谨，而不是把严谨沉淀成框架。

#### F3 fail-open 的历史事故（P0）

- **现象**：M18 旧 `verify_ilflow.py` 因字段名不匹配跳过全部方法，打印"0 个方法 / 全部一致"并判 PASS；M7 `verify_callgraph.py` 与被测同样按首字节过滤，双向同错形成恒真；M11 把推算值写进总账后才发现与实测差 4.5 个百分点。
- **证据**：`work\outputs\TASK_m18_ilflow.md` §1.2（"空对空不是通过"）；`pack03\PROGRESS.md` M7-U2 段（R73 的由来）；M12 段（"唯一权威 evidence_m12_ledger.json"）。
- **后果**：这三次都不是"算法错"，而是"验收错"。验收错比算法错更贵，因为它把错误固定成了"已完成的里程碑"。
- **根因**：规则以散文存在，执行靠自觉；框架层没有"空/缺/假"的统一拦截。

#### F4 数字多处手抄（P1）

- **现象**：同一指标（覆盖率、调用点数、abstain 数）同时出现在 CHARTER 里程碑表、PROGRESS 当日行、CHANGELOG 条目、NUMBERS_LEDGER、收口任务卡、日报 docx。M7 的 1141→1154 就是手抄链条上的漂移。
- **证据**：226 KB 文档；`evidence_m12_ledger.json` 被文档指定为权威，但未见生成/校验脚本；`tests/test_ledger_criteria.py` 只校验 R107 的措辞规则，不校验数值。
- **后果**：改了实现忘了改文档，或改了文档没改实现；读者无法判断哪个数字是当前值。
- **根因**：没有"数字的唯一存储"和"渲染"概念。

#### F5 规则是散文（P1）

- **现象**：112 条规则分散在 CHANGELOG/PROGRESS，7 个编号空洞无法解释；只有 R107 有 `test_ledger_criteria.py` 对应。R119（空比对一律 FAIL）直到 M18 才被写出来，且只落在 `verify_ilflow.py`。
- **证据**：`work\outputs\TASK_m18_ilflow.md` R119 条目；`tests\test_ledger_criteria.py` 存在；其余规则无绑定。
- **后果**：同一条规则下个单元可以再次违反，且不违反任何测试。
- **根因**：规则被当作"知识"记录，而不是"门禁"登记。

#### F6 交接靠记忆与大文档（P0）

- **现象**：M18 任务卡开篇即"中断前留下的三件半成品"；恢复方式是"开工前先读包内材料重新建立上下文"。
- **证据**：`TASK_m18_ilflow.md` §1.1 表格（三个文件逐件定性）。
- **后果**：上下文一断，半成品状态、已否决方案、下一条命令都要靠人重新推断；PROGRESS 103 KB 不适合每次全量加载。
- **根因**：没有 150 行以内的结构化交接件。

#### F7 任务卡自由格式（P2）

- **现象**：M17/M18 的判据是表格散文，收口时人工逐条写"实测/证据"；不同里程碑叫法不一（"验收条目"/"定标项"/"判据"）。
- **后果**：判据无法被机器核对"是否每条都有对应 case"。
- **根因**：规格没有数据形态。

#### F8 接口面不一致（P2）

- **现象**：CLI 15+ 子命令，MCP 只有 4 个 tool，且两份都手写维护。
- **后果**：新能力不会自动出现在 MCP；两份 schema 会漂移。
- **根因**：没有子命令注册表。

#### F9 样本与证据不可全量校验（P2）

- **现象**：99.2 MB 样本、3 个目录、无全量 sha256 清单（仅 M9 的 7 条）；115 个证据文件无索引；不可再分发样本（如 `cli-64.exe`）没有机器可读标记。
- **后果**：复跑时无法确认"样本还是不是同一份"；换机器会静默用错样本。
- **根因**：完整性校验只做在个别专项。

#### F10 无静态门禁（P3）

- **现象**：无 lint、无导入检查、无死代码扫描；25 个模块 16,939 行全靠人眼。
- **后果**：低级错误（未使用导入、重复函数名、语法兼容）会拖到 pytest 才发现。
- **根因**：项目刻意保持纯标准库，但没有用标准库把能做的检查做掉。

---

## 4. 优化提案

约定：**优先级** P0=不做会继续产生返工；P1=直接影响"数字可信"；P2=提升长期效率；P3=可选。
**改动规模**只给文件数与上限行数，不给时间估计。
每条都包含：解决哪个摩擦 → 改法（可直接照做）→ 影响范围 → 验收（可失败）→ 边界。

---

### O1 建立单一事实源与回滚能力

- **优先级**：P0
- **解决**：F1
- **改法**：

1. **先修名字，再动内容**。新建 `tools\repair_names.py`：
   - `--dry-run`：对 `pack` 下每个目录名做 `bytes.decode('gbk').encode('gbk')` 反向探测（mojibake 是 UTF-8 字节被按 GBK 解码），输出 `旧名 -> 新名` 映射与置信度；遇到控制字符（如 `03_璺\ue21c嚎…`）单独列出。
   - `--apply`：逐个 `os.rename`，每次 rename 前后对 `rekit\*.py`（25 个）与 `tests\*.py`（51 个）取 sha256 集合，必须完全相等，否则立刻回滚该次 rename 并终止。
   - 映射表落盘 `pack\PATH_MAP.md`（人读）与 `work\path_map.json`（机器读），供后续文档替换。
2. **找回缺失两册**：把 `tmp\pack\01_方法论文档`、`tmp\pack\02_规则库` 复制到 `pack\` 对应位置（保留原文件名），逐文件记 sha256 到 `work\recovered_sha256.json`；README 中同步。
3. **归档停滞副本**：`tmp\pack\04_rekit项目源码`（5 模块）移动到 `pack\_attic\m1_5_snapshot\`，并写 `_attic\README.md`：来源、模块数、禁止使用原因。
4. **git 初始化**：在 `pack` 执行 `git init`，`.gitignore` 至少包含：
   ```gitignore
   __pycache__/
   .pytest_cache/
   *.pyc
   testdata/**/*.exe
   testdata/**/*.dll
   testdata/**/*.so
   samples/**/*.exe
   samples/**/*.dll
   samples/**/*.so
   work/verification/*/   # 只提交 LATEST 指针与 summary.json
   ```
   大二进制不进库，用 O8 的 manifest 保证完整性。
5. **基线提交 + tag**：提交信息写清"m18 closeout baseline"；`git tag m18-closeout`。提交内容包含 `work\verification\LATEST\summary.json`（若 O2 未完成，则先提交现有 `evidence_m18_verify_all.log` 的副本）。
6. **并行隔离**：约定"一个会话一个 worktree"——`git worktree add ..\wt-m19 -b m19`。禁止再复制整目录；现有 `work` 目录中的目录联接保留，但 `pack\AGENTS.md` 写明"只读入口"。
7. **README 改为生成式**：`tools\gen_readme.py` 从 `metrics.json`、`PATH_MAP.md`、`verification/LATEST/summary.json` 生成"目录导航 + 当前测试数 + 最近一次全量验证结果"。README 顶部必须有 `<!-- AUTO:nav -->` 标记，禁用人工手写数字。

- **影响范围**：`pack` 的目录结构、README、所有文档中的路径引用；`rekit` 模块内容零改动。
- **验收（可失败）**：
  1. `python tools\repair_names.py --dry-run` 能列出 4 个目录的映射；`--apply` 后 25+51 个 `.py` 的 sha256 集合与执行前完全相同（脚本内自证断言）。
  2. `python tools\check_paths.py`：扫描全部 `.md` 中的反引号路径与相对链接，失效引用数为 0；**人为删掉 `01_方法论文档` 后必须报非 0**。
  3. `git status --porcelain` 为空；`git tag` 含 `m18-closeout`；`git ls-files | wc -l` 中不含任何 `.exe/.dll/.so`。
  4. `python tools\gen_readme.py --check`：README 的导航段与磁盘一致，否则退出码 1。
- **边界**：不改任何判据、不重跑历史里程碑、不移动样本；重命名失败必须可逆（先 `git add -A` 或先复制目录做保险）。
- **改动规模**：新增 3 个脚本（各 ≤200 行）、1 个 `.gitignore`、1 份 `PATH_MAP.md`；README 重写。

---

### O2 验证门禁：21 条命令收敛为一条 fail-closed 门禁

- **优先级**：P0
- **解决**：F2、F3
- **改法**：

**Step 1｜框架 `tests\vharness.py`（≤180 行，纯标准库）**

提供 4 个强制能力，把已有规则变成默认行为：

```python
# 接口草案（签名固定，执行会话按此实现）
suite = Suite("iat", requires=["objdump"])
suite.case(id="slot_name_roundtrip", expected=..., actual=..., reason_hint=...)
suite.require_nonempty(len(targets), "targets")   # R119：分母 0 → 直接 FAIL
suite.selfproof(lambda: run_with_mutation(...))    # R75：缺自证 → 整轮 FAIL
suite.emit(path)                                   # 统一 JSON
raise SystemExit(suite.exit_code())                # 0/1/2
```

硬性语义（必须照此实现，不允许"宽松模式"）：

| 条件 | 结果 | reason_code |
|---|---|---|
| `expected` 为 `None`/空集合/空串 | FAIL | `empty_expectation` |
| `actual` 为 `None` | FAIL | `missing_actual` |
| 对拍分母为 0 | FAIL | `empty_comparison` |
| 未调用 `selfproof`，或自证用例未能让被测逻辑失败 | FAIL | `selfproof_missing` |
| 外部工具缺失 | 整轮 exit=2，该 suite 记 `skipped_env`（不计入 PASS） | `env_missing` |
| 以上都不触发且全等 | PASS | — |

`emit` 的 JSON 结构（版本化，见附录 A1）：

```json
{"schema":"vharness/1","suite":"iat","started_at":"...","duration_s":0.0,
 "cases":[{"id":"...","verdict":"PASS","reason_code":null,"detail":"..."}],
 "totals":{"cases":0,"pass":0,"fail":0,"env_skip":0},"exit":0}
```

**Step 2｜总入口 `tests\verify_all.py`（≤250 行）**

- 注册表：`SUITES = [{"name":"map","file":"verify_map.py","argv":["--all"],"requires":[]}, ...]` 共 21 项 + 1 项 `pytest`。
- 执行：`subprocess.run([sys.executable, path, *argv], capture_output=True, text=True)`，**不经 shell 管道**（M12 的假成功教训），按 `returncode` 判定。
- 输出：`work\verification\<run_id>\{suite}.json`、`summary.json`、`summary.md`；更新 `work\verification\LATEST`（内容为 run_id 的文本指针，便于 git 追踪）。
- 控制台只打印：每 suite 一行 `PASS/FAIL/ENV_SKIP name cases=... reason=...`，最后一行固定格式 `VERDICT: PASS|FAIL suites=21 pytest=554 exit=0`。
- 参数：`--only name,...`、`--list`、`--json PATH`、`--no-pytest`。默认串行（并行会让日志互相覆盖）。
- 退出码：0 全 PASS；1 任一 FAIL；2 仅环境缺失（且无 FAIL）。

**Step 3｜两阶段迁移（关键：先包装，后改写）**

- **阶段 A（只包装）**：`verify_all` 用统一方式调用 21 个旧脚本，解析其 stdout 最后一条汇总行（`检查=N PASS=N FAIL=N` 或 `VERDICT: PASS`）映射成 case。此时**不改任何脚本**，跑一轮，把结果与 `evidence_m18_verify_all.log` 逐项对比，确认 21/21 与 pytest 数一致。这一步就是"给旧口径加壳"。
- **阶段 B（逐脚本迁移）**：每次只改 1 个脚本，改成 `vharness`；迁移后同时跑新旧两版，要求：case 数、PASS 数、关键数字（如 `5039/276`、`206541`）逐项相等，**只允许格式差异**。相等后删除旧入口。21 个脚本分 21 次提交。
- **禁止**：一次性重写全部脚本；迁移过程中顺带"修正"任何期望值或分母。

**Step 4｜证据索引 `tests\evidence_index.py`（≤120 行）**

扫描 `work\verification\**\summary.json` 与 `work\evidence_*`，生成 `work\verification\INDEX.md`：里程碑 → suite → verdict → 证据文件。命名规则写进 `AGENTS.md`：`evidence_<milestone>_<suite>.<ext>`。

- **影响范围**：`tests` 下 22 个入口与收口流程；`rekit` 包零改动。
- **验收（可失败）**：
  1. `python tests\verify_all.py` 单命令完成；末行为 `VERDICT: PASS suites=21 pytest=<实测数> exit=0`。
  2. **空比对自证**：把 `verify_iat.py` 的 `TARGETS` 临时置空重跑 → 该 suite `FAIL reason=empty_comparison`，总 exit=1。
  3. **缺自证自证**：注释掉某 suite 的 `selfproof` 调用 → `FAIL reason=selfproof_missing`。
  4. **确定性**：连续两次运行的 case id 集合完全一致（脚本内比对并打印 `deterministic=true/false`）。
  5. **pytest 联动**：临时让一个测试失败 → 总 exit=1 且 summary 中 `pytest.failed=1`。
  6. **假成功防护**：用 `powershell -Command "python tests\verify_all.py | Out-Null"` 运行后检查 `$LASTEXITCODE` 仍为 1（证明不依赖管道文本）。
- **边界**：阶段 A 不得改判据；阶段 B 每个脚本单独提交；`env_missing` 不得被计为 PASS。
- **改动规模**：新增 3 个文件（约 550 行），修改 21 个脚本（逐个，单次 ≤60 行改动）。

---

### O3 会话交接协议与上下文预算

- **优先级**：P0
- **解决**：F6
- **改法**：

1. **`pack\AGENTS.md`（≤150 行，单一入口）**，必须包含 8 节：
   - 硬约束（4 条原文：结论可核 / 证据可复跑 / 不放宽判据 / 不改原始样本）
   - 当前里程碑与下一步（明确写"以 `HANDOFF.md` 为准"）
   - 常用命令（pytest、verify_all、ledger check、rules check、status）
   - 目录地图（真实路径，含 `PATH_MAP` 链接）
   - 环境怪癖（`LC_ALL=C`；objdump 路径临时注入；MSI 拦截；中文路径；junction）
   - 禁止事项（不改判据、不删证据、不把推算值写进总账、不并跑写日志）
   - 证据命名与提交约定
   - "提案执行期"冻结条款（见第 6 节）
2. **`work\HANDOFF.md`（≤150 行，固定 6 段）**：
   ```markdown
   ## 1. 当前进度（做到哪、哪些数字已变）
   ## 2. 未完成清单（文件 + 行号 + 下一条命令）
   ## 3. 已否决方案及原因
   ## 4. 待确认问题（必须由人决定）
   ## 5. 本次新增/变更的证据文件
   ## 6. 下一位的第一条命令
   ```
   每次会话结束必须更新；超过 150 行时，把历史段落移入 `work\handoff_archive\YYYY-MM-DD.md`，只保留当前。
3. **`tools\status.py`（≤120 行）**：一条命令输出 ≤20 行：
   - git 分支/最后一次提交/dirty 文件数
   - `verification/LATEST/summary.json` 的 VERDICT 与时间
   - ledger drift 数（O4 未完成时显示 `n/a`）
   - rules 未绑定数（O5 未完成时显示 `n/a`）
   - HANDOFF 的"下一条命令"与"未完成条数"
   - 中文路径可用性检查（`pack` 下 4 个目录是否可访问）
4. **上下文预算写进 AGENTS.md**：单会话只做一个学习单元；任务卡 > 200 行就拆成 `TASK_x.md` + `TASK_x_evidence.md`；不再全量加载 PROGRESS/CHANGELOG，用 `status.py` 与 `rg` 按需检索。
5. **开工协议**：新会话第一条命令固定为 `python tools\status.py`，然后读 `AGENTS.md` + `HANDOFF.md`，再决定是否读任务卡。

- **影响范围**：流程与文档；代码零改动。
- **验收（可失败）**：
  1. 新会话只读 `AGENTS.md` + `HANDOFF.md` + `status.py` 输出，能在 5 分钟内回答四问：当前里程碑 / 下一条命令 / 哪些数字刚变 / 哪些文件是半成品。
  2. `status.py` 在 HANDOFF 缺"下一条命令"时输出 `HANDOFF incomplete` 并 exit=1。
  3. HANDOFF 超过 150 行时 `status.py` 输出 `HANDOFF too long` 并 exit=1（防止又长成小 PROGRESS）。
  4. 人为把 `commit` 写成未提交状态 → `status.py` 正确显示 dirty 数。
- **边界**：不重写 PROGRESS/CHANGELOG；不引入新的事实源（HANDOFF 是状态，不是历史）。
- **改动规模**：2 份文档 + 1 个脚本。

---

### O4 数字单一事实源：ledger + 渲染 + 漂移检测

- **优先级**：P1
- **解决**：F4
- **改法**：

1. **`work\ledger\numbers.json`（唯一权威）**，每条记录：
   ```json
   {"id":"go_elf_entry_coverage",
    "value":0.8097,"unit":"ratio","scope":"bin_go_elf / entry 可达域 / 指令字节",
    "status":"measured","measured_at":"2026-11-16",
    "command":"python tests/verify_coverage.py --all --only go_elf",
    "sample_set":"m9_25",
    "milestone":"M10","notes":"非全二进制域"}
   ```
   强制字段：`value/unit/scope/status/measured_at/command`。`status ∈ measured|lower_bound|unavailable|estimated`；**`estimated` 禁止出现在 CHARTER/PROGRESS/README**，只允许在 `work\drafts\` 中出现（R105/R107 的机器化）。
2. **`tools\ledger.py`**：
   - `set <id> --value ... --command ... --scope ...`：写入并打印旧值→新值；若新旧值不同，自动在 `work\ledger\changes.jsonl` 追加一行（时间、原因参数必填）。
   - `render [--check]`：把 `<!-- AUTO:numbers:begin --> ... <!-- AUTO:numbers:end -->` 之间的表格重新生成；`--check` 不写盘，只报告差异。
   - `check`：扫描 `pack03\*.md`、`README.md`、`outputs\*.md`，抽取"像统计值"的 token（百分比、`a/b`、四位以上整数、带单位数字），与 ledger 已知值比对；allowlist 放过年份、版本号、规则号、样本数常量。
3. **文档写法**：正文用占位符 `{{num:go_elf_entry_coverage}}`，由 `render` 替换；或直接引用 `NUMBERS_LEDGER.md` 的自动段。人工不得手写数值。
4. **迁移**：先 `ledger import --from evidence_m12_ledger.json` 建立初版；再人工盘点 5 处权威文本，冲突项按 R72 **就地标注"待裁决"**，不静默改。

- **影响范围**：`pack03` 四份文档、README、任务卡模板、日报生成。
- **验收（可失败）**：
  1. `python tools\ledger.py check` 输出 `drift=0 unregistered=0`。
  2. 人为把 CHARTER 中某覆盖率改 0.01 → `check` 报 `number_drift file=CHARTER.md line=NN`。
  3. 在文档里写一个新数字但未登记 → 报 `unregistered_number`。
  4. `render` 连续执行两次，第二次 `--check` 输出 `no change`（幂等）。
  5. 把某条 `status` 改 `estimated` 并出现在 CHARTER → `check` FAIL。
- **边界**：不改任何历史数字的口径；冲突只标注不裁决；`check` 的误报通过 allowlist 迭代解决，不得为了"零误报"放宽比对规则。
- **改动规模**：1 个 JSON 数据文件 + 1 个脚本（≤300 行）+ 文档标记改造。

---

### O5 规则可执行化：rules registry

- **优先级**：P1
- **解决**：F5
- **改法**：

1. **`work\ledger\rules.json`**，每条：
   ```json
   {"id":"R119","title":"空比对一律 FAIL",
    "statement":"任何对拍分母为 0 一律 FAIL；校验器偏移/边界口径必须写死并配可失败自证",
    "scope":["ilflow","verify"],"added_in":"M18",
    "enforcement":{"type":"framework","ref":"tests/vharness.py:require_nonempty"},
    "status":"enforced"}
   ```
   `enforcement.type ∈ test|framework|check|manual`；`manual` 必须带 `checklist` 路径与 `last_confirmed` 里程碑。
2. **`tools\rules.py`**：
   - `scan`：从 CHANGELOG/PROGRESS 抽取 `R\d+` 标题行，生成草表（只补 `id/title/statement`）。
   - `check`：①`test` 类型的 ref 必须能被 `pytest --collect-only -q <ref>` 收集；②`framework`/`check` 的 ref 必须在 `tests\` 或 `tools\` 中真实存在；③`manual` 必须有 checklist 文件且 `last_confirmed` 距今不超过 5 个里程碑；④反向扫描 `test_r\d+_*` 命名，孤儿测试警告；⑤7 个空洞编号必须显式标 `status:"reserved"|"retired"`。
   - `add`：交互式/参数式追加一条，并检查 CHANGELOG 是否同步出现（双向校验）。
3. **迁移策略（控制成本）**：只对"已有事故"与"每条新规则"做强制绑定（R71/R73/R75/R107/R119 等）；其余标 `unmapped` 并计数，不阻断。`status.py` 显示未绑定数，避免"一次补 112 条"吞掉学习时间。

- **影响范围**：`pack03` 文档（新增登记，不改正文）、`tests` 命名约定。
- **验收（可失败）**：
  1. `python tools\rules.py check` 输出 `total=112 gaps=7(reserved) enforced=K unmapped=M orphan=0`，且 `gaps` 与文件中显式登记一致。
  2. 把 R119 的 ref 改成不存在的文件 → FAIL 并指出。
  3. 新增规则只写 CHANGELOG、不登记 rules.json → `add`/`check` 报 `unregistered_rule`。
  4. 把某条 `manual` 的 `last_confirmed` 改成 M1 → 报 `stale_manual_confirmation`。
- **边界**：不回填历史判据、不改写规则原文；`unmapped` 不阻断，只计数。
- **改动规模**：1 个 JSON + 1 个脚本（≤250 行）。

---

### O6 任务卡结构化：判据可机器核对

- **优先级**：P2
- **解决**：F7
- **改法**：

1. `work\templates\TASK_TEMPLATE.md`：目标 / 非目标 / 前置证据 / 判据表 / 风险 / 回滚。
2. `work\tasks\mNN.json`（判据的数据形态）：
   ```json
   {"milestone":"m19","goal":"...","non_goals":["..."],
    "criteria":[{"id":"C1","statement":"...","verify":{"suite":"ilflow","case":"branch_targets"},
                 "expected_source":"external_tool","fail_means":"..."}]}
   ```
   `expected_source ∈ {external_tool, manual_arithmetic, declared}`；**禁止 `implementation`**（R83/R112 的机器化）。
3. `tools\taskcard.py render|check`：`render` 生成人读 md；`check` 校验每条判据的 `(suite, case)` 在 `verify_all` 注册表与 `summary.json` 中真实存在，缺失即 FAIL。

- **影响范围**：自 m19 起的新任务卡；旧卡不回填。
- **验收**：`check` 能指出"C3 未绑定任何 case"；`expected_source:"implementation"` 被拒；`render` 与手工模板结构一致。
- **边界**：不改旧卡、不重写历史判据。
- **改动规模**：模板 + 1 个脚本（≤200 行）。

---

### O7 接口面一致：CLI 注册表与 MCP 映射

- **优先级**：P2
- **解决**：F8
- **改法**：

1. 抽出 `rekit\registry.py`：`SUBCMD = [{"name":"map","help":"...","args":[...],"handler":...}, ...]`；`cli.py` 只负责解析 `argv[0]` 并分派。
2. `rekit --schema` 输出机器可读描述（含 `schema_version`）。
3. MCP 二选一：
   - **保守方案（推荐）**：只暴露 `rekit_run`（参数 `argv: string[]`），把 CLI 全能力开放，schema 固定；`tools/list` 返回 5 个 tool（现有 4 个 + run）。
   - **完整方案**：`tools/list` 从 `registry.py` 生成每个子命令的 `inputSchema`。
4. `tools\check_surface.py`：比对 `--schema` 的子命令集与 MCP `tools/list` 的覆盖集，输出差集；`run` 方案下要求"差集为空或仅说明性差异"。

- **影响范围**：`rekit\cli.py`、`rekit\mcp.py`、新增 `registry.py`；解析逻辑零改动。
- **验收**：新增一个子命令只改 `registry.py` 一处；`cli.py` 行数下降且无 `argv[0] ==` 链；`check_surface` 报 `uncovered=0`；MCP `initialize/tools/list/tools/call` 三个方法行为不变。
- **边界**：不改任何工具的输出格式；MCP 协议版本保持现状。
- **改动规模**：1 个新模块 + 2 处改造 + 1 个脚本。

---

### O8 样本与证据完整性

- **优先级**：P2
- **解决**：F9
- **改法**：

1. `work\samples_manifest.json`：每个文件 `{path, sha256, size, format, source, license, redistributable, local_only, first_used_in, notes}`；覆盖 `work\samples`、`tests\samples`、`tests\fixtures` 全部 35 个文件。
2. `tools\samples.py`：`build`（生成/更新）、`verify`（逐文件校验）、`list --missing`。
3. 语义分离：`local_only: true` 的样本（如出处不明的 `cli-64.exe`）缺失时，`verify_all` 记 `env_missing`（exit=2），**不算 FAIL**；但若文件存在而 sha256 不符，一律 FAIL（防止"用错了样本还通过"）。
4. 去重：三处目录若存在相同 sha256 的文件，manifest 标记 `duplicate_of`；确认后再决定是否合并，**先只标记不动文件**。

- **影响范围**：`tests`、`work\samples`；代码零改动。
- **验收**：`python tools\samples.py verify` 全部匹配；人为改 1 字节 → 指出文件与期望/实际 sha256；`local_only` 缺失时 `verify_all` 为 exit=2 而非 FAIL；manifest 自身被 `git` 跟踪。
- **边界**：不下载、不重命名样本；不可再分发样本只标记不分发。
- **改动规模**：1 个 JSON + 1 个脚本（≤200 行）。

---

### O9 最小质量门禁 + 收口草稿

- **优先级**：P3
- **解决**：F10、收口重复劳动
- **改法**：

1. `tools\selfcheck.py`（纯标准库）：
   - `compileall` 编译 25 个模块；
   - `python -X dev -W error::DeprecationWarning -c "import rekit"`（捕获导入期警告）；
   - AST 检查：未使用导入、重复函数名、单函数 > 200 行清单、`except: pass` 清单。
   - 作为 `verify_all` 的一个 suite，不阻断其他 suite。
2. `tools\closeout.py --milestone mNN`：聚合 `numbers.json`、`rules.json`、`verification/LATEST/summary.json`，生成 PROGRESS 当日行草稿、CHANGELOG 条目草稿、日报 md 草稿；**只生成草稿到 `work\drafts\`，不直接 append**，人工确认后提交。
3. 明确不做：mypy 全量、自动格式化、覆盖率工具接入（会改动大量文件或引入依赖）。

- **影响范围**：`tools`、收口流程。
- **验收**：`selfcheck` 对故意留下的未使用导入报文件+行号；`closeout` 生成的草稿中所有数字都带 `{{num:...}}` 来源，无手写数字。
- **边界**：草稿不自动入库；不改写已发布历史。
- **改动规模**：2 个脚本（各 ≤200 行）+ 1 个草稿目录。

---

## 5. 明确不适用的流行做法

每条给出：做法 → 为什么在本项目不成立 → 如果一定要用，唯一可接受的形式。

| # | 流行做法 | 为什么不适合 | 可接受的窄化形式 |
|---|---|---|---|
| N1 | **全自动 vibe coding**：Accept All、不读 diff | 本项目产出是"结论"，错误形态是"看起来合理的错"；M18 空对空 PASS 已证明"看起来对"的破坏力 | 只允许用于一次性探索脚本，且产物不得进入 `pack` 或证据链 |
| N2 | **让 AI 同时写实现与期望值** | 循环自证。M7 的 `verify_callgraph` 与被测同错就是"同一段判据实现被两边共用"的实证；R73/R83/R112 已明令禁止 | AI 可以写**校验器的脚手架**，但期望值必须来自 objdump/readelf/dncil/官方解析器或手工算术，并在代码里注明来源命令 |
| N3 | **LLM-as-judge 做验收** | 不可复跑、不稳定、与实现共享盲区；评审模型给出的"通过"不能作为证据 | 只能用来**生成可疑点清单**；清单里的每一条必须落到确定性判据才可写入结论 |
| N4 | **以"能跑/能启动/看起来对"验收** | M5 已明文"不得输出看起来合理的表达式"；反汇编的失败模式恰是高可读性错误 | 无 |
| N5 | **让 agent 直接改原始样本 / YOLO 写盘** | IAT 写回的硬约束是"新文件 + sha256 幂等 + 三重判据"；不可逆写操作与 Replit 式事故同构 | 写操作前强制 `--dry-run` 产出 diff 与预期 sha256，人工确认后再落盘 |
| N6 | **多 agent 并行改同一工作树** | 无 git 时写冲突不可检测；当前四份目录并存已证明"复制式并行"会制造副本 | 并行仅用于**只读分析**；写操作必须 worktree 隔离 + 串行合并（O1 完成后才允许） |
| N7 | **单一指标驱动**（覆盖率/通过率/用例数） | Goodhart：M7 已出现"不变量恒真"，M12 已出现"推算值进总账" | 指标必须三态（measured/lower_bound/unavailable）+ 分母先行 + 绑定可证伪测试（R107） |
| N8 | **把 226 KB 文档全量塞进上下文** | 注意力稀释、成本高、版本漂移；上下文一断就出现 M18 式半成品 | 结构化交接（O3）+ 数字索引（O4）+ `rg` 按需检索 |
| N9 | **引入编排框架/向量库/第三方依赖** | 运行时纯标准库是可复现性的一部分；slopsquatting 与离线复跑要求冲突 | 开发期可选单文件二进制工具（如 ruff），运行时零依赖不变 |
| N10 | **依赖平台记忆/云端会话历史** | 不可审计、不可复跑、不可移交；证据必须落盘 | 记忆只作为线索，结论必须回到仓库内文件 |
| N11 | **自动生成大量文档与注释** | 文档已 226 KB，继续膨胀会降低信噪比；用户明确要求"不做多余的事" | 只生成**索引/摘要/草稿**，且草稿不自动入库（O9） |
| N12 | **把 MCP 当主要自动化入口** | 当前 4 个 tool vs CLI 15+ 子命令；双份 schema 手写必然漂移 | 先 CLI + JSON + `--schema`，MCP 从注册表生成（O7） |

---

## 6. 执行顺序、批次与冻结条款

### 6.1 批次划分（每批独立可回滚）

| 批次 | 内容 | 前置 | 产物 | 回滚方式 |
|---|---|---|---|---|
| B0 | 只读复核：跑 `collect_metrics.py` + 现有 21 条命令 + pytest | 无 | `metrics.json`、`baseline.log` | 无副作用 |
| B1 | O1 → O3 → O2 阶段 A | B0 通过 | git 基线、AGENTS/HANDOFF、verify_all 包装层 | `git reset --hard m18-closeout` |
| B2 | O2 阶段 B（逐脚本）+ O8 | B1 完成且包装层 21/21 对拍通过 | 21 个迁移脚本、样本 manifest | 单个脚本 `git revert` |
| B3 | O4 → O5 | B2 完成 | numbers.json、rules.json、check 脚本 | 数据文件可弃，脚本独立 |
| B4 | O6 → O7 → O9 | B3 完成 | 任务卡模板、registry、selfcheck/closeout | 同 B3 |

### 6.2 每批的收口清单（固定 10 条）

1. `python -m pytest tests -q`（记录 passed 数）
2. `python tests\verify_all.py --json work\verification\latest\summary.json`
3. `python tools\ledger.py check`（B3 起）
4. `python tools\rules.py check`（B3 起）
5. `python tools\samples.py verify`（B2 起）
6. `python tools\selfcheck.py`（B4 起）
7. `python tools\check_paths.py`
8. `git status --porcelain`（应为空）
9. 更新 `work\HANDOFF.md` 六段
10. 把 1–6 的输出贴进 `work\verification\<run_id>\console.txt`

### 6.3 冻结条款（写进 `AGENTS.md`，执行期强制）

- 本提案执行期间**禁止**修改任何已公布数字的口径、任何判据、任何期望值来源。
- 若发现提案本身与现有规则冲突，**停下来记录到 HANDOFF 的"待确认问题"**，不得自行裁决。
- 任何"顺手优化"都必须单独提交，并在提交信息里写明"非提案范围"。
- 每次提交只做一件事；提交信息格式：`[O2] verify_all: 包装 verify_map`。

---

## 7. 风险与本提案可能错的地方

| 风险 | 触发条件 | 缓解 |
|---|---|---|
| 重命名目录导致目录联接断开、工具找不到文件 | `--apply` 直接执行 | 先 `--dry-run` + sha256 前后比对 + 逐个 rename；失败即回滚 |
| git 仓库被大样本撑爆 | 误提交 99 MB 样本 | `.gitignore` 先落地再 `git add`；提交前 `git status` 人工确认；`git ls-files` 断言无二进制 |
| verify_all 包装层改变旧口径 | 解析汇总行时误判 | 阶段 A 只读 stdout，不改脚本；与 `evidence_m18_verify_all.log` 逐项对拍 |
| ledger 的漂移检测误报太多，被迫放宽 | allowlist 不完善 | 先 `--report-only` 模式运行 3 个里程碑，统计误报类型后再设为阻断；**放宽只允许在 allowlist，不允许改比对逻辑** |
| rules 登记吞掉学习时间 | 一次补 112 条 | 只强制"新规则 + 事故规则"；其余 `unmapped` 计数不阻断 |
| 执行者顺手改判据 | 缺少约束 | AGENTS.md 冻结条款 + 每批独立提交 + 收口清单第 10 条留痕 |
| 并行会话继续复制目录 | 习惯难改 | O1 完成后删除/归档多余副本；status.py 检测"同名目录多份"并 warn |

**本提案可能错的地方（欢迎反驳）**：

1. **对 21 个脚本差异的低估**。我只精读了 `verify_disasm.py`，其余是按参数面和汇总文案统计的；实际迁移工作量可能显著高于估计，且个别脚本可能有我没看到的特殊约定（例如 `verify_fingerprint --all --matrix` 的双模式）。
2. **数字漂移检测的覆盖率有限**。正则抽取"像统计值"的 token 必然有漏报；allowlist 也会随文档增长而失效。它只能降低漂移概率，不能证明"没有漂移"——这一点必须写进工具输出，不能宣称"已根治"。
3. **git 的收益依赖执行方式**。如果执行会话继续复制目录、继续绕过 worktree，那么 O1 只会多出第四份副本，净收益为负。这条需要人在流程上守住，工具保证不了。

---

## 8. 参考来源

### 一手/原始材料（优先）

1. Andrej Karpathy, X 帖文，2025-02-02（推文 ID 反解 `2025-02-02T23:17:15Z`）：<https://x.com/karpathy/status/1886192184808149383>
2. Simon Willison, "Not all AI-assisted programming is vibe coding (but vibe coding rocks)", 2025-03-19：<https://simonwillison.net/2025/Mar/19/vibe-coding/>
3. Simon Willison, "Vibe engineering", 2025-10-07（2026-02-23 更新提到 Agentic Engineering）：<https://simonwillison.net/2025/Oct/7/vibe-engineering/>
4. Simon Willison, "Designing agentic loops", 2025-09-30：<https://simonwillison.net/2025/Sep/30/designing-agentic-loops/>
5. Anthropic, "Claude Code Best Practices"（含 "Give Claude a way to verify its work"）：<https://www.anthropic.com/engineering/claude-code-best-practices>（现指向 <https://code.claude.com/docs/en/best-practices>）
6. METR, "Measuring the Impact of Early-2025 AI on Experienced Open-Source Developer Productivity", 2025-07-10：<https://metr.org/blog/2025-07-10-early-2025-ai-experienced-os-dev-study/>；论文：<https://metr.org/Early_2025_AI_Experienced_OS_Devs_Study-paper.pdf>；2026-02-24 更新：<https://metr.org/blog/2026-02-24-uplift-update/>
7. Peng, Kalliamvakou, Cihon, Demirer, "The Impact of AI on Developer Productivity: Evidence from GitHub Copilot", 2023：<https://arxiv.org/abs/2302.06590>
8. GitHub Blog, "Spec-driven development with AI: Get started with a new open source toolkit", 2025-09-02：<https://github.blog/ai-and-ml/generative-ai/spec-driven-development-with-ai-get-started-with-a-new-open-source-toolkit/>
9. Google Cloud Blog, "How are developers using AI? Inside Google's 2025 DORA report"：<https://blog.google/technology/developers/dora-report-2025/>
10. Stack Overflow, 2025 Developer Survey（AI 章节）：<https://survey.stackoverflow.co/2025/ai/>；新闻稿：<https://stackoverflow.co/company/press/archive/stack-overflow-2025-developer-survey/>
11. Fortune, "AI-powered coding tool wiped out a software company's database in 'catastrophic failure'", 2025-07-23：<https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/>
12. Replit Blog, "Doubling down on our commitment to secure vibe coding"：<https://ld.replit.com/blog/doubling-down-on-our-commitment-to-secure-vibe-coding>

### 研究/行业数据（需标注口径）

13. Veracode, 2025 GenAI Code Security Report：<https://www.veracode.com/wp-content/uploads/2025_GenAI_Code_Security_Report_Final.pdf>；2025-10 更新：<https://www.veracode.com/wp-content/uploads/October-2025-GenAI-Code-Security-Report-Update.pdf>（厂商基准测试，80 个任务 / 100+ 模型）
14. GitClear, "Write-Only Mode: 2026 AI Code Quality Research"：<https://www.gitclear.com/write_only_mode_ai_research>；汇总页：<https://www.gitclear.com/recent_ai_developer_productivity_code_quality_research>（厂商遥测，相关性非因果）
15. Spracklen et al., "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs", USENIX Security 2025；2026 复现：<https://arxiv.org/pdf/2605.17062v3>；CSA 研究简报：<https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/>
16. "Configuring Agentic AI Coding Tools: An Exploratory Study"（2,853 个仓库，AGENTS.md 采用）：<https://arxiv.org/html/2602.14690v1>
17. Addy Osmani, "Agentic Engineering Glossary"（70% 问题条目，观点性）：<https://addyosmani.com/agentic-engineering/>

### 项目内文件（一手）

18. `2026-11-15\m3-task-card\work\pack03\CHARTER.md` / `PROGRESS.md` / `CHANGELOG.md` / `RE-ROADMAP.md`
19. `2026-11-15\m3-task-card\work\outputs\TASK_m18_ilflow.md`（§1.1 中断半成品、§1.2 空对空 PASS 三条硬伤、R119）
20. `2026-11-15\m3-task-card\work\outputs\TASK_m17_dotnet.md`
21. `2026-11-15\m3-task-card\work\rekit\cli.py`、`mcp.py`
22. `2026-11-15\m3-task-card\work\tests\verify_disasm.py`
23. `2026-11-15\m3-task-card\work\evidence_m18_verify_all.log`、`evidence_m12_ledger.json`、`m9_sample_manifest.json`

---

## 附录 A：接口草案

### A1 `verify_all` 与 `summary.json`

```json
{
  "schema": "verify_summary/1",
  "run_id": "20261116T031500Z",
  "started_at": "2026-11-16T03:15:00Z",
  "duration_s": 0.0,
  "python": "3.14.x",
  "suites": [
    {"name": "map", "verdict": "PASS", "cases": 0, "pass": 0, "fail": 0,
     "env_skip": 0, "reason_code": null, "json": "work/verification/<run_id>/map.json"}
  ],
  "pytest": {"passed": 0, "failed": 0, "skipped": 0, "exit": 0},
  "verdict": "PASS",
  "exit": 0
}
```

命令行约定：

```
python tests/verify_all.py [--only a,b] [--list] [--json PATH] [--no-pytest]
末行格式固定：VERDICT: PASS|FAIL suites=21 pytest=554 exit=0
```

### A2 `vharness` 最小 API

```python
class Suite:
    def __init__(self, name: str, requires: list[str] | None = None): ...
    def case(self, id: str, expected, actual, detail: str = "") -> None: ...
    def require_nonempty(self, n: int, what: str) -> None: ...   # n==0 => FAIL empty_comparison
    def selfproof(self, fn) -> None: ...                        # 必须让被测逻辑失败一次
    def emit(self, path: str | None = None) -> dict: ...
    def exit_code(self) -> int: ...                              # 0/1/2
```

### A3 `numbers.json` 与检查规则

```json
{"schema":"numbers/1",
 "items":[{"id":"...","value":0.0,"unit":"ratio|count|pp|bytes",
           "scope":"...","status":"measured|lower_bound|unavailable|estimated",
           "measured_at":"YYYY-MM-DD","command":"...","sample_set":"...",
           "milestone":"M10","notes":"..."}],
 "allowlist":["2026","R119","554"]}
```

`check` 的判定顺序：先 allowlist → 再精确匹配 `id.value` → 再匹配 render 后的文本 → 都不中则 `unregistered_number`。

### A4 `rules.json`

```json
{"schema":"rules/1",
 "items":[{"id":"R119","title":"...","statement":"...","scope":["ilflow"],
           "added_in":"M18","status":"enforced|unmapped|reserved|retired",
           "enforcement":{"type":"framework","ref":"tests/vharness.py:require_nonempty"}}]}
```

### A5 `AGENTS.md` 骨架（8 节，≤150 行）

```
1. 这个仓库是什么（3 行）
2. 硬约束（4 条，原文）
3. 当前里程碑与下一条命令（指向 HANDOFF）
4. 常用命令（pytest / verify_all / ledger / rules / samples / status）
5. 目录地图（真实路径 + PATH_MAP）
6. 环境怪癖（LC_ALL=C、objdump 注入、MSI、中文路径、junction）
7. 禁止事项（改判据、删证据、推算入账、并跑写日志、复制目录）
8. 证据与提交约定（命名、格式、每次一件事）
```

### A6 `HANDOFF.md` 模板

```markdown
# HANDOFF · <日期> <会话标识>
## 1. 当前进度
## 2. 未完成清单（文件 / 行号 / 下一条命令）
## 3. 已否决方案及原因
## 4. 待确认问题（需人决定）
## 5. 本次新增/变更的证据文件
## 6. 下一位的第一条命令
```

### A7 `samples_manifest.json`

```json
{"schema":"samples/1",
 "files":[{"path":"tests/samples/foo.exe","sha256":"...","size":0,
           "format":"pe|elf|dotnet","source":"...","license":"...",
           "redistributable":true,"local_only":false,
           "first_used_in":"M9","notes":""}]}
```

### A8 `status.py` 输出上限（20 行）

```
repo: pack@<branch> <commit> dirty=<n>
milestone: M18 (ilflow)   next: <HANDOFF §6>
verify_all: PASS 21/21 pytest=554 at 2026-11-16T03:15Z
ledger: drift=0 unregistered=0 (n/a if not installed)
rules: total=112 enforced=K unmapped=M gaps=7
samples: 35 files, verified=35, local_only_missing=0
paths: pack dirs ok=4/4
handoff: lines=<n> incomplete=no
```

---

## 附录 B：本次核查命令与产物

### B1 过程材料

| 文件 | 内容 |
|---|---|
| `work\collect_metrics.py` | 只读指标采集脚本 |
| `work\metrics.json` | 全部量化指标（25 模块 / 16,939 行 / 21 脚本 / 226,885 字节文档 / 112 规则 等） |
| `work\project_survey.md` | 项目工作方式勘察记录（含原文摘录与出处） |
| `work\research_sources.md` | 公开来源清单、关键引文、证据强度标注 |

### B2 复跑命令

```powershell
# 1) 指标
python "2026-11-16\vibe-coding-review\work\collect_metrics.py"

# 2) 当前基线（本提案未执行，供 B0 使用）
python -m pytest "2026-11-15\m3-task-card\work\tests" -q
python "2026-11-15\m3-task-card\work\tests\verify_disasm.py" --all
python "2026-11-15\m3-task-card\work\tests\verify_fingerprint.py" --all --matrix

# 3) 目录名与副本核查（在 Windows PowerShell 下）
python "2026-11-16\vibe-coding-review\work\collect_metrics.py"
# pack 的真实目录名见 work\metrics.json 的 pack_dirs_on_disk 字段
```

### B3 未验证项（必须在 B0 复核）

1. `pytest` 实际 passed 数（文档记录 554，本次未跑）。
2. `tmp\pack` 的 5 模块快照是否能被 Python 导入（未运行）。
3. 21 个验证脚本中 20 个的判据细节（仅精读 `verify_disasm.py`）。
4. Windows 之外平台的可移植性（未评估）。

---

## 9. 实际落地校准（v0.2，2026-11-16）

> 本节只做**评估与修订**，不改 `rekit` 代码。证据来自实际文件：`tests\vharness.py`、`tests\verify_expr.py`、
> `pack\tools\verify_gate.py`、`pack\tools\status.py`、`work\outputs\NUMBERS_LEDGER.md`、`pack\rules.json`。
> 原则：不沿用 v0.1 写作时的「门禁是空白」假设，按实际证据重排。

### 9.1 P0 项落地状态重排

| 提案项 | v0.1 假设 | 实测证据 | 状态 | 还差什么 |
|---|---|---|---|---|
| **O1 单一事实源 / 回滚** | git 未初始化、目录名损坏、`01/02` 缺失 | `01/02` 已从 `tmp` 复制恢复；`status.py` 仍报 4/7 目录 mojibake；`pack` 仍无 `.git` | **未落地（约 20%）** | 目录改名（维护窗口）+ `git init` + 基线 tag |
| **O2-Step1 `vharness.py`** | 需新建 | 已建；21 suite / 63 检查点；实测 `suites=21 legacy_pass=21 pass=21 fail=0`；已实现 `empty_expectation` / `empty_comparison` / `selfproof_missing` / `env_missing` | **已落地（100%）** | 见 9.2 的语义加固 |
| **O2-Step2 `verify_all.py`** | 单一总入口 + pytest + summary.md + LATEST | **无 `verify_all.py`**；实际是两套半成品：`vharness --all`（无 pytest、无 summary.md/LATEST）与 `pack\tools\verify_gate.py`（有 pytest、summary.json、latest 副本，但不消费 vharness） | **半落地（约 40%）** | 合并为一条入口：`verify_gate` 委托 `vharness --json`，再跑 pytest，统一 schema 与退出码 |
| **O2-Step3 两阶段迁移** | 先包装、后逐脚本迁移 | vharness 仍靠解析旧脚本 stdout 的 `检查=N PASS=N FAIL=N`；6 个脚本已补自证，但那是「脚本侧改造」，不是「迁移到 vharness API」 | **半落地（约 50%）** | 阶段 B 未开始：逐脚本改用 `Suite.case/require_nonempty/selfproof`，旧文本契约退场 |
| **O2-Step4 `evidence_index.py`** | 证据索引 | 文件不存在 | **未落地（0%）** | 建索引或明确取消 |
| **O3 交接协议** | 需新建 | `AGENTS.md` / `PATH_MAP.md` / `HANDOFF.md` / `status.py` 均已建 | **已落地（约 80%）** | `status.py` 目前只对 HANDOFF 硬失败；git/ledger/latest/mojibake 全是 `[info]/[WARN]`，会出现「PASS 但权威已过期」 |
| **O4 数字单一事实源** | 需建 ledger + 漂移检测 | `NUMBERS_LEDGER.md` 存在，但标题是 **M13-patch**，无 M18 节；页首声明唯一权威是 `evidence_m13_ledger.json` | **半落地（约 50%）** | 补 M18 节、重生成权威 JSON、加「文档↔JSON」漂移检查 |
| **O5 规则可执行化** | 需建 registry + 收敛 | `rules.json` 119 条；R33–R119 **87 条已收敛为规范定义**；9 条撞号已裁决（**0 条真撞号**）；21 条多写法已唯一化 | **基本落地（约 85%）** | 8 项待定（覆盖 14 个规则号），见 `batch4\human_decisions.md` |

**结论修正**：v0.1 把「验证门禁」整体当空白，这是错的。实际是 **Step1 已满、Step2/3 半、Step4 空**；真正的缺口不是「有没有门禁」，而是「两套门禁语义不一致」。

### 9.2 这套做法暴露出的、v0.1 没预见的风险与反模式

1. **门禁双实现 → 语义分叉（最严重，已有实证）**
   `verify_gate.py` 在 B2 报 21/21 PASS，随后 `vharness` 首跑抓出 6 个「从未有可失败自证」的失败。同一棵树、同一批脚本，两套门禁给出不同结论。原因是前者只看 `exit=0 + 非空输出`，后者才看「证据是否可失败」。**反模式：把「进程成功」当成「证据成立」。**
2. **`selfproof` 会退化成布尔证书**
   `vharness.Suite.selfproof(fn)` 只要求「调用过且返回真」。`lambda: True` 即可通过。这正好复刻了 R74/R84 已经记录过的「自证自证」问题。**修法**：自证必须产出可审计工件——注入 ID、未注入时基线、注入后观察到的失败行、时间戳，落进 suite JSON；只认工件，不认布尔。
3. **只防「分母为 0」，不防「分母为 1」**
   `require_nonempty` 只要求 `n>0`。一个只有 1 个对象的 universe 仍可 PASS。**修法**：每个 suite 声明 `min_cases`/`min_denominator`，低于下限 FAIL（对应 R14 的「计数下限」）。
4. **外部 oracle 的可用性没有统一成硬约束**
   `verify_expr` 现在做对了：objdump 不可用直接 FAIL。但 `vharness` 不知道某个 suite 是否真的用了外部 oracle；其他 suite 仍可退化成 Ghidra/同类工具互证而 PASS。**修法**：SUITES 增加 `oracle=` 声明；`weak_only` 记 `DEGRADED`，不得计 PASS。
5. **「残差单列」可能变成洗白通道**
   任何无法解释的差额都能标成 residual，既不计 FAIL 也不计 PASS。单列本身不是错，错在**没有上界、没有落盘、没有禁止它污染已公布数字**。见 9.3。
6. **`status.py` 默认绿灯**
   它把 git/ledger/latest/mojibake 都当 `[info]/[WARN]`，只有 HANDOFF 缺失才 FAIL。于是「权威 JSON 过期 + 无 git + 目录损坏」仍打印 `VERDICT: PASS`。**修法**：区分 blocking / advisory；`latest` 的 verdict=FAIL 或 ledger 过期必须 blocking。
7. **并发写冲突（跨会话）**
   `vharness`/`verify_gate` 的 run_id 是秒级时间戳，且都写 `work\verification\`；本工作树明确有另一个会话在用。**修法**：run_id 加 pid/uuid，加锁文件，检测到并发运行直接 exit=2。
8. **文本汇总契约脆弱**
   `vharness` 用正则 `检查=N PASS=N FAIL=N` 解析旧脚本 stdout。格式漂移会 fail-closed（这点是对的），但它也奖励「打印一行漂亮汇总」。**修法**：阶段 B 后改为每 suite 输出 JSON，文本只作人读镜像。

### 9.3 第 6 条残差（objdump 线性扫描 vs CFG 可达子集）怎么处理才算诚实

**结论：可以先单列，但必须同时满足 4 个条件；任一不满足就必须归因后才能进总账。**

条件（缺一不可）：

1. **结构性原因可命名且可测**：线性全扫 vs CFG 可达子集；不是「不知道」。
2. **不污染已公布数字**：残差不进入任何已公布比率的分子或分母。M5 的 14 项数字（全二进制 10 + 抽样 4）已逐项核对相等，说明当前口径下残差未进分母。
3. **机器落盘**：样本 / 函数 / 地址 / 条数 / objdump 版本写进证据 JSON；只在 stdout 打印不算「已记录」。
4. **有上界**：给出每个样本的残差上界；上界变化触发复核。

**触发必须归因的判据**（任一成立）：

- 任何比率改用「函数域全量 / objdump 分母」；
- 残差与某个已公布分母相交；
- 残差上界随样本或工具版本变化。

归因时至少三分：`data_in_text`（.text 里的数据表）/ `cfg_not_reached`（可达性差异）/ `decode_difference`（解码差异）；三分之后才允许进总账。

**当前动作**：M5 数字口径是 expr 可达子集，残差不影响，因此**单列是诚实的**；但要把 stdout 残差升级为 `evidence_*_expr_residual.json`，并在总账 M5 节加一句「残差单列、不入分母、上界见 JSON」。

### 9.4 剩余待办优先级（含串行/并行）

| 优先级 | 事项 | 理由 | 串/并行 |
|---|---|---|---|
| **P0** | **总账链路**：补 M18 节、重生成权威 JSON、加漂移检查 | 所有已公布数字都指向它；权威过期是**正确性风险**，不是整洁问题。M18 已收口但总账停在 M13-patch，任何人引用都会引到旧值 | **必须串行**（单一写者）；先做 |
| **P0** | **门禁语义统一**：`verify_gate` 委托 `vharness --json`；加 `min_denominator`、`oracle` 声明、自证工件；`status.py` 消费 `latest` verdict + ledger 新鲜度 | 6 个假 PASS 证明「exit=0 不等于证据成立」；这是所有后续结论的安全网 | 与总账可并行（不同文件），但两者都写 `tools/` 与 `work/`，建议同会话串行；跨会话禁止同时跑验证 |
| **P1** | **目录改名 + `git init` + 基线 tag** | 目录名损坏会让路径引用不可靠；git 是回滚前提。必须在 P0 之后做，基线才能包含修复 | **必须串行**，且需维护窗口（另一会话在用）；改名是路径级破坏性操作，先冻结 |
| **P2** | **8 项规则史待定**（R49/R93/R110 材料不足；R102-103/R67/R95 口径；R33-35、R72/87/88/89 写法） | 不阻塞代码与数字；但需人给参数/清单/裁决 | **可并行**，随时可做；不依赖 P0/P1，也不应占用维护窗口 |

**顺序理由**：先修「真假」→ 再修「证据可信度」→ 再建立「可回滚基线」→ 最后处理「需人裁决」。
**可并行**：总账链路 ∥ 规则史 8 项（不同文件、不同人）。
**必须串行**：目录改名（路径级）、git 基线（依赖改名）、总账写入（单一权威）、验证运行（run_id/日志目录冲突）。

### 9.5 对 v0.1 §6.1 批次划分的修订

- 原批次把 O1（git/目录）排第一。**修订为最后**：在权威数字和门禁语义未统一前建立基线，等于把过期状态冻结进 git。
- 原批次把 O2 当「从零建门禁」。**修订为「合并两套门禁 + 语义加固」**：Step1 已完成，不要再写第二个 harness。
- 新增一条前置：**任何门禁改造必须先用「6 个假 PASS」做回归样本**，改造后这 6 个必须仍然 FAIL（除非已补真自证），否则说明语义被放松了。

