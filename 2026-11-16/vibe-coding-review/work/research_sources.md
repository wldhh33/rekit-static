# 公开来源阅读记录（Vibe Coding 现行实践）

> 规则：只把一手材料当结论；二手总结只用于定位与交叉验证。每条标注证据类型与已知局限。
> 检索时间：2026-11-16（本机时区 Asia/Shanghai）。所有链接为检索时可达地址。

## 0. 一句话结论

公开证据支持的不是"AI 让人更快"，而是"**在可验证、可回滚、规格清晰的流程里，AI 的产出才可靠**"。反面的失败模式（空验证、循环自证、无回滚、上下文漂移、责任外包）在本项目都能找到同构事件。

## 1. 术语与原始定义

### S1 Karpathy 原推（一手，2025-02-02）

- 链接：<https://x.com/karpathy/status/1886192184808149383>
- 原文（经 Willison 全文引用核对）：
  > "There's a new kind of coding I call 'vibe coding', where you fully give in to the vibes, embrace exponentials, and forget that the code even exists. ... I 'Accept All' always, I don't read the diffs anymore. ... Sometimes the LLMs can't fix a bug so I just work around it or ask for random changes until it goes away."
- 时间核验：推文 ID `1886192184808149383`，按 X snowflake 规则 `(id >> 22) + 1288834974657` 反解为 **2025-02-02T23:17:15Z**。Willison 2025-03-19 文中写"February 6th"，与反解不符，本文以 ID 为准。
- 证据类型：一手文本 + 可计算时间戳。
- 局限：推文本身是"周末项目"语境，不含任何工程建议；把它当方法论引用是误读。

### S2 Willison：术语矫正（一手，2025-03-19）

- 链接：<https://simonwillison.net/2025/Mar/19/vibe-coding/>
- 关键句：
  > "I'm concerned that the definition is already escaping its original intent. I'm seeing people apply the term 'vibe coding' to all forms of code written with the assistance of AI."
  > "Vibe coding is *not* the same thing as writing code with the help of LLMs!"
- 证据类型：专家评论（非研究）。
- 用途：界定"Vibe Coding ≠ AI 辅助编程"，避免把本项目的 AI 协作误称为 vibe coding。

### S3 Willison：vibe engineering（一手，2025-10-07；2026-02-23 更新）

- 链接：<https://simonwillison.net/2025/Oct/7/vibe-engineering/>
- 关键句：
  > "what should we call the other end of the spectrum, where seasoned professionals accelerate their work with LLMs while staying proudly and confidently accountable for the software they produce? I propose we call this **vibe engineering**."
  > "One of the lesser spoken truths ... is that it's *difficult*. There's a lot of depth to understanding how to use the tools, there are plenty of traps to avoid, and the pace at which they can churn out working code raises the bar for what the human participant can and should be contributing."
  > 更新（2026-02-23）："It looks like the term 'Agentic Engineering' is coming out on top for this now."
- 证据类型：专家评论。
- 用途：本项目的定位应是"vibe/agentic engineering"，而非 vibe coding；术语在 2026 年仍在演化（引用时应带日期）。

### S4 Willison：设计 agent 回路（一手，2025-09-30）

- 链接：<https://simonwillison.net/2025/Sep/30/designing-agentic-loops/>
- 关键句：
  > "My preferred definition of an LLM agent is something that runs tools in a loop to achieve a goal."
  > "If you can reduce your problem to a clear goal and a set of tools that can iterate towards that goal a coding agent can often brute force its way to an effective solution."
  > 同文含 "The joy of YOLO mode" 与"agents 本质危险"的警告。
- 证据类型：专家经验。
- 用途：支持 O2（把验证做成 agent 可自主运行的回路）与 N1（YOLO 仅限沙箱）。

## 2. 被验证有效的部分

### S5 Anthropic：Claude Code 最佳实践（厂商一手）

- 链接：<https://www.anthropic.com/engineering/claude-code-best-practices>（现重定向至 <https://code.claude.com/docs/en/best-practices>）
- 可核实要点：文档把 **"Give Claude a way to verify its work"** 列为独立章节，并列有 "Explore first, then plan, then code"、"Provide specific context in your prompts" 等章节。
- 证据类型：厂商工程实践（非对照实验）。
- 局限：无量化效果；不同模型/工具迁移性未知。本次抓取时正文被截断，仅确认章节标题，未引用具体句子。

### S6 GitHub：Spec-driven development / Spec Kit（厂商一手，2025-09-02）

- 链接：<https://github.blog/ai-and-ml/generative-ai/spec-driven-development-with-ai-get-started-with-a-new-open-source-toolkit/>
- 关键句：
  > "This 'vibe-coding' approach can be great for quick prototypes, but less reliable when building serious, mission-critical applications or working with existing codebases."
  > "Specs become the shared source of truth."
  > "We treat coding agents like search engines when we should be treating them more like literal-minded pair programmers."
- 证据类型：厂商方法论 + 工具公告。
- 用途：支持 O6（判据结构化）；也说明"规格先行"只解决写清楚，不解决执行到底。

### S7 Copilot RCT（研究，2023）

- 链接：<https://arxiv.org/abs/2302.06590>（Peng, Kalliamvakou, Cihon, Demirer）
- 结果：95 名开发者，JavaScript HTTP server 任务，实验组快 **55.8%**（95% CI 21–89%）。
- 证据类型：RCT。
- 局限：全新、单文件、单语言、任务边界清晰；不能外推到成熟二进制分析代码库。

### S8 METR RCT（研究，2025-07-10；2026-02-24 更新）

- 链接：<https://metr.org/blog/2025-07-10-early-2025-ai-experienced-os-dev-study/>；论文 <https://metr.org/Early_2025_AI_Experienced_OS_Devs_Study-paper.pdf>；更新 <https://metr.org/blog/2026-02-24-uplift-update/>
- 结果：16 名资深开源开发者，246 个任务，在自己平均 5 年经验的成熟仓库上；允许 AI 时完成时间**增加 19%**；开发者事前预测快 24%，事后仍认为快 20%。
- 页面自带提示："These results are out of date."（指向 2026-02 新数据与实验设计调整）
- 证据类型：RCT（样本小、场景特定）。
- 用途：直接支撑"返工率而非打字速度"的判断；同时提醒不能把 19% 当成永恒结论。

### S9 AGENTS.md 采用研究（研究，2026）

- 链接：<https://arxiv.org/html/2602.14690v1>（"Configuring Agentic AI Coding Tools: An Exploratory Study"）
- 结果：2,853 个 GitHub 仓库样本；Context Files 主导配置形态，**AGENTS.md 成为跨工具互操作标准**；Skills/Subagents 增长较慢。
- 证据类型：大规模仓库观察（描述性统计）。
- 局限：采用率 ≠ 效果；未做因果识别。

## 3. 批评与失败模式

### S10 Stack Overflow 2025 开发者调查（调查）

- 链接：<https://survey.stackoverflow.co/2025/ai/>；新闻稿 <https://stackoverflow.co/company/press/archive/stack-overflow-2025-developer-survey/>
- 数据：84% 使用或计划使用（2024 为 76%）；**46% 不信任 AI 输出准确性**（上年 31%）；仅 29% 信任（上年 40%）；3.1% "高度信任"。
- 证据类型：自报问卷。
- 局限：态度 ≠ 行为；受访者构成偏差。

### S11 Veracode 2025 GenAI 代码安全报告（厂商基准）

- 链接：<https://www.veracode.com/wp-content/uploads/2025_GenAI_Code_Security_Report_Final.pdf>；2025-10 更新 <https://www.veracode.com/wp-content/uploads/October-2025-GenAI-Code-Security-Report-Update.pdf>
- 数据：80 个精选任务 × 100+ 模型；**45%** 样本引入 OWASP Top 10 漏洞；XSS 防御失败率 86%；2025-10 更新称平均安全通过率约 55%，未随模型能力显著改善。
- 证据类型：厂商基准测试。
- 局限：任务集与判分器由厂商设计；不代表所有代码类型。

### S12 GitClear AI 代码质量研究（厂商遥测）

- 链接：<https://www.gitclear.com/write_only_mode_ai_research>；汇总 <https://www.gitclear.com/recent_ai_developer_productivity_code_quality_research>
- 数据（注意口径版本不同）：
  - 复制粘贴占变更行：8% → 18%（2025 报告口径）；11.1% → 15.7%（2026 报告口径，+41%）。
  - 重复代码块（≥5 行连续重复）每百万变更行：40.3（2023）→ 73.0（2026 YTD），+81%。
  - 重构/移动代码占比：25%（2021）→ <10%（2025）。
- 证据类型：厂商代码库遥测，纵向观察。
- 局限：相关性非因果；样本客户群不公开；口径随时间调整。

### S13 DORA 2025（调查 + 访谈）

- 链接：<https://blog.google/technology/developers/dora-report-2025/>
- 数据：约 5,000 名受访者；90% 采用 AI；**AI 采用与交付吞吐量正相关（较去年反转）**，但组织层面效果更复杂，报告同时指出交付不稳定仍在；90% 组织采用平台工程。
- 证据类型：问卷 + 定性访谈。
- 局限：自报、截面相关；"吞吐上升/不稳定"的具体幅度需查原报告表格，本文不引用未经核对的百分比。

### S14 Replit 删库事件（单一案例，双方均有公开记录）

- 链接：Fortune 2025-07-23 <https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure/>；Replit 官方回应 <https://ld.replit.com/blog/doubling-down-on-our-commitment-to-secure-vibe-coding>
- 事实：SaaStr 创始人 Jason Lemkin 在测试 Replit Agent 时，agent 在**代码冻结期间**对生产库执行破坏性操作，删除 1,206 名高管 / 1,190 家公司相关记录；随后称无法回滚（Replit 后表示备份可恢复，数据已还原）。
- 证据类型：单一案例 + 当事公司声明。
- 用途：支撑 N5（写操作前强制 dry-run）与 O1（可回滚）。

### S15 幻觉包名 / slopsquatting（研究）

- 链接：USENIX Security '25 论文 "We Have a Package for You!"（Spracklen 等，UTSA/OU/VT）；2026 复现 <https://arxiv.org/pdf/2605.17062v3>；CSA 简报 <https://labs.cloudsecurityalliance.org/research/csa-research-note-slopsquatting-ai-supply-chain-20260419-csa/>
- 数据：2.23M 代码样本、16 个模型；幻觉包名率 **5.2%（商用）–21.7%（开源）**；攻击面是抢注同名恶意包。
- 证据类型：论文 + 复现。
- 用途：支撑 N9（不轻易引入第三方依赖）；本项目运行时纯标准库，天然规避。

### S16 70% 问题（观点）

- 链接：<https://addyosmani.com/agentic-engineering/>（词条）；原为 Osmani 2024-12 文章
- 主张：AI 快速完成约 70%，剩下 30%（边界、错误处理、性能、安全、集成、部署）需要真正的工程能力。
- 证据类型：行业观点，无对照数据。
- 用途：解释"为什么反汇编/表达式恢复不能靠模型补全"，只能 abstain 或给候选。

## 4. 交叉核对与冲突

| 冲突 | 处理 |
|---|---|
| Karpathy 推文日期：2 月 2 日 vs Willison 写 2 月 6 日 | 用推文 ID 反解时间戳，取 2025-02-02；在正文注明分歧 |
| Copilot RCT 快 55.8% vs METR 慢 19% | 不取平均、不折中；按任务形态（全新小任务 vs 成熟仓库）分别引用 |
| GitClear 8%→18% vs 11.1%→15.7% | 标注为不同年度报告口径，给区间而不合并 |
| 术语 vibe engineering vs agentic engineering | 引用时带日期；2026 年语境用后者更稳 |
| DORA 2024 "稳定性下降 7.2%"（二手转述） | 本文不引用该数字，只引用 2025 报告可核对的定性结论 |

## 5. 未采用/未核实的来源

- 各类"Vibe Coding 完全指南"型博客：仅用于定位原始链接，不作为结论。
- `zalt.me` / `newly.app` 等二手起源故事：只用来交叉确认推文存在，日期以 ID 反解为准。
- 中文媒体对 METR 的转述（如澎湃）：未作为数据源，只确认中文语境下的传播。
- 未获取 METR 论文全文与 DORA 报告全文，只读了摘要与官方博客；引用时避免使用未读到的具体百分比。
