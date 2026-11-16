# 规则事实源缺口报告（R01–R119）

> 生成：`2026-11-16\vibe-coding-review\work\batch3\mine_rules.py`（机器生成，数字可复跑）
> 配套产物：`pack\rules.json`（登记表）、`rules_coverage.json`（覆盖统计）、`rules_extracted.json`（逐候选）

## 0. 一句话结论

R01–R119 **全部 119 个编号都能在文档里找到出处**，但只有 R01–R32 有规范定义文件；R33–R119 的定义散落在 CHANGELOG 的「新增规则」行与 PROGRESS 的「规则：」行里，属于**日志即规范**。因此本表能给出「摘录」，不能给出「权威定义」。

## 1. 覆盖统计

| 状态 | 条数 | 含义 |
|---|---|---|
| corroborated | 47 | ≥2 个源文件有相近表述 |
| single_source | 39 | 只有 1 处出处 |
| multi_candidate | 21 | 多处措辞不同但相近，需抽查 |
| suspect | 9 | 多处表述相差极大，疑撞号 |
| terse | 3 | 摘录 <15 字，需补上下文 |

完全无出处的编号：无

## 2. 结构性缺口（比单条缺句更要紧）

1. `pack\02_规则库\规则库_R01-R32.md` 只到 R32，之后 87 个编号没有规范文件。
2. R33–R119 的定义只存在于**当天的工作日志**：CHANGELOG 的「新增规则 R##–R##：...」行、PROGRESS 的「规则：...」行。这是「日志即规范」，不是规则库。
3. 所以「补历史」不是补一张表，而是**把日志提炼成规则**：需要一次人工收敛，grep 拼不出来。
4. 口径警告：早期采集 `metrics.json` 报 `rules.gaps=[9,10,11,14,17,20,26]`，经复核是**假缺口**——规则库原文写 `R9` 而非 `R09`，旧正则只匹配补零写法。同一事实换一种统计口径就得出不同结论，所以本报告把口径写进 `pack\rules.json` 的 `policy` 字段。

## 3. 只在任务卡能查到的编号（置信度最低）

无 —— 所有编号至少在 CHANGELOG/PROGRESS/规则库 之一出现。

## 4. 疑似撞号（suspect，需人工裁决）

| 编号 | 当前摘录（源） | 另一处表述（源） | 相似度 |
|---|---|---|---|
| R18 | 工具写入权限分层：Bash 与 Write/Edit 工具的权限通道不同，root 属主文件写入会被拒（`规则库_R01-R32.md:41`） | + verify 模板，归档 artifacts/2026-11-10/（`RE-ROADMAP.md:68`） | 0.11 |
| R19 | 内联吞噬调用链：-O2 下小函数默认内联，call 从调用方消失（`规则库_R01-R32.md:46`） | noinline 纪律）+ 编译器把 set1(x)+set1(y)+add_pd 合并成标量 vaddsd 再广播（指（`RE-ROADMAP.md:69`） | 0.07 |
| R21 | 传参双轨：整型与浮点寄存器编号独立计数（rdi..r9 与 xmm0..xmm7 互不占位（`规则库_R01-R32.md:50`） | + 3 份证据日志，归档 artifacts/2026-11-11/（`RE-ROADMAP.md:69`） | 0.08 |
| R25 | 锚点唯一性检查：split 外部工具输出前先确认锚点串只出现一次（`规则库_R01-R32.md:63`） | 加固（verify_cli.py anchor_line() 前置锚点唯一断言 + --selftest 重复/缺失锚点（`PROGRESS.md:46`） | 0.14 |
| R27 | 列宽差异用 \s+：4 位 hint 与 8 位 RVA 的填充空格数不同，对齐列一律 \s+（`规则库_R01-R32.md:67`） | 验证脚本三板斧：锚点唯一性/正则边界对齐列语义/列宽 \s+（`PROGRESS.md:45`） | 0.16 |
| R48 | 补强）：“确定边为 0”原来把真零（minidll 全是单条 ret 桩，确实无控制流）和标签性零（dyn_pie 有 （`PROGRESS.md:68`） | 落地更彻底，两个 0 不再共用一句话（`CHANGELOG.md:23`） | 0.11 |
| R75 | 已定「硬不变量须有独立来源」，本轮把「期望值来源」也纳入：读 objdump 注释或复用被测解析等于自证（`CHANGELOG.md:79`） | 先怀疑校验器，确认校验器三处修复（空比对/偏移/缺表）后该差异仍在，才判为实现缺陷（`CHANGELOG.md:107`） | 0.10 |
| R102 | 推算值不得进总账，总账只收实测（可复现命令 + 机器快照 + 逐样本 sha256），推算只能出现在过程文档且必须标注前（`PROGRESS.md:264`） | 任何推算值不得进入总账（`CHANGELOG.md:96`） | 0.20 |
| R110 | 三档归因不合并、after_object 只表示邻接（`PROGRESS.md:306`） | 引用点归因三档（首地址/对象内部/对象之后窗口）不得合并（`CHANGELOG.md:103`） | 0.19 |

## 5. 摘录过短（terse）

| 编号 | 摘录 | 出处 |
|---|---|---|
| R33 | GT 标注须独立证据复核 | `2026-11-15\m3-task-card\work\pack03\PROGRESS.md:58` |
| R50 | 弱参照只判可机械项并逐条归因 | `2026-11-15\m3-task-card\work\pack03\CHANGELOG.md:29` |
| R52 | 段覆盖前缀不得展开为绝对地址 | `2026-11-15\m3-task-card\work\pack03\CHANGELOG.md:29` |

## 6. 建议动作（给源码会话 / 人工）

1. **不要**把 `rules.json` 的 statement 直接当规范定义贴进 `02_规则库`——它们是日志摘录，可能截断。
2. 先裁决 §4 的 9 条 suspect（撞号风险最高），再抽查 §1 的 21 条 multi_candidate。
3. §3 的编号若任务卡也不够，只能回溯聊天记录；在此之前标 `canonical=false`。
4. 收敛后新建 `pack\02_规则库\规则库_R33-R119.md`，并在 `rules.json` 每条加 `canonical: true/false`。

## 7. 复跑

```powershell
python "2026-11-16\vibe-coding-review\work\batch3\mine_rules.py"
```
