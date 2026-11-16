# 白银任务（2026-11-14 收口日，降档从轻）：rekit M1 统一 CLI + 终对账 + R25 加固

> 背景：11-13 验证脚本 3 返工触发降档条款 → 今日从轻：不新增解析能力，只做**统一入口、
> 对账收口、验证脚本加固**三件事。M1 十二项清单的最后一项（CLI）今日补齐。

## 任务内容

1. **统一 cli.py**：argparse 入口 `python3 -m rekit.cli <file>`，magic 字节自动识别
   ELF（`\x7fELF`）/ PE（`MZ` + e_lfanew→`PE\0\0` 双重校验）并分发到 elf/pe 渲染通道；
   `--format` 可强制指定；识别失败友好报错（stderr 一行 + 非零退出码，禁止 traceback）。
2. **终对账**：CHARTER M1 12 项逐条 ✅ 并附证据（代码行 / 测试断言 / 日志），
   产出 M1_CLOSEOUT_AUDIT.md；超额项（重定位 / checksec / fixtures 10 样本 / 断言数）
   回写 CHARTER，走 CHANGELOG 记录。
3. **R25 加固**：当日验证脚本内嵌**锚点唯一性自检**——凡从文本中提取字段的锚点，
   提取前必须断言锚点出现次数 == 1；并提供 `--selftest` 负测试：喂入含重复锚点的
   构造输入，脚本必须显式报错退出（而非静默取错段）。

## 验收标准（执行前写定，不许放宽）

- **D1 自动识别全量通过**：10 个 fixtures 逐一 `python3 -m rekit.cli <f>`，
  全部 exit 0；且每个 fixture 的 cli 输出与对应模块直调
  （`python3 -m rekit.elf <f>` 或 `python3 -m rekit.pe <f>`）**逐字节一致**（diff 证
  据）。识别路由正确性由"PE 样本经 cli 得到 PE 输出而非 ELF 崩溃"证伪点保证。
- **D2 负样本友好降级**：纯文本文件、MZ-无-PE-签名的构造文件，均输出一行可读错误
  到 stderr 且 exit code ≠ 0，stdout 无 traceback 字样。
- **D3 终对账完整**：M1_CLOSEOUT_AUDIT.md 覆盖 CHARTER M1 12 项，每项有可点击/可
  复核的证据；超额项已回写 CHARTER 且 CHANGELOG 有对应条目（日期|旧→新|原因|影响）。
- **D4 锚点自检可证伪**：verify_cli.py `--selftest` 对重复锚点输入显式失败（exit ≠ 0
  且报错信息含锚点名）；正常模式下对每个用到的锚点先 assert 唯一。
- **D5 回归常绿 + 断言入库**：`python3 -m pytest tests/` 全过（原 49 + 新增 ≥6 条
  test_cli.py 断言，覆盖自动识别/负样本/format 覆写/cli≡模块输出四类）。

## 降档从轻约束（纪律）

- 核心代码目标 0 返工；验证脚本若返工，如实记录（已内嵌锚点自检，理论上应免 R25–R27 坑）。
- 预算：扩展型 1–2 min 纯执行 + 对账分析；不新增解析功能（留给 M2+）。
