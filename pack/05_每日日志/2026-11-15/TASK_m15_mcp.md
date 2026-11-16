# 白银任务：rekit M1.5 MCP 化 —— `rekit mcp` 本地服务器（CLI+MCP 双身份）

日期：2026-11-15 ｜ 依据：CHARTER.md M1.5 ｜ 任务类型：扩展型（包装既有 parse 能力，新协议层从零）

## 任务布置

实现 MCP (Model Context Protocol) stdio 本地服务器，把 rekit 的分诊能力包装为两个 MCP 工具：

1. `rekit_info`：分诊摘要（格式/架构/类型/入口/段节数/安全态或 Rich 摘要/依赖）
2. `rekit_map`：内存映射（ELF 段表或节表；PE 节表）

- 协议：JSON-RPC 2.0 over stdio，行分帧（每行一条 JSON，无内嵌换行）
- 生命周期：`initialize` → `notifications/initialized` → `tools/list` / `tools/call`
- 入口：`python3 -m rekit.cli mcp`；仅 stdlib，无第三方依赖
- CLI 单文件分析行为保持逐字节不变（58 断言回归不破）

## 验收标准（先行，全部可证伪）

- **E1 协议握手**：initialize 响应含三要素——protocolVersion ∈ {回显客户端版本, 服务器支持版本}、capabilities.tools 存在、serverInfo.name=="rekit"；initialized 通知后服务器不产生任何响应输出（stdout 保持协议纯净）。
- **E2 工具清单**：tools/list 返回 ≥2 工具；rekit_info 与 rekit_map 均有非空 description；inputSchema.type=="object" 且 "path" ∈ required。
- **E3 info 交叉验证（readelf 权威）**：rekit_info(tests/fixtures/bin_ls.elf) 返回 JSON 与 readelf -h/-l/-SW 权威输出逐项全等：类型(DYN-PIE)、entry、段数、节数、NX/RELRO/PIE 三态（≥8 字段）。
- **E4 map 交叉验证**：rekit_map(bin_ls.elf, segments) 段数+段类型序列与 readelf -lW 全等；(sections) 节数与 readelf -SW 全等；PE 样本 minidll.dll map 节数与节名序列和已知构造（3 节）全等。
- **E5 回归与负路径**：pytest 58→≥65 全绿（新增 tests/test_mcp.py：握手/清单/info/map/不存在路径与 text 文件 isError=true/错误后连接存活）；错误不产生 traceback 直出。

## 基线纪律

- 扩展型基线：1–2 min 时钟、~8 工具轮次；返工 ≥3 次次日降档
- 返工计数口径：实现或验证脚本因缺陷需要修改一次记 1 返工

## 完成标准（CHARTER 原文）

> cron 日报的自我验收环节实际调用 rekit 工具完成一次交叉验证。

——即本日报 E3/E4 的验证必须通过真实 MCP 客户端（子进程 stdio）调用完成，不允许进程内 import 直测替代。
