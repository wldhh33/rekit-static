# MCP 协议知识卡 + rekit M1.5 规则沉淀（2026-11-15）

## 一、MCP (Model Context Protocol) stdio 服务器知识卡

### 协议栈与帧格式
- 传输：JSON-RPC 2.0 over stdio，**每行一条 JSON**（newline-delimited），禁止内嵌换行
- 与 LSP 的区别：LSP 用 `Content-Length:` 头分帧，MCP stdio 用换行分帧

### 生命周期（4 步）
```
client → {"method":"initialize", params:{protocolVersion,...}}      # 带 id
server → {result:{protocolVersion, capabilities, serverInfo}}
client → {"method":"notifications/initialized"}                     # 通知，无 id
client → tools/list / tools/call / ping ...                         # 正常会话
```
- **通知 vs 请求**：有无 `id` 字段是唯一判据；通知**不得**产生响应
- 版本协商：客户端传服务器支持的版本则回显；不支持则回服务器最新版，客户端不认就断开

### tools 三要素
- `tools/list` → `[{name, description, inputSchema}]`，inputSchema 是 JSON Schema
- `tools/call {name, arguments}` → `{content:[{type:"text",text}], isError?}`
- **两层错误语义**（本次实现的核心设计）：
  - 工具级错误（文件不存在/格式不识别/参数缺失）→ `isError:true` 的**正常响应**，连接存活
  - 协议级错误（未知方法 -32601 / 坏帧 -32700）→ JSON-RPC error
  - 混淆两层 = 每次分析失败都断连接，Agent 体验灾难

### 实现三坑（全部命中过预防位）
1. **不 flush**：stdout 有缓冲，客户端死等——每条响应必须 `flush()`
2. **stdout 是协议通道**：日志/错误只走 stderr，混入一行日志整个会话报废
3. **id 回显**：id 可能是 int/str，必须原样返回（客户端按 id 配对）

## 二、动态基础：PIE 相对断点（阶段一 #4，环境无 gdb 的实证版）

- 原理：PIE 二进制静态侧只有 RVA（如 bin_ls.elf entry=0x6760），运行时加载基址由 ASLR 随机化
- 实证（本机）：两次 `ldd bin_ls.elf`，libc 基址 `0x7f5e9abd2000` vs `0x7fa0b9494000`——每次不同
- 静态侧配合：`rekit mcp` 的 `rekit_info` 给出 entry RVA + PIE 三态，直接换算 `break *$base+RVA`
- gdb 命令速查：`starti`（停在加载器入口）→ `break *$_base()+0x6760`（pwndbg: `$_base()`）
- watchpoint：`watch *0xADDR`（数据断点，DR0–DR3 硬件寄存器 x86 只有 4 个）；`rwatch`/`awatch` 读/读写
- 内存搜索：`find /b $rsp, $rsp+0x200, 0x7f`（pwndbg: `search`）
- 练习建议（本地机，需装 gdb+pwndbg）：写 10 行 crackme → (1) PIE 相对断点断 main (2) watchpoint 抓 flag 比较变量 (3) search 找栈上输入串

## 三、新规则（R30–R32）

- **R30 协议服务器双错误语义**：工具执行错误 → isError:true（连接存活）；协议错误 → JSON-RPC error；stdout 是协议通道（flush 必须、日志只走 stderr）。与 CLI exit code 语义分层（D2）同源——"失败路径可控"从进程级推广到会话级。
- **R31 权威期望提取防边界吞噬**：从权威工具输出正则提取期望值时用排除字符类（`[^\]\s]+` 而非 `\S+`），提取后先打印再对拍——本次 `]` 被吃进 interpreter 期望值造成假 FAIL，R25–R27 验证脚本三板斧的延伸。
- **R32 新接口层命名对齐权威工具**：rekit MCP 段名直接用 readelf 词汇（GNU_EH_FRAME 而非 elf.py 内部的 EH_FRAME），交叉验证零名称映射成本。新接口层没有历史包袱，命名权一次性对齐权威源。

## 四、rekit mcp 使用示例（真实客户端调用）

```python
# 启动：python3 -m rekit.cli mcp（或子进程 spawn）
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call",
 "params":{"name":"rekit_info","arguments":{"path":"bin_ls.elf"}}}
# → content[0].text = {"format":"ELF","entry":"0x6760","security":{...},...}
```

## 五、当日执行数据（供 PROGRESS 回写）

- 验收：verify_mcp 35/35 PASS（E1×5 E2×5 E3×11 E4×7 E5×7）；pytest 73/73（58→+15）
- 返工：2 次（cli.py 编辑重复行×1 自纠、verify 正则边界×1）——< 3，不降档
- 任务类型：扩展型偏新协议层（mcp.py 236 行新代码，零第三方依赖）
