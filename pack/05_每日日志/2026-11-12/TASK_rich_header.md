# TASK 2026-11-12 白银#1：pe.py Rich 头解析（M1 收口路径 1/3）

> 类型：扩展型（基线 A 预期 1–2 min 纯执行 + 今日预研语义修正）。
> 前置：2026-11-11 M1_GAP_AUDIT A4 决策第 1 步；权威期望值已于今日以
> pefile 源码 + 手动 dump 双重定标（见下"定标记录"），修正昨日日志误读。

## 定标记录（写代码前钉死的事实，证据等级：源码级 + 字节级 dump）

- cli-64.exe 真实结构：`0x80: DanS(加密) + 3×padding(解密后=0) + 11 对 comp.id(加密) + 0xe8: "Rich"(明文) + key(明文)`
- key = 0x31a563a3；11 对 = [(0x937809,16),(0x1017ea4,2),(0xfd7ea4,4),(0x1057ea4,19),(0x1047ea4,10),(0x1037ea4,3),(0x101784b,3),(0x10000,69),(0x1047f14,1),(0xff7f14,1),(0x1027f14,1)]
- pefile `values` 语义（源码级确认）：**解密后 comp.id 对的平铺列表**（22 = 11×2），不含 DanS/padding 头与 Rich/key 尾；其 4-dword 头跳过逻辑与"DanS+3×0 padding"新格式形式等价（0 加密后=key，恰好吻合老格式 DanS^ck,ck,ck,ck）
- **昨日日志"9 对"系误读**：把真实第 11 对 (0x1027f14,1) 当成了 Rich^key+key 尾。证伪：0x01027f14 ^ 0x31a563a3 = 0x30a71cb7 ≠ 0x68636952("Rich")

## 验收标准（可证伪，逐条判定）

- **C1 正样本全等**：`rekit.pe.parse_rich_header(cli-64.exe)` 返回 key=0x31a563a3、
  11 对 (id,count)，与 pefile `values` 两两配对结果**逐项全等**；
  另含 dans_off=0x80、rich_off=0xe8。
- **C2 负样本优雅降级（含限界防误匹配）**：
  minipe.exe → None；自构造 minipe_fakerich.exe（数据深处埋 "Rich" ASCII）→ None；
  CLI 层跑 28MB 的 Aspose.Words.dll（深处 0x147ba89 有 "Rich" 字节串）→ 输出无 Rich、不崩溃。
- **C3 双向锚定**：实现必须"找明文 Rich+key 后向前找 DanS^key 双向验证"，
  仅单向匹配不算通过（防 .NET 元数据/数据段误匹配——比 pefile 单找 Rich 更严）。
- **C4 断言入库 ≥6**：test_pe.py 新增断言 ≥6 条（key/对数/首对/尾对/偏移/负样本×2），
  pytest 全绿（34 → ≥40）；fixtures +2（cli-64.exe 14KB 入库、fakerich 自构造）。
- **C5 语义修正沉淀**：误读根因写入知识卡新规则（权威工具输出必须源码级对齐），
  PROGRESS.md 修正"10 对"旧记载。

## 执行纪律

- 字段计数先行（R1）：DOS stub 无 struct 串，但 padding 数=3 必须先钉（已钉，见定标）
- 三方验证（R3）：手写解析 vs pefile vs 手动 dump
- 返工 ≥3 次次日降档；失败如实记录
