# TASK 2026-11-13 · rekit M1 白银#2：自构造 minidll + pe.py 导出表解析

> 类型：白银·从零型（≈ 基线 B：5–8 min 时钟 / 15–20 轮 / 预留 2 返工）
> 背景：11-11 收口评估 A2 结论——系统正样本导出表全缺（.NET DLL 导出全空、cli-64.exe 是 EXE），
> 故走自构造路线（objdump 三方验证）。本任务是 M1 收口前最后一个从零子任务。

## 任务布置

1. **构造器** `tests/make_minidll.py`：纯 struct 构造 PE32+ DLL（IMAGE_FILE_DLL 特征位），
   含 `.edata` 节与完整导出目录 IMAGE_EXPORT_DIRECTORY(40B)。
   导出设计（4 函数，Base=1，**故意让名字表顺序 ≠ EAT 顺序**以检验序号换算）：
   | EAT idx | 函数 RVA | 名字表 | ordinal = Base+idx |
   |---|---|---|---|
   | 0 | 0x1010 | Add | 1 |
   | 1 | 0x1020 | Sub | 2 |
   | 2 | 0x1030 | Mul | 3 |
   | 3 | 0x1040 | **（纯序号导出，无名）** | 4 |
   名字表按链接器惯例字母序 [Add, Mul, Sub]，序号表映射 [0, 2, 1]——
   "Mul"在名字表第 2 位但 EAT 第 3 位，偷懒假设"名字序=EAT 序"的实现必错。
   无导入表（顺带覆盖「只有导出没有导入」路径）。
2. **解析器** `rekit/pe.py::parse_exports`：DataDirs[0] → rva_to_raw → 解包 40B →
   三数组（EAT/NamePtrs/Ordinals）联动解析；CLI 输出导出段。
3. **三方验证**：构造器 ↔ objdump -p ↔ rekit。

## 验收标准（执行前写定，不许事后放宽）

- **B1 构造正确性**：`objdump -p minidll.dll` 无报错读出导出表；导出集合与构造参数
  完全一致：4 函数（Add/Sub/Mul/无名纯序号）、ordinal 1–4、DLL 名 `minidll.dll`。
- **B2 三方逐项全等**：rekit 解析输出（name, ordinal, RVA）vs objdump -p 逐项 diff = 0；
  名字导出的 ordinal 映射（Add→1, Sub→2, Mul→3）须经 AddressOfNameOrdinals 正确换算。
- **B3 纯序号导出语义**：无名 EAT 项以 ordinal=4 形式被解析出来（解析器须遍历全 EAT
  发现不在名字表的项），不是只输出 3 个名字导出。
- **B4 负样本鲁棒**：minipe.exe（ExportDir RVA=0）与 cli-64.exe（EXE 无导出）→ 导出结果
  为空 / None，不崩溃。
- **B5 回归入库**：minidll.dll 入 fixtures（9→10）；pytest 新增断言 ≥ 8 条（40→48+），
  `python3 -m pytest tests/ -q` 全套件常绿。

## 红线

- 返工 ≥ 3 次次日降档；未达标项如实记录次日补课；严禁虚报。
- R1（字段计数先行）/ R2（RVA→RAW 区间表画完再写）/ R3（三方交叉）全程遵守。
