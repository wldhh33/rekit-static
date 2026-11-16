# 导出表解析知识卡 + 规则沉淀（2026-11-13 白银#2）

## 一、IMAGE_EXPORT_DIRECTORY 速查（40B，DataDirs[0]）

| 偏移 | 字段 | 类型 | 本样例值 |
|---|---|---|---|
| 0x00 | Characteristics | DWORD | 0 |
| 0x04 | TimeDateStamp | DWORD | 0x672A0000 |
| 0x08 | Major/MinorVersion | 2×WORD | 0/0 |
| 0x0C | Name（DLL 名 RVA） | DWORD | 0x2028 |
| 0x10 | Base（序号基址） | DWORD | 1 |
| 0x14 | NumberOfFunctions（EAT 项数） | DWORD | 4 |
| 0x18 | NumberOfNames（名字表项数） | DWORD | 3 |
| 0x1C | AddressOfFunctions（EAT RVA） | DWORD | 0x2040 |
| 0x20 | AddressOfNames（名字RVA表） | DWORD | 0x2050 |
| 0x24 | AddressOfNameOrdinals（EAT索引表,WORD） | DWORD | 0x205C |

## 二、三数组联动语义（本任务的全部考点）

```
名字导出:  名字表[i] --(AddressOfNameOrdinals[i])--> EAT[idx]
           ordinal = Base + idx；RVA = EAT[idx]
纯序号导出: 只占 EAT 槽位、不在名字表 → 遍历全 EAT 反查发现
```

1. **名字表顺序 ≠ EAT 顺序**：名字表按字母序（链接器惯例），EAT 按定义序。
   本样例 EAT=[Add,Sub,Mul,ordinal-only]，名字表=[Add,Mul,Sub]，
   序号表=[0,2,1]——假设"名字第 i 个=EAT 第 i 个"必错。
2. **ordinal = Base + EAT 索引**（不是名字表索引）。MinGW/MSVC 常见 Base=1。
3. **NumberOfFunctions ≥ NumberOfNames**，差值=纯序号导出数（本例 4-3=1）。
4. 转发器：EAT 项若指向导出目录内部（exp_rva ≤ 值 < exp_rva+size），是指向
   "NTDLL.RtlAllocateHeap" 样式字符串的**转发 RVA**，非代码地址（本样例未构造，下同）。
5. DLL 特征位：COFF Characteristics |= 0x2000 (IMAGE_FILE_DLL)。

## 三、objdump -p 导出段输出解读

```
Export Address Table -- Ordinal Base 1     ← EAT 明细段（锚点，全输出唯一）
        [   0] +base[   1] 00001010 Export RVA  ← [EAT索引] ordinal  RVA  "Export RVA"=Type列
[Ordinal/Name Pointer] Table -- Ordinal Base 1
        [   0] +base[   1]  0000 Add            ← [EAT索引] ordinal  hint 名字
```

## 四、验证脚本三板斧（R25–R27，今日 3 返工换来的）

- **R25 锚点唯一性检查**：split 外部工具输出前先确认锚点串只出现一次
  （"Export Address Table" 在 objdump 输出出现 3 次：Number in 段 / Table Addresses
  段 / 明细段标题——split()[1] 静默取错段，匹配 0 项才暴露）。
- **R26 正则边界对齐列语义**：`(\w+)` 会把行尾 Type 列 "Export RVA" 的 "Export"
  吃成函数名——正则吃出了 {'Export': 4} 这种"看起来对"的脏数据。捕获组必须锚定
  到列的确切语义（这里是 `[0-9a-f]{8} Export RVA` 整体作为右边界）。
- **R27 列宽差异用 \s+**：hint 列（4 hex）与 RVA 列（8 hex）填充空格数不同
  （1 vs 2）——单空格正则静默失配。对齐列一律 `\s+`。
- 通用心法（三板斧之前的第 0 步）：**先 dump 原始输出肉眼锚定，再写正则**；
  正则跑通后先 print 提取结果抽样看，再进 assert。

## 五、返工明细（如实记录）

| # | 位置 | 症状 | 根因 |
|---|---|---|---|
| 1 | verify_exports.py | {'Export': 4} 脏数据 | R26：正则吃 Type 列 |
| 2 | verify_exports.py | EAT 匹配 0 项 | R25：split 锚点不唯一 |
| 3 | verify_exports.py | 名字段 {} | R27：hint 列双空格 |

- 核心交付（make_minidll.py / pe.py::parse_exports）：**0 返工，一次写对**
  （R1 字段计数 + R2 区间表先行的红利）
- 验证脚本 3 返工 → **触发 ≥3 次降档条款**：11-14 原计划 M1 收口（cli.py 整合，
  扩展型）从轻执行，并内嵌验证脚本加固自检（锚点计数断言）。

## 六、可复用资产

- `verify_exports.py`：导出表三方比对模板（五项断言，可传任意 DLL 路径）
- `make_minidll.py`：最小 DLL+导出表构造器（可改造为转发器/纯序号边界样本）
- pe.py 现已覆盖：头/节/导入/导出/Rich —— M1 PE 侧解析能力集齐，待 cli 统一收口
