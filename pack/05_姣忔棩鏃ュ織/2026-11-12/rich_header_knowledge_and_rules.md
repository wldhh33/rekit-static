# Rich 头知识卡（2026-11-12 白银#1）

## 结构（字节级定标，cli-64.exe 实证）

```
DOS stub 区（[0x40, e_lfanew)，Rich 头通常起于 0x80，4 字节对齐）：
  [DanS^key][0^key ×3]        ← 加密域头部（DanS='S'<<24|'n'<<16|'a'<<8|'D'? 否：
                                DanS dword = 0x536E6144，小端读作 'DanS'）
  [(comp.id^key)(count^key)]×N ← 加密域对序列
  ['Rich' 明文 0x68636952][key 明文]  ← 尾锚（不加密）
```

- key（checksum）= Rich 尾随明文 dword；解密 = 每 dword ^ key
- **老格式 `DanS^ck, ck, ck, ck` 与新格式 `DanS, 0,0,0` 在解密域统一为 `[DanS,0,0,0]`**：
  老格式描述的是存储域（ck 明文存 = 0^ck），新格式描述的是明文域——同一字节两种话术
- comp.id 解码：**prodid = cid>>16（高16位），build = cid & 0xFFFF（低16位）**
  - 佐证：30729=MSC 19.29(VS2019 16.11)、32420=MSC 19.34(VS2022 17.4)、30795=VS2019 16.11 rc、
    32532=VS2022 17.5；cli-64.exe 呈现 VS2019+VS2022 混合链接指纹
  - 特殊对 (0x00010000, N)：prodid=1, build=0 —— 计数标记（unnamed objects），非编译器
- comp.id 对是"出现过的工具+次数"清单 → M2 编译器指纹的原始数据

## 陷阱与防御（已固化进 rekit/pe.py + 回归套件）

| 陷阱 | 场景 | 防御 |
|---|---|---|
| 数据深处 "Rich" 字节串 | Aspose.Words.dll 0x147ba89（28MB .NET）实测 | 搜索限界 [0x40, e_lfanew) |
| stub 区 Rich+key 但无 DanS | 自构造 minipe_fakerich.exe 陷阱1 | 双向锚定：回找 DanS^key |
| .text 里 Rich+key | 自构造陷阱2（0x500） | 同限界 |
| 尾对被误读为 Rich^key | 11-11 日志"9 对"误读 | pefile values 语义=解密对平铺，见 R22 |

## 新规则（编号接 PROGRESS.md 规律沉淀）

- **R22 权威工具输出须源码级对齐**：昨日探测日志把 pefile `values` 尾部 (0x1027f14, 1) 误读为
  "Rich^key + key"，导致"9 对"错误记载。根因：没读 `parse_rich_header` 源码就按直觉解释输出格式。
  修正流程：读源码 → 手动 dump 字节 → 三方对齐，才可写进期望值。（R16 的深化：不仅常量表，
  权威工具的**输出格式本身**也要对拍才能引用）
- **R23 双向锚定防御巧合字节串**：结构解析找签名时，若存在"明文锚 A + 由 A 派生的加密锚 B"，
  必须双锚验证（Rich+key → DanS^key）。单向锚会被大文件深处巧合字节串命中（fakerich 陷阱1
  实验证明：单向实现被骗出 key=0x11223344 的垃圾结果）。pefile 只单向找 Rich——rekit 比 pefile 严。
- **R24 格式话术统一律**：同一结构在"存储域/明文域"两种描述下可能形似而实异（DanS^ck,ck,ck,ck
  vs DanS,0,0,0）。对拍时先声明自己站在哪个域，再比较——域不一致的对拍必然误判。

## 交付物清单

- `rekit/pe.py`：`parse_rich_header(data, e_lfanew)`（双向锚定）+ parse() 挂载 + CLI 输出
- `tests/make_fakerich.py`：双陷阱负样本构造器（e_lfanew=0x200 长 stub 变体）
- `tests/fixtures/`：+cli-64.exe（14KB 正样本）、+minipe_fakerich.exe（2KB 陷阱样本）
- `tests/test_pe.py`：+6 测试函数 10 断言（含 pefile importorskip 交叉验证）
- 回归 40/40 常绿（34→40），fixtures 7→9
