# 基线A任务卡 · 2026-11-07（速度基线测试）

## 任务
将 mini_elf.py 升级为 rekit/elf.py，新增节区表解析：解出 /bin/ls 全部节的名字
（e_shstrndx → shstrtab → sh_name 偏移读 C 字符串）、类型、地址、偏移、大小。

## 验收标准（执行前写定）
- A1：节名序列与 `readelf -S /bin/ls` 完全一致（30/30，顺序一致）
- A2：每节 Address / Off / Size 与 readelf -S 数值一致
- A3：import 白名单 {struct, sys}（AST 证据）

## 记录口径
耗时（分）/ 工具调用轮次 / 返工次数
