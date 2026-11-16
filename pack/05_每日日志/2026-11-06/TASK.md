# 实操任务卡 · 2026-11-06（白银·构建型）

## 任务
纯 Python（仅允许 import struct / sys，禁止 pyelftools 等解析库）手写 ELF64 解析器
`mini_elf.py`，解析 `/bin/ls`，输出：魔术数、Class/Data、e_type、e_machine、
e_entry（十六进制）、e_shnum、全部 Program Header（type/offset/vaddr/filesz/flags）、
PT_LOAD 计数。

## 验收标准（执行前写定，不许事后放宽）
1. **S1 一致性**：e_entry、e_type、e_machine、e_shnum 与 `readelf -h /bin/ls` 输出完全一致
2. **S2 段表一致**：PT_LOAD 段数及每段 offset / vaddr / filesz / flags 与 `readelf -l /bin/ls` 完全一致
3. **S3 纯手解**：脚本 import 白名单仅 struct、sys（用 AST 检查证据）
4. **S4 归档**：脚本、运行输出、readelf 对照输出、本验收记录全部存于本目录

## 执行记录
（见 ACCEPTANCE.md）

## 验收结论
✅ **4/4 达标，白银任务完成**（详见 ACCEPTANCE.md）。
升级说明：本任务卡即每日闭环的格式范本——任务布置、验收标准、执行记录、
验收结论、总结归纳五件套，后续每期日报照此执行。
