# rekit 白银任务卡 2026-11-07（M1 子任务）

## 任务布置

**任务**：rekit.elf 新增动态段解析——遍历 PT_DYNAMIC 段，解析 ELF64 `Elf64_Dyn` 条目（16 字节：d_tag 8B + d_val 8B），提取 DT_NEEDED 依赖库列表，并正确定位动态字符串表（DT_STRTAB）。

**技术核心（预判的坑）**：DT_STRTAB 的值是**虚拟地址（vaddr）**而非文件偏移。PIE 可执行文件（ET_DYN）中 vaddr ≠ file offset（实证：/bin/ls 的 DYNAMIC 段 vaddr=0x269f8 而 offset=0x259f8，差 0x1000）。必须遍历 PT_LOAD 段建立 vaddr→offset 映射：`file_off = vaddr - p_vaddr + p_offset`。

**级别**：🥈 白银·扩展型（基线 A：期望 1–2 min / 5–8 轮 / 预留 1–2 次返工）

## 验收标准（执行前写死，不得事后放宽）

- **S1【列表一致性】** 对 /bin/ls，rekit.elf 输出的 DT_NEEDED 依赖列表与 `readelf -d` 提取的 Shared library 列表**逐项一致**（名称、顺序、数量），由脚本自动比对，diff 为空。
- **S2【多样本交叉验证】** 至少 3 个不同 ELF 样本，每个的 NEEDED 列表均与 readelf -d 一致（3/3 通过才算过）。样本覆盖两类：
  - /bin/ls（系统 PIE，vaddr≠offset）
  - gcc -no-pie 编译的动态链接程序（非 PIE）
  - gcc + -lm 编译的程序（多一条 libm 依赖）
- **S3【段定位正确】** 解析出的 PT_DYNAMIC p_offset / p_vaddr / p_filesz 与 `readelf -lW` 的 DYNAMIC 行逐字段一致（全样本）。
- **S4【纯手解约束】** 代码仅用 struct.unpack_from（不引入 pyelftools/ lief 等库）；字符串表定位必须经 PT_LOAD 映射换算（代码审查 + PIE/非 PIE 双样本行为证明）。

**交叉验证权威源**：readelf -d / readelf -lW（binutils 权威输出）。

## 执行记录

- 实现：`rekit/elf.py` 新增 PT/DT 常量表、`vaddr_to_off()`（遍历 PT_LOAD 映射）、`Elf64_Dyn` 16 字节条目循环（DT_NULL 终止）、STRTAB 换算定位、NEEDED 提取。
- 验收脚本：`verify_dynamic.py`（rekit vs readelf 全自动比对），证据存 `verify_output.txt`。
- 加固测试①：`gcc -static` 产物 → `dynamic=None` 鲁棒性 PASS。
- 加固测试②（反证）：dyn_nopie 文件仅 0x3ce8 字节，STRTAB vaddr=0x400418 直用当 offset → ValueError 越界，证明换算不可省略。
- 基线对比：时钟 ≈1.5 min（基线 A 期望 1–2 min ✓）｜工具轮次 ≈8（期望 5–8 ✓）｜返工 0 次（预留 1–2，优于基线）。
- 诚实记录偏差：S2 原预期「-lm 增加一条 libm 依赖」，实际未出现——glibc 2.34+ 已将 libm 并入 libc.so.6，故自编译样本仅 1 条 NEEDED。S2 标准本身（3 样本逐项一致）不受影响，按原标准执行，未降级。

## 验收结果

| 标准 | 结果 | 证据 |
|---|---|---|
| S1 NEEDED 列表一致（/bin/ls） | **PASS** | 3/3 条（libselinux.so.1 / libcap.so.2 / libc.so.6）名称顺序全同 |
| S2 多样本交叉验证 | **PASS（3/3+1）** | 系统 PIE / 自编译 PIE / 自编译非 PIE 全一致，附加静态 ELF 鲁棒性 |
| S3 PT_DYNAMIC 段字段 | **PASS** | 3 样本 off/va/fsz 逐字段与 readelf -lW 一致 |
| S4 纯手解+换算正确 | **PASS** | 纯 struct；非 PIE 0x400418→0x418 换算生效；直用 vaddr 反证越界 |

**总判定：4/4 全 PASS，0 返工，一次通过。**

