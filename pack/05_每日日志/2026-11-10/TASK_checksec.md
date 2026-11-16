# TASK 2026-11-10（白银·扩展）：rekit.elf 段权限与 RELRO 检测

> rekit M1 下一子任务（PROGRESS.md 2026-11-09 预定）：输出 NX/RELRO/PIE 三态，对齐 checksec 语义，为 M2 fingerprint 铺路。
> 类型：白银·扩展型 ｜ 基线 A 预期：1–2 min / 5–8 轮 / ≤2 返工

## 任务布置

给 `rekit/elf.py` 新增安全态检测：

1. **NX**：读 `PT_GNU_STACK`(0x6474e551) 的 p_flags——含 X → NX disabled；不含 X（RW）→ NX enabled；段缺失 → NX unknown（按内核默认栈可执行，保守报 disabled 并标注原因）。
2. **RELRO 三态**：`PT_GNU_RELRO`(0x6474e552) 不存在 → none；存在且动态段有立即绑定标志 → full；存在且无 → partial。
   立即绑定三路判定：`DT_BIND_NOW`(tag 24) 存在 ∨ `DT_FLAGS`(tag 30) 含 DF_BIND_NOW(0x8) ∨ `DT_FLAGS_1`(0x6ffffffb) 含 DF_1_NOW(0x1)。
3. **PIE**：`ET_EXEC`(2) → no；`ET_DYN`(3)+PT_INTERP → yes；`ET_DYN` 无 INTERP → dso（共享库语义）。
4. **W+X 段扫描**（加项，为 M2 恶意样本分诊铺路）：任一 PT_LOAD 同时含 W(2)+X(1) → 报警。
5. 输出进 `parse()` 返回值 `security` 键 + `main()` 顶部一行 checksec 汇总。

新增 2 个 fixture 补布局：`dyn_norelro`（-no-pie -z norelro）、`dyn_execstack`（-z execstack）。

## 验收标准（执行前写定，不放宽）

- **A1 权威期望表全等**：用 readelf -lW（GNU_STACK/GNU_RELRO/INTERP）+ readelf -d（BIND_NOW/FLAGS/FLAGS_1）+ readelf -h（Type）逐格推导 6 个 ELF fixture 的 NX/RELRO/PIE 权威值制成期望表；rekit 对 6 样本输出与期望表 **18/18 格 diff=0**。
- **A2 状态覆盖**：NX{enabled,disabled}、RELRO{full,partial,none}、PIE{yes,no} 各状态至少 1 个样本命中（execstack 样本须真实含 X 的 GNU_STACK，readelf 证明）。
- **A3 判定语义可证伪**：立即绑定必须走 FLAGS/FLAGS_1 位掩码路径（bin_ls 的 DT_FLAGS BIND_NOW + FLAGS_1 NOW 真实覆盖）；旧式 tag-24 路径允许实现为防御性收录但如实标注「无真实样本覆盖」（证据等级：implemented, untested-by-sample）。
- **A4 pytest 固化**：≥6 条新断言（6 样本三态快照 + GNU_STACK flags 原始值 + W+X 扫描），套件 25 → ≥31 全绿。
- **A5 CLI 集成留证**：`python3 -m rekit.elf` 对 bin_ls.elf 与 dyn_execstack 输出 checksec 行，证据存档。

## 权威期望表（readelf 2026-11-10 采集，执行 A1 的比对基准）

| fixture | NX | RELRO | PIE | 证据（readelf 原始行） |
|---|---|---|---|---|
| bin_ls.elf | enabled | full | yes | GNU_STACK RW；GNU_RELRO 有；FLAGS BIND_NOW + FLAGS_1 NOW；DYN+INTERP |
| dyn_pie | enabled | partial | yes | GNU_STACK RW；GNU_RELRO 有；仅 FLAGS_1 PIE（无 NOW）；DYN+INTERP |
| dyn_nopie | enabled | partial | no | GNU_STACK RW；GNU_RELRO 有；无 NOW；EXEC |
| dyn_static | enabled | partial | no | GNU_STACK RW；GNU_RELRO 有；静态无立即绑定语义；EXEC |
| dyn_norelro（新） | enabled | none | no | 预期：GNU_STACK RW；无 GNU_RELRO；EXEC —— 构造后以实际 readelf 为准 |
| dyn_execstack（新） | disabled | partial | yes | 预期：GNU_STACK RWE；GNU_RELRO 有；DYN+INTERP —— 构造后以实际 readelf 为准 |

> 新样本预期值在构造后必须用 readelf 实测刷新，若与预期不符以实测为准并记录差异原因。
