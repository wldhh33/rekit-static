# 白银任务：rekit M3 map&patch —— 内存映射视图 / RVA↔offset 换算 / IAT 修复雏形

日期：2026-11-15 ｜ 依据：CHARTER.md M3 + PROGRESS.md 2026-11-15 尾行 ｜ 任务类型：扩展型（复用 M1 解析结果）
本轮性质：**任务卡 + 首个子单元（降档从轻）** —— 2026-11-15 返工 6 次 ≥3，触发 11-13 降档条款

## 执行口径（2026-11-15 定档）

- **降档执行**：M3 首日按「从轻」执行 = 先出任务卡 + 完成 U0（真值冻结）与 U1（映射模型 + ELF 换算 + 对拍）；PE / IAT / 收口矩阵顺延到后续单元。降档只压缩**当日范围**，不降低任何 E 条目的判定强度。
- **连续推进授权**：用户已授权做完一个子单元接着下一个，不必逐单元等拍板；但**每个子单元完成即汇报里程碑**。
- **停下来汇报的四个条件**（命中任一即停）：需要下载而网络不可达；样本来源/许可不明；判据本身要改；验收出现「证据不足」这类边界结论。
- **不因节奏快而放宽**：不改阈值、不换弱参照、不跳过验收。任何判据改动必须先报告，改了要写 CHANGELOG（旧→新/原因/影响）。

---

## 0. 一句话定义

给 rekit 增加第 5 类能力：**把文件里的字节位置与进程内存里的地址严格对应起来**——
`RVA/vaddr ⇄ 文件偏移` 双向换算、内存映射视图（哪段有文件背书、哪段是零填充、哪段根本不存在）、
以及 PE 的 IAT 定位/解码/**修复雏形**（在镜像副本上把指针回写为可读符号）。
验收硬指标：**换算对全部段 100% 正确（与手工计算 + 外部工具对照）**。

## 1. 现状勘察（写卡前实测）

| 能力 | 现在有什么 | M3 缺什么 |
|---|---|---|
| ELF 段/节 | `elf.parse` 给出 `phdrs`（type/flags/offset/vaddr/filesz）与 `sections`（name/type/addr/offset/size） | 缺 **memsz**（解析时被丢弃）、缺双向换算 API、缺「不可落盘区」语义（.bss） |
| ELF 换算 | 仅 `elf.py` 内部 `vaddr_to_off()` 私有函数，且只用于 DT_STRTAB | 缺公开 API、缺反向、缺边界/空洞判定 |
| PE 换算 | `pe.rva_to_raw()`：`va <= rva < va+max(vsize,rawsize)`，`rawsize==0 → None` | 该实现把**虚拟尾部**（rva 落在 rawsize 之外）也当成可落盘；缺 header 区；缺反向；M3 不改它（既有断言依赖），另立新模块 |
| PE 映射视图 | `rekit_map`（M1.5）返回节表 RVA/VSize/RawPtr/RawSize | 缺「按 RVA 区间看内存布局」、缺 header 区与空洞标注 |
| IAT | `pe.parse` 已解出 `imports=[(dll, funcs)]`（只到函数名，无地址/无 slot） | 缺 IAT 区间定位、slot 级解码、修复动作 |
| 对拍工具 | binutils 2.47（readelf/objdump）+ pefile 2024.8.26 + pyelftools 0.33（2026-11-15 已装/已验） | 无（**本卡不需要新下载**） |

## 2. 范围

### 2.1 做

1. **映射模型**：统一的「映射单元」抽象 —— ELF 用 PT_LOAD 段，PE 用节 + header 区；每个单元同时记录 *文件区间* 与 *内存区间*，两者不等长时必须显式标注（.bss / 虚拟尾部 / 对齐填充）。
2. **双向换算**：`vaddr→offset`、`offset→vaddr`（ELF）；`rva→offset`、`offset→rva`（PE）。**三值语义**：命中 / `not_in_file`（内存有、文件无）/ `unmapped`（不在任何单元，含空洞）。
3. **映射视图**：`rekit map <file>` 输出按地址排序的布局，含每单元的文件/内存区间、权限、以及单元间空洞；JSON 供 MCP 复用。
4. **IAT 修复雏形**：定位 IAT 区间 → 逐 slot 解出 (dll, name|#ordinal, hint) → 对「被 loader 填充过的镜像副本」回解并回写，**往返后与原始文件 IAT 区间逐字节全等**。
5. **对拍与矩阵**：外部工具（readelf/objdump/pefile）采集真值 → 冻结快照 → 一次性混淆矩阵。

### 2.2 明确不做（写死边界）

- **不运行样本、不做真实注入**。IAT「修复」只作用于内存镜像副本（bytes），不加载进程、不写回原文件。
- **不做重定位修复**（ELF RELA / PE BaseReloc 的地址搬迁）→ 属后续里程碑；本轮只做 IAT 指针回解。
- **不做反汇编**（M4 的 CFG 才需要）；IAT 修复只到「指针→符号」层级。
- **不改 M1/M1.5/M2 的既有输出与 92 条断言**；`pe.rva_to_raw`、`elf.parse` 的返回结构保持原样（新模型独立成模块）。
- **不引入第三方运行时依赖**：`rekit/mapview.py` 仍纯 stdlib；pefile/pyelftools 只用于测试与真值采集。

## 3. 子单元拆分与顺序

| 单元 | 内容 | 覆盖验收 | 依赖 | 粒度 |
|---|---|---|---|---|
| **U0 真值冻结** | `work/collect_map_gt.py`：用 readelf -lW/-SW、objdump -h/-p、pefile 采集 18 样本的映射真值 → `work/map_ground_truth.json` + sha256，**实现前冻结** | E2–E9 的前置 | binutils/pefile（已在） | 从零型 5–8 min |
| **U1 映射模型 + ELF 换算**（今日） | `rekit/mapview.py`：`MapUnit` 抽象、ELF 段/节装载、双向换算三值语义、边界（含 0 长段、文件空洞、重叠冲突检测）、CLI `map` 骨架；对拍脚本 | E1/E2/E3/E5(ELF 半边) | U0 | 扩展型 2–4 min |
| **U2 PE 换算 + 节身份**（2026-11-15 完成） | PE 节 + header 区 + 虚拟尾部 + `VirtualSize=0` 兜底 + 零长度节跳过；反向换算；`--section` 在 CLI/MCP 双侧暴露（E1.1 契约） | E4/E5(PE 半边)/E1.1 | U1 | 扩展型 2–4 min |
| **U3 IAT 定位/解码/修复雏形**（2026-11-15 完成） | `rekit/iat.py`（`headers`/`rva_to_off`/`locate_bytes`/`repair_bytes`/`repair_file` + CLI `iat`）；`tests/verify_iat.py`（对拍 + 反例 + `--selftest`）；`tests/test_iat.py`（17 项） | E6/E7/E8/E10 | U2 | 从零型 5–8 min |
| **U4 矩阵与收口**（2026-11-15 完成） | `tests/verify_map.py --all --matrix`、`tests/verify_iat.py --all --selftest`、pytest 扩充、E10 可解释弃权、CHARTER/PROGRESS/CHANGELOG 回写 | E9/E10 | U1–U3 | 扩展型 2–3 min |

## 4. 验收条目（先行写定，全部可证伪）

> 通用口径：
> - **分母 = 可判定格**：真值明确（外部工具可读出）且本工具本应给出答案的格。
> - **不可判定格（弃权格）单列**：如 UPX-ELF 无节表、SHT_NOBITS 无文件背书、无导入表。
>   弃权格给确定值 = **误报（FP）**；正确弃权 = 命中，但单独统计，**不得混入可判定格**凑 100%。
> - **强结论**（「该地址可落盘/不可落盘」也属强结论）必须能指名证据（单元名 + 区间算式）；
>   证据不足一律给 `unknown`/`abstain`，不得逼近。
> - 真值来自外部工具（readelf/objdump/pefile），**执行前冻结**；发现真值错必须另行取证并留痕，
>   **不得为了让矩阵好看而改真值**，也不得改判据迁就结果。

### E1 接口契约与零回归
- 判据：`python -m rekit.cli map <file> [--json]` 输出含 6 个顶层键 `format/units/entry/gaps/evidence/stats`；
  `units[]` 每项必备 `name/kind/file[off,size]/mem[addr,size]/mapped`；MCP `rekit_map` 既有行为（segments/sections 两种 kind）**逐字节不变**。
- 验证：`python -m pytest tests -q`（基线 **92 passed / 0 skipped**，本轮只增不减）；
  `python -m pytest tests/test_map.py -q`；`python -m pytest tests/test_mcp.py -q -k map`（3 条既有断言不许改）。

#### E1.1 查询输出契约（U2 落地；CLI 与 MCP 同一 dict）

两种问法回答的是**两个不同问题**，不得合并成一个模糊答案；输出必须能区分，
且只看裸地址结果的调用方不会被告知"可改"。

| 字段 | 裸地址 `query_mode="addr"` | 节级 `query_mode="section"` | 文件偏移 `query_mode="offset"` |
|---|---|---|---|
| `status` | hit / not_in_file / unmapped / multi | 同左 | hit / unmapped / multi |
| `offset` | hit 时给文件偏移；其余为 null | 同左（按节身份解析后） | — |
| `section` | 仅 NOBITS 反例取证时出现（如 `.tbss`） | 恒出现（请求的节名） | — |
| `section_matched` | **不出现** | 恒出现（该节是否存在且覆盖该地址） | — |
| `host_section` | NOBITS 且算术落点有宿主字节时出现 | 同左 | — |
| `addrs` / `units` | — | — | 恒出现（multi 时给全部解） |

- 裸地址口径（保守）：重叠地址（`.tbss` 与 `.init_array` 同址）判 `not_in_file` + `host_section`，
  **不宣称可改**；节级口径只在调用方明确指定节身份时，才按该节类型回答。
- `--section` 只能配合 `--addr`（文件偏移没有节身份），违反 → 退出码 2；`section` 不覆盖该地址
  → `status=unmapped`、`section_matched=false`，不静默退回裸地址结果。
- 文本通道以 `[bare]` / `[section .init_array]` / `[offset]` 标签区分；JSON 通道以 `query_mode` 区分。
- MCP `rekit_map` 传入 `addr`/`off`/`section` 时，结果多出 `query` 对象，内部结构与上表逐字段一致；
  不传查询参数时，输出与 M1/M2 既有行为逐字节不变。

### E2 ELF 段映射 100%
- 判据：全部样本的 **每个 PT_LOAD 段**，(p_offset, p_vaddr, p_filesz, p_memsz) 与 readelf -lW 逐段全等；
  且对每段的 3 个探针地址（首字节、末字节 filesz-1、若 memsz>filesz 则 filesz 处的零填充点）双向换算全部正确。
- 验证：`python tests/verify_map.py --all --matrix --dim elf_seg`；真值 `map_ground_truth.json`。
- 对拍：readelf -lW（**进程独立**）+ pyelftools（实现独立）双源，不一致即报。

### E3 ELF 节级一致性与不可落盘区
- 判据：对每个 `SHF_ALLOC` 且非 `SHT_NOBITS` 的节，`vaddr→offset` 结果必须等于 `sh_offset`（readelf -SW 真值）；
  **NOBITS 无文件表示，算术判定的优先级低于节类型**：`SHT_NOBITS`（.bss/.tbss）必须答 `not_in_file`，
  且 `offset` 必须为空（不得向 map & patch 宣称"此地址可改"）；不属于任何 LOAD 的节必须答 `unmapped` 并注明。
- 反例（为什么不能只看算术）：`dyn_static .tbss` addr=0x49ee40 off=0x9de40 size=0x28 NOBITS；
  覆盖单元 LOAD#3 off=0x9de10 vaddr=0x49ee10 filesz=0x5cb8 memsz=0xb4f8；
  `delta = 0x30 < filesz`，算术落点 0x9de40 处确有真实机器码——但那是宿主节的字节，不是 TLS 模板。
  故 NOBITS 判 `not_in_file` 的同时，必须用**独立字段**报告该地址被哪个宿主节覆盖
  （实测 `.init_array`，与 `.tbss` 同地址；字段语义与 `not_in_file` 并存，不合并）。
- 已知限制：NOBITS 节与后续节共用文件偏移（TLS 布局下 `.tbss` 的 `sh_addr` 还与
  `.init_array`/`.fini_array`/`.data.rel.ro` 地址重叠）。裸地址查询保守按 NOBITS 判；
  节级一致性按**节身份**查询：每个节仍须精确命中自己的 `sh_offset`，一格不差。
- 弃权格：UPX-ELF（`e_shnum=0`，节表被移除）→ 必须答「节表缺失」而不是 0 节或猜。

### E4 PE 节映射 100%
- 判据：每个样本 **每个节**的 (VA, VSize, RawPtr, RawSize) 与 `objdump -h` 逐节全等；
  每节 3 个探针（RVA 首字节、rawsize-1、若 vsize>rawsize 则 rawsize 处）双向换算正确；
  **`RawSize == 0` 的节：整节 `not_in_file`**（整节无任何文件字节，比"节首 hit"更严；实测 UPX0）；
  **header 区**：`RVA < SizeOfHeaders` 且 `SizeOfHeaders <= 第一节 RawPtr` 时必须 `offset == rva`（实测校验该前提，不满足就报 caveat 而非硬算）。
- 弃权格：`VirtualSize == 0`（老链接器）→ 以 RawSize 兜底，并在 evidence 里注明用了兜底。

### E5 边界与空洞语义
- 判据：区间一律 **左闭右开**；四类边界逐一断言：
  ① 区间末字节（size-1）命中、区间外 1 字节（size）不命中；
  ② 段/节之间的文件空洞 → `unmapped`（不是"最近段"）；
  ③ ELF 对齐填充（p_offset..p_filesz 之内但节不覆盖）→ 仍算该 LOAD 命中（文件背书存在，如实标注"pad"）；
  ④ `p_filesz == 0` 的 LOAD（纯 bss 段）→ 任何地址都 `not_in_file`，不得崩。
- 判据不许"容错 +1/-1"：差一字节即 FAIL。

### E6 IAT 定位与解码
- 判据：每个 PE 样本的每个 IAT slot → `(dll, name|#ordinal, hint)`，与 `objdump -p` 的 "The Import Tables" 段
  （DLL 名 + vma + hint/name 表）逐项全等；slot 数 = Σ(每个 descriptor 的 thunk 个数)。
- 弃权格：无导入表的 PE（如自构造 minidll 若为 0 导入）→ 明确 `no_imports`。
- U3 落地口径（2026-11-15）：
  - `hello_go.exe` 的 objdump 导入记录不可用（Go 长节名 `/nn` 致 objdump 的 RVA→节映射错位，
    把 `.idata` 解释成 `.zdebug_info`），真值中已标 `objdump_imports_reliable=False`；
    该样本只与 pefile 主源对拍并留痕，**不降级为"跳过该样本"**（其 143 格仍计入）。
  - 加壳样本（UPX，`OriginalFirstThunk=0`）的**解码**照常对拍并计入 `iat_packed`，
    与**修复**能力分开统计，互不冲抵。

### E7 IAT 修复雏形（往返可证伪）
- 判据：构造「被 loader 填充过的镜像副本」（把每个 IAT slot 写成 `0x7FF800000000 + i` 的伪地址）→
  修复能把每个 slot 回解成原 `(dll, func)` 并写回 hint/name RVA →
  **修复后 IAT 区间与原始文件的 IAT 区间逐字节全等**（sha256 相等）。为 0 个样本通过即 FAIL。
- 反例要求：故意篡改 1 个 slot 使其不对应任何导入项 → 必须报 `unresolved` 且**不写**该 slot（不许猜）。
- U3 落地补充（2026-11-15）：
  - 实现名 `repair_bytes(data)` / `repair_file(src, dst)`；`dst==src` 一律拒绝（同串与同一真实路径都拒），
    写盘走 `dst.tmp` + `os.replace`。
  - **幂等**：同一输入两次写同一 `--repair-out` 路径，产物 sha256 必须相等；原样本 sha256 必须不变。
  - **加壳单列**：`OriginalFirstThunk=0` → 加载后名称源被覆盖 → 全部 `unresolved` 且
    `wrote_any=False`；与未加壳成功率分开报，不合并。
  - **未加载原件必须拒绝**：槽值 < ImageBase → 全部 `unresolved`、字节不动、CLI 退出码 4。

### E8 负路径与不猜
- 判据：非 ELF/PE、截断文件、`vaddr` 超过 `p_vaddr+p_memsz`、RVA 超过 `SizeOfImage`、负数/非整数输入
  → 一律 `unmapped`/`not_in_file`/一行可读错误，**零 traceback**，退出码与 M1 分层一致（2 分诊失败 / 3 解析失败）。

### E9 混淆矩阵裁决
- 判据：`tests/verify_map.py --all --matrix` 一次性产出 **4 张矩阵**（ELF 段换算、ELF 节换算、PE 节换算、IAT slot），
  口径：可判定格分母、弃权格单列、`unmapped` 只在真值为「不在映射内」时算命中、越界给确定值记 FP。
- PASS 条件：可判定格命中率 100% + 弃权格正确弃权 100% + FP 0 + 强结论证据违规 0 + 解析异常 0。
- 载体自证：`--selftest` 人为翻转 1 个真值 → 退出码必须非 0。

### E10 可解释弃权（U4 新增，只增字段）
- 判据：**结构上不可修复**的样本，查 IAT 时输出必须自带原因，不得只给一堆 `unresolved`。
- 契约：
  - `locate_bytes` 顶层 `repairable`（bool）+ `caveats`（人话原因数组）；每个 descriptor 带
    `repairable`/`reason`；`repair_bytes` 报告同步带出 `repairable`/`caveats`；
  - CLI 文本：`Repair: 可以 / 不可完整修复` 一行 + `! <caveat>` 行 + 描述符尾部 `[不可修复]`；
    `--repair-out` 有 unresolved 时额外打印原因（退出码仍为 4）；
  - MCP：新增只读工具 `rekit_iat`（**不暴露 repair**：写盘动作不经协议），description 写明
    `repairable=false` 的含义。
- 双向断言：加壳样本必须 `repairable=false` 且 caveats 含 `OriginalFirstThunk=0` 与"脱壳"；
  未加壳样本必须 `repairable=true`——只测一个方向会让"永远报不可修复"也通过。
- 措辞纪律：只报结构后果（INT 与 IAT 同址 → 加载态名称源被覆盖），**不据单一信号断言"这就是加壳"**；
  是否加壳由 M2 指纹层裁决（避免用 IAT 结构去抢指纹层的结论）。

## 5. 样本与对拍源（全部本地，无需下载）

> 18 个样本 = `tests/fixtures/` 10 个 + `tests/samples/fingerprint/` 8 个；sha256 已在 M2 `sample_manifest.json` 登记，本卡不重复。

| 组 | 样本 | 映射相关的关键事实 | 真值来源 |
|---|---|---|---|
| ELF 动态 | `dyn_pie` / `dyn_nopie` / `dyn_norelro` / `dyn_execstack` | 4 个 LOAD、含 .bss（memsz>filesz） | readelf -lW/-SW + pyelftools |
| ELF 静态 | `dyn_static` | 4 LOAD、无 PT_INTERP | 同上 |
| ELF 系统 | `bin_ls.elf` | 4 LOAD / 30 节 / NOBITS 占位 | 同上 |
| ELF Go | `hello_go_linux` | 静态、`.go.buildinfo` 等非常规节 | 同上 |
| ELF 加固 | `busybox-1.35.0-musl-x86_64` | stripped、10 节 | 同上 |
| ELF 加壳 | `upx_dyn_pie` | **节表被移除（e_shnum=0）** → 节级弃权格；段表仍在 | readelf -lW（节级只取"节表缺失"事实） |
| PE 自构造 | `minipe.exe` / `minipe_fakerich.exe` / `minidll.dll` | 1–2 节、RawPtr=0x200、VSize≈RawSize | objdump -h/-p + pefile |
| PE 真实 | `cli-64.exe` / `hello_rust.exe` / `putty-64bit.exe` | 多节、有导入表 | 同上 |
| PE Go | `hello_go.exe` | COFF 长节名 `/nn`、节数多 | 同上 |
| PE 加壳 | `upx_cli-64.exe` / `upx_putty-64bit.exe` | 节名 UPX0/1、RawSize 与 VSize 关系异常 | objdump -h/-p |

**权威性标注（沿用 M2 口径，按条目区分）**：
- readelf/objdump（GNU binutils 2.47）= **进程独立**；
- pefile 2024.8.26 / pyelftools 0.33 = **实现独立**（同为 Python 解析同格式，不构成进程独立）;
- 两者不一致时：**先记录差异，再判定谁错**，不得择"顺眼"的一方。

## 6. 缺口与风险登记

| 编号 | 缺口/风险 | 影响 | 处置 |
|---|---|---|---|
| G1 | UPX-ELF 无节表 | 节级换算不可判定 | E3 的弃权格，必须答「节表缺失」，不得记 0 节 |
| G2 | UPX-PE 的 `VSize` 与 `RawSize` 关系被壳改写 | 节区间可能"看起来合法但不真实" | 只对文件字节负责：`file` 区间取 RawSize，`mem` 区间取 VSize，两者不一致如实标注 |
| G3 | 自构造 PE 的 `VirtualSize` 与 `RawSize` 相等（构造器写死） | 覆盖不到 vsize>rawsize 的分支 | 用 `putty/cli-64/go` 真实样本覆盖；并新增 1 个"构造器写 vsize>rawsize"的 fixture 补格（若现有样本已覆盖则不加） |
| G4 | `SizeOfHeaders > 第一节 RawPtr`（异常但可能存在） | header 区直接映射会越界 | 实测校验该前提，不满足时 header 区答 `unmapped` 并报 caveat |
| G5 | IAT 被 bound import 改写（TimeDateStamp≠0） | IAT 原值不是 hint/name RVA | 用 INT 优先；INT=0 且 bound → `not_repairable`，不猜 |
| G6 | 差一字节错（左闭右开写错） | 全表静默错 | E5 四条边界硬断言 + 探针取 `size-1` 与 `size` |

## 7. 净室纪律

1. 只用 PE/ELF 公开规范 + 本卡签发的实测观察；不抄任何现成工具的实现细节。
2. 「能落盘/不能落盘」是强结论：必须指名映射单元 + 区间算式，不许"大概在这个段里"。
3. 不猜：证据不足给 `unknown`/`abstain`，并写明缺什么。
4. 真值冻结后不改；发现真值错 → 重新取证 + CHANGELOG 留痕，矩阵里保留修正记录。
5. 误报口径：对 `unmapped`/`not_in_file` 给出确定偏移（或反之）记 1 次 FP。

## 8. 完成标准映射（CHARTER M3）

> 原文：换算对全部段 100% 正确（与手工计算+工具对照）。

| 原文要素 | 由谁裁决 |
|---|---|
| 全部段 | E2（ELF 全 LOAD 段逐段 × 3 探针）+ E4（PE 全节逐节 × 3 探针） |
| 100% 正确 | E9 矩阵：可判定格 100%、弃权格 100%、FP 0 |
| 与手工计算对照 | 探针地址的算式在 `verify_map.py` 里**独立重算**（不复用实现），双算比对 |
| 与工具对照 | readelf/objdump 进程独立 + pefile/pyelftools 实现独立 |

## 9. 基线纪律与回写

- 粒度：U1/U2/U4 扩展型 2–4 min；U0/U3 从零型 5–8 min；当日单元数按降档条款从轻。
- 返工计数：实现或验证脚本修一次 = 1 返工；≥3 次 → 次日继续降档。
- 回写：PROGRESS 一行（完成项 + 耗时 + 工具轮 + 返工 + 新规则 R36+）；判据若变 → CHANGELOG（只增不删）。
- 证据归档：`work/evidence_map_<日期>.log`；矩阵输出同目录。

## 10. 本卡的工作文件

| 文件 | 用途 |
|---|---|
| `work/collect_map_gt.py` / `work/map_ground_truth.json` | 真值采集器与**冻结快照**（含 sha256、采集命令、工具版本） |
| `work/tests/verify_map.py` | E9 载体：`--all --matrix`、`--dim`、`--selftest` |
| `work/tests/verify_iat.py` | E6/E7 载体：对拍 + 反例 + 幂等 + `--selftest`（加壳单列） |
| `work/evidence_map_2026-11-15.log` | 证据日志（append-only） |
| `work/rekit/mapview.py` | M3 实现（纯 stdlib） |
| `work/rekit/iat.py` | IAT 定位/解码/修复（纯 stdlib，写回只产新文件） |
| `work/tests/test_map.py` / `work/tests/test_iat.py` | 回归断言（只增不减） |
| `work/pack03/{CHARTER,PROGRESS,CHANGELOG}.md` | 收口回写 |
