# rekit JSON 输出契约（v0.1.0 冻结，2026-11-17）

> **冻结含义**：以下命令 `--json` 的字段名自 `v0.1.0` 起冻结。今后**改名或删除**任一字段按
> **破坏性变更**处理：必须升版本号、在本文件登记旧→新映射、并在 CHANGELOG 写迁移说明；
> 新增字段不算破坏性变更，但必须同步更新本文件。
>
> 契约只冻结**字段名与层级**，不冻结数值。所有命令的数值口径以对应模块文档与数字总账为准。

## 1. `rekit info <file> --json`

顶层键（15 个，正常分支全部存在；不适用写 `null`，不省略键）：

```
schema, path, format, arch, bits, type, entry, image_base, subsystem,
nsections, sections, security, imports, exports, dotnet
```

- `schema`：整数，当前 `1`。
- `format`：`"ELF"` / `"PE"`。
- `arch`：字符串（如 `"x86-64"`、`"AMD64"`）；未知机器返回十六进制字符串。
- `bits`：整数 `32` / `64`。
- `type`：ELF `"REL"/"EXEC"/"DYN"/"CORE"`；PE `"EXE"/"DLL"`。
- `entry`：整数（ELF 虚拟地址 / PE RVA）。
- `image_base`、`subsystem`：PE 有效，ELF 为 `null`。
- `nsections`：整数；`sections`：数组，元素键固定 `name, addr, offset, size`。
- `security`：仅 ELF，键沿用 `elf.parse()["security"]`（`nx, nx_reason, relro,
  bind_now, pie, gnu_stack_flags, relro_filesz, wx_segments`）；PE 为 `null`。
- `imports`：PE 为 DLL 名字符串数组（已排序）；ELF 为 `null`。
- `exports`：PE 为 `{"dll": str, "nfuncs": int}` 或 `null`；ELF 为 `null`。
- `dotnet`：PE 为 `{"is_cli": bool|null, "status": str, "reason": str|null}`；
  ELF 为 `null`。`status` 取值来自 `rekit.dotnet.STATUS_*`。

失败语义：退出码 `2` = 文件不存在/格式不可识别；`3` = 解析失败。失败分支不产出 JSON。

## 2. `rekit map <file> --json`

顶层键（10 个，正常分支全部存在）：

```
format, bits, entry, image, units, caveats, sections, evidence, stats, gaps
```

- 无 `schema` 键（历史原因，`format` 即稳定标识）；新增 `schema` 属新增字段，允许但需登记。
- 带 `--addr` / `--off` 时追加 `queries` 对象：
  - `queries.addr` 键：`query_mode, status, offset, unit, delta, reason`；
    带 `--section` 时追加 `section, section_matched`（`query_mode` 变为 `"section"`）。
  - `queries.off` 键：`query_mode, status, addrs, units, reason`。
- `status` 取值：`hit` / `not_in_file` / `unmapped` / `multi`。

## 3. `rekit ilflow <file> --json`

正常分支顶层键（12 个）：

```
schema, path, status, reason, assembly, caliber, caveats, cross_layer,
scope, denominators, methods, method_errors
```

错误分支（`status != "ok"`）只保证 7 个键：

```
schema, path, status, reason, caliber, caveats, cross_layer
```

消费方必须先判 `status`，再读其余键。

## 4. `rekit datarefs <file> --json`

正常分支顶层键（22 个）：

```
schema, path, format, section, status, reason, caliber, sections, sources,
objects, rejected, duplicates, denominator, sites, forms, tiers, unlifted,
unresolved_forms, pointer_edges, pointer_values_inside, caveats, limit
```

错误分支（解析/声明来源异常）只保证 4 个键：

```
schema, path, status, reason
```

退出码：`status ∈ {"ok", "no_data_sections", "no_declaration_source"}` 返回 `0`，其余返回 `2`。

## 变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v0.1.0 | 2026-11-17 | 首次冻结：`info` 新增并冻结；`map` / `ilflow` / `datarefs` 顶层字段按现行实现冻结 |
