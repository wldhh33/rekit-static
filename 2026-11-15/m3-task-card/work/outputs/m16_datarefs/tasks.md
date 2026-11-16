# M16 任务清单（datarefs）

- [x] T1 口径与 spec：对象定义/引用形态/三档归因/分母先行/格式层拒收（`spec.md`）
- [x] T2 DWARF 扩展：保留 `DW_TAG_variable` 与类型 DIE（`paramdecl.py`，形参语义不变）
- [x] T3 层实现：`rekit/datarefs.py`（声明→对象、形态→引用点、三档归因、指针槽、渲染）
- [x] T4 CLI：`rekit datarefs <file> [--section] [--json] [--limit]`（`cli.py`）
- [x] T5 正样本：`tests/make_datarefs_full.py` → `tests/m16_fixtures/datarefs_full.exe`
- [x] T6 funcreport 回接：`SCHEMA=2`、七层白名单、`data_refs` 状态映射（`funcreport.py`）
- [x] T7 单测：`tests/test_datarefs.py`（23 项）+ `tests/test_funcreport.py` 同步
- [x] T8 外部抽查：`tests/verify_datarefs.py`（readelf/objdump 独立重算 + 可失败自证）
- [x] T9 文档与全量回归：`TASK_m16_datarefs.md` / `NUMBERS_LEDGER.md` / 章程三件套
- [x] T10 回归稳定性：修 `paramdecl._abbrev_table` 以 `id()` 作缓存键导致的 `full-e`
  偶发失败（约 1/15）；`no_declaration_source` 拆“无 DWARF 节 / 有节但解析失败”；
  12 次新鲜进程 verify 全 PASS，新增 2 项护栏单测（R111）
