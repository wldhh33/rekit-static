# M17 任务清单（dotnet）

- [x] T1 样本来源：确认本机真实 `mscorlib.dll` / `System.Console.dll`；用 `csc`
  编译受控样本 `samples/m17/_gen/RekitSample.dll`（方法体/字符串/泛型/抽象/接口/
  PInvoke/EH），局限写入 `spec.md` 与报告 caveat
- [x] T2 口径规格：`outputs/m17_dotnet/spec.md`（声明链/表流/分母/方法体/IL/跨层/DoD）
- [x] T3 层实现：`rekit/dotnet.py`（CLI 头、元数据根、45 表 schema、14 表行值、
  TypeDef/MethodDef、tiny/fat、EH、IL 边界、#US、泛型、跨层说明）
- [x] T4 CLI：`rekit dotnet <file> [--json] [--limit] [--detail-methods]
  [--detail-insns] [--il-token]`（`cli.py`）
- [x] T5 funcreport 守卫：.NET → `not_applicable`（写原因、指向 `rekit dotnet`，
  `absence_summary` 覆盖 8 行）
- [x] T6 单测：`tests/test_dotnet.py`（19 项：分母恒等式、类型分母、无体原因、
  `Add` 边界、`switch`/`r8` 操作数、EH、#US、泛型、跨层、not_dotnet、CLI 目录清零、
  BSJB 坏、声明长度越界、坏 RVA、未知 opcode、funcreport、确定性/只读）
- [x] T7 外部抽查：`tests/verify_dotnet.py`（dnfile 表/行/偏移、dncil IL 逐条、
  CLR 反射、#US 逐条、4 项可失败自证）→ `work/evidence_m17_dotnet.json`
- [x] T8 全量 IL 加测：真实样本全部方法逐条 dncil 比对（console 396/396、
  mscorlib 25315/25315）→ `work/evidence_m17_il_full.log`
- [x] T9 全量回归：pytest 528 passed；verify 20/20 PASS
  （`evidence_m17_pytest.log` / `evidence_m17_verify_all.log`）
- [x] T10 文档与账本：`TASK_m17_dotnet.md`、`NUMBERS_LEDGER.md`（R112）、
  章程三件套
