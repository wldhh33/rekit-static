# 知识卡：静态分析流水线（上）—— Ghidra 无头流水线（2026-11-14）

> 阶段二 #4（上）。今日 rekit 收口日正好补齐了自家流水线的"分诊级"入口（cli.py），
> 本卡讲行业标杆 Ghidra 的"深挖级"无头流水线——两级结构合成一条完整静态分析流水线。

## 一、为什么需要"无头流水线"（headless）

GUI 反编译器（IDA/Ghidra 桌面版）是**交互式**工具：人在环、逐个看、不可复现。
但真实工作负载里三类场景必须脱离 GUI：

| 场景 | GUI 痛点 | headless 价值 |
|---|---|---|
| 批量分诊（100+ 样本入库） | 手点不可能 | 一条命令循环 |
| 可复现研究（writeup/证据链） | 截图不构成证据 | 脚本输出可 diff、可进 git |
| 与外部工具拼接（CI/蜜罐自动分析） | 无 API 入口 | stdout/JSON 即接口 |

**流水线两级结构**（rekit 今天收口正好补齐第一级）：
`分诊级（rekit cli：magic→格式→保护态→导入导出概要，毫秒级）→
深挖级（Ghidra headless：反汇编+反编译+函数发现+交叉引用，分钟级）`。
分诊级决定"要不要深挖、往哪个方向挖"，成本差三个数量级。

## 二、Ghidra 项目模型（headless 的心智基础）

```
Ghidra Project（目录：.gpr 文件 + .rep 仓库目录）
  └── Program（导入后的二进制 + 分析结果 + 程序数据库，全部状态存这里）
```
- **关键认知**：Ghidra 的分析结果不是"重新计算"的，是存进 Program 数据库的——
  所以 headless 分两步：`-import`（导入+自动分析）和 `-process`（对已入库 Program
  跑脚本），后者不重复分析，这就是"增量流水线"的基础。
- 自动分析（auto-analysis）本身是插件流水线：loader 识别格式 → 字符串/入口
  → 反汇编发散 → 函数识别 → 数据类型/引用标注 → （可选）反编译。

## 三、analyzeHeadless 速查（三阶段）

```bash
# 1) 导入 + 全自动分析 + 跑后处理脚本（最常用形态）
analyzeHeadless <项目目录> <项目名> \
    -import <样本> \
    -scriptPath <脚本目录> -postScript my_report.py \
    -deleteProject          # 一次性任务不留项目残骸

# 2) 对已入库样本批量跑脚本（不重复分析）
analyzeHeadless <项目目录> <项目名> \
    -process <样本名模式> -recursive \
    -scriptPath <脚本目录> -postScript my_report.py

# 3) 常用修饰
-readOnly            # 不写回 Program（纯观察）
-max-cpu <N>         # 并行分析核数
-loader <格式>       # 强制 loader（识别失败时的逃生门，类比 rekit --format）
```
退出码即脚本成败信号，`-deleteProject` 用于 CI 场景的幂等。

## 四、postScript 脚本 API 基础（Python/Jython）

脚本运行时有三个全局对象直接可用（无需 import）：

| 对象 | 是什么 | 常用操作 |
|---|---|---|
| `currentProgram` | 当前 Program 句柄 | `getLanguage()`/`getMemory()`/`getFunctionManager()` |
| `monitor` | 进度条句柄 | 长循环里 `monitor.checkCanceled()` |
| `state` | 脚本运行状态 | `state.getArgs()` 取脚本参数 |

最小可用脚本骨架（导出函数清单）：
```python
# my_report.py — Ghidra postScript（Jython）
fm = currentProgram.getFunctionManager()
out = open("/tmp/functions.txt", "w")
for f in fm.getFunctions(True):          # True = 按地址序
    out.write("%s @ %s\n" % (f.getName(), f.getEntryPoint()))
out.close()
print("exported %d functions" % fm.getFunctionCount())
```
- 高层 API 在 `FlatProgramAPI`（脚本基类已继承）：`getGlobalFunctions(name)`、
  `currentAddress`、`toAddr(long)`、`createBookmark()` 等。
- Ghidra 12 起 Debugger/源码构建需 Python 3.9–3.13；脚本层 Jython 语法按 Python 2 写
  （print 语句兼容，但建议写函数式），CPython 插件（PyGhidra）是新方向。

## 五、和 rekit 的同构关系（今日收口的呼应）

| 概念 | rekit（自研分诊级） | Ghidra（深挖级） |
|---|---|---|
| 格式识别 | `cli.py detect_format()`（两级 magic） | loader 插件协商 + `-loader` 强制 |
| 入口 | e_entry / AddressOfEntryPoint | `getSymbol("entry")` |
| 函数清单 | 符号表解析（有限） | 函数识别引擎（反汇编推导，无符号也行） |
| 保护态 | checksec 四态 | 安全属性标注 |
| 批处理 | `for f in *; rekit.cli $f` | `-process` 批模式 |
| 失败语义 | exit 2（分诊）/ exit 3（解析） | 进程退出码 + 日志 |

**结论**：两者不是竞争是分层——rekit 毫秒出分诊报告，Ghidra 分钟出深挖报告；
未来 rekit M2（指纹）的输出可直接作为 Ghidra headless 的路由前置（`-loader` 提示）。

## 六、练习建议（装机后第一步，约 20 min）

1. **装机**：Ghidra 12.2（JDK 21 本机已备 ✓，Ghidra 本体未装——列阶段二环境准备项）
2. **热身**：`analyzeHeadless /tmp/ghidra-proj demo -import tests/fixtures/bin_ls.elf
   -postScript 函数清单脚本 -deleteProject`，对 30 节的系统 ls 跑通全链路
3. **交叉验证**（闭环纪律）：脚本导出的函数数 vs `readelf -sW bin_ls.elf | grep FUNC`
   ——Ghidra 函数识别（含无符号函数）应 ≥ 符号表函数数，多出的就是 local 静态函数
4. **进阶**：给脚本加参数（`getScriptArgs()`），批量处理 fixtures 10 样本，输出统一
   JSON——这就是"分诊→深挖"两级流水线的第一版

## 七、坑位预告（先记下，装机后验证）

- **G1**：`-import` 会全量自动分析（慢），只要元数据时用 `-noanalysis` 也要显式关
- **G2**：项目目录被上次运行锁住（.lock 文件）→ headless 前清残骸或用 `-deleteProject`
- **G3**：Jython 与 CPython 语法差异（`except Exception, e` 老写法、无 f-string）——
  模板代码先在 CPython 里 lint 再搬
- **G4**：`-process` 模式下 `currentProgram` 每轮变化，跨样本状态不要存全局变量
