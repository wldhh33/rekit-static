# checksec 三态知识卡 + 规则沉淀（2026-11-10）

## 一、NX / RELRO / PIE 判定语义（对齐 checksec / pwntools）

| 机制 | 判定来源 | 输出语义 |
|---|---|---|
| NX | `PT_GNU_STACK`(0x6474e551) 的 p_flags | 含 X(1) → disabled（栈可执行）；RW → enabled；**段缺失 → disabled（老内核回退栈可执行）** |
| RELRO | `PT_GNU_RELRO`(0x6474e552) 存在性 × 立即绑定 | 无段 → none；有段+立即绑定 → full；有段+延迟绑定 → partial |
| PIE | e_type × PT_INTERP | ET_EXEC(2) → no；ET_DYN(3)+INTERP → yes；ET_DYN 无 INTERP → dso |
| 立即绑定 | DT_BIND_NOW(24) ∨ DT_FLAGS(30)&0x8 ∨ DT_FLAGS_1(0x6ffffffb)&0x1 | 三路任一命中即 BIND_NOW |

**为什么 RELRO 分两态**：PT_GNU_RELRO 只是告诉加载器"这段（.init_array/.fini_array/.got/.dynamic 等）重定位完成后降为只读"。若仍有延迟绑定（PLT 惰性解析），`.got.plt` 需要运行时可写 → mprotect 降只读发生在首次解析之后，窗口仍在 → Partial。BIND_NOW 让所有符号在启动时解析完 → 整段一次性只读 → Full。

**NX 真正生效点**：PT_GNU_STACK 的 X 位控制的是**栈**（及内核对 READ_IMPLIES_EXEC 的继承），PT_LOAD 段的可执行性由各自 flags 决定——两者独立，所以 W+X 段扫描必须单独做（malware 常见 W+X 自修改段）。

## 二、今日实证数据（6 fixtures，readelf -hW/-lW/-d 权威推导 18/18 全等）

| fixture | 构造 | NX | RELRO | PIE | 关键证据 |
|---|---|---|---|---|---|
| bin_ls.elf | 系统二进制 | enabled | **full** | yes | FLAGS BIND_NOW + FLAGS_1 NOW |
| dyn_pie | gcc 默认 | enabled | partial | yes | 仅 FLAGS_1 PIE |
| dyn_nopie | -no-pie | enabled | partial | no | EXEC + GNU_RELRO 有 |
| dyn_static | -static | enabled | partial | no | 静态也有 PT_GNU_RELRO |
| dyn_norelro | -no-pie -z norelro | enabled | **none** | no | 无 PT_GNU_RELRO |
| dyn_execstack | -z execstack | **disabled** | partial | yes | GNU_STACK flags=0x7(RWE) |

## 三、新规则

- **R16 常量表必须经权威源校验后才可用于语义判定**：elf.py 的 DT_TAGS 显示名有 3 处错位史（15 误标 DEBUG、21 误标 JMPREL、23 误标 BIND_NOW），潜伏两天，直到今日 RELRO 语义需要 tag 24 精确值才爆雷。教训：**"能显示"≠"正确"**，凡进入判定逻辑的常量，落码前先用 readelf 实测值核对一遍（readelf -d 第一列即 tag 原值，是最好的对拍源）。
- **R17 语义型任务的样本布局先行**：三态判定类任务，先画"状态×样本"覆盖矩阵再动手——今日 2 个新 fixture（norelro/execstack）正是矩阵缺格倒逼出来的，避免了"6 个样本全是 partial+enabled 的同质化验证"假覆盖。
- **R18 工具写入权限分层**：Bash 以用户 z 运行，Write/Edit 工具走提权通道——root 属主的历史文件（tests/*.py、rekit/*.py）只能用 Edit/Write 改，heredoc/cat 追加会 Permission denied（今日返工 #1 的根因）。

## 四、遗留与证据等级

- 立即绑定 tag-24（旧式 DT_BIND_NOW）：已实现为防御性路径，**无真实样本覆盖**（现代 gcc/binutils 只产 FLAGS/FLAGS_1），证据等级 implemented-untested-by-sample。若 M2 需要，可手工 patch 动态段构造样本补测。
- PIE 的 dso 态：语义已实现（ET_DYN 无 INTERP），fixtures 无共享库样本，未覆盖——M1.5/M2 接触 .so 分析时补断言。
