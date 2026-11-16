# 基线B任务卡 · 2026-11-07（速度基线测试）

## 任务
新领域从零：编写 `tests/make_minipe.py`（独立构造一个最小 PE32+ 文件，带 2 个节 +
1 个 DLL 的导入表）与 `rekit/pe.py`（手解解析该 PE：头/节表/入口/导入 DLL+函数名）。
构造与解析代码相互独立，构成双向验证；外部再以 `objdump -x` 三方交叉验证。

## 验收标准（执行前写定）
- B1：pe.py 输出的 Machine/Magic/EntryPoint/ImageBase/Subsystem/SizeOfImage
  与构造参数及 objdump -x 输出三方一致
- B2：节表（.text/.idata 的 VA/RawPtr/RawSize）与 objdump -x 一致
- B3：导入表解析出 KERNEL32.dll → ExitProcess（hint/name 结构手解），
  与构造参数一致
- B4：import 白名单 {struct, sys}（AST 证据）

## 记录口径
耗时（分）/ 工具调用轮次 / 返工次数
