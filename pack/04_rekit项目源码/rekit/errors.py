"""rekit 的公开异常类型（契约见 pack\\03_路线图与章程\\LIBRARY_API.md）。

失败语义（对库调用方承诺的是类型，不是异常消息文本）：
  OSError         —— 路径读不了（不存在 / 权限 / 是目录）
  FormatMismatch  —— 输入不是目标格式（例如 `parse_pe` 收到 ELF）
  MalformedBinary —— 格式标识对，但结构截断 / 损坏，底层解不下去
  TypeError       —— 调用方参数类型用错（路径不是 str / os.PathLike）

这些判定不走 `assert`：`python -O` 会把断言整段剥掉，失败会退化成静默错值；
显式 raise 在 -O 下行为不变（tests\\verify_api.py 用 `-O` 实跑同一判据）。

**不继承 `ValueError`**：仓内多处 `except ValueError` 表达的是"格式不认识 / 参数不合法"
（退出码 2），若新异常混入该族，解析失败会被静默降级成格式不认识；而旧实现抛的是
`AssertionError`，从来不由 `except ValueError` 接住。独立成族才能保证行为兼容。
"""


class RekitError(Exception):
    """rekit 自定义异常的基类：`except RekitError` 一次兜住格式与结构两类失败。"""


class FormatMismatch(RekitError):
    """输入不是该函数要求的格式，或缺少该格式的签名（MZ / PE\\0\\0 / \\x7fELF）。"""


class MalformedBinary(RekitError):
    """格式签名匹配，但头部/表结构截断或损坏，底层解析无法完成。"""
