"""rekit 公共库接口（对外承诺稳定；契约见 pack\\03_路线图与章程\\LIBRARY_API.md）。

只有本模块导出的符号是公开承诺；其余 `rekit.*` 模块是内部实现，签名与返回结构
可随时变化，不构成 API。新增公开能力时：先登记 LIBRARY_API.md，再在 `examples\\`
补一个 import 示例，并在 `tests\\verify_api.py` 加一项与 CLI 的对拍。

输入一律是文件系统路径（str / os.PathLike），不读 cwd、不读环境变量；
样本路径由调用方给出。失败语义沿用各实现：读不了抛 OSError，格式不符可能抛
AssertionError（`python -O` 下断言被移除），所以先用 `detect_format` 判格式。
"""
from .cli import build_info, detect_format
from .dotnet import build as build_dotnet
from .dotnet import probe as probe_dotnet
from .elf import parse as parse_elf
from .pe import parse as parse_pe

__all__ = [
    "build_info",        # 分诊报告（CLI `rekit info --json` 的同一构造器）
    "detect_format",     # "elf" / "pe" / None
    "parse_pe",          # PE 头/节/导入导出（dict，字段见 LIBRARY_API.md）
    "parse_elf",         # ELF 头/节/动态段/安全属性（dict）
    "build_dotnet",      # .NET 程序集结构报告（dict，CLI `rekit dotnet --json` 同一构造器）
    "probe_dotnet",      # 轻量探测 {is_cli, cli_rva, reason}
]
