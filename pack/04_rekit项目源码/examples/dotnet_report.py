#!/usr/bin/env python3
""".NET 示例：用 import（不是 subprocess）调用 rekit.api.build_dotnet，输出可核对数字。

用法: python examples\\dotnet_report.py <托管 DLL/EXE>
输出: JSON（stdout）。字段与 `rekit dotnet <file> --json` 的对应项逐项相等，
      由 tests\\verify_api.py 机械核对。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))          # 仓库内直接可跑，不依赖安装

from rekit import api                              # noqa: E402


def main(argv):
    if len(argv) != 1:
        print("用法: python examples\\dotnet_report.py <托管 DLL/EXE>", file=sys.stderr)
        return 2
    r = api.build_dotnet(argv[0])
    out = {
        "format": "PE",
        "status": r["status"],
        "assembly": r["assembly"],
        "file": r["file"],
        "denominators": r["denominators"],
        "ntypes": len(r["types"]),
        "nmethods": len(r["methods"]),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
