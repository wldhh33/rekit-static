#!/usr/bin/env python3
"""PE 示例：用 import（不是 subprocess）调用 rekit.api.parse_pe，输出可核对数字。

用法: python examples\\pe_report.py <pe 文件>
输出: JSON（stdout）。字段与 `rekit info <file> --json` 的对应项逐项相等，
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
        print("用法: python examples\\pe_report.py <pe 文件>", file=sys.stderr)
        return 2
    r = api.parse_pe(argv[0])
    out = {
        "format": "PE",
        "machine": r["machine"],
        "bits": 64 if r["magic"] == 0x20B else 32,
        "entry": r["entry"],
        "image_base": r["image_base"],
        "subsystem": r["subsystem"],
        "nsections": r["nsect"],
        "sections": [{"name": s[4], "addr": s[0], "offset": s[2], "size": s[3]}
                     for s in r["sections"]],
        "imports": sorted([dll, funcs] for dll, funcs in r["imports"]),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
