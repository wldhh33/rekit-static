"""允许 `python -m rekit <cmd> ...`（等价于 `python -m rekit.cli`）。"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
