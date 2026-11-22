#!/usr/bin/env python3
r"""首次 clone 状态判定：区分「从未 setup」与「setup 过但资产坏了」。

背景：样本与工具链按许可/体积策略不入库，work 下的 junction 也不入库。
干净 clone 直接跑 status.py / gate.ps1 必然失败——这是缺资产，不是仓库损坏。
但「缺资产」与「setup 过之后被删坏」需要给读者不同的话：前者是引导，后者是 FAIL。

判据（三类独立证据，任一存在即视为「setup 过」）：
  1. setup 标记   2026-11-15\m3-task-card\work\.rekit_setup.json（setup.ps1 成功后写入）
  2. work junction  work\rekit、work\tests、work\pack03（任一存在）
  3. 资产树        m3 samples、m2 samples、m2 tools（任一非空）
三类全部缺失才判 not_setup。任一存在但仍有缺项 = initialized（按 FAIL 报，
由调用方给出缺什么），不是「未初始化」。

用法:
  python "pack\tools\firstrun.py" --state     # 只打印 not_setup / initialized
  python "pack\tools\firstrun.py" --json      # 完整细节
退出码: 0 = initialized / 3 = not_setup（便于脚本分支，不把未初始化混进 0/1）
"""
import argparse
import json
import os

MARKER = os.path.join("2026-11-15", "m3-task-card", "work", ".rekit_setup.json")
LINKS = (
    os.path.join("2026-11-15", "m3-task-card", "work", "rekit"),
    os.path.join("2026-11-15", "m3-task-card", "work", "tests"),
    os.path.join("2026-11-15", "m3-task-card", "work", "pack03"),
)
ASSETS = (
    os.path.join("2026-11-15", "m3-task-card", "work", "samples"),
    os.path.join("2026-11-15", "m2-task-card", "work", "samples"),
    os.path.join("2026-11-15", "m2-task-card", "work", "tools"),
)


def _nonempty_dir(path):
    """目录存在且至少有一个条目。空目录/不存在都算「没有资产」。"""
    try:
        with os.scandir(path) as it:
            return next(it, None) is not None
    except OSError:
        return False


def classify(root):
    """返回判定细节；state 只有 not_setup / initialized 两值。"""
    marker = os.path.join(root, MARKER)
    links = [p for p in LINKS if os.path.isdir(os.path.join(root, p))]
    assets = [p for p in ASSETS if _nonempty_dir(os.path.join(root, p))]
    marker_exists = os.path.isfile(marker)
    evidence = marker_exists or bool(links) or bool(assets)
    return {
        "state": "initialized" if evidence else "not_setup",
        "marker": marker_exists,
        "links_present": links,
        "links_missing": [p for p in LINKS if p not in links],
        "assets_present": assets,
        "assets_missing": [p for p in ASSETS if p not in assets],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="首次 clone 状态判定")
    ap.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), help="仓库根（默认按本文件位置推断）")
    ap.add_argument("--state", action="store_true", help="只打印 state 单词")
    ap.add_argument("--json", action="store_true", help="打印完整判定细节")
    args = ap.parse_args(argv)

    info = classify(os.path.abspath(args.root))
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    elif args.state:
        print(info["state"])
    else:
        print("state=%s marker=%s links=%d/%d assets=%d/%d"
              % (info["state"], "present" if info["marker"] else "absent",
                 len(info["links_present"]), len(LINKS),
                 len(info["assets_present"]), len(ASSETS)))
    return 0 if info["state"] == "initialized" else 3


if __name__ == "__main__":
    raise SystemExit(main())
