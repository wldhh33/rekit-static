#!/usr/bin/env python3
# tests/test_firstrun.py — firstrun.classify 的可失败自证（2026-11-22）
#
# 判据：只有「setup 标记 / junction / 资产树」三类证据全部缺失才算 not_setup。
# 自证方式：同一个函数在合成目录上必须给出不同结论——
#   空树 → not_setup；只放任意一类证据 → initialized；全齐 → initialized 且无缺项。
# 若把判据写成恒真（永远 not_setup）或恒假（永远 initialized），
# 下面成对断言必有一边失败；空目录与空资产目录两条专门防“目录存在就算已初始化”。
import importlib.util
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
_spec = importlib.util.spec_from_file_location("rekit_firstrun", TOOLS / "firstrun.py")
firstrun = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(firstrun)


def _touch(path, text="x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_empty_tree_is_not_setup(tmp_path):
    info = firstrun.classify(str(tmp_path))
    assert info["state"] == "not_setup"
    assert info["links_present"] == []
    assert info["assets_present"] == []
    assert info["marker"] is False


def test_marker_alone_means_initialized(tmp_path):
    _touch(tmp_path / firstrun.MARKER)
    assert firstrun.classify(str(tmp_path))["state"] == "initialized"


def test_one_junction_alone_means_initialized(tmp_path):
    (tmp_path / firstrun.LINKS[0]).mkdir(parents=True)
    assert firstrun.classify(str(tmp_path))["state"] == "initialized"


def test_one_nonempty_asset_tree_means_initialized(tmp_path):
    _touch(tmp_path / firstrun.ASSETS[0] / "sample.bin")
    info = firstrun.classify(str(tmp_path))
    assert info["state"] == "initialized"
    assert info["assets_missing"] == list(firstrun.ASSETS[1:])


def test_empty_asset_dir_is_not_evidence(tmp_path):
    (tmp_path / firstrun.ASSETS[0]).mkdir(parents=True)
    assert firstrun.classify(str(tmp_path))["state"] == "not_setup"


def test_full_setup_has_no_missing(tmp_path):
    _touch(tmp_path / firstrun.MARKER)
    for link in firstrun.LINKS:
        (tmp_path / link).mkdir(parents=True)
    for asset in firstrun.ASSETS:
        _touch(tmp_path / asset / "sample.bin")
    info = firstrun.classify(str(tmp_path))
    assert info["state"] == "initialized"
    assert info["links_missing"] == []
    assert info["assets_missing"] == []


def test_cli_exit_code_is_nonzero_for_not_setup(tmp_path):
    """未初始化必须是非 0 退出（不能退化成 WARN/0），且输出可被脚本解析。"""
    for root, code, word in ((tmp_path, 3, "not_setup"),):
        p = subprocess.run([sys.executable, str(TOOLS / "firstrun.py"),
                            "--root", str(root), "--state"],
                           capture_output=True, text=True, encoding="utf-8")
        assert p.returncode == code, p.stderr
        assert p.stdout.strip() == word

    _touch(tmp_path / firstrun.MARKER)
    p = subprocess.run([sys.executable, str(TOOLS / "firstrun.py"),
                        "--root", str(tmp_path), "--state"],
                       capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0 and p.stdout.strip() == "initialized"
