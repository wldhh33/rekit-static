r"""status.py 的可失败自证：在临时工作区复现 exit=1 与 exit=0 三种情形。

用法: python "2026-11-16\vibe-coding-review\work\batch1\selfproof_status.py"
只写 batch1\status_selfproof.txt；不触碰真实工作区文件。
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
STATUS = os.path.join(ROOT, "pack", "tools", "status.py")
TEMPLATE = ["# H", "## 1. 当前进度", "x", "## 2. 未完成清单", "x", "## 3. 已否决方案", "{s3}",
            "## 4. 待确认问题", "x", "## 5. 新增证据文件", "x", "## 6. 下一位第一条命令", "x"]


def run(tmp):
    p = subprocess.run([sys.executable, os.path.join(tmp, "pack", "tools", "status.py")],
                       capture_output=True)
    first = (p.stdout.decode("utf-8", "replace").splitlines() or ["(no output)"])[0]
    return p.returncode, first


def main():
    tmp = tempfile.mkdtemp(prefix="status_selfproof_")
    try:
        os.makedirs(os.path.join(tmp, "pack", "tools"))
        shutil.copy(STATUS, os.path.join(tmp, "pack", "tools", "status.py"))
        work = os.path.join(tmp, "2026-11-15", "m3-task-card", "work")
        os.makedirs(work)
        handoff = os.path.join(work, "HANDOFF.md")
        rows = []
        for tag, s3 in [("A 无 HANDOFF", None), ("B 空段", ""), ("C 完整", "x")]:
            if s3 is not None:
                open(handoff, "w", encoding="utf-8").write("\n".join(l.format(s3=s3) for l in TEMPLATE))
            code, first = run(tmp)
            rows.append("[%s] exit=%d | %s" % (tag, code, first))
        txt = "status.py 可失败自证（临时工作区，不触碰真实文件）\n" + "\n".join(rows) + "\n"
        open(os.path.join(HERE, "status_selfproof.txt"), "w", encoding="utf-8").write(txt)
        print(txt)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
