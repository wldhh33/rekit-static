#!/usr/bin/env python3
# repo_contract.py — 只用仓库内资产就能跑的可证伪契约检查（2026-11-22）
#
# 依赖边界（刻意收窄）：
#   * 纯 Python 标准库 + `pack\04_rekit项目源码` 里的 rekit 源码；
#   * 只用 `git ls-files` 里已跟踪的样本（见 repo_contract.json，不含 13 个被移除样本）；
#   * 不需要 binutils / UPX / pwsh / dnfile / .NET 运行时 / setup.ps1 / junction。
#
# 判据：对每个样本冻结 sha256、大小、格式与头字段（入口、机器、节数等）逐项对拍；
# 任一不符 exit 1；清单为空、单个 expect 为空、期望含未知字段一律 FAIL（空比对不算通过）。
#
# 可失败自证：`--selftest` 会（1）先要求基线全过；（2）把某个整数期望 +1，必须被检出；
# （3）把某条 expect 清空，必须 FAIL；（4）空清单必须 FAIL。
# 这四步同时排除“恒真”和“恒假”：比较器若永远 PASS，第 2/3/4 步失败；
# 若永远 FAIL，第 1 步失败。
#
# 用法:
#   python "pack\tools\repo_contract.py"            # 主检查
#   python "pack\tools\repo_contract.py" --selftest # 可失败自证
# 退出码: 0 = 全部通过（或自证全部检出）/ 1 = 有不符或自证失败 / 2 = 清单或源码缺失
import argparse
import copy
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "pack", "04_rekit项目源码")
MANIFEST = os.path.join(ROOT, "pack", "tools", "repo_contract.json")


def _load_manifest(path=MANIFEST):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _load_api():
    if SRC not in sys.path:
        sys.path.insert(0, SRC)
    import rekit.api  # noqa: E402  （延迟导入，缺源码时给出明确 exit 2）
    return rekit.api


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _observed(api, path):
    """返回 (format, 冻结字段 dict)；detect 为 None 时返回 (None, None)。"""
    fmt = api.detect_format(path)
    if fmt == "pe":
        r = api.parse_pe(path)
        return fmt, {"machine": r["machine"], "entry": r["entry"],
                     "image_base": r["image_base"], "subsystem": r["subsystem"],
                     "nsect": len(r["sections"])}
    if fmt == "elf":
        r = api.parse_elf(path)
        return fmt, {"type": r["type"], "machine": r["machine"], "entry": r["entry"],
                     "nsect": len(r["sections"]), "nphdr": len(r["phdrs"])}
    return fmt, None


def check_entry(api, entry):
    rel = entry.get("file", "")
    fails = []
    if not rel:
        return ["清单条目缺少 file"]
    path = os.path.join(SRC, rel.replace("/", os.sep))
    if not os.path.isfile(path):
        return ["%s: 文件不存在 %s" % (rel, path)]

    if not entry.get("sha256"):
        fails.append("%s: empty expectation: sha256" % rel)
    else:
        actual = _sha256(path)
        if actual != entry["sha256"]:
            fails.append("%s: sha256 期望 %s 实际 %s" % (rel, entry["sha256"], actual))
    if "size" in entry:
        actual_size = os.path.getsize(path)
        if actual_size != entry["size"]:
            fails.append("%s: size 期望 %r 实际 %r" % (rel, entry["size"], actual_size))

    try:
        fmt = api.detect_format(path)
    except Exception as e:  # noqa: BLE001 —— 任何异常都算不符，不许静默
        return fails + ["%s: detect_format 异常 %s: %s" % (rel, type(e).__name__, e)]
    if fmt != entry.get("format"):
        return fails + ["%s: format 期望 %r 实际 %r" % (rel, entry.get("format"), fmt)]

    if entry.get("error"):
        want = entry["error"]
        try:
            (api.parse_pe if fmt == "pe" else api.parse_elf)(path)
        except api.MalformedBinary:
            pass
        except Exception as e:  # noqa: BLE001
            fails.append("%s: 期望 %s，实际抛 %s: %s" % (rel, want, type(e).__name__, e))
        else:
            fails.append("%s: 期望 %s，实际解析成功" % (rel, want))
        return fails

    expect = entry.get("expect")
    if not isinstance(expect, dict) or not expect:
        return fails + ["%s: empty expectation: expect（空期望按 FAIL）" % rel]
    try:
        _, obs = _observed(api, path)
    except Exception as e:  # noqa: BLE001
        return fails + ["%s: 解析异常 %s: %s" % (rel, type(e).__name__, e)]
    if obs is None:
        return fails + ["%s: 解析结果为空" % rel]
    unknown = sorted(set(expect) - set(obs))
    if unknown:
        fails.append("%s: 期望含未知字段 %s（防字段名拼错后恒真）" % (rel, ", ".join(unknown)))
    for key, want in expect.items():
        if key in obs and obs[key] != want:
            fails.append("%s: %s 期望 %r 实际 %r" % (rel, key, want, obs[key]))
    return fails


def run(doc, api):
    samples = doc.get("samples") or []
    if not samples:
        return samples, ["empty manifest: samples 为空（空比对按 FAIL）"]
    fails = []
    for entry in samples:
        fails.extend(check_entry(api, entry))
    return samples, fails


def selftest(doc, api):
    checks = []

    samples, fails = run(doc, api)
    checks.append(("基线必须全过", not fails and bool(samples), fails))

    tampered = copy.deepcopy(doc)
    target = None
    for entry in tampered.get("samples", []):
        for key, val in (entry.get("expect") or {}).items():
            if isinstance(val, int):
                entry["expect"][key] = val + 1
                target = (entry["file"], key)
                break
        if target:
            break
    if target is None:
        checks.append(("篡改期望必须被检出", False, ["清单里没有可篡改的整数期望"]))
    else:
        _, tfails = run(tampered, api)
        hit = any(target[1] in m and target[0] in m for m in tfails)
        checks.append(("篡改 %s.%s 必须被检出" % target, hit, tfails))

    emptied = copy.deepcopy(doc)
    victim = next((e for e in emptied.get("samples", []) if e.get("expect")), None)
    if victim is None:
        checks.append(("空 expect 必须 FAIL", False, ["清单里没有 expect 可清空"]))
    else:
        victim["expect"] = {}
        _, efails = run(emptied, api)
        checks.append(("空 expect 必须 FAIL", any("empty expectation" in m for m in efails), efails))

    _, mfails = run({"samples": []}, api)
    checks.append(("空清单必须 FAIL", bool(mfails), mfails))

    for name, passed, detail in checks:
        print("[SELFTEST %s] %s" % ("PASS" if passed else "FAIL", name))
        for msg in detail[:3]:
            print("    %s" % msg)
    ok = all(c[1] for c in checks)
    print("SELFTEST: %s (%d/%d)" % ("PASS" if ok else "FAIL",
                                    sum(1 for c in checks if c[1]), len(checks)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description="仓库内资产契约检查（不依赖外部样本/工具链）")
    ap.add_argument("--selftest", action="store_true", help="跑可失败自证（篡改/空期望/空清单）")
    args = ap.parse_args(argv)

    if not os.path.isfile(MANIFEST):
        print("CONTRACT: FAIL missing manifest: %s" % MANIFEST)
        return 2
    try:
        api = _load_api()
    except Exception as e:  # noqa: BLE001
        print("CONTRACT: FAIL 无法导入 rekit（%s: %s）" % (type(e).__name__, e))
        return 2

    doc = _load_manifest()
    if args.selftest:
        return selftest(doc, api)

    for note in doc.get("excluded", []):
        print("[NOTE] 不覆盖 %s：%s" % (note.get("file", "?"), note.get("reason", "")))
    samples, fails = run(doc, api)
    for entry in samples:
        print("[%s] %s" % ("PASS" if not any(entry["file"] in f for f in fails) else "FAIL",
                           entry.get("file", "?")))
    for msg in fails:
        print("[FAIL] %s" % msg)
    neg = sum(1 for e in samples if e.get("error"))
    pos = len(samples) - neg
    if fails:
        print("CONTRACT: FAIL (%d 项不符)" % len(fails))
        return 1
    print("CONTRACT: PASS %d/%d（%d 个正向解析 + %d 个负向失败语义）"
          % (len(samples), len(samples), pos, neg))
    print("  绿代表: 入库字节（sha256/大小）未漂；%d 个 PE/ELF 的格式与头字段与冻结期望逐项一致；"
          "负向样本仍按 LIBRARY_API 的失败语义报错。" % pos)
    print("  不代表: 反汇编/CFG/函数归属/DWARF/.NET 签名等分析层正确；不与 objdump 等外部工具对拍；"
          "不是 25 套门禁或 pytest 的结果；不覆盖从历史移除的 13 个样本与样本重建。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
