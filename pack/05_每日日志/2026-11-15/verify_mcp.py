#!/usr/bin/env python3
# verify_mcp.py — rekit M1.5 MCP 服务器验收脚本（2026-11-15）
# 方法：独立实现的 MCP stdio 客户端（子进程）真实调用 `rekit mcp`，
#       与 readelf/pefile 权威输出交叉对拍（E1–E5，标准见 TASK_m15_mcp.md）
# 证据：stdout 全量日志 → evidence_mcp_verify.log
import json
import os
import re
import subprocess
import sys

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
REPO = os.path.join(_ROOT, "pack", "04_rekit项目源码")
FIX = REPO + "/tests/fixtures"
BIN_LS = FIX + "/bin_ls.elf"
MINIDLL = FIX + "/minidll.dll"


# ── 独立 MCP stdio 客户端（不 import rekit——交叉验证的独立性） ──────
class McpClient:
    def __init__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "rekit.cli", "mcp"], cwd=REPO,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def read(self):
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line)

    def call(self, method, params=None, msg_id=None, _id=[0]):
        if msg_id is None:
            _id[0] += 1
            msg_id = _id[0]
        msg = {"jsonrpc": "2.0", "id": msg_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        resp = self.read()
        assert resp is not None and resp.get("id") == msg_id, \
            "响应缺失或 id 错位: %r" % resp
        return resp

    def tool_text(self, name, args):
        resp = self.call("tools/call", {"name": name, "arguments": args})
        result = resp["result"]
        return result["content"][0]["text"], result.get("isError", False)

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


# ── 权威采集 ─────────────────────────────────────────────────
def readelf(*flags, path=BIN_LS):
    return subprocess.run(["readelf", *flags, path], capture_output=True,
                          text=True).stdout


def readelf_expect_binls():
    """从 readelf 权威输出推导 bin_ls.elf 的期望值"""
    h = readelf("-h")
    etype = re.search(r"Type:\s+(\S+)", h).group(1)               # DYN
    entry = re.search(r"Entry point address:\s+(0x[0-9a-f]+)", h).group(1)
    phnum = int(re.search(r"Number of program headers:\s+(\d+)", h).group(1))
    shnum = int(re.search(r"Number of section headers:\s+(\d+)", h).group(1))
    machine = re.search(r"Machine:\s+(.+)$", h, re.M).group(1).strip()
    arch = "x86-64" if "X86-64" in machine else machine

    lw = readelf("-lW")
    interp = re.search(r"Requesting program interpreter: ([^\]\s]+)", lw)
    interp = interp.group(1) if interp else None
    seg_types, seg_flags = [], []
    for line in lw.splitlines():
        m = re.match(r"\s{2}([A-Z_]+)\s+0x[0-9a-f]+\s", line)
        if not m:
            continue
        seg_types.append(m.group(1))
        toks = line.split()
        # Flg 列：去掉 Type+5 列地址尺寸与末尾 Align，中间全归 flags
        seg_flags.append("".join(toks[6:-1]).replace(" ", ""))
    gnu_stack = seg_flags[seg_types.index("GNU_STACK")]
    nx = "disabled" if "E" in gnu_stack else "enabled"
    has_relro = "GNU_RELRO" in seg_types
    d = readelf("-d")
    bind_now = ("BIND_NOW" in d) or bool(re.search(r"\(FLAGS\).*NOW", d))
    relro = ("full" if bind_now else "partial") if has_relro else "none"
    pie = "yes" if (etype == "DYN" and interp) else \
          ("shared" if etype == "DYN" else "no")
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[(\S+)\]", d)

    sw = readelf("-SW")
    sh_count = len(re.findall(r"\[\s*\d+\]", sw))
    return dict(etype=etype, entry=entry, phnum=phnum, shnum=shnum, arch=arch,
                nx=nx, relro=relro, pie=pie, needed=needed, interp=interp,
                seg_types=seg_types, seg_flags=seg_flags, sh_count=sh_count)


def pefile_sections_minidll():
    import pefile
    pe = pefile.PE(MINIDLL)
    return [s.Name.rstrip(b"\x00").decode() for s in pe.sections]


# ── 验收主流程 ───────────────────────────────────────────────
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print("[%s] %s%s" % ("PASS" if ok else "FAIL", name,
                         ("  | " + detail) if detail and not ok else
                         (("  | " + detail) if detail else "")))


def main():
    exp = readelf_expect_binls()
    pe_sect = pefile_sections_minidll()
    print("== 权威期望（readelf/pefile 现场采集）==")
    print("  type=%s entry=%s phdrs=%d sections=%d arch=%s" %
          (exp["etype"], exp["entry"], exp["phnum"], exp["shnum"], exp["arch"]))
    print("  nx=%s relro=%s pie=%s interp=%s" %
          (exp["nx"], exp["relro"], exp["pie"], exp["interp"]))
    print("  needed=%s" % exp["needed"])
    print("  段类型序列(%d): %s" % (len(exp["seg_types"]), exp["seg_types"]))
    print("  pefile 节表: %s" % pe_sect)

    cli = McpClient()

    # ---- E1 协议握手 ----
    print("\n== E1 协议握手 ==")
    r = cli.call("initialize", {"protocolVersion": "2025-06-18",
                                "capabilities": {}, "clientInfo": {"name": "verify", "version": "0"}}, msg_id=101)
    init = r.get("result", {})
    check("E1.1 protocolVersion 回显 2025-06-18",
          init.get("protocolVersion") == "2025-06-18", repr(init.get("protocolVersion")))
    check("E1.2 capabilities.tools 存在", "tools" in init.get("capabilities", {}))
    check("E1.3 serverInfo.name == rekit",
          init.get("serverInfo", {}).get("name") == "rekit")
    cli.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    # 通知不得产生响应：下一条响应必须属于 tools/list (id=102)
    r = cli.call("tools/list", msg_id=102)
    check("E1.4 initialized 通知零响应（下一响应 id=102）",
          r.get("id") == 102)
    # 不认识的客户端版本 → 回服务器最新
    cli2 = McpClient()
    r2 = cli2.call("initialize", {"protocolVersion": "1999-01-01"},
                   msg_id=1)
    check("E1.5 未知客户端版本回退服务器最新版",
          r2["result"]["protocolVersion"] == "2025-06-18",
          repr(r2["result"]["protocolVersion"]))
    cli2.close()

    # ---- E2 工具清单 ----
    print("\n== E2 工具清单 ==")
    tools = r["result"]["tools"]
    names = [t["name"] for t in tools]
    check("E2.1 工具数 ≥ 2", len(tools) >= 2, str(names))
    for tn in ("rekit_info", "rekit_map"):
        t = next((x for x in tools if x["name"] == tn), None)
        if t is None:
            check("E2.%s 存在" % tn, False, "missing")
            continue
        check("E2.2 %s description 非空" % tn, bool(t.get("description", "").strip()))
        schema = t.get("inputSchema", {})
        check("E2.3 %s inputSchema.type=object 且 required 含 path" % tn,
              schema.get("type") == "object" and "path" in schema.get("required", []))

    # ---- E3 info 交叉验证（readelf 权威） ----
    print("\n== E3 rekit_info(bin_ls.elf) × readelf ==")
    text, is_err = cli.tool_text("rekit_info", {"path": BIN_LS})
    check("E3.0 工具调用无错误", not is_err, text[:200])
    info = json.loads(text)
    check("E3.1 type == %s" % exp["etype"], info.get("type") == exp["etype"],
          repr(info.get("type")))
    check("E3.2 entry == %s" % exp["entry"], info.get("entry") == exp["entry"],
          repr(info.get("entry")))
    check("E3.3 phdrs == %d" % exp["phnum"], info.get("phdrs") == exp["phnum"],
          repr(info.get("phdrs")))
    check("E3.4 sections == %d" % exp["shnum"], info.get("sections") == exp["shnum"],
          repr(info.get("sections")))
    check("E3.5 arch == %s" % exp["arch"], info.get("arch") == exp["arch"],
          repr(info.get("arch")))
    sec = info.get("security", {})
    check("E3.6 nx == %s" % exp["nx"], sec.get("nx") == exp["nx"], repr(sec.get("nx")))
    check("E3.7 relro == %s" % exp["relro"], sec.get("relro") == exp["relro"],
          repr(sec.get("relro")))
    check("E3.8 pie == %s" % exp["pie"], sec.get("pie") == exp["pie"], repr(sec.get("pie")))
    check("E3.9 needed 全等", info.get("needed") == exp["needed"],
          repr(info.get("needed")))
    check("E3.10 interpreter == %s" % exp["interp"],
          info.get("interpreter") == exp["interp"], repr(info.get("interpreter")))

    # ---- E4 map 交叉验证 ----
    print("\n== E4 rekit_map × readelf/pefile ==")
    text, is_err = cli.tool_text("rekit_map", {"path": BIN_LS, "kind": "segments"})
    check("E4.0 segments 调用无错误", not is_err, text[:200])
    segs = json.loads(text)
    check("E4.1 段数 == %d" % exp["phnum"], segs.get("count") == exp["phnum"],
          repr(segs.get("count")))
    got_types = [e["type"] for e in segs["entries"]]
    check("E4.2 段类型序列全等", got_types == exp["seg_types"],
          "%r vs %r" % (got_types, exp["seg_types"]))
    got_flags = [e["flags"].replace(" ", "") for e in segs["entries"]]
    check("E4.3 段 flags 序列全等(readelf 风格)", got_flags == exp["seg_flags"],
          "%r vs %r" % (got_flags, exp["seg_flags"]))
    text, is_err = cli.tool_text("rekit_map", {"path": BIN_LS, "kind": "sections"})
    secs = json.loads(text)
    check("E4.4 节数 == %d (readelf -SW)" % exp["sh_count"],
          secs.get("count") == exp["sh_count"], repr(secs.get("count")))
    text, is_err = cli.tool_text("rekit_map", {"path": MINIDLL})
    pmap = json.loads(text)
    got_names = [e["name"] for e in pmap["entries"]]
    check("E4.5 PE 节名序列 == pefile (%s)" % pe_sect,
          got_names == pe_sect, repr(got_names))
    # default kind 缺省 = segments
    text2, _ = cli.tool_text("rekit_map", {"path": BIN_LS})
    check("E4.6 kind 缺省为 segments", json.loads(text2)["kind"] == "segments")

    # ---- E5 负路径与连接健壮性 ----
    print("\n== E5 负路径 ==")
    text, is_err = cli.tool_text("rekit_info", {"path": "/no/such/file"})
    check("E5.1 不存在路径 → isError", is_err and "不存在" in text, text[:120])
    text, is_err = cli.tool_text("rekit_info", {"path": __file__})
    check("E5.2 文本文件 → isError", is_err and "无法识别" in text, text[:120])
    text, is_err = cli.tool_text("rekit_info", {})
    check("E5.3 缺 path 参数 → isError", is_err and "path" in text, text[:120])
    text, is_err = cli.tool_text("rekit_map", {"path": BIN_LS, "kind": "bogus"})
    check("E5.4 非法 kind → isError", is_err, text[:120])
    # 错误后连接存活
    text, is_err = cli.tool_text("rekit_info", {"path": BIN_LS})
    alive = not is_err and json.loads(text)["entry"] == exp["entry"]
    check("E5.5 连续错误后连接存活且结果正确", alive)
    # 协议层：未知方法 → JSON-RPC -32601
    r = cli.call("bogus/method", msg_id=200)
    check("E5.6 未知方法 → -32601", r.get("error", {}).get("code") == -32601)
    # 未知通知 → 静默忽略
    cli.send({"jsonrpc": "2.0", "method": "notifications/whatever"})
    r = cli.call("ping", msg_id=201)
    check("E5.7 未知通知零响应 + ping 正常", r.get("id") == 201 and "result" in r)
    cli.close()

    n_pass = sum(1 for _, ok in RESULTS if ok)
    print("\n== 汇总: %d/%d PASS ==" % (n_pass, len(RESULTS)))
    for name, ok in RESULTS:
        if not ok:
            print("  FAIL:", name)
    return 0 if n_pass == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
