#!/usr/bin/env python3
"""outputs/m19_sigblob/make_negatives.py — M19 负样本构造（2026-11-17 补证批次）

从 SigSample.dll 复制出四个样本，每个只在目标签名 blob 里原位改 1 个字节，
长度不变，因此 #Blob 堆索引、表行数、其余签名全部保持原样：

  BadCompressed.dll   MSimple 的 ParamCount 03 -> E0
                      111xxxxx 保留前缀 -> bad_compressed_int
  TruncatedSig.dll    MSimple 的 ParamCount 03 -> 08
                      声明 8 个参数但只剩 3 个类型字节 -> truncated_signature
  UnknownCodedTag.dll MMod 的 TypeDefOrRefOrSpec 编码 09 -> 0B
                      tag=3 非法 -> 修饰类型解不出，按 unknown 政策记账
                      （结构解完 = decoded，但 unknown 非空 -> with_unknown）
  UnknownElemType.dll MSimple 的返回类型 01 -> 6F
                      0x6F 不是 ECMA-335 元素类型 -> unknown 节点不消耗字节，
                      方法签名 exact 判据留下 1 字节 -> trailing_bytes

定位方式：在整文件里搜索每个锚点字节序列（构造时断言恰好 1 处），不解析
PE/metadata，避免“用被测实现的定位逻辑造负样本”。

用法：python make_negatives.py <SigSample.dll> <输出目录>
退出码：0 成功 / 1 锚点不唯一或文件缺失
"""
import hashlib
import json
import os
import sys

# key -> (锚点字节序列, 补丁在锚点内的下标)
ANCHORS = {
    # MSimple: void(int64, float64, string)；下标 1 = ParamCount
    "simple_paramcount": (bytes.fromhex("0003010a0d0e"), 1),
    # 同一 blob；下标 2 = 返回类型元素字节
    "simple_ret": (bytes.fromhex("0003010a0d0e"), 2),
    # MMod: int32 modopt(IsConst)；下标 4 = TypeDefOrRefOrSpec 编码
    "modopt_ref": (bytes.fromhex("000108200908"), 4),
}
CASES = (
    ("BadCompressed.dll", "simple_paramcount", 0xE0, "bad_compressed_int",
     "ParamCount: 0x03 -> 0xE0（111xxxxx 保留前缀）"),
    ("TruncatedSig.dll", "simple_paramcount", 0x08, "truncated_signature",
     "ParamCount: 0x03 -> 0x08（声明 8 个参数，剩余 3 个类型字节）"),
    ("UnknownCodedTag.dll", "modopt_ref", 0x0B, "decoded_with_unknown",
     "modopt 引用编码: 0x09 -> 0x0B（tag=3 非法，类型解不出记 unknown）"),
    ("UnknownElemType.dll", "simple_ret", 0x6F, "trailing_bytes",
     "返回类型: 0x01 -> 0x6F（非 ECMA 元素类型，unknown 不消耗字节）"),
)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def locate(data):
    """返回 {key: 锚点起始偏移}；锚点不唯一/缺失直接报错。"""
    hits = {}
    for key, (pat, _at) in ANCHORS.items():
        first = data.find(pat)
        if first < 0 or data.find(pat, first + 1) >= 0:
            raise RuntimeError("锚点不唯一（%s 找到 %d 处）: %s"
                               % (key, data.count(pat), pat.hex()))
        hits[key] = first
    return hits


def main(argv):
    if len(argv) < 3:
        print("用法: python make_negatives.py <SigSample.dll> <输出目录>")
        return 1
    src = os.path.abspath(argv[1])
    outdir = os.path.abspath(argv[2])
    if not os.path.isfile(src):
        print("FAIL 源文件缺失: %s" % src)
        return 1
    data = open(src, "rb").read()
    try:
        anchors = locate(data)
    except RuntimeError as e:
        print("FAIL %s" % e)
        return 1
    os.makedirs(outdir, exist_ok=True)
    base_sha = sha256(src)
    rows = []
    for name, key, new_byte, reason, desc in CASES:
        pos, at = anchors[key], ANCHORS[key][1]
        blob = bytearray(data)
        old = blob[pos + at]
        blob[pos + at] = new_byte
        dst = os.path.join(outdir, name)
        with open(dst, "wb") as f:
            f.write(bytes(blob))
        rows.append({
            "file": name,
            "sha256": sha256(dst),
            "size": len(blob),
            "source_sha256": base_sha,
            "anchor": ANCHORS[key][0].hex(),
            "patch_offset": pos + at,
            "patch": "%02x -> %02x" % (old, new_byte),
            "expect": reason,
            "description": desc,
        })
        print("%s  sha256=%s  patch@%d %02x->%02x"
              % (name, rows[-1]["sha256"], pos + at, old, new_byte))
    print(json.dumps({"negatives": rows}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
