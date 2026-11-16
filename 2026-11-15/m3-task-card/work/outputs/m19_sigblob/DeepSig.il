// outputs/m19_sigblob/DeepSig.il — M19 负样本：depth_exceeded（2026-11-17 补证批次）
// 参数类型 = int32 后接 64 层 SZARRAY；实测边界：63 层可解，64 层触发
// sigblob 的 MAX_DEPTH=64（第 65 层深度超限 -> depth_exceeded）。
// 由 ilasm 正常汇编，metadata 合法；不靠改字节破坏文件，只把深度推到边界外。
.assembly DeepSig { .ver 1:0:0:0 }
.module DeepSig.dll

.class public auto ansi beforefieldinit DeepSig.Holder
       extends [mscorlib]System.Object
{
  .method public hidebysig static int32 MDeep(int32[][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][] a) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}
