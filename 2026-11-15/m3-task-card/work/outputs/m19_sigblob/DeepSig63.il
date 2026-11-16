// outputs/m19_sigblob/DeepSig63.il — M19 depth_exceeded 的边界对照组（2026-11-17 补证批次）
// 参数类型 = int32 后接 63 层 SZARRAY；与 DeepSig.il（64 层）成对使用：
//   63 层可解、64 层触发 sigblob 的 MAX_DEPTH=64 -> depth_exceeded。
// 两者都由 ilasm 正常汇编，metadata 合法；不靠改字节破坏文件，只把深度推到边界。
.assembly DeepSig63 { .ver 1:0:0:0 }
.module DeepSig63.dll

.class public auto ansi beforefieldinit DeepSig63.Holder
       extends [mscorlib]System.Object
{
  .method public hidebysig static int32 MDeep63(int32[][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][] a) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}
