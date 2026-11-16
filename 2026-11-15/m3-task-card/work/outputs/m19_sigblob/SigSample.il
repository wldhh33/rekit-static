// outputs/m19_sigblob/SigSample.il — M19 签名层补证受控样本（2026-11-17 补证批次）
// 目的：让 M19 已实现但原样本未覆盖的四条解码路径各有一个受控样本：
//   MArray : 多维数组 ARRAY（rank=2，下界 0,0）        -> ELEMENT_TYPE_ARRAY(0x14)
//   MFn    : 函数指针 FNPTR（unmanaged cdecl）          -> ELEMENT_TYPE_FNPTR(0x1B)
//   MMod   : 自定义修饰符 modopt(IsConst)               -> CMOD_OPT(0x20)
//   MOpt   : modopt 里嵌 TypeSpec 引用（List`1<int32>） -> TypeDefOrRefOrSpec tag=2
// MSimple 只用于负样本（bad_compressed_int / truncated_signature）的字节补丁锚点：
//   其签名 blob 为 00 03 01 0A 0D 0E（void(int64,float64,string)），在文件内唯一。
// 期望值来源：本文件声明 + ECMA-335 §II.23.2；与 SRM 的 canonical 整串比较由
//   tests/verify_sigblob.py 的 srm-sigsample 负责，本样本不引入被测实现的特有格式。
.assembly SigSample { .ver 1:0:0:0 }
.module SigSample.dll

.class public auto ansi beforefieldinit SigSample.Holder
       extends [mscorlib]System.Object
{
  .method public hidebysig static void MSimple(int64 a, float64 b, string c) cil managed
  {
    .maxstack 1
    ret
  }

  .method public hidebysig static int32 MArray(int32[0...,0...] a) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }

  .method public hidebysig static int32 MFn(method unmanaged cdecl int32 *(int32) p) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }

  .method public hidebysig static int32 MMod(int32 modopt([mscorlib]System.Runtime.CompilerServices.IsConst) x) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }

  .method public hidebysig static int32 MOpt(int32 modopt(class [mscorlib]System.Collections.Generic.List`1<int32>) x) cil managed
  {
    .maxstack 1
    ldc.i4.0
    ret
  }
}
