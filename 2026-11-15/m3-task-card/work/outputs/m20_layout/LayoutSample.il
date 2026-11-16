// M20 controlled IL sample: FieldLayout / ClassLayout / FieldRVA.
// Hand-written IL (assembled with ilasm), not representative of real
// assembly distribution. Comments must stay ASCII: ilasm reads this file
// as ANSI.
.assembly extern mscorlib { .ver 4:0:0:0 }
.assembly LayoutSample { .ver 1:0:0:0 }
.module LayoutSample.dll

// Explicit layout: three FieldLayout rows (offsets 0/4/8) and one
// ClassLayout row (pack=1, size=24).
.class public explicit ansi sealed LayoutSample.ExplicitBlob
       extends [mscorlib]System.ValueType
{
  .pack 1
  .size 24
  .field [0] public int32 A
  .field [4] public int32 B
  .field [8] public int64 C
}

// Sequential layout: ClassLayout only (pack=2, size=16), no FieldLayout.
.class public sequential ansi sealed LayoutSample.SeqStruct
       extends [mscorlib]System.ValueType
{
  .pack 2
  .size 16
  .field public int16 X
  .field public int64 Y
}

// Auto layout: no ClassLayout and no FieldLayout. Offsets are runtime-derived
// only; this type exists to show that boundary explicitly.
.class public auto ansi sealed LayoutSample.AutoStruct
       extends [mscorlib]System.ValueType
{
  .field public int32 X
  .field public float64 Y
}

// FieldRVA host: three static fields with declared data.
//   Blob24       -> length from ClassLayout.ClassSize (24)
//   StaticInt    -> length from primitive Int32 (4)
//   ExternalValue-> valuetype from another assembly: no ClassLayout
//                   available in this module -> length unknown
.class public auto ansi beforefieldinit LayoutSample.DataHolder
       extends [mscorlib]System.Object
{
  .field public static valuetype LayoutSample.ExplicitBlob Blob24 at I_0001
  .field public static int32 StaticInt at I_0002
  .field public static valuetype [mscorlib]System.DateTime ExternalValue at I_0003
}

.data cil I_0001 = bytearray (01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18)
.data cil I_0002 = int32 (0x11223344)
.data cil I_0003 = bytearray (DE AD BE EF DE AD BE EF)
