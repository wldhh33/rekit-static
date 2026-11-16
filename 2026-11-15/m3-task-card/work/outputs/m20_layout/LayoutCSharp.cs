// M20 controlled C# sample (compiled with .NET Framework csc).
// Purpose: explicit/sequential/auto layout + a static array initializer that
// the compiler is expected to place in FieldRVA via RuntimeHelpers.InitializeArray.
using System;
using System.Runtime.InteropServices;

namespace LayoutCSharp
{
    [StructLayout(LayoutKind.Explicit, Size = 32)]
    public struct ExplicitPair
    {
        [FieldOffset(0)] public int A;
        [FieldOffset(8)] public long B;
        [FieldOffset(24)] public short C;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct SeqPack4
    {
        public byte B;
        public long L;
        public short S;
    }

    // No StructLayout attribute: auto layout, offsets are runtime-derived only.
    public struct Plain
    {
        public int X;
        public double Y;
        public byte Z;
    }

    public static class Blobs
    {
        // 32 bytes. This literal is the source-of-truth expectation for the
        // FieldRVA data bytes (little-endian byte order on disk is identical
        // because the array element type is byte).
        public static readonly byte[] Table = new byte[]
        {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
            0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F
        };
    }
}
