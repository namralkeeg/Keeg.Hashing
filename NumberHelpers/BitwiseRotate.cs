using System;

namespace Keeg.Hashing.NumberHelpers
{
    public static partial class NumberHelpers
    {
        public static byte RotateLeft(this byte value, int count)
        {
            return (byte)((value << count) | (value >> (8 - count)));
        }

        public static sbyte RotateLeft(this sbyte value, int count)
        {
            return (sbyte)(((byte)value).RotateLeft(count));
        }

        public static ushort RotateLeft(this ushort value, int count)
        {
            return (ushort)((value << count) | (value >> (16 - count)));
        }

        public static short RotateLeft(this short value, int count)
        {
            return (short)(((ushort)value).RotateLeft(count));
        }

        public static uint RotateLeft(this uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }

        public static int RotateLeft(this int value, int count)
        {
            return (int)(((uint)value).RotateLeft(count));
        }

        public static ulong RotateLeft(this ulong value, int count)
        {
            return (value << count) | (value >> (64 - count));
        }

        public static long RotateLeft(this long value, int count)
        {
            return (long)(((ulong)value).RotateLeft(count));
        }

        public static byte RotateRight(this byte value, int count)
        {
            return (byte)((value >> count) | (value << (8 - count)));
        }

        public static sbyte RotateRight(this sbyte value, int count)
        {
            return (sbyte)(((byte)value).RotateRight(count));
        }

        public static ushort RotateRight(this ushort value, int count)
        {
            return (ushort)((value >> count) | (value << (16 - count)));
        }

        public static short RotateRight(this short value, int count)
        {
            return (short)(((ushort)value).RotateRight(count));
        }

        public static uint RotateRight(this uint value, int count)
        {
            return (value >> count) | (value << (32 - count));
        }

        public static int RotateRight(this int value, int count)
        {
            return (int)(((uint)value).RotateRight(count));
        }

        public static ulong RotateRight(this ulong value, int count)
        {
            return (value >> count) | (value << (64 - count));
        }

        public static long RotateRight(this long value, int count)
        {
            return (long)(((ulong)value).RotateRight(count));
        }
    }
}
