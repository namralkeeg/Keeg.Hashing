using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Algorithm by Paul Hsieh
    public sealed class SuperFastHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private uint hash;

        public SuperFastHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = 0;
        }

        private ushort Get16Bits(byte[] array, int pos)
        {
            return (ushort)((array[pos + 1] << 8) + array[pos]);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int length = cbSize;
            uint temp;
            int rem = length & 3;
            int pos = ibStart;

            if (hash == 0)
            {
                hash = (uint)length;
            }

            length >>= 2;

            for (; length > 0; length--)
            {
                hash += Get16Bits(array, pos);
                pos += 2;
                temp = (uint)(Get16Bits(array, pos) << 11) ^ hash;
                hash = (hash << 16) ^ temp;
                pos += 2;
                hash += hash >> 11;
            }

            // Handle end cases
            switch (rem)
            {
                case 3:
                    hash += Get16Bits(array, pos);
                    pos += 2;
                    hash ^= hash << 16;
                    hash ^= (byte)(array[pos] << 18);
                    hash += hash >> 11;
                    break;
                case 2:
                    hash += Get16Bits(array, pos);
                    hash ^= hash << 11;
                    hash += hash >> 17;
                    break;
                case 1:
                    hash += array[pos];
                    hash ^= hash << 10;
                    hash += hash >> 1;
                    break;
                default:
                    break;
            }
        }

        protected override byte[] HashFinal()
        {
            // Force "avalanching" of final 127 bits
            hash ^= hash << 3;
            hash += hash >> 5;
            hash ^= hash << 4;
            hash += hash >> 17;
            hash ^= hash << 25;
            hash += hash >> 6;

            return BitConverter.GetBytes(hash);
        }
    }
}
