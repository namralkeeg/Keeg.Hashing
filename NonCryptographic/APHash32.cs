using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Hashing algorithm by Arash Partow
    public sealed class APHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private const uint seed = 0xAAAAAAAAu;
        private uint hash;

        public APHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = seed;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash ^= ((i & 0x01) == 0) ? 
                    ((hash << 7) ^ array[i] ^ (hash >> 3)) : 
                    (~((hash << 11) ^ array[i] ^ (hash >> 5)));
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
