using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Shift-Add-XOR hash
    public sealed class SaxHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private readonly uint seed;
        private uint hash;

        public SaxHash32()
        {
            seed = 0;
            Initialize();
        }

        public SaxHash32(uint seed)
        {
            this.seed = seed;
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
                hash ^= (hash << 5) + (hash >> 2) + array[i];
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
