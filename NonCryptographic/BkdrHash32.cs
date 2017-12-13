using System;
using System.Security.Cryptography;

namespace KeegCS.Hashing.NonCryptographic
{
    // Hash is from Brian Kernighan and Dennis Ritchie's book "The C Programming Language"
    public sealed class BkdrHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private readonly uint seed = 131u;
        private uint hash;

        public BkdrHash32()
        {
            Initialize();
        }

        public BkdrHash32(uint seed)
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
                hash = (hash * seed) + array[i];
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
