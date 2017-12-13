using System;
using System.Security.Cryptography;

namespace KeegCS.Hashing.NonCryptographic
{
    // Algorithm proposed by Donald E. Knuth in The Art Of Computer Programming Volume 3
    public sealed class DekHash32 : HashAlgorithm
    {
        public override int HashSize => base.HashSize;
        private uint hash;

        public DekHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (hash == 0)
            {
                hash = (uint)cbSize;
            }

            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = ((hash << 5) ^ (hash >> 27)) ^ array[i];
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
