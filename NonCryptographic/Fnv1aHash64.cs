using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    public sealed class Fnv1aHash64 : HashAlgorithm
    {
        public override int HashSize => 64;
        private const ulong fnvPrime = 0x00000100000001B3ul;
        private const ulong offsetBasis = 0xCBF29CE484222325ul;
        private ulong hash;

        public Fnv1aHash64()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = offsetBasis;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < cbSize; i++)
            {
                unchecked
                {
                    hash = (hash ^ array[i]) * fnvPrime;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
