using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    public sealed class Fnv1Hash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private const uint fnvPrime = 0x01000193u;
        private const uint offsetBasis = 0x811C9DC5u;
        private uint hash;

        public Fnv1Hash32()
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
                    hash = (fnvPrime * hash) ^ array[i];
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
