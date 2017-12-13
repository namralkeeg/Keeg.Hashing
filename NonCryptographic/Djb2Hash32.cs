using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Algorithm produced by Professor Daniel J.Bernstein
    public sealed class Djb2Hash32 : HashAlgorithm
    {
        private static readonly uint DefaultSeed = 5381u;
        private uint seed;
        private uint hash;

        public override int HashSize => 32;

        public Djb2Hash32()
        {
            seed = DefaultSeed;
            Initialize();
        }

        public Djb2Hash32(uint seed)
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
                hash = ((hash << 5) + hash) + array[i]; /* hash * 33 + c */
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
