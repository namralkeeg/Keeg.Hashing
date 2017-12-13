using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Justin Sobel Hash
    public sealed class JSHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private const uint seed = 1315423911u;
        private uint hash;

        public JSHash32()
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
                hash ^= ((hash << 5) + array[i] + (hash >> 2));
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
