using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // A simple hash function from Robert Sedgwicks Algorithms in C book.
    public sealed class RSHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private const uint b = 378551u;
        private uint a;
        private uint hash;

        public RSHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            a = 63689u;
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = hash * a + array[i];
                a = a * b;
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
