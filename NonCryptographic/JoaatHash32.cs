using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Bob Jenkins One-at-a-Time hash
    public sealed class JoaatHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private uint hash;

        public JoaatHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash += array[i];
                hash += (hash << 10);
                hash ^= (hash >> 6);
            }
        }

        protected override byte[] HashFinal()
        {
            hash += (hash << 3);
            hash ^= (hash >> 11);
            hash += (hash << 15);

            return BitConverter.GetBytes(hash);
        }
    }
}
