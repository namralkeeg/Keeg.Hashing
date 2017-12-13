using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // The algorithm of choice which is used in the open source SDBM project.
    public sealed class SdbmHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private uint hash;

        public SdbmHash32()
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
                hash = array[i] + (hash << 6) + (hash << 16) - hash;
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
