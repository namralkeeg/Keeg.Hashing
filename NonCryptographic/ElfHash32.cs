using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Similar to the PJW Hash function, widley used on UNIX based systems.
    public sealed class ElfHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private uint hash;

        public ElfHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            uint high = 0u;
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = (hash << 4) + array[i];
                high = hash & 0xF0000000u;
                if (high != 0)
                {
                    hash ^= high >> 24;
                }

                hash &= ~high;
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
