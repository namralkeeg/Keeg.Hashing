using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.NonCryptographic
{
    // Peter J. Weinberger hash
    public sealed class PjwHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private const uint BitsInUnsignedInt = 32;
        private const uint ThreeQuarters = ((BitsInUnsignedInt * 3) / 4);
        private const uint OneEighth = (BitsInUnsignedInt / 8);
        private const uint HighBits = (0xFFFFFFFFu << (int)(BitsInUnsignedInt - OneEighth));
        private uint hash;

        public PjwHash32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hash = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            uint test = 0;
            for (var i = ibStart; i < ibStart + cbSize; i++)
            {
                hash = (hash << (int)OneEighth) + array[i];

                test = hash & HighBits;
                if (test != 0)
                {
                    hash = ((hash ^ (test >> (int)ThreeQuarters)) & (~HighBits));
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }
    }
}
