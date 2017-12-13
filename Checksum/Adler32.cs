using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.Checksum
{
    public sealed class Adler32 : HashAlgorithm
    {
        public override int HashSize => 32;
        private const uint ModAdler = 65521;
        private uint hashA;
        private uint hashB;

        public Adler32()
        {
            Initialize();
        }

        public override void Initialize()
        {
            hashA = 1;
            hashB = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (array == null)
            {
                hashA = 1u;
            }

            if (array.Length == 1)
            {
                hashA += array[0];
                if (hashA >= ModAdler)
                    hashA -= ModAdler;
                hashB += hashA;
                if (hashB >= ModAdler)
                    hashB -= ModAdler;
            }
            else
            {
                for (var i = ibStart; i < cbSize; i++)
                {
                    hashA = (hashA + array[i]) % ModAdler;
                    hashB = (hashB + hashA) % ModAdler;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(((hashB << 16) | hashA));
        }
    }
}
