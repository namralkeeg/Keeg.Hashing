using System;
using System.Security.Cryptography;

namespace Keeg.Hashing.Crc
{
    public sealed class Crc64 : HashAlgorithm
    {
        public override int HashSize => 64;
        public const ulong DefaultPolynomial = 0xD800000000000000ul; //Iso 3309 Polynomial
        public const ulong DefaultSeed = 0x0ul;

        private static ulong[] defaultTable;
        private readonly ulong[] table;

        private readonly ulong seed;
        private ulong hash;

        public Crc64()
        {
            seed = DefaultSeed;
            table = InitializeTable(DefaultPolynomial);
            Initialize();
        }

        public Crc64(ulong polynomial, ulong seed)
        {
            this.seed = seed;
            table = InitializeTable(polynomial);
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
                hash = (hash >> 8) ^ table[array[i] ^ (hash & 0xFF)];
            }
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(hash);
        }

        private ulong[] InitializeTable(ulong polynomial)
        {
            if ((polynomial == DefaultPolynomial) && (defaultTable != null))
                return defaultTable;

            var createTable = new ulong[256];
            for (ulong i = 0; i < 256; i++)
            {
                ulong entry = i;
                for (ulong j = 0; j < 8; ++j)
                {
                    if ((entry & 1) == 1)
                        entry = (entry >> 1) ^ polynomial;
                    else
                        entry >>= 1;
                }
                createTable[i] = entry;
            }

            if (polynomial == DefaultPolynomial)
                defaultTable = createTable;

            return createTable;
        }
    }
}
