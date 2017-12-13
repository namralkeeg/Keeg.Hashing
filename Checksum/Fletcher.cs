using System;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace Keeg.Hashing.Checksum
{
    public sealed class Fletcher : HashAlgorithm
    {
        public enum BitSize : int
        {
            Bits16 = 16,
            Bits32 = 32,
            Bits64 = 64,
        }

        public override int HashSize => (int)bitSize;
        private BitSize bitSize = BitSize.Bits32;
        private int bytesPerCycle;
        private readonly ulong modValue;
        private ulong sum1;
        private ulong sum2;

        public Fletcher(BitSize bitSize)
        {
            this.bitSize = bitSize;
            bytesPerCycle = (int)bitSize / 16;
            modValue = (ulong)(Math.Pow(2, 8 * bytesPerCycle) - 1);
            Initialize();
        }

        public override void Initialize()
        {
            sum1 = 0;
            sum2 = 0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            foreach (ulong block in Blockify(array, bytesPerCycle))
            {
                sum1 = (sum1 + block) % modValue;
                sum2 = (sum2 + sum1) % modValue;
            }
        }

        protected override byte[] HashFinal()
        {
            ulong hash = (sum1 + (sum2 * (modValue + 1)));
            switch (bitSize)
            {
                case BitSize.Bits16:
                    return BitConverter.GetBytes((ushort)hash);
                case BitSize.Bits32:
                    return BitConverter.GetBytes((uint)hash);
                case BitSize.Bits64:
                    return BitConverter.GetBytes(hash);
                default:
                    return BitConverter.GetBytes(hash);
            }
        }

        private IEnumerable<ulong> Blockify(byte[] inputAsBytes, int blockSize)
        {
            int i = 0;

            // Using an unsigned type is important - otherwise an arithmetic overflow will result
            ulong block = 0;

            // Run through all the bytes			
            while (i < inputAsBytes.Length)
            {
                // Keep stacking them side by side by shifting left and OR-ing				
                block = block << 8 | inputAsBytes[i];

                i++;

                // Return a block whenever we meet a boundary
                if (i % blockSize == 0 || i == inputAsBytes.Length)
                {
                    yield return block;

                    // Set to 0 for next iteration
                    block = 0;
                }
            }
        }
    }
}
