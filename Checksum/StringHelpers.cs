using System;
using System.Security.Cryptography;
using System.Text;

namespace Keeg.Hashing.Checksum
{
    public static partial class StringHelpers
    {
        internal static readonly Encoding DefaultEncoding = Encoding.UTF8;

        public static uint HashAdler32(this string input, Encoding encoding)
        {
            var enc = encoding ?? DefaultEncoding;
            using (HashAlgorithm hasher = new Adler32())
            {
                return BitConverter.ToUInt32(hasher.ComputeHash(enc.GetBytes(input)), 0);
            }
        }

        public static uint HashAdler32(this string input)
        {
            return input.HashAdler32(DefaultEncoding);
        }

        public static ushort HashFletcher16(this string input, Encoding encoding)
        {
            var enc = encoding ?? DefaultEncoding;
            using (HashAlgorithm hasher = new Fletcher(Fletcher.BitSize.Bits16))
            {
                return BitConverter.ToUInt16(hasher.ComputeHash(enc.GetBytes(input)), 0);
            }
        }

        public static ushort HashFletcher16(this string input)
        {
            return input.HashFletcher16(DefaultEncoding);
        }

        public static uint HashFletcher32(this string input, Encoding encoding)
        {
            var enc = encoding ?? DefaultEncoding;
            using (HashAlgorithm hasher = new Fletcher(Fletcher.BitSize.Bits32))
            {
                return BitConverter.ToUInt32(hasher.ComputeHash(enc.GetBytes(input)), 0);
            }
        }

        public static uint HashFletcher32(this string input)
        {
            return input.HashFletcher32(DefaultEncoding);
        }

        public static ulong HashFletcher64(this string input, Encoding encoding)
        {
            var enc = encoding ?? DefaultEncoding;
            using (HashAlgorithm hasher = new Fletcher(Fletcher.BitSize.Bits64))
            {
                return BitConverter.ToUInt64(hasher.ComputeHash(enc.GetBytes(input)), 0);
            }
        }

        public static ulong HashFletcher64(this string input)
        {
            return input.HashFletcher64(DefaultEncoding);
        }
    }
}
