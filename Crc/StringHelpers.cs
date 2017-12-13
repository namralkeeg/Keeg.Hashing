using System;
using System.Security.Cryptography;
using System.Text;

namespace Keeg.Hashing.Crc
{
    public static partial class StringHelpers
    {
        internal static readonly Encoding DefaultEncoding = Encoding.UTF8;

        public static uint HashCrc32(this string input, Encoding encoding)
        {
            var enc = encoding ?? DefaultEncoding;
            using (HashAlgorithm hasher = new Crc32())
            {
                return BitConverter.ToUInt32(hasher.ComputeHash(enc.GetBytes(input)), 0);
            }
        }

        public static uint HashCrc32(this string input)
        {
            return input.HashCrc32(DefaultEncoding);
        }

        public static ulong HashCrc64(this string input, Encoding encoding)
        {
            var enc = encoding ?? DefaultEncoding;
            using (HashAlgorithm hasher = new Crc64())
            {
                return BitConverter.ToUInt64(hasher.ComputeHash(enc.GetBytes(input)), 0);
            }
        }

        public static ulong HashCrc64(this string input)
        {
            return input.HashCrc32(DefaultEncoding);
        }
    }
}
