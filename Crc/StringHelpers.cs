#region Copyright
/*
 * Copyright (C) 2017 Larry Lopez
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#endregion
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
