﻿#region Copyright
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
