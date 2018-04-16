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
using Keeg.Hashing.NumberHelpers;

namespace Keeg.Hashing.NonCryptographic
{
    // Algorithm by Yann Collet
    public sealed class XXHash64 : HashAlgorithm
    {
        public override int HashSize => 64;
        // magic constants :-)
        private const ulong Prime1 = 11400714785074694791ul;
        private const ulong Prime2 = 14029467366897019727ul;
        private const ulong Prime3 = 1609587929392839161ul;
        private const ulong Prime4 = 9650029242287828579ul;
        private const ulong Prime5 = 2870177450012600261ul;
        // temporarily store up to 31 bytes between multiple add() calls
        private const uint MaxBufferSize = 31 + 1;

        private readonly ulong seed;
        private uint bufferSize;
        private ulong totalLength;
        // internal state and temporary buffer
        private ulong[] state = new ulong[4];
        private byte[] buffer = new byte[MaxBufferSize];

        public XXHash64()
        {
            seed = 0;
            Initialize();
        }

        public XXHash64(ulong seed)
        {
            this.seed = seed;
            Initialize();
        }

        public override void Initialize()
        {
            state[0] = seed + Prime1 + Prime2;
            state[1] = seed + Prime2;
            state[2] = seed;
            state[3] = seed - Prime1;
            bufferSize = 0;
            totalLength = 0;

            Array.Clear(buffer, 0, buffer.Length);
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ulong length = (uint)cbSize;
            totalLength += length;
            int current = ibStart;

            // unprocessed old data plus new data still fit in temporary buffer ?
            if (bufferSize + length < MaxBufferSize)
            {
                // just add new data
                while (length-- > 0)
                {
                    buffer[bufferSize++] = array[current++];
                }
            }
            else
            {
                int stop = (ibStart + cbSize);
                int stopBlock = stop - (int)MaxBufferSize;
                ulong[] tempBuff = new ulong[4];
                uint i = 0;

                // some data left from previous update ?
                if (bufferSize > 0)
                {
                    // make sure temporary buffer is full (16 bytes)
                    while (bufferSize < MaxBufferSize)
                    {
                        buffer[bufferSize++] = array[current++];
                    }

                    uint tempBuffIndex = 0;
                    for (i = 0, tempBuffIndex = 0; i < bufferSize && tempBuffIndex < 4; i += 4)
                    {
                        tempBuff[tempBuffIndex++] = BitConverter.ToUInt32(buffer, (int)i);
                    }

                    // process these 32 bytes (4x8)
                    Process(tempBuff, ref state[0], ref state[1], ref state[2], ref state[3]);
                }

                // copying state to local variables helps optimizer A LOT (For C++, not sure for C#)
                // TODO: Check performance of this.
                ulong s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];

                // 32 bytes at once
                while (current <= stopBlock)
                {
                    for (i = 0; i < sizeof(uint); i++)
                    {
                        tempBuff[i] = BitConverter.ToUInt64(array, current);
                        current += sizeof(ulong);
                    }

                    // local variables s0..s3 instead of state[0]..state[3] are much faster
                    Process(tempBuff, ref s0, ref s1, ref s2, ref s3);
                    current += 32;
                }

                // copy back
                state[0] = s0; state[1] = s1; state[2] = s2; state[3] = s3;

                bufferSize = (uint)(stop - current);
                // copy remainder to temporary buffer
                Buffer.BlockCopy(array, current, buffer, 0, (int)bufferSize);
            }
        }

        protected override byte[] HashFinal()
        {
            // fold 256 bit state into one single 64 bit value
            ulong result;
            if (totalLength >= MaxBufferSize)
            {
                result = state[0].RotateLeft(1) +
                         state[1].RotateLeft(7) +
                         state[2].RotateLeft(12) +
                         state[3].RotateLeft(18);
                result = (result ^ ProcessSingle(0, state[0])) * Prime1 + Prime4;
                result = (result ^ ProcessSingle(0, state[1])) * Prime1 + Prime4;
                result = (result ^ ProcessSingle(0, state[2])) * Prime1 + Prime4;
                result = (result ^ ProcessSingle(0, state[3])) * Prime1 + Prime4;
            }
            else
            {
                // internal state wasn't set in add(), therefore original seed is still stored in state2
                result = state[2] + Prime5;
            }

            result += totalLength;

            // at least 8 bytes left ? => eat 8 bytes per step
            int currentByte = 0;
            for (; currentByte + 8 <= bufferSize; currentByte += 8)
            {
                result = (result ^ ProcessSingle(0, BitConverter.ToUInt64(buffer, currentByte)))
                    .RotateLeft(27) * Prime1 + Prime4;
            }

            // 4 bytes left ? => eat those
            if (currentByte + 4 <= bufferSize)
            {
                result = (result ^ BitConverter.ToUInt32(buffer, currentByte) * Prime1)
                    .RotateLeft(23) * Prime2 + Prime3;
                currentByte += 4;
            }

            // take care of remaining 0..3 bytes, eat 1 byte per step
            while (currentByte != bufferSize)
            {
                result = (result ^ buffer[currentByte++] * Prime5).RotateLeft(11) * Prime1;
            }

            // mix bits
            result ^= result >> 33;
            result *= Prime2;
            result ^= result >> 29;
            result *= Prime3;
            result ^= result >> 32;

            return BitConverter.GetBytes(result);
        }

        private static ulong ProcessSingle(ulong previous, ulong input)
        {
            return (previous + input * Prime2).RotateLeft(31) * Prime1;
        }

        // process a block of 4x8 bytes, this is the main part of the XXHash64 algorithm
        private void Process(ulong[] block, ref ulong state0, ref ulong state1, ref ulong state2, ref ulong state3)
        {
            //state0 = ProcessSingle(state0, block[0]);
            state0 = (state0 + block[0] * Prime2).RotateLeft(31) * Prime1;
            //state1 = ProcessSingle(state1, block[1]);
            state1 = (state1 + block[1] * Prime2).RotateLeft(31) * Prime1;
            //state2 = ProcessSingle(state2, block[2]);
            state2 = (state2 + block[2] * Prime2).RotateLeft(31) * Prime1;
            //state3 = ProcessSingle(state3, block[3]);
            state3 = (state3 + block[3] * Prime2).RotateLeft(31) * Prime1;
        }
    }
}
