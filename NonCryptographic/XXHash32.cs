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
    public sealed class XXHash32 : HashAlgorithm
    {
        public override int HashSize => 32;
        // magic constants :-)
        private const uint Prime1 = 2654435761u;
        private const uint Prime2 = 2246822519u;
        private const uint Prime3 = 3266489917u;
        private const uint Prime4 = 668265263u;
        private const uint Prime5 = 374761393u;
        // temporarily store up to 15 bytes between multiple add() calls
        private const uint MaxBufferSize = 15 + 1;

        private readonly uint seed;
        private uint bufferSize;
        private ulong totalLength;
        // internal state and temporary buffer
        private uint[] state = new uint[4];
        private byte[] buffer = new byte[MaxBufferSize];

        public XXHash32()
        {
            seed = 0;
            Initialize();
        }

        public XXHash32(uint seed)
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
            uint length = (uint)cbSize;
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
                uint[] tempBuff = new uint[4];
                uint i = 0;

                // some data left from previous update ?
                if (bufferSize > 0)
                {
                    // make sure temporary buffer is full (16 bytes)
                    while (bufferSize < MaxBufferSize)
                    {
                        buffer[bufferSize++] = array[current++];
                    }

                    int tempBuffIndex;
                    for (i = 0, tempBuffIndex = 0; i < bufferSize && tempBuffIndex < 4; i += 4)
                    {
                        tempBuff[tempBuffIndex++] = BitConverter.ToUInt32(buffer, (int)i);
                    }

                    // process these 16 bytes (4x4)
                    Process(tempBuff, ref state[0], ref state[1], ref state[2], ref state[3]);
                }

                // copying state to local variables helps optimizer A LOT (Not sure for C#)
                // TODO: Check performance of this.
                uint s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];

                // 16 bytes at once
                while (current <= stopBlock)
                {
                    // Calculations are all Little-Endian
                    for (i = 0; i < sizeof(uint); i++)
                    {
                        tempBuff[i] = BitConverter.ToUInt32(array, current);
                        current += sizeof(uint);
                    }

                    // local variables s0..s3 instead of state[0]..state[3] are much faster
                    Process(tempBuff, ref s0, ref s1, ref s2, ref s3);
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
            uint result = (uint)totalLength;

            // fold 128 bit state into one single 32 bit value
            if (totalLength >= MaxBufferSize)
            {
                result += state[0].RotateLeft(1) +
                          state[1].RotateLeft(7) +
                          state[2].RotateLeft(12) +
                          state[3].RotateLeft(18);
            }
            else
            {
                // internal state wasn't set in add(), therefore original seed is still stored in state2
                result += state[2] + Prime5;
            }

            uint currentByte = 0;
            uint working;

            // at least 4 bytes left ? => eat 4 bytes per step
            while (currentByte + 4 <= bufferSize)
            {
                working = BitConverter.ToUInt32(buffer, (int)currentByte);
                result = (result + working).RotateLeft(17) * Prime3;
                currentByte += 4;
            }

            // take care of remaining 0..3 bytes, eat 1 byte per step
            while (currentByte != bufferSize)
            {
                result = (result + (buffer[currentByte++]) * Prime5).RotateLeft(11) * Prime1;
            }

            // mix bits
            result ^= result >> 15;
            result *= Prime2;
            result ^= result >> 13;
            result *= Prime3;
            result ^= result >> 16;

            return BitConverter.GetBytes(result);
        }

        //private static uint ProcessSingle(uint previous, uint input)
        //{
        //    return (previous + input * Prime2).RotateLeft(13) * Prime1;
        //}

        // process a block of 4x4 bytes, this is the main part of the XXHash32 algorithm
        private void Process(uint[] block, ref uint state0, ref uint state1, ref uint state2, ref uint state3)
        {
            //state0 = ProcessSingle(state0, block[0]);
            state0 = (state0 + block[0] * Prime2).RotateLeft(13) * Prime1;
            //state1 = ProcessSingle(state1, block[1]);
            state1 = (state1 + block[1] * Prime2).RotateLeft(13) * Prime1;
            //state2 = ProcessSingle(state2, block[2]);
            state2 = (state2 + block[2] * Prime2).RotateLeft(13) * Prime1;
            //state3 = ProcessSingle(state3, block[3]);
            state3 = (state3 + block[3] * Prime2).RotateLeft(13) * Prime1;
        }
    }
}
