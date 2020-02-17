//
// Hkdf.cs
//
// Author:
//       Stefan Thöni <stefan@savvy.ch>
//
// Copyright (c) 2020 Stefan Thöni
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

using System;
using System.Security.Cryptography;

namespace MatrixLib
{
    public static class Hkdf
    {
        private static byte[] Hmac(byte[] key, byte[] message)
        {
            using (var hmac = new HMACSHA256())
            {
                hmac.Key = key;
                return hmac.ComputeHash(message);
            }
        }

        private static byte[] Extract(byte[] salt, byte[] inputKeyMaterial)
        {
            return Hmac(salt, inputKeyMaterial);
        }

        private static byte[] Expand(byte[] prk, byte[] info, int outputLength)
        {
            var resultBlock = new byte[0];
            var result = new byte[outputLength];
            var bytesRemaining = outputLength;
            for (int j = 1; bytesRemaining > 0; j++)
            {
                var currentInfo = new byte[resultBlock.Length + info.Length + 1];
                Array.Copy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
                Array.Copy(info, 0, currentInfo, resultBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)j;
                resultBlock = Hmac(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, outputLength - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }
            return result;
        }

        public static byte[] DeriveKey(byte[] salt, byte[] inputKeyMaterial, byte[] info, int outputLength)
        {
            var prk = Extract(salt, inputKeyMaterial);
            var result = Expand(prk, info, outputLength);
            return result;
        }
    }
}
