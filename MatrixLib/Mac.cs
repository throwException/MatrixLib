//
// Mac.cs
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
using System.Text;
using System.Security.Cryptography;

namespace MatrixLib
{
    public static class Mac
    {
        public static byte[] Compute(byte[] secret, string message, string info)
        {
            Console.WriteLine("secret:  " + secret.ToHexString());
            Console.WriteLine("message: " + message);
            Console.WriteLine("info:    " + info);

            var infoBytes = Encoding.UTF8.GetBytes(info);
            var macKey = Hkdf.DeriveKey(new byte[0], secret, infoBytes, 32);

            var messageBytes = Encoding.UTF8.GetBytes(message);
            using (var hmac = new HMACSHA256())
            {
                hmac.Key = macKey;
                return hmac.ComputeHash(messageBytes);
            }
        }
    }
}
