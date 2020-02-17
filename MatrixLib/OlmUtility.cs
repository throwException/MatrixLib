//
// OlmUtility.cs
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
using System.Runtime;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace MatrixLib
{
    public class OlmUtility : IDisposable
    {
        private byte[] _data;
        private GCHandle _handle;

        public OlmUtility()
        {
            var size = NativeMethods.OlmUtilitySize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmUtility(_handle.AddrOfPinnedObject());
        }

        public bool Verify(string key, string message, string signature)
        {
            using (var keyData = new PinnedData(key))
            {
                using (var messageData = new PinnedData(message))
                {
                    using (var signatureData = new PinnedData(signature))
                    {
                        var result = NativeMethods.OlmEd25519Verify(Pointer, keyData.Pointer, keyData.Size, messageData.Pointer, messageData.Size, signatureData.Pointer, signatureData.Size);
                        return NativeMethods.CheckOnOlmError(result);
                    }
                }
            }
        }

        private IntPtr Pointer
        {
            get { return _handle.AddrOfPinnedObject(); }
        }

        public void Dispose()
        {
            if (_handle.IsAllocated)
            {
                _handle.Free();
            }
        }
    }
}
