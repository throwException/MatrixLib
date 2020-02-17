//
// OlmInboundSession.cs
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
    public class OlmInboundSession : IDisposable, IOlmErrorProvider
    {
        private readonly byte[] _data;
        private readonly GCHandle _handle;

        public OlmInboundSession(byte[] data, GCHandle handle)
        {
            _data = data;
            _handle = handle;
        }

        public OlmInboundSession(string base64, byte[] key)
        {
            var size = NativeMethods.OlmInboundGroupSessionSize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmInboundGroupSession(_handle.AddrOfPinnedObject());

            using (var base64Data = new PinnedData(base64))
            {
                using (var keyData = new PinnedData(key))
                {
                    var result = NativeMethods.OlmUnpickleInboundGroupSession(Pointer, keyData.Pointer, keyData.Size, base64Data.Pointer, base64Data.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                }
            }
        }

        public OlmInboundSession(string key)
        {
            var size = NativeMethods.OlmInboundGroupSessionSize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmInboundGroupSession(_handle.AddrOfPinnedObject());

            using (var keyData = new PinnedData(key))
            {
                var result = NativeMethods.OlmInitInboundGroupSession(Pointer, keyData.Pointer, keyData.Size);
                NativeMethods.ThrowOnOlmError(result, this);
            }
        }

        private IntPtr Pointer
        {
            get { return _handle.AddrOfPinnedObject(); }
        }

        public string ToBase64(byte[] key)
        {
            using (var keyData = new PinnedData(key))
            {
                var length = NativeMethods.OlmPickleInboundGroupSessionLength(_handle.AddrOfPinnedObject());
                using (var base64 = new PinnedData(length))
                {
                    var result = NativeMethods.OlmPickleInboundGroupSession(Pointer, keyData.Pointer, keyData.Size, base64.Pointer, base64.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                    return Encoding.UTF8.GetString(base64.Data);
                }
            }
        }

        public void Dispose()
        {
            if (_handle.IsAllocated)
            {
                _handle.Free();
            }
        }

        public string LastError
        {
            get
            {
                var stringPointer = NativeMethods.OlmInboundGroupSessionLastError(Pointer);
                return Marshal.PtrToStringAuto(stringPointer);
            }
        }

        public Tuple<uint, string> Decrypt(string cipherText)
        {
            long maxMessageLength = 0;

            using (var cipherData = new PinnedData(cipherText))
            {
                maxMessageLength = NativeMethods.OlmGroupDecryptMaxPlaintextLength(
                    Pointer, cipherData.Pointer, cipherData.Size);
            }

            using (var cipherData = new PinnedData(cipherText))
            {
                using (var plainData = new PinnedData(maxMessageLength))
                {
                    uint messageIndex = 0;
                    var result = NativeMethods.OlmGroupDecrypt(Pointer,
                        cipherData.Pointer, cipherData.Size,
                        plainData.Pointer, plainData.Size,
                        out messageIndex);
                    NativeMethods.ThrowOnOlmError(result, this);
                    return new Tuple<uint, string>(messageIndex, Encoding.UTF8.GetString(plainData.Data.Part(0, (int)result)));
                }
            }
        }
    }
}
