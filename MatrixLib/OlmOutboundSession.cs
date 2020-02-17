//
// OlmOutboundSession.cs
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
using System.Runtime.InteropServices;
using System.Text;

namespace MatrixLib
{
    public class OlmOutboundSession : IDisposable, IOlmErrorProvider
    {
        private readonly byte[] _data;
        private readonly GCHandle _handle;

        public OlmOutboundSession(byte[] data, GCHandle handle)
        {
            _data = data;
            _handle = handle;
        }

        public OlmOutboundSession()
        {
            var size = NativeMethods.OlmOutboundGroupSessionSize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmOutboundGroupSession(_handle.AddrOfPinnedObject());

            var randomLength = NativeMethods.OlmInitOutboundGroupSessionRandomLength(_handle.AddrOfPinnedObject());
            using (var random = new RandomData(randomLength))
            {
                var result = NativeMethods.OlmInitOutboundGroupSession(_handle.AddrOfPinnedObject(), random.Pointer, random.Size);
                NativeMethods.ThrowOnOlmError(result, this);
            }
        }

        public OlmOutboundSession(string base64, byte[] key)
        {
            var size = NativeMethods.OlmOutboundGroupSessionSize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmOutboundGroupSession(_handle.AddrOfPinnedObject());

            using (var base64Data = new PinnedData(Encoding.UTF8.GetBytes(base64)))
            {
                using (var keyData = new PinnedData(key))
                {
                    var result = NativeMethods.OlmUnpickleOutboundGroupSession(Pointer, keyData.Pointer, keyData.Size, base64Data.Pointer, base64Data.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                }
            }
        }

        public string Id
        {
            get 
            {
                var length = NativeMethods.OlmOutboundGroupSessionIdLength(Pointer);

                using (var id = new PinnedData(length))
                {
                    var result = NativeMethods.OlmOutboundGroupSessionId(Pointer, id.Pointer, id.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                    return id.Text;
                }
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
                var length = NativeMethods.OlmPickleOutboundGroupSessionLength(_handle.AddrOfPinnedObject());
                using (var base64 = new PinnedData(length))
                {
                    var result = NativeMethods.OlmPickleOutboundGroupSession(Pointer, keyData.Pointer, keyData.Size, base64.Pointer, base64.Size);
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

        public Tuple<uint, string> Encrypt(string plainText)
        {
            using (var plainData = new PinnedData(plainText))
            {
                var messageLength = NativeMethods.OlmGroupEncryptMessageLength(
                    Pointer, plainData.Size);

                uint messageIndex = NativeMethods.OlmOutboundGroupSessionMessageIndex(
                    Pointer);

                using (var messageData = new PinnedData(messageLength))
                {
                    var result = NativeMethods.OlmGroupEncrypt(Pointer,
                        plainData.Pointer, plainData.Size,
                        messageData.Pointer, messageData.Size);
                    NativeMethods.ThrowOnOlmError(result, this);

                    return new Tuple<uint, string>(messageIndex, messageData.Text);
                }
            }
        }

        public string LastError
        {
            get
            {
                var stringPointer = NativeMethods.OlmOutboundGroupSessionLastError(Pointer);
                return Marshal.PtrToStringAuto(stringPointer);
            }
        }

        public uint NextChainIndex
        {
            get
            {
                var result = NativeMethods.OlmOutboundGroupSessionMessageIndex(Pointer);
                NativeMethods.ThrowOnOlmError(result, this);
                return result;
            }
        }

        public string Export()
        {
            var keyLength = NativeMethods.OlmOutboundGroupSessionKeyLength(Pointer);
            NativeMethods.ThrowOnOlmError(keyLength, this);

            using (var key = new PinnedData(keyLength))
            {
                var result = NativeMethods.OlmOutboundGroupSessionKey(Pointer, key.Pointer, key.Size);
                NativeMethods.ThrowOnOlmError(result, this);
                return Encoding.UTF8.GetString(key.Data.Part(0, (int)result));
            }
        }
    }
}
