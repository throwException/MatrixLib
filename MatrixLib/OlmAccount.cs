//
// OlmAccount.cs
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
    public interface IOlmErrorProvider
    {
        string LastError { get; } 
    }

    public class OlmAccount : IDisposable, IOlmErrorProvider
    {
        private readonly byte[] _data;
        private readonly GCHandle _handle;

        public OlmAccount()
        {
            var size = NativeMethods.OlmAccountSize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmAccount(_handle.AddrOfPinnedObject());
            var randomLength = NativeMethods.OlmCreateAccountRandomLength(_handle.AddrOfPinnedObject());
            using (var random = new RandomData(randomLength))
            {
                var result = NativeMethods.OlmCreateAccount(Pointer, random.Pointer, random.Size);
                NativeMethods.ThrowOnOlmError(result, this);
            }
        }

        public OlmAccount(string base64, byte[] key)
        {
            var size = NativeMethods.OlmAccountSize();
            _data = new byte[size];
            _handle = GCHandle.Alloc(_data, GCHandleType.Pinned);
            NativeMethods.OlmAccount(_handle.AddrOfPinnedObject());

            using (var base64Data = new PinnedData(Encoding.UTF8.GetBytes(base64)))
            {
                using (var keyData = new PinnedData(key))
                {
                    var result = NativeMethods.OlmUnpickleAccount(Pointer, keyData.Pointer, keyData.Size, base64Data.Pointer, base64Data.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
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
                var length = NativeMethods.OlmPickleAccountLength(_handle.AddrOfPinnedObject());
                using (var base64 = new PinnedData(length))
                {
                    var result = NativeMethods.OlmPickleAccount(Pointer, keyData.Pointer, keyData.Size, base64.Pointer, base64.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                    return Encoding.UTF8.GetString(base64.Data);
                }
            }
        }

        public string IdentityKeys
        {
            get 
            {
                var length = NativeMethods.OlmAccountIdentityKeysLength(Pointer);
                using (var base64 = new PinnedData(length))
                {
                    var result = NativeMethods.OlmAccountIdentityKeys(Pointer, 
                        base64.Pointer, base64.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                    return Encoding.UTF8.GetString(base64.Data);
                }
            }
        }

        public string Sign(string message)
        {
            using (var messageData = new PinnedData(message))
            {
                var length = NativeMethods.OlmAccountSignatureLength(Pointer);
                using (var base64 = new PinnedData(length))
                {
                    var result = NativeMethods.OlmAccountSign(Pointer, 
                        messageData.Pointer, messageData.Size,
                        base64.Pointer, base64.Size);
                    NativeMethods.ThrowOnOlmError(result, this);
                    return Encoding.UTF8.GetString(base64.Data);
                }
            }
        }

        public long MaxNumberOfOneTimeKeys
        {
            get
            {
                return NativeMethods.OlmAccountMaxNumberOfOneTimeKeys(Pointer);
            }
        }

        public string GenerateOneTimeKeys(long count)
        {
            long randomLength = NativeMethods.OlmAccountGenerateOneTimeKeysRandomLength(Pointer, count);

            using (var randomData = new RandomData(randomLength))
            {
                var result = NativeMethods.OlmAccountGenerateOneTimeKeys(Pointer, count, randomData.Pointer, randomData.Size);
                NativeMethods.ThrowOnOlmError(result, this);
            }

            long unpublishedLength = NativeMethods.OlmAccountOneTimeKeysLength(Pointer);

            using (var unpublishedData = new PinnedData(unpublishedLength))
            {
                var result = NativeMethods.OlmAccountOneTimeKeys(Pointer, unpublishedData.Pointer, unpublishedData.Size);
                NativeMethods.ThrowOnOlmError(result, this);
                return unpublishedData.Text;
            }
        }

        public void MarkOneTimeKeysPublished()
        {
            var result = NativeMethods.OlmAccountMarkKeysAsPublished(Pointer);
            NativeMethods.ThrowOnOlmError(result, this);
        }

        public void Dispose()
        {
            if (_handle.IsAllocated)
            {
                _handle.Free();
            }
        }

        public OlmSession CreateInboundSession(string oneTimeKeyMessage, string identityKey)
        {
            var size = NativeMethods.OlmSessionSize();
            var sessionData = new byte[size];
            var sessionHandle = GCHandle.Alloc(sessionData, GCHandleType.Pinned);
            NativeMethods.OlmSession(sessionHandle.AddrOfPinnedObject());

            using (var oneTimeKeyMessageData = new PinnedData(oneTimeKeyMessage))
            {
                using (var identityKeyData = new PinnedData(identityKey))
                {
                    var result = NativeMethods.OlmCreateInboundSessionFrom(
                        sessionHandle.AddrOfPinnedObject(), Pointer,
                        identityKeyData.Pointer, identityKeyData.Size,
                        oneTimeKeyMessageData.Pointer, oneTimeKeyMessageData.Size);
                    NativeMethods.ThrowOnOlmError(result, new OlmSession(sessionData, sessionHandle));
                }
            }

            var result2 = NativeMethods.OlmRemoveOneTimeKeys(Pointer, sessionHandle.AddrOfPinnedObject());
            NativeMethods.ThrowOnOlmError(result2, this);

            return new OlmSession(sessionData, sessionHandle);
        }

        public string LastError
        {
            get
            {
                var stringPointer = NativeMethods.OlmAccountLastError(Pointer);
                return Marshal.PtrToStringAuto(stringPointer);
            }
        }

        public OlmSession CreateOutboundSession(string theirIdentityKey, string theirOneTimeKey)
        {
            var size = NativeMethods.OlmSessionSize();
            var sessionData = new byte[size];
            var sessionHandle = GCHandle.Alloc(sessionData, GCHandleType.Pinned);
            NativeMethods.OlmSession(sessionHandle.AddrOfPinnedObject());

            using (var theirIdentityKeyData = new PinnedData(theirIdentityKey))
            {
                using (var theirOneTimeKeyData = new PinnedData(theirOneTimeKey))
                {
                    var randomLength = NativeMethods.OlmCreateOutboundSessionRandomLength(
                        sessionHandle.AddrOfPinnedObject());

                    using (var randomData = new RandomData(randomLength))
                    {
                        var result = NativeMethods.OlmCreateOutboundSession(
                            sessionHandle.AddrOfPinnedObject(), Pointer,
                            theirIdentityKeyData.Pointer, theirIdentityKeyData.Size,
                            theirOneTimeKeyData.Pointer, theirOneTimeKeyData.Size,
                            randomData.Pointer, randomData.Size);
                        NativeMethods.ThrowOnOlmError(result, new OlmSession(sessionData, sessionHandle));
                    }
                }
            }

            return new OlmSession(sessionData, sessionHandle);
        }
    }
}
