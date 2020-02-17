//
// PinnedData.cs
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
    public class PinnedData : IDisposable
    {
        private readonly GCHandle _handle;

        public byte[] Data { get; }

        public PinnedData(long size)
        {
            Data = new byte[size];
            _handle = GCHandle.Alloc(Data, GCHandleType.Pinned);
        }

        public PinnedData(byte[] data)
        {
            Data = data;
            _handle = GCHandle.Alloc(Data, GCHandleType.Pinned);
        }

        public PinnedData(string text)
        {
            Data = Encoding.UTF8.GetBytes(text);
            _handle = GCHandle.Alloc(Data, GCHandleType.Pinned);
        }

        public string Text
        {
            get { return Encoding.UTF8.GetString(Data); }
        }

        public IntPtr Pointer
        {
            get { return _handle.AddrOfPinnedObject(); }
        }

        public long Size
        {
            get { return Data.Length; }
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
