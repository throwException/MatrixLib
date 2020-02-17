//
// MatrixException.cs
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
using System.Net;

namespace MatrixLib
{
    public class MatrixException : Exception
    {
        public string ErrorCode { get; private set; }

        public MatrixException(string errorCode, string errorText)
            : base(errorText)
        {
            ErrorCode = errorCode;
        }
    }

    public class MatrixLimitException : MatrixException
    {
        public MatrixLimitException(string errorCode, string errorText)
            : base(errorCode, errorText)
        {
        }
    }

    public class MatrixWebException : Exception
    {
        public HttpStatusCode StatusCode { get; private set; }

        public MatrixWebException(HttpStatusCode statusCode)
            : base("Http error " + statusCode.ToString())
        {
            StatusCode = statusCode;
        }
    }

    public class MatrixConnectionException : Exception
    {
        public MatrixConnectionException(string mesaage)
            : base(mesaage)
        {
        }
    }
}
