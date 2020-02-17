//
// DeviceKey.cs
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
using Org.Webpki.JsonCanonicalizer;
using Newtonsoft.Json.Linq;

namespace MatrixLib
{
    public class DeviceKey
    {
        private readonly JObject _data;

        public string UserId { get; private set; }
        public string DeviceId { get; private set; }
        public string Curve25519PublicKey { get; private set; }
        public string Ed25519PublicKey { get; private set; }
        public string Ed25519Signtaure{ get; private set; }

        public DeviceKey(JObject data)
        {
            _data = data;
            UserId = _data.Value<string>("user_id");
            DeviceId = _data.Value<string>("device_id");
            var keys = _data.Value<JObject>("keys");
            Curve25519PublicKey = keys.Value<string>("curve25519:" + DeviceId);
            Ed25519PublicKey = keys.Value<string>("ed25519:" + DeviceId);
            var signatures = _data.Value<JObject>("signatures");
            var userSignatures = signatures.Value<JObject>(UserId);
            Ed25519Signtaure = userSignatures.Value<string>("ed25519:" + DeviceId);
        }

        public string CanonicalData
        {
            get 
            {
                var data = _data.DeepClone() as JObject;
                data.Remove("signatures");
                data.Remove("unsigned");
                var canon = new JsonCanonicalizer(data.ToString());
                return canon.GetEncodedString();
            }
        }

        public bool Validate()
        {
            using (var utility = new OlmUtility())
            {
                return utility.Verify(Ed25519PublicKey, CanonicalData, Ed25519Signtaure);
            }
        }
    }
}
