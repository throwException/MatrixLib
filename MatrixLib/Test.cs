//
// Test.cs
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
using System.Linq;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MatrixLib
{
    public static class Test
    {
        public static void OlmTest()
        {
            var alice = new OlmAccount();
            var aliceIdKs = alice.IdentityKeys;
            var aliceIdKjson = JObject.Parse(aliceIdKs);
            var aliceIdK = aliceIdKjson.Value<string>("curve25519");

            var bob = new OlmAccount();
            var bobIdKs = bob.IdentityKeys;
            var bobIdKjson = JObject.Parse(bobIdKs);
            var bobIdK = bobIdKjson.Value<string>("curve25519");

            var bobOTKs = bob.GenerateOneTimeKeys(bob.MaxNumberOfOneTimeKeys / 2);
            bob.MarkOneTimeKeysPublished();
            var bobOTKjson = JObject.Parse(bobOTKs);
            var bobOTK = bobOTKjson.Value<JObject>("curve25519").Properties().First().Value.Value<string>();

            var aliceSession = alice.CreateOutboundSession(bobIdK, bobOTK);
            var helloCrypt = aliceSession.Encrypt("hello");

            var bobSession = bob.CreateInboundSession(helloCrypt.Item2, aliceIdK);
            var helloPlain = bobSession.Decrypt(helloCrypt.Item1, helloCrypt.Item2);
            if (helloPlain != "hello") throw new Exception();

            var hiCrypt = bobSession.Encrypt("hi");
            var hiPlain = aliceSession.Decrypt(hiCrypt.Item1, hiCrypt.Item2);
            if (hiPlain != "hi") throw new Exception();

            var key = Bytes.GetRandom(32);
            var bobData = bobSession.ToBase64(key);
            bobSession = new OlmSession(bobData, key);

            var olaCrypt = aliceSession.Encrypt("ola");
            var olaPlain = bobSession.Decrypt(olaCrypt.Item1, olaCrypt.Item2);
            if (olaPlain != "ola") throw new Exception();
        }

        public static void MegOlmTest()
        {
            var alice = new OlmOutboundSession();
            var key = alice.Export();

            var bob = new OlmInboundSession(key);

            var helloCrypt = alice.Encrypt("hello");
            var helloPlain = bob.Decrypt(helloCrypt.Item2);
            if (helloCrypt.Item1 != helloPlain.Item1) throw new Exception();
            if (helloPlain.Item2 != "hello") throw new Exception();

            var olaCrypt = alice.Encrypt("ola");
            var olaPlain = bob.Decrypt(olaCrypt.Item2);
            if (olaCrypt.Item1 != olaPlain.Item1) throw new Exception();
            if (olaPlain.Item2 != "ola") throw new Exception();

            var hollaCrypt = alice.Encrypt("holla");
            var hollaPlain = bob.Decrypt(hollaCrypt.Item2);
            if (hollaCrypt.Item1 != hollaPlain.Item1) throw new Exception();
            if (hollaPlain.Item2 != "holla") throw new Exception();
        }
    }
}
