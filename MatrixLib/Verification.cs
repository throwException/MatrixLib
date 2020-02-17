//
// Verification.cs
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
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using Sodium;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.Webpki.JsonCanonicalizer;

namespace MatrixLib
{
    public class Verification
    {
        public string ThisUserId { get; private set; }
        public string ThisDeviceId { get; private set; }
        public string OtherUserId { get; private set; }
        public string OtherDeviceId { get; private set; }
        public string TransactionId { get; private set; }
        public DateTime Time { get; private set; }

        private IStorage _storage;
        private KeyPair _keys;
        private string _commitmentHash;
        private byte[] _sharedSecret;
        private Action<Verification, string, string> _cancel;
        private Action<VerificationEvent> _userVerify;
        private Action<string, JObject, IDevice> _sendToDevice;

        public Verification(
            IStorage storage,
            string thisUserId, 
            string thisDeviceId,
            string otherUserId,
            string otherDeviceId,
            string transactionId, 
            Action<Verification, string, string> cancel,
            Action<VerificationEvent> userVerify,
            Action<string, JObject, IDevice> sendToDevice)
        {
            _storage = storage;
            ThisUserId = thisUserId;
            ThisDeviceId = thisDeviceId;
            OtherUserId = otherUserId;
            OtherDeviceId = otherDeviceId;
            TransactionId = transactionId;
            _cancel = cancel;
            _userVerify = userVerify;
            _sendToDevice = sendToDevice;
            Time = DateTime.UtcNow;
            _keys = PublicKeyBox.GenerateKeyPair();
        }

        public void Handle(KeyVerificationEvent evt)
        {
            if (evt is KeyVerificationKeyEvent keyVerificationKeyEvent)
            {
                if (DateTime.UtcNow > Time.AddMinutes(10))
                {
                    Console.WriteLine("key verificaton timed out.");
                    _cancel(this, "m.timeout", "Key verification timeout");
                }
                else if (string.IsNullOrEmpty(_commitmentHash))
                {
                    SendKeyVerificationKey();
                    var publicKey = keyVerificationKeyEvent.Key.FromBase64WithoutPadding();
                    _sharedSecret = ScalarMult.Mult(_keys.PrivateKey, publicKey);
                    _userVerify(new VerificationEvent(DeriveKey()));
                }
                else
                {
                    // TODO handle case when I'm initiator
                }
            }
            else if (evt is KeyVerificationMacEvent keyVerificationMacEvent)
            {
                if (DateTime.UtcNow > Time.AddMinutes(10))
                {
                    Console.WriteLine("key verificaton timed out.");
                    _cancel(this, "m.timeout", "Key verification timeout");
                }
                else
                {
                    if (VerifyMacKeys(keyVerificationMacEvent))
                    {
                        if (string.IsNullOrEmpty(_commitmentHash))
                        {
                            // TODO implement send macs
                        }
                    }
                    else
                    {
                        _cancel(this, "m.key_mismatch", "Wrong mac");
                    }
                }
            }
        }

        private bool VerifyMacKeys(KeyVerificationMacEvent keyVerificationMacEvent)
        {
            var baseInfo = "MATRIX_KEY_VERIFICATION_MAC";
            baseInfo += OtherUserId;
            baseInfo += OtherDeviceId;
            baseInfo += ThisUserId;
            baseInfo += ThisDeviceId;
            baseInfo += TransactionId;

            var keyIdList = keyVerificationMacEvent.Macs
                .Select(k => k.Key)
                .OrderBy(x => x)
                .ToList();
            var keyIds = string.Join(",", keyIdList);

            var keyMac = Mac.Compute(_sharedSecret, keyIds, baseInfo + "KEY_IDS");
            if (!keyMac.Equal(keyVerificationMacEvent.Keys.FromBase64WithoutPadding()))
                return false;

            var device = _storage.GetDevice(OtherUserId, OtherDeviceId);
            foreach (var m in keyVerificationMacEvent.Macs)
            {
                var mMac = Mac.Compute(_sharedSecret, device.Ed25519PublicKey, baseInfo + m.Key);
                if (!mMac.Equal(m.Value.FromBase64WithoutPadding()))
                    return false;
            }

            return true;
        }

        private byte[] DeriveKey()
        {
            var input = "MATRIX_KEY_VERIFICATION_SAS";

            if (string.IsNullOrEmpty(_commitmentHash))
            {
                input += OtherUserId;
                input += OtherDeviceId;
                input += ThisUserId;
                input += ThisDeviceId;
            }
            else
            {
                input += ThisUserId;
                input += ThisDeviceId;
                input += OtherUserId;
                input += OtherDeviceId;
            }

            input += TransactionId;

            return Hkdf.DeriveKey(new byte[0], _sharedSecret, Encoding.UTF8.GetBytes(input), 6);
        }

        private void SendKeyVerificationKey()
        {
            var device = _storage.GetDevice(OtherUserId, OtherDeviceId);
            var message = new JObject(
                new JProperty("key", _keys.PublicKey.ToBase64WithoutPadding()),
                new JProperty("transaction_id", TransactionId));
            _sendToDevice("m.key.verification.key", message, device);
        }

        private string ComputeCommitment(JObject startMessage)
        {
            var content = startMessage.Value<JObject>("content");
            var canon = new JsonCanonicalizer(content.ToString());
            var input = _keys.PublicKey.ToBase64WithoutPadding() + canon.GetEncodedString();
            var hash = Encoding.UTF8.GetBytes(input).HashSha256();
            var base64Hash = hash.ToBase64WithoutPadding(); ;
            return base64Hash;
        }

        public void SendKeyVerificationAccept(JObject startMessage)
        {
            var commitment = ComputeCommitment(startMessage);
            var device = _storage.GetDevice(OtherUserId, OtherDeviceId);
            var message = new JObject(
                new JProperty("hash", "sha256"),
                new JProperty("key_agreement_protocol", "curve25519"),
                new JProperty("message_authentication_code", "hkdf-hmac-sha256"),
                new JProperty("short_authentication_string",
                    new JArray("emoji")),
                new JProperty("commitment", commitment),
                new JProperty("method", "m.sas.v1"),
                new JProperty("transaction_id", TransactionId));
            _sendToDevice("m.key.verification.accept", message, device);
        }
    }
}
