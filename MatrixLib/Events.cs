//
// Events.cs
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
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace MatrixLib
{
    public interface IEvent
    {
        string RoomId { get; }
        string UserId { get; }
        string DeviceId { get; }
        bool Encrypted { get; }
        int VerificationLevel { get; }
    }

    public class BaseEvent : IEvent
    {
        public string RoomId { get; private set; }
        public string UserId { get; private set; }
        public string DeviceId { get; private set; }
        public bool Encrypted { get; private set; }
        public int VerificationLevel { get; private set; }

        public BaseEvent(string roomId, string userId, string deviceId, bool encrypted, int verificationLevel)
        {
            RoomId = roomId;
            UserId = userId;
            DeviceId = deviceId;
            Encrypted = encrypted;
            VerificationLevel = verificationLevel;
        }
    }

    public class TimelineEvent : IEvent
    {
        public string Type { get; private set; }
        public string EventId { get; private set; }
        public string RoomId { get; protected set; }
        public string UserId { get; protected set; }
        public string DeviceId { get; protected set; }
        public DateTime Time { get; private set; }
        public bool Encrypted { get; private set; }
        public int VerificationLevel { get; private set; }

        public TimelineEvent(JObject eventData, IEvent parent)
        {
            Type = eventData.Value<string>("type");
            EventId = eventData.Value<string>("event_id");
            RoomId = parent.RoomId;
            UserId = eventData.Value<string>("sender") ?? parent.UserId;
            DeviceId = parent.DeviceId;
            Time = new DateTime(1970, 1, 1).AddMilliseconds(eventData.Value<long>("origin_server_ts"));
            Encrypted = parent.Encrypted;
            VerificationLevel = parent.VerificationLevel;
        }

        public static TimelineEvent Parse(JObject eventData, IEvent parent)
        {
            var type = eventData.Value<string>("type");

            switch (type)
            {
                case "m.room.message":
                    return new MessageEvent(eventData, parent);
                case "m.room.encryption":
                    return new EncryptionEvent(eventData, parent);
                case "m.room.encrypted":
                    return new EncryptedEvent(eventData, parent);
                case "m.room.member":
                    return new MemberEvent(eventData, parent);
                case "m.room_key":
                    return new RoomKeyEvent(eventData, parent);
                case "m.room_key_request":
                    return new RoomKeyRequestEvent(eventData, parent);
                case "m.key.verification.start":
                    return new KeyVerificationStartEvent(eventData, parent);
                case "m.key.verification.cancel":
                    return new KeyVerificationCancelEvent(eventData, parent);
                case "m.key.verification.key":
                    return new KeyVerificationKeyEvent(eventData, parent);
                case "m.key.verification.mac":
                    return new KeyVerificationMacEvent(eventData, parent);
                case "m.room.create":
                case "m.room.guest_access":
                case "m.room.history_visibility":
                case "m.room.join_rules":
                case "m.room.name":
                case "m.room.power_levels":
                    return null;
                default:
                    Console.WriteLine("Unknown message: " + type);
                    return null;
            }
        }
    }

    public class EncryptionEvent : TimelineEvent
    {
        public string Algorithm { get; private set; }

        public EncryptionEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            Algorithm = content.Value<string>("algorithm");
        }
    }

    public class MemberEvent : TimelineEvent
    {
        public MemberEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            UserId = eventData.Value<string>("user_id");
        }
    }

    public class RoomKeyEvent : TimelineEvent
    {
        public string SessionId { get; private set; }
        public string SessionKey { get; private set; }
        public int ChainIndex { get; private set; }

        public RoomKeyEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            SessionId = content.Value<string>("session_id");
            SessionKey = content.Value<string>("session_key");
            ChainIndex = content.Value<int>("chain_index");
        }
    }

    public class RoomKeyRequestEvent : TimelineEvent
    {
        public string Action { get; private set; }

        public string RequestId { get; private set; }

        public string RequestingDeviceId { get; private set; }

        public string Algorithm { get; private set; }

        public string SenderKey { get; private set; }

        public string SessionId { get; private set; }

        public RoomKeyRequestEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            Action = content.Value<string>("action");
            RequestId = content.Value<string>("request_id");
            RequestingDeviceId = content.Value<string>("requesting_device_id");
            if (Action == "request")
            {
                var body = content.Value<JObject>("body");
                RoomId = body.Value<string>("room_id");
                Algorithm = body.Value<string>("algorithm");
                SenderKey = body.Value<string>("sender_key");
                SessionId = body.Value<string>("session_id");
            }
        }
    }

    public class EncryptedEvent : TimelineEvent
    {
        public JObject Content { get; private set; }    

        public EncryptedEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            Content = eventData.Value<JObject>("content");
        }
    }

    public class KeyVerificationStartEvent : TimelineEvent
    {
        public string TransactionId { get; private set; }
        public string Method { get; private set; }
        public IEnumerable<string> Hashes { get; private set; }
        public IEnumerable<string> KeyAgreementProtocols { get; private set; }
        public IEnumerable<string> MessageAuthenticationCodes { get; private set; }
        public IEnumerable<string> ShortAuthenticationString { get; private set; }

        public KeyVerificationStartEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            DeviceId = content.Value<string>("from_device");
            TransactionId = content.Value<string>("transaction_id");
            Method = content.Value<string>("method");
            Hashes = content.ArrayValues<string>("hashes");
            KeyAgreementProtocols = content.ArrayValues<string>("key_agreement_protocols");
            MessageAuthenticationCodes = content.ArrayValues<string>("message_authentication_codes");
            ShortAuthenticationString = content.ArrayValues<string>("short_authentication_string");
        }
    }

    public class KeyVerificationCancelEvent : TimelineEvent
    {
        public string TransactionId { get; private set; }
        public string Code { get; private set; }
        public string Reason { get; private set; }

        public KeyVerificationCancelEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            TransactionId = content.Value<string>("transaction_id");
            Code = content.Value<string>("code");
            Reason = content.Value<string>("reason");
        }
    }

    public class KeyVerificationEvent : TimelineEvent
    {
        public string TransactionId { get; private set; }

        public KeyVerificationEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            TransactionId = content.Value<string>("transaction_id");
        }
    }

    public class KeyVerificationKeyEvent : KeyVerificationEvent
    {
        public string Key { get; private set; }

        public KeyVerificationKeyEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            Key = content.Value<string>("key");
        }
    }

    public class KeyVerificationMacEvent : KeyVerificationEvent
    {
        public string Keys { get; private set; }
        public IEnumerable<KeyValuePair<string, string>> Macs { get; private set; }

        public KeyVerificationMacEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            Keys = content.Value<string>("keys");
            var macs = content.Value<JObject>("mac");
            var macList = new List<KeyValuePair<string, string>>();
            foreach (var property in macs.Properties())
            {
                macList.Add(new KeyValuePair<string, string>(property.Name, property.Value.Value<string>()));
            }
            Macs = macList;
        }
    }

    public class MessageEvent : TimelineEvent
    {
        public string Body { get; private set; }
        public string MessageType { get; private set; }
        public string Format { get; private set; }
        public string FormattedBody { get; private set; }

        public MessageEvent(JObject eventData, IEvent parent)
            : base(eventData, parent)
        {
            var content = eventData.Value<JObject>("content");
            Body = content.Value<string>("body");
            MessageType = content.Value<string>("msgtype");
            Format = content.Value<string>("format");
            FormattedBody = content.Value<string>("formatted_body");
        }
    }

    public class VerificationEvent
    {
        public IEnumerable<int> Emojis { get; }

        public VerificationEvent(byte[] derivedKey)
        {
            var chars = Convert.ToBase64String(derivedKey);
            var emojis = new List<int>();

            for (int i = 0; i < 7; i++)
            {
                char c = chars[i];

                if (c >= 'A' && c <= 'Z')
                {
                    int value = (int)c - (int)'A' + 0;
                    emojis.Add(value);
                }
                else if (c >= 'a' && c <= 'z')
                {
                    int value = (int)c - (int)'a' + 26;
                    emojis.Add(value);
                }
                else if (c >= '0' && c <= '9')
                {
                    int value = (int)c - (int)'0' + 52;
                    emojis.Add(value);
                }
                else if (c == '+')
                {
                    emojis.Add(62);
                }
                else if (c == '/')
                {
                    emojis.Add(63);
                }
                else 
                {
                    throw new ArgumentOutOfRangeException(); 
                }
            }

            Emojis = emojis;
        }
    }
}
