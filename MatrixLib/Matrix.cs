//
// Matrix.cs
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
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Security.Cryptography;
using System.Threading;
using Newtonsoft.Json.Linq;
using Org.Webpki.JsonCanonicalizer;
using Sodium;

namespace MatrixLib
{
    public class Matrix
    {
        private readonly string _apiUrl;
        private readonly byte[] _dataKey;
        private readonly IStorage _storage;
        private readonly OlmAccount _olmAccount;
        private readonly string _senderKeyCurve25519;
        private readonly string _senderKeyEd25519;

        private string _accessToken;
        private string _syncNextBatch;
        private Dictionary<string, Verification> _verifications;

        public string DeviceId { get; private set; }
        public string UserId { get; private set; }
        public string HomeServer { get; private set; }

        public event EventHandler<MessageEvent> OnMessage;
        public event EventHandler<VerificationEvent> OnUserVerify;

        public Matrix(IStorage storage)
        {
            _storage = storage;
            _verifications = new Dictionary<string, Verification>();

            var config = _storage.GetConfig();
            _apiUrl = config.ApiUrl;
            _dataKey = config.DataKey;

            var state = _storage.GetState();
            _accessToken = state.AccessToken;
            _syncNextBatch = state.SyncNextBatch;
            UserId = state.UserId;
            DeviceId = state.DeviceId;
            HomeServer = state.HomeServer;

            var accountData = _storage.GetState().AccountData;
            if (string.IsNullOrEmpty(accountData))
            {
                _olmAccount = new OlmAccount();
                _storage.SetOlmAccountData(_olmAccount.ToBase64(_storage.GetConfig().DataKey));
            }
            else
            {
                _olmAccount = new OlmAccount(accountData, _storage.GetConfig().DataKey);
            }

            var keys = JObject.Parse(_olmAccount.IdentityKeys);
            _senderKeyCurve25519 = keys.Value<string>("curve25519");
            _senderKeyEd25519 = keys.Value<string>("ed25519");

            byte major = 0;
            byte minor = 0;
            byte patch = 0;
            NativeMethods.OlmGetLibraryVersion(ref major, ref minor, ref patch);

            if (major != 2 ||
                minor < 2)
            {
                var message = string.Format(
                    "Library version {0}.{1}.{2} not supported", 
                    major, minor, patch);
                throw new NotSupportedException(message); 
            }
        }

        private void SyncJoinedRoom(string roomId, JObject roomData)
        {
            var timeline = roomData.Value<JObject>("timeline");
            var timelineEvents = timeline.Value<JArray>("events");
            foreach (JObject eventData in timelineEvents.Values<JObject>())
            {
                var evt = TimelineEvent.Parse(eventData, new BaseEvent(roomId, null, null, false, 0));
                if (evt != null)
                {
                    HandleEvent(evt, eventData);
                }
            }
        }

        public void UpdateJoinedRooms()
        {
            var response = Request<JObject>("_matrix/client/r0/joined_rooms", HttpMethod.Get, null);

            var rooms = response.Value<JArray>("joined_rooms");
            foreach (var roomId in rooms.Values<string>())
            {
                _storage.AddRoom(roomId);
            }
        }

        private void RequestRoomKey(string roomId, string senderKey, string sessionId)
        {
            var room = _storage.GetRoom(roomId);

            if (room != null)
            {
                foreach (var membership in room.Memberships)
                {
                    RequestRoomKey(membership, senderKey, sessionId);
                }
            }
        }

        private void RequestRoomKey(IMembership membership, string senderKey, string sessionId)
        {
            var requestId = Bytes.GetRandom(16).ToHexString();
            var message = new JObject(
                new JProperty("content",
                    new JObject(
                        new JProperty("action", "request"),
                        new JProperty("body",
                            new JObject(
                                new JProperty("algorithm", "m.megolm.v1.aes-sha2"),
                                new JProperty("room_id", membership.Room.Id),
                                new JProperty("sender_key", senderKey),
                                new JProperty("session_id", sessionId))),
                        new JProperty("request_id", requestId),
                        new JProperty("requesting_device_id", DeviceId))),
                new JProperty("type", "m.room_key_request"));
            SendToDevice("m.room_key_request", message, membership.Device);
        }

        private JObject EncryptOlm(JObject data, string userId, string deviceId)
        {
            var device = _storage.GetDevice(userId, deviceId);
            return EncryptOlm(data, device);
        }

        private JObject EncryptOlm(JObject data, IDevice device)
        {
            if (string.IsNullOrEmpty(device.SessionData))
            {
                var oneTimeKey = ClaimOneTimeKey(device);

                if (oneTimeKey != null)
                {
                    using (var olmSession = _olmAccount.CreateOutboundSession(device.Curve25519PublicKey, oneTimeKey))
                    {
                        var sessionData = olmSession.ToBase64(_storage.GetConfig().DataKey);
                        _storage.SetDeviceSession(device.User.Id, device.Id, sessionData);
                    }
                }
            }

            device = _storage.GetDevice(device.User.Id, device.Id);
            if (!string.IsNullOrEmpty(device.SessionData))
            {
                using (var olmSession = new OlmSession(device.SessionData, _storage.GetConfig().DataKey))
                {
                    var cipherText = olmSession.Encrypt(data.ToString());
                    _storage.SetDeviceSession(device.User.Id, device.Id, olmSession.ToBase64(_storage.GetConfig().DataKey));
                    var encrypted = new JObject(
                        new JProperty("algorithm", "m.olm.v1.curve25519-aes-sha2"),
                        new JProperty("sender_key", _senderKeyCurve25519),
                        new JProperty("ciphertext",
                            new JObject(
                                new JProperty(device.Curve25519PublicKey,
                                    new JObject(
                                        new JProperty("type", cipherText.Item1),
                                        new JProperty("body", cipherText.Item2))))));
                    return encrypted;
                }
            }
            else
            {
                return null;
            }
        }

        private void SendToDevice(string eventType, JObject message, IDevice device)
        {
            var transactionId = Bytes.GetRandom(16).ToHexString();
            var endpoint = string.Format("_matrix/client/r0/sendToDevice/{0}/{1}", eventType, transactionId);
            var request = new JObject(
                new JProperty("messages",
                    new JObject(
                        new JProperty(device.User.Id,
                            new JObject(
                                new JProperty(device.Id,
                                    message))))));
            var response = Request<JObject>(endpoint, HttpMethod.Put, request);
            Console.WriteLine("Sent to {0} {1}", device.User.Id, device.Id);
        }

        private void HandleEvent(TimelineEvent evt, JObject message)
        {
            if (evt is MessageEvent messageEvent)
            {
                Console.WriteLine("MessageEvent");
                OnMessage?.Invoke(this, messageEvent);
            }
            else if (evt is EncryptionEvent encryptionEvent)
            {
                Console.WriteLine("EncryptionEvent");
                _storage.SetRoomEncrypted(encryptionEvent.RoomId);
            }
            else if (evt is EncryptedEvent encryptedEvent)
            {
                Console.WriteLine("EncryptedEvent");
                Decrypt(encryptedEvent);
            }
            else if (evt is MemberEvent memberEvent)
            {
                if (!string.IsNullOrEmpty(memberEvent.UserId))
                {
                    Console.WriteLine("MemberEvent");
                    AddMember(memberEvent);
                }
            }
            else if (evt is RoomKeyEvent roomKeyEvent)
            {
                if (roomKeyEvent.Encrypted)
                {
                    using (var megOlmSession = new OlmInboundSession(roomKeyEvent.SessionKey))
                    {
                        _storage.SetMegOlmInboundRoomKey(roomKeyEvent.UserId, roomKeyEvent.DeviceId, roomKeyEvent.SessionId, megOlmSession.ToBase64(_storage.GetConfig().DataKey));
                    }
                }
            }
            else if (evt is RoomKeyRequestEvent roomKeyRequestEvent)
            {
                if (roomKeyRequestEvent.Action == "request")
                {
                    var membership = _storage.AddMembership(roomKeyRequestEvent.UserId, roomKeyRequestEvent.RequestingDeviceId, evt.RoomId);
                    if (_senderKeyCurve25519 == roomKeyRequestEvent.SenderKey)
                    {
                        using (var session = new OlmOutboundSession(membership.Room.OutboundSessionData, _dataKey))
                        {
                            SendRoomKey(membership, session);
                        }
                    }
                }
            }
            else if (evt is KeyVerificationStartEvent keyVerificationStartEvent)
            {
                if (!string.IsNullOrEmpty(keyVerificationStartEvent.TransactionId) &&
                    !string.IsNullOrEmpty(keyVerificationStartEvent.UserId) &&
                    !string.IsNullOrEmpty(keyVerificationStartEvent.DeviceId))
                {
                    if (keyVerificationStartEvent.Method != "m.sas.v1" ||
                        !keyVerificationStartEvent.Hashes.Contains("sha256") ||
                        !keyVerificationStartEvent.KeyAgreementProtocols.Contains("curve25519") ||
                        !keyVerificationStartEvent.MessageAuthenticationCodes.Contains("hkdf-hmac-sha256") ||
                        !keyVerificationStartEvent.ShortAuthenticationString.Contains("emoji"))
                    {
                        SendKeyVerificationCancel(
                            keyVerificationStartEvent.UserId,
                            keyVerificationStartEvent.DeviceId,
                            "m.unknown_method",
                            "Unkonwn verification method",
                            keyVerificationStartEvent.TransactionId);
                    }
                    else
                    {
                        var verification = new Verification(
                            _storage,
                            UserId,
                            DeviceId,
                            keyVerificationStartEvent.UserId,
                            keyVerificationStartEvent.DeviceId,
                            keyVerificationStartEvent.TransactionId,
                            CancelVerification,
                            UserVerfiyVerification,
                            SendToDevice);
                        _verifications.Add(verification.TransactionId, verification);
                        verification.SendKeyVerificationAccept(message);
                    }
                }
            }
            else if (evt is KeyVerificationCancelEvent keyVerificationCancelEvent)
            {
                if (_verifications.ContainsKey(keyVerificationCancelEvent.TransactionId))
                {
                    Console.WriteLine("key verificaton canceled: " + keyVerificationCancelEvent.Reason);
                    _verifications.Remove(keyVerificationCancelEvent.TransactionId);
                }
            }
            else if (evt is KeyVerificationEvent keyVerificationEvent)
            {
                if (_verifications.ContainsKey(keyVerificationEvent.TransactionId))
                {
                    _verifications[keyVerificationEvent.TransactionId].Handle(keyVerificationEvent);
                }
            }
        }

        private void UserVerfiyVerification(VerificationEvent evt)
        {
            OnUserVerify?.Invoke(this, evt);
        }

        private void CancelVerification(Verification verification, string code, string reason)
        {
            _verifications.Remove(verification.TransactionId);
            SendKeyVerificationCancel(
                verification.OtherUserId,
                verification.OtherDeviceId,
                code,
                reason,
                verification.TransactionId);
        }

        public string GetShortAuthenticationEmojiName(int emoji)
        {
            switch (emoji)
            {
                case 0:
                    return "Dog";
                case 1:
                    return "Cat";
                case 2:
                    return "Lion";
                case 3:
                    return "Horse";
                case 4:
                    return "Unicorn";
                case 5:
                    return "Pig";
                case 6:
                    return "Elephant";
                case 7:
                    return "Rabbit";
                case 8:
                    return "Panda";
                case 9:
                    return "Rooster";
                case 10:
                    return "Penguin";
                case 11:
                    return "Turtle";
                case 12:
                    return "Fish";
                case 13:
                    return "Octopus";
                case 14:
                    return "Butterfly";
                case 15:
                    return "Flower";
                case 16:
                    return "Tree";
                case 17:
                    return "Cactus";
                case 18:
                    return "Mushroom";
                case 19:
                    return "Globe";
                case 20:
                    return "Moon";
                case 21:
                    return "Cloud";
                case 22:
                    return "Fire";
                case 23:
                    return "Banana";
                case 24:
                    return "Apple";
                case 25:
                    return "Strawberry";
                case 26:
                    return "Corn";
                case 27:
                    return "Pizza";
                case 28:
                    return "Cake";
                case 29:
                    return "Heart";
                case 30:
                    return "Smiley";
                case 31:
                    return "Robot";
                case 32:
                    return "Hat";
                case 33:
                    return "Glasses";
                case 34:
                    return "Spanner";
                case 35:
                    return "Santa";
                case 36:
                    return "Thumbs Up";
                case 37:
                    return "Umbrella";
                case 38:
                    return "Hourglass";
                case 39:
                    return "Clock";
                case 40:
                    return "Gift";
                case 41:
                    return "Light Bulb";
                case 42:
                    return "Book";
                case 43:
                    return "Pencil";
                case 44:
                    return "Paperclip";
                case 45:
                    return "Scissors";
                case 46:
                    return "Lock";
                case 47:
                    return "Key";
                case 48:
                    return "Hammer";
                case 49:
                    return "Telephone";
                case 50:
                    return "Flag";
                case 51:
                    return "Train";
                case 52:
                    return "Bicycle";
                case 53:
                    return "Aeroplane";
                case 54:
                    return "Rocket";
                case 55:
                    return "Trophy";
                case 56:
                    return "Ball";
                case 57:
                    return "Guitar";
                case 58:
                    return "Trumpet";
                case 59:
                    return "Bell";
                case 60:
                    return "Anchor";
                case 61:
                    return "Headphones";
                case 62:
                    return "Folder";
                case 63:
                    return "Pin";
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private void SendKeyVerificationCancel(string userId, string deviceId, string code, string reason, string transactionId)
        {
            var device = _storage.GetDevice(userId, deviceId);
            var message = new JObject(
                new JProperty("code", code),
                new JProperty("reason", reason),
                new JProperty("transaction_id", transactionId));
            SendToDevice("m.key.verification.cancel", message, device);
        }

        private void AddMember(MemberEvent memberEvent)
        {
            foreach (var deviceKey in GetDeviceKeys(memberEvent.UserId))
            {
                _storage.AddMembership(memberEvent.UserId, deviceKey.DeviceId, memberEvent.RoomId);
            }
        }

        private string ClaimOneTimeKey(IDevice device)
        {
            var request = new JObject(
                new JProperty("one_time_keys",
                    new JObject(
                        new JProperty(device.User.Id,
                            new JObject(
                                new JProperty(device.Id, "signed_curve25519"))))));
            var response = Request<JObject>("_matrix/client/r0/keys/claim", HttpMethod.Post, request);
            var oneTimeKeys = response.Value<JObject>("one_time_keys");
            if (oneTimeKeys != null)
            {
                var userKeys = oneTimeKeys.Value<JObject>(device.User.Id);
                if (userKeys != null)
                {
                    var deviceObject = userKeys.Value<JObject>(device.Id);
                    if (deviceObject != null)
                    {
                        var property = deviceObject.Properties().FirstOrDefault();
                        if (property != null)
                        {
                            var keyObject = property.Value as JObject;
                            if (VerifyObject(keyObject, device))
                            {
                                return keyObject.Value<string>("key");
                            }
                        }
                    }
                }
            }

            return null;
        }

        private void Decrypt(EncryptedEvent evt)
        {
            var algorithm = evt.Content.Value<string>("algorithm");

            switch (algorithm)
            {
                case "m.olm.v1.curve25519-aes-sha2":
                    DecryptOlm(evt);
                    break;
                case "m.megolm.v1.aes-sha2":
                    DecryptMegolm(evt);
                    break;
                default:
                    Console.WriteLine("message with unknown algorithm");
                    break;
            }
        }

        private JObject EncryptMegOlm(JObject data, IRoom room)
        {
            using (var session = GetOutboundOlmSession(room.Id))
            {
                var cipherText = session.Encrypt(data.ToString());
                var eventId = Bytes.GetRandom(16).ToHexString();
                var encrypted = new JObject(
                            new JProperty("algorithm", "m.megolm.v1.aes-sha2"),
                            new JProperty("ciphertext", cipherText.Item2),
                            new JProperty("device_id", DeviceId),
                            new JProperty("sender_key", _senderKeyCurve25519),
                            new JProperty("session_id", session.Id));
                _storage.SetRoomOutboundSession(room.Id, session.ToBase64(_dataKey));
                return encrypted;
            }
        }

        private OlmOutboundSession GetOutboundOlmSession(string roomId)
        {
            var room = _storage.GetRoom(roomId);

            if (string.IsNullOrEmpty(room.OutboundSessionData) &&
                room.OutboundSessionMessageCount < 100)
            {
                var session = new OlmOutboundSession();
                SendRoomKey(roomId, session);
                _storage.SetRoomOutboundSession(roomId, session.ToBase64(_storage.GetConfig().DataKey));
                return session;
            }
            else
            {
                return new OlmOutboundSession(room.OutboundSessionData, _storage.GetConfig().DataKey);
            }
        }

        private void SendRoomKey(string roomId, OlmOutboundSession session)
        {
            UpdateRoomState(roomId);
            var room = _storage.GetRoom(roomId);

            foreach (var membership in room.Memberships)
            {
                if (!membership.HaveSentKey)
                {
                    if (membership.Device.User.Id == UserId &&
                        membership.Device.Id == DeviceId)
                    {
                        _storage.SetHaveSentKey(membership.Room.Id, membership.Device.User.Id, membership.Device.Id);
                    }
                    else
                    {
                        SendRoomKey(membership, session);
                    }
                }
            }
        }

        private void SendRoomKey(IMembership membership, OlmOutboundSession session)
        {
            if (membership.Device.VerificationLevel >= membership.Room.VerificationLevel)
            {
                var message = new JObject(
                    new JProperty("sender", UserId),
                    new JProperty("sender_device", DeviceId),
                    new JProperty("keys",
                        new JObject(
                            new JProperty("ed25519", _senderKeyEd25519))),
                    new JProperty("recipient", membership.Device.User.Id),
                    new JProperty("recipient_keys",
                        new JObject(
                            new JProperty("ed25519", membership.Device.Ed25519PublicKey))),
                    new JProperty("type", "m.room_key"),
                    new JProperty("content",
                        new JObject(
                            new JProperty("algorithm", "m.megolm.v1.aes-sha2"),
                            new JProperty("room_id", membership.Room.Id),
                            new JProperty("session_id", session.Id),
                            new JProperty("session_key", session.Export()),
                            new JProperty("chain_index", session.NextChainIndex))));
                var encrypted = EncryptOlm(message, membership.Device);
                if (encrypted != null)
                {
                    SendToDevice("m.room.encrypted", encrypted, membership.Device);
                    _storage.SetHaveSentKey(membership.Room.Id, membership.Device.User.Id, membership.Device.Id);
                }
            }
        }

        private void DecryptOlm(EncryptedEvent evt)
        {
            var senderKey = evt.Content.Value<string>("sender_key");
            var encrypted = evt.Content
                .Value<JObject>("ciphertext")
                .Value<JObject>(_senderKeyCurve25519);
            var type = encrypted.Value<int>("type");
            var body = encrypted.Value<string>("body");
            var device = _storage.GetUser(evt.UserId).Devices.SingleOrDefault(d => d.Curve25519PublicKey == senderKey);

            if (device != null)
            {
                if (string.IsNullOrEmpty(device.SessionData))
                {
                    using (var olmSession = _olmAccount.CreateInboundSession(body, senderKey))
                    {
                        var plainText = olmSession.Decrypt(type, body);
                        _storage.SetDeviceSession(device.User.Id, device.Id, olmSession.ToBase64(_dataKey));
                        var eventData = JObject.Parse(plainText);
                        var baseEvent = new BaseEvent(evt.RoomId, device.User.Id, device.Id, true, device.VerificationLevel);
                        var innerEvent = TimelineEvent.Parse(eventData, baseEvent);
                        if (innerEvent != null)
                        {
                            HandleEvent(innerEvent, eventData);
                        }
                    }
                }
                else
                {
                    using (var olmSession = new OlmSession(device.SessionData, _dataKey))
                    {
                        var plainText = olmSession.Decrypt(type, body);
                        _storage.SetDeviceSession(device.User.Id, device.Id, olmSession.ToBase64(_dataKey));
                        var eventData = JObject.Parse(plainText);
                        var baseEvent = new BaseEvent(evt.RoomId, device.User.Id, device.Id, true, device.VerificationLevel);
                        var innerEvent = TimelineEvent.Parse(eventData, baseEvent);
                        if (innerEvent != null)
                        {
                            HandleEvent(innerEvent, eventData);
                        }
                    }
                }
            }
        }

        private void DecryptMegolm(EncryptedEvent evt)
        {
            var sessionId = evt.Content.Value<string>("session_id");
            var session = _storage.GetMegOlmInboundRoomKey(sessionId);

            if (session != null && !string.IsNullOrEmpty(session.Data))
            {
                var cipherText = evt.Content.Value<string>("ciphertext");
                using (var inboundSession = new OlmInboundSession(session.Data, _dataKey))
                {
                    var plainText = inboundSession.Decrypt(cipherText);
                    _storage.SetMegOlmInboundRoomKey(session.Device.User.Id, session.Device.Id, sessionId, inboundSession.ToBase64(_dataKey));
                    // TODO check message index
                    var eventData = JObject.Parse(plainText.Item2);
                    var baseEvent = new BaseEvent(evt.RoomId, evt.UserId, null, true, session.Device.VerificationLevel);
                    var newEvt = TimelineEvent.Parse(eventData, baseEvent);
                    HandleEvent(newEvt, eventData);
                }
            }
        }

        public void UpdateRoomStates()
        {
            foreach (var room in _storage.GetRooms())
            {
                UpdateRoomState(room.Id); 
            } 
        }

        public void UpdateRoomState(string roomId)
        {
            var endpoint = string.Format("_matrix/client/r0/rooms/{0}/state", roomId);
            var result = Request<JArray>(endpoint, HttpMethod.Get, null);
            foreach (JObject eventData in result.Values<JObject>())
            {
                var evt = TimelineEvent.Parse(eventData, new BaseEvent(roomId, null, null, false, 0));
                if (evt != null)
                {
                    HandleEvent(evt, eventData);
                }
            }
        }

        public void Join(string roomId)
        {
            string endpoint = string.Format("_matrix/client/r0/rooms/{0}/join", roomId);
            Request<JObject>(endpoint, HttpMethod.Post, new JObject());
        }

        private void JoinedInvitedRooms(JObject invited)
        {
            foreach (JProperty property in invited.Properties())
            {
                var roomId = property.Name;
                Join(roomId);
            }
        }

        private void HandleDeviceLists(JObject deviceLists)
        {
            var updateList = new List<string>();
            var changed = deviceLists.Value<JArray>("changed");
            updateList.AddRange(changed.Values<string>());
            var left = deviceLists.Value<JArray>("left");
            updateList.AddRange(left.Values<string>());
            if (updateList.Count > 0)
            {
                GetDeviceKeys(updateList).ToList();
            }
        }

        private void HandleToDevice(JObject toDevice)
        {
            var events = toDevice.Value<JArray>("events");
            foreach (JObject eventData in events.Values<JObject>())
            {
                Console.WriteLine("incoming to device message");
                var evt = TimelineEvent.Parse(eventData, new BaseEvent(null, null, null, false, 0));
                if (evt != null)
                {
                    HandleEvent(evt, eventData);
                }
            }
        }

        private void SyncJoinedRooms(JObject joined)
        { 
            foreach (JProperty property in joined.Properties())
            {
                var roomId = property.Name;
                SyncJoinedRoom(roomId, property.Value as JObject);
            }
        }

        private bool VerifyObject(JObject obj, IDevice device)
        {
            var signatures = obj.Value<JObject>("signatures");
            var userSignatures = signatures.Value<JObject>(device.User.Id);
            var ed25519Signtaure = userSignatures.Value<string>("ed25519:" + device.Id);
            var data = obj.DeepClone() as JObject;
            data.Remove("signatures");
            data.Remove("unsigned");
            var canon = new JsonCanonicalizer(data.ToString());
            using (var utility = new OlmUtility())
            {
                return utility.Verify(device.Ed25519PublicKey, canon.GetEncodedString(), ed25519Signtaure);
            }
        }

        private void SignObject(JObject obj)
        {
            var canon = new JsonCanonicalizer(obj.ToString());
            var canonicalData = canon.GetEncodedString();
            var signature = _olmAccount.Sign(canonicalData);
            obj.Add(
                new JProperty("signatures",
                    new JObject(
                            new JProperty(UserId,
                                new JObject(
                                    new JProperty("ed25519:" + DeviceId, signature))))));
        }

        public void UploadDeviceKeys()
        {
            var keys = JObject.Parse(_olmAccount.IdentityKeys);
            var curve25519PublicKey = keys.Value<string>("curve25519");
            var ed25519PublicKey = keys.Value<string>("ed25519");

            var deviceKey = new JObject(
                new JProperty("user_id", UserId),
                new JProperty("device_id", DeviceId),
                new JProperty("algorithms",
                    new JArray("m.olm.curve25519-aes-sha256", "m.megolm.v1.aes-sha")),
                new JProperty("keys",
                    new JObject(
                        new JProperty("curve25519:" + DeviceId, curve25519PublicKey),
                        new JProperty("ed25519:" + DeviceId, ed25519PublicKey))));
            SignObject(deviceKey);

            var request = new JObject(
                new JProperty("device_keys", deviceKey));

            Request<JObject>("_matrix/client/r0/keys/upload", HttpMethod.Post, request);
        }

        public string Send(string roomId, string messageText)
        {
            var message = new JObject(
                new JProperty("msgtype", "m.text"),
                new JProperty("body", messageText));

            var room = _storage.GetRoom(roomId);

            if (room.Encrypted)
            {
                var container = new JObject(
                    new JProperty("content", message),
                    new JProperty("room_id", roomId),
                    new JProperty("type", "m.room.message"),
                    new JProperty("sender", UserId));
                var encrypted = EncryptMegOlm(container, room);
                var endpoint = string.Format(
                    "_matrix/client/r0/rooms/{0}/send/m.room.encrypted/{1}",
                    HttpUtility.UrlDecode(roomId),
                    Guid.NewGuid().ToString());
                var result = Request<JObject>(endpoint, HttpMethod.Put, encrypted);
                return result.Value<string>("event_id");
            }
            else
            {
                var endpoint = string.Format(
                    "_matrix/client/r0/rooms/{0}/send/m.room.message/{1}",
                    HttpUtility.UrlDecode(roomId),
                    Guid.NewGuid().ToString());
                var result = Request<JObject>(endpoint, HttpMethod.Put, message);
                return result.Value<string>("event_id");
            }
        }

        public void Sync()
        {
            var parameters = new List<UrlParameter>();

            if (_syncNextBatch != null)
            {
                parameters.Add(new UrlParameter("since", _syncNextBatch));
            }

            var result = Request<JObject>("_matrix/client/r0/sync", HttpMethod.Get, null, parameters.ToArray());

            var rooms = result.Value<JObject>("rooms");
            var joined = rooms.Value<JObject>("join");
            SyncJoinedRooms(joined);
            var invited = rooms.Value<JObject>("invite");
            JoinedInvitedRooms(invited);
            var toDevice = result.Value<JObject>("to_device");
            HandleToDevice(toDevice);
            var deviceLists = result.Value<JObject>("device_lists");
            HandleDeviceLists(deviceLists);

            var oneTimeKeysCount = result.Value<JObject>("device_one_time_keys_count");
            var curve25519KeyCount = oneTimeKeysCount.Value<int>("curve25519");
            var signedCurve25519KeyCount = oneTimeKeysCount.Value<int>("signed_curve25519");
            UploadOneTimeKeys(curve25519KeyCount, signedCurve25519KeyCount);

            _syncNextBatch = result.Value<string>("next_batch");
            _storage.SetSyncNextBatch(_syncNextBatch);
        }

        private void UploadOneTimeKeys(int curve25519KeyCount, int signedCurve25519KeyCount)
        {
            var maxKeys = _olmAccount.MaxNumberOfOneTimeKeys;
            var newCurve25519KeyCount = (maxKeys / 4) - curve25519KeyCount;
            var newSignedCurve25519KeyCount = (maxKeys / 4) - signedCurve25519KeyCount;

            if (newCurve25519KeyCount > 0 ||
                newSignedCurve25519KeyCount > 0)
            {
                var keys = JObject.Parse(_olmAccount.GenerateOneTimeKeys(newCurve25519KeyCount + newSignedCurve25519KeyCount));
                var curve25519keys = keys.Value<JObject>("curve25519");
                var keyList = new Queue<JProperty>(curve25519keys.Properties());
                var oneTimeKeys = new JObject();

                while (newCurve25519KeyCount > 0)
                {
                    var key = keyList.Dequeue();
                    oneTimeKeys.Add(new JProperty("curve25519:" + key.Name, key.Value));
                    newCurve25519KeyCount--;
                }

                while (newSignedCurve25519KeyCount > 0)
                {
                    var key = keyList.Dequeue();
                    var keyObject = new JObject(
                        new JProperty("key", key.Value));
                    SignObject(keyObject);
                    oneTimeKeys.Add(new JProperty("signed_curve25519:" + key.Name, keyObject));
                    newSignedCurve25519KeyCount--;
                }

                var request = new JObject(
                    new JProperty("one_time_keys", oneTimeKeys));

                var response = Request<JObject>("_matrix/client/r0/keys/upload", HttpMethod.Post, request);

                _olmAccount.MarkOneTimeKeysPublished();
                _storage.SetOlmAccountData(_olmAccount.ToBase64(_storage.GetConfig().DataKey));
            }
        }

        private bool CanPasswordLogin()
        {
            var result = Request<JObject>("_matrix/client/r0/login", HttpMethod.Get, null);
            var flows = result.Value<JArray>("flows");

            foreach (var flow in flows.Values<JObject>())
            { 
                if (flow.Value<string>("type") == "m.login.password")
                {
                    return true; 
                }
            }

            return false;
        }

        public bool IsLoggedIn
        {
            get { return !string.IsNullOrEmpty(_accessToken); }
        }

        public void Login(string username, string password, string deviceName)
        {
            if (!CanPasswordLogin())
            {
                throw new InvalidOperationException("Password login not available");
            }

            var request = new JObject(
                new JProperty("type", "m.login.password"),
                new JProperty("identifier", new JObject(
                    new JProperty("type", "m.id.user"),
                    new JProperty("user", username))),
                new JProperty("password", password),
                new JProperty("initial_device_display_name", deviceName));

            var result = Request<JObject>("_matrix/client/r0/login", HttpMethod.Post, request);

            _accessToken = result.Value<string>("access_token");
            _syncNextBatch = null;
            UserId = result.Value<string>("user_id");
            DeviceId = result.Value<string>("device_id");
            HomeServer = result.Value<string>("home_server");

            _storage.SetAccessToken(_accessToken, UserId, DeviceId, HomeServer);
            _storage.SetSyncNextBatch(_syncNextBatch);
        }

        public IEnumerable<string> GetVersions()
        {
            var result = Request<JObject>("_matrix/client/versions", HttpMethod.Get, null);

            var versions = new List<string>(result
                .Value<JArray>("versions")
                .Values<string>());

            return versions;
        }

        public IEnumerable<DeviceKey> GetDeviceKeys(params string[] userIds)
        {
            return GetDeviceKeys((IEnumerable<string>)userIds);
        }

        public IEnumerable<DeviceKey> GetDeviceKeys(IEnumerable<string> userIds)
        {
            var userList = new JObject();
            foreach (var userId in userIds)
            {
                userList.Add(new JProperty(userId, new JArray()));
            }

            var request = new JObject(
                new JProperty("timeout", 10000),
                new JProperty("device_keys", userList),
                new JProperty("token", _syncNextBatch));

            var response = Request<JObject>("_matrix/client/r0/keys/query", HttpMethod.Post, request);

            var deviceKeys = response.Value<JObject>("device_keys");

            foreach (var userProperty in deviceKeys.Properties())
            {
                var userId = userProperty.Name;
                var userObject = userProperty.Value as JObject;
                var userKeys = new List<DeviceKey>();

                foreach (var deviceProperty in userObject.Properties())
                {
                    var key = new DeviceKey(deviceProperty.Value as JObject);
                    if (key.Validate())
                    {
                        _storage.SetDeviceKey(key.UserId, key.DeviceId, key.Curve25519PublicKey, key.Ed25519PublicKey);
                        userKeys.Add(key);
                    }
                }

                var user = _storage.GetUser(userId);
                var oldDevices = user.Devices.Where(i => !userKeys.Any(j => j.DeviceId == i.Id)).ToList();
                foreach (var oldDevice in oldDevices)
                {
                    _storage.RemoveDevice(oldDevice.User.Id, oldDevice.Id);
                }

                foreach (var key in userKeys)
                {
                    yield return key; 
                }
            }
        }

        public string GetDeviceCurve25519PublicKey(IDevice device)
        {
            if (string.IsNullOrEmpty(device.Curve25519PublicKey))
            {
                var keys = GetDeviceKeys(device.User.Id).ToList();
                var key = keys.SingleOrDefault(k => k.DeviceId == device.Id);
                return key != null ? key.Curve25519PublicKey : null;
            }
            else
            {
                return device.Curve25519PublicKey;
            }
        }

        private void CheckError(JObject obj)
        {
            if (obj["errcode"] != null)
            {
                var errorCode = obj.Value<string>("errcode");
                var errorText = obj.Value<string>("error");
                switch (errorCode)
                {
                    case "M_LIMIT_EXCEEDED":
                        throw new MatrixLimitException(errorCode, errorText);
                    default:
                        throw new MatrixException(errorCode, errorText);
                }
            }
        }

        private T Request<T>(
            string endpoint,
            HttpMethod method,
            JToken data,
            params UrlParameter[] parameters)
            where T : JToken
        {
            Exception lastException = null;

            for (int i = 1; i <= 32; i *= 2)
            {
                try
                {
                    return RequestInternal<T>(endpoint, method, data, parameters);
                }
                catch (MatrixLimitException exception)
                {
                    Console.WriteLine("request limit exceeded");
                    lastException = exception;
                    Thread.Sleep(300 * i);
                }
                catch (MatrixWebException exception)
                {
                    Console.WriteLine(exception.Message);
                    lastException = exception;
                    Thread.Sleep(300 * i);
                }
                catch (MatrixConnectionException exception)
                {
                    Console.WriteLine(exception.Message);
                    lastException = exception;
                    Thread.Sleep(300 * i);
                }
            }

            throw lastException;
        }

        private T RequestInternal<T>(
            string endpoint,
            HttpMethod method,
            JToken data,
            params UrlParameter[] parameters)
            where T : JToken
        {
            var url = string.Join("/", _apiUrl, endpoint);
            var paramString = string.Join("&", parameters.Select(p => string.Format("{0}={1}", p.Key, p.Value)));

            if (paramString.Length > 0)
            {
                url += "?" + paramString;
            }

            var request = new HttpRequestMessage();
            request.Method = method;
            request.RequestUri = new Uri(url);

            if (!string.IsNullOrEmpty(_accessToken))
            {
                request.Headers.Add("Authorization", "Bearer " + _accessToken);
            }

            if (method == HttpMethod.Post ||
                method == HttpMethod.Put)
            {
                request.Content = new StringContent(data.ToString(), Encoding.UTF8, "application/json");
            }

            HttpResponseMessage response = Transact(request);

            switch (response.StatusCode)
            {
                case System.Net.HttpStatusCode.OK:
                    break;
                default:
                    throw new MatrixWebException(response.StatusCode);
            }

            var waitRead = response.Content.ReadAsByteArrayAsync();
            waitRead.Wait();
            var responseText = Encoding.UTF8.GetString(waitRead.Result);

            if (typeof(T) == typeof(JObject))
            {
                var obj = JObject.Parse(responseText);
                CheckError(obj);
                return obj as T;
            }
            else if (typeof(T) == typeof(JArray))
            {
                return JArray.Parse(responseText) as T;
            }
            else if (typeof(T) == typeof(JValue))
            {
                return new JValue(responseText) as T;
            }
            else
            {
                throw new NotSupportedException();
            }
        }

        private static HttpResponseMessage Transact(HttpRequestMessage request)
        {
            try
            {
                var client = new HttpClient();
                var waitResponse = client.SendAsync(request);
                waitResponse.Wait();
                var response = waitResponse.Result;
                return response;
            }
            catch (AggregateException exception)
            {
                var innerException = exception.InnerExceptions.First();
                throw new MatrixConnectionException(innerException.Message);
            }
            catch (Exception exception)
            {
                throw new MatrixConnectionException(exception.Message);
            }
        }
    }
}
