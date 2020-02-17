//
// VolatileStorage.cs
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

namespace MatrixLib
{
    public class VolatileStorage : IStorage
    {
        private class Room : IRoom
        {
            private readonly Dictionary<string, Membership> _memberships;

            public string Id { get; private set; }

            public bool Encrypted { get; set; }

            public string OutboundSessionData { get; set; }

            public int VerificationLevel { get; set; }

            public IEnumerable<IMembership> Memberships { get { return _memberships.Values; } }

            public int OutboundSessionMessageCount { get; set; }

            public Room(string id)
            {
                Id = id;
                _memberships = new Dictionary<string, Membership>();
            }

            public Membership AddMembership(Device device)
            {
                if (_memberships.ContainsKey(device.DualId))
                {
                    return _memberships[device.DualId];
                }
                else
                {
                    var membership = new Membership(device, this);
                    _memberships.Add(device.DualId, membership);
                    return membership;
                }
            }
        }

        private class User : IUser
        {
            private readonly Dictionary<string, Device> _devices;

            public string Id { get; private set; }

            public IEnumerable<IDevice> Devices { get { return _devices.Values; } }

            public User(string id)
            {
                Id = id;
                _devices = new Dictionary<string, Device>();
            }

            public Device AddDevice(string deviceId, User user)
            {
                if (_devices.ContainsKey(deviceId))
                {
                    return _devices[deviceId];
                }
                else
                {
                    var device = new Device(deviceId, user);
                    _devices.Add(deviceId, device);
                    return device;
                }
            }

            public void RemoveDevice(string deviceId)
            {
                if (_devices.ContainsKey(deviceId))
                {
                    _devices.Remove(deviceId);
                } 
            }
        }

        private class Device : IDevice
        {
            private User _user;

            public string Id { get; private set; }

            public IUser User { get { return _user; } }

            public string Curve25519PublicKey { get; set; }

            public string Ed25519PublicKey { get; set; }

            public string SessionData { get; set; }

            public int VerificationLevel { get; set; }

            public string DualId { get { return _user.Id + "_" + Id; } }

            public Device(string id, User user)
            {
                Id = id;
                _user = user; 
            }
        }

        private class Membership : IMembership
        {
            private readonly Device _device;

            private Room _room;

            public IDevice Device { get { return _device; } }

            public IRoom Room { get { return _room; } }

            public bool HaveSentKey { get; set; }

            public Membership(Device device, Room room)
            {
                _device = device;
                _room = room; 
            }
        }

        private class Config : IConfig
        {
            public string ApiUrl { get; private set; }

            public byte[] DataKey { get; private set; }

            public Config(string apiUrl)
            {
                ApiUrl = apiUrl;
                DataKey = Bytes.GetRandom(32); 
            }
        }

        private class State : IState
        {
            public string AccessToken { get; set; }

            public string SyncNextBatch { get; set; }

            public string AccountData { get; set; }

            public string HomeServer { get; set; }

            public string UserId { get; set; }

            public string DeviceId { get; set; }
        }

        private class MegOlmInboundSession : IMegOlmInboundSession
        {
            public string Data { get; set; }
            public IDevice Device { get; set; }

            public MegOlmInboundSession(IDevice device, string data)
            {
                Device = device;
                Data = data;
            }
        }

        private readonly Config _config;
        private readonly State _state;
        private readonly Dictionary<string, IRoom> _rooms;
        private readonly Dictionary<string, IUser> _users;
        private readonly Dictionary<string, IMegOlmInboundSession> _megOlmInboundRoomKeys;

        public VolatileStorage(string apiUrl)
        {
            _config = new Config(apiUrl);
            _state = new State();
            _rooms = new Dictionary<string, IRoom>();
            _users = new Dictionary<string, IUser>();
            _megOlmInboundRoomKeys = new Dictionary<string, IMegOlmInboundSession>();
        }

        public IDevice AddDevice(string userId, string deviceId)
        {
            var user = AddUser(userId) as User;
            return user.AddDevice(deviceId, user);
        }

        public IMembership AddMembership(string userId, string deviceId, string roomId)
        {
            var device = AddDevice(userId, deviceId) as Device;
            var room = AddRoom(roomId) as Room;
            return room.AddMembership(device);
        }

        public IRoom AddRoom(string roomId)
        {
            if (_rooms.ContainsKey(roomId))
            {
                return _rooms[roomId];
            }
            else
            {
                var room = new Room(roomId);
                _rooms.Add(roomId, room);
                return room;
            }
        }

        public IUser AddUser(string userId)
        {
            if (_users.ContainsKey(userId))
            {
                return _users[userId];
            }
            else
            {
                var user = new User(userId);
                _users.Add(userId, user);
                return user;
            }
        }

        public IConfig GetConfig()
        {
            return _config;
        }

        public IDevice GetDevice(string userId, string deviceId)
        {
            var user = AddUser(userId) as User;
            return user.AddDevice(deviceId, user);
        }

        public IMegOlmInboundSession GetMegOlmInboundRoomKey(string sessionId)
        {
            if (_megOlmInboundRoomKeys.ContainsKey(sessionId))
            {
                return _megOlmInboundRoomKeys[sessionId];
            }
            else
            {
                return null; 
            }
        }

        public IRoom GetRoom(string roomId)
        {
            if (_rooms.ContainsKey(roomId))
            {
                return _rooms[roomId];
            }
            else
            {
                var room = new Room(roomId);
                _rooms.Add(roomId, room);
                return room;
            }
        }

        public IEnumerable<IRoom> GetRooms()
        {
            return _rooms.Values;
        }

        public IState GetState()
        {
            return _state;
        }

        public IUser GetUser(string userId)
        {
            if (_users.ContainsKey(userId))
            {
                return _users[userId];
            }
            else
            {
                var user = new User(userId);
                _users.Add(userId, user);
                return user;
            }
        }

        public IEnumerable<IUser> GetUsers()
        {
            return _users.Values;
        }

        public void SetAccessToken(string accessToken, string userId, string deviceId, string homeServer)
        {
            _state.AccessToken = accessToken;
            _state.UserId = userId;
            _state.DeviceId = deviceId;
            _state.HomeServer = homeServer;
        }

        public void SetDeviceKey(string userId, string deviceId, string curve25519PublicKey, string ed25519PublicKey)
        {
            var device = GetDevice(userId, deviceId) as Device;
            device.Curve25519PublicKey = curve25519PublicKey;
            device.Ed25519PublicKey = ed25519PublicKey;
        }

        public void SetDeviceSession(string userId, string deviceId, string sessionData)
        {
            var device = GetDevice(userId, deviceId) as Device;
            device.SessionData = sessionData;
        }

        public void SetHaveSentKey(string roomId, string userId, string deviceId)
        {
            var room = GetRoom(roomId) as Room;
            var device = GetDevice(userId, deviceId) as Device;
            var membership = room.AddMembership(device);
            membership.HaveSentKey = true;
        }

        public void SetMegOlmInboundRoomKey(string userId, string deviceId, string sessionId, string value)
        {
            var device = GetDevice(userId, deviceId) as Device;

            if (_megOlmInboundRoomKeys.ContainsKey(sessionId))
            {
                _megOlmInboundRoomKeys[sessionId].Data = value;
                _megOlmInboundRoomKeys[sessionId].Device = device;
            }
            else
            {
                var session = new MegOlmInboundSession(device, value);
                _megOlmInboundRoomKeys.Add(sessionId, session);
            }
        }

        public void SetOlmAccountData(string value)
        {
            _state.AccountData = value;
        }

        public void SetRoomEncrypted(string roomId)
        {
            var room = GetRoom(roomId) as Room;
            room.Encrypted = true;
        }

        public void SetRoomOutboundSession(string roomId, string value)
        {
            var room = GetRoom(roomId) as Room;
            room.OutboundSessionData = value;
        }

        public void SetSyncNextBatch(string value)
        {
            _state.SyncNextBatch = value;
        }

        public void SetDeviceVerificationLevel(string userId, string deviceId, int verificationLevel)
        {
            var device = GetDevice(userId, deviceId) as Device;
            device.VerificationLevel = verificationLevel;
        }

        public void SetRoomVerificationLevel(string roomId, int verificationLevel)
        {
            var room = GetRoom(roomId) as Room;
            room.VerificationLevel = verificationLevel;
        }

        public void IncrementMegOlmOutboundMessageCount(string roomId)
        {
            var room = GetRoom(roomId) as Room;
            room.OutboundSessionMessageCount++;
        }

        public void RemoveDevice(string userId, string deviceId)
        {
            var user = GetUser(userId) as User;
            user.RemoveDevice(deviceId);
        }
    }
}
