//
// IStorage.cs
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
using System.Collections.Generic;

namespace MatrixLib
{
    public interface IStorage
    {
        IEnumerable<IRoom> GetRooms();

        IEnumerable<IUser> GetUsers();

        IRoom AddRoom(string roomId);

        IUser AddUser(string userId);

        IDevice AddDevice(string userId, string deviceId);

        IMembership AddMembership(string userId, string deviceId, string roomId);

        IRoom GetRoom(string roomId);

        IUser GetUser(string userId);

        IDevice GetDevice(string userId, string deviceId);

        IConfig GetConfig();

        IState GetState();

        void SetOlmAccountData(string value);

        void SetAccessToken(string accessToken, string userId, string deviceId, string homeServer);

        void SetSyncNextBatch(string value);

        void SetDeviceKey(string userId, string deviceId, string curve25519PublicKey, string ed25519PublicKey);

        void SetRoomEncrypted(string roomId);

        void SetDeviceSession(string userId, string deviceId, string sessionData);

        IMegOlmInboundSession GetMegOlmInboundRoomKey(string sessionId);

        void SetMegOlmInboundRoomKey(string userId, string deviceId, string sessionId, string value);

        void SetRoomOutboundSession(string roomId, string value);

        void SetHaveSentKey(string roomId, string userId, string deviceId);

        void SetDeviceVerificationLevel(string userId, string deviceId, int verificationLevel);

        void SetRoomVerificationLevel(string roomId, int verificationLevel);

        void IncrementMegOlmOutboundMessageCount(string roomId);

        void RemoveDevice(string userId, string deviceId);
    }
}
