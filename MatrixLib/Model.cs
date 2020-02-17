//
// Model.cs
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

namespace MatrixLib
{
    public interface IRoom
    { 
        string Id { get; }
        bool Encrypted { get; }
        string OutboundSessionData { get; }
        int OutboundSessionMessageCount { get; }
        IEnumerable<IMembership> Memberships { get; }
        int VerificationLevel { get; }
    }

    public interface IUser
    {
        string Id { get; }
        IEnumerable<IDevice> Devices { get; }
    }

    public interface IDevice
    {
        string Id { get; }
        IUser User { get; }
        string Curve25519PublicKey { get; }
        string Ed25519PublicKey { get; }
        string SessionData { get; }
        int VerificationLevel { get; }
    }

    public interface IMembership
    { 
        IDevice Device { get; }
        IRoom Room { get; }
        bool HaveSentKey { get; }
    }

    public interface IConfig
    {
        string ApiUrl { get; } 
        byte[] DataKey { get; }
    }

    public interface IState
    {
        string AccessToken { get; }
        string SyncNextBatch { get; }
        string AccountData { get; }
        string HomeServer { get; }
        string UserId { get; }
        string DeviceId { get; }
    }

    public interface IMegOlmInboundSession
    { 
        string Data { get; set; }
        IDevice Device { get; set; }
    }
}
