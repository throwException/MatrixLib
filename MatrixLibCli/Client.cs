//
// Client.cs
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
using MatrixLib;

namespace MatrixLibCli
{
    public class Client
    {
        private MatrixClientClient _config;
        private IStorage _storage;
        private Matrix _matrix;

        public Client()
        {
            _config = new MatrixClientClient();
            _config.Load("/Security/Test/matrix.xml");

            _storage = new VolatileStorage(_config.ApiUrl);

            _matrix = new Matrix(_storage);
            _matrix.OnMessage += _matrix_OnMessage;
            _matrix.OnUserVerify += _matrix_OnUserVerify;

            if (!_matrix.IsLoggedIn)
            {
                _matrix.GetVersions();
                _matrix.Login(_config.UserName, _config.Password, "MatrixLibCli");
            }
            else
            {
                _matrix.GetVersions();
            }

            _matrix.UploadDeviceKeys();
            _matrix.UpdateJoinedRooms();
            _matrix.UpdateRoomStates();
        }

        public void Run()
        { 
            while (true)
            {
                _matrix.Sync();
                System.Threading.Thread.Sleep(100);
            }
        }

        private void _matrix_OnMessage(object sender, MessageEvent e)
        {
            Console.WriteLine("{0}: {1}", e.UserId, e.Body);

            if (e.UserId != _matrix.UserId)
            {
                _matrix.Send(e.RoomId, e.Body);
            }
        }

        private void _matrix_OnUserVerify(object sender, VerificationEvent e)
        {
            Console.WriteLine("Verification:");
            foreach (var x in e.Emojis)
            {
                Console.WriteLine(_matrix.GetShortAuthenticationEmojiName(x));
            }
        }
    }
}
