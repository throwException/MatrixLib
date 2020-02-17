//
// NativeMethods.cs
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
using System.Runtime.InteropServices;
using OlmAccountPtr = System.IntPtr;
using OlmSessionPtr = System.IntPtr;
using OlmUtilityPtr = System.IntPtr;
using OlmOutboundGroupSessionPtr = System.IntPtr;
using OlmInboundGroupSessionPtr = System.IntPtr;
using MemPtr = System.IntPtr;
using StrPtr = System.IntPtr;
using KeyPtr = System.IntPtr;

namespace MatrixLib
{
    public class OlmException : Exception
    {
        public OlmException(string message)
            : base(message)
        { }
    }

    public static class NativeMethods
    {
        const string LibraryName = "libolm.so";

        /// <summary>
        /// Get the version number of the library.
        /// Arguments will be updated if non-null.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_get_library_version")]
        public static extern void OlmGetLibraryVersion(ref byte major, ref byte minor, ref byte patch);

        /// <summary>
        /// The size of an account object in bytes
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_size")]
        public static extern ulong OlmAccountSize();

        /// <summary>
        /// The size of a session object in bytes
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_session_size")]
        public static extern ulong OlmSessionSize();

        /// <summary>
        /// The size of a utility object in bytes
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_utility_size")]
        public static extern ulong OlmUtilitySize();

        /// <summary>
        /// Initialise an account object using the supplied memory
        /// The supplied memory must be at least olm_account_size() bytes
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account")]
        public static extern OlmAccountPtr OlmAccount(
            MemPtr memory
        );

        /// <summary>
        /// Initialise a session object using the supplied memory
        /// The supplied memory must be at least olm_session_size() bytes
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_session")]
        public static extern OlmSessionPtr OlmSession(
            MemPtr memory
        );

        /// <summary>
        /// Initialise a utility object using the supplied memory
        /// The supplied memory must be at least olm_utility_size() bytes
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_utility")]
        public static extern OlmUtilityPtr OlmUtility(
            MemPtr memory
        );

        /// <summary>
        /// The value that olm will return from a function if there was an error
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_error")]
        public static extern long OlmError();

        public static void ThrowOnOlmError(long value, IOlmErrorProvider provider)
        {
            if (value == OlmError())
            {
                throw new OlmException(provider.LastError);
            }
        }

        public static bool CheckOnOlmError(long value)
        {
            return (value != OlmError());
        }

        /// <summary>
        /// A null terminated string describing the most recent error to happen to an
        /// account
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_last_error")]
        public static extern StrPtr OlmAccountLastError(
            OlmAccountPtr account
        );

        /// <summary>
        /// A null terminated string describing the most recent error to happen to a
        /// session
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_session_last_error")]
        public static extern StrPtr OlmSessionLastError(
            OlmSessionPtr session
        );

        /// <summary>
        /// A null terminated string describing the most recent error to happen to a
        /// utility
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_utility_last_error")]
        public static extern StrPtr OlmUtilityLastError(
            OlmUtilityPtr utility
        );

        /// <summary>
        /// Clears the memory used to back this account
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_clear_account")]
        public static extern long OlmClearAccount(
            OlmAccountPtr account
        );

        /// <summary>
        /// Clears the memory used to back this session
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_clear_session")]
        public static extern long OlmClearSession(
            OlmSessionPtr session
        );

        /// <summary>
        /// Clears the memory used to back this utility
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_clear_utility")]
        public static extern long OlmClearUtility(
            OlmUtilityPtr utility
        );

        /// <summary>
        /// Returns the number of bytes needed to store an account
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_pickle_account_length")]
        public static extern long OlmPickleAccountLength(
            OlmAccountPtr account
        );

        /// <summary>
        /// Returns the number of bytes needed to store a session
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_pickle_session_length")]
        public static extern long OlmPickleSessionLength(
            OlmSessionPtr session
        );

        /// <summary>
        /// Stores an account as a base64 string. Encrypts the account using the
        /// supplied key. Returns the length of the pickled account on success.
        /// Returns olm_error() on failure. If the pickle output buffer
        /// is smaller than olm_pickle_account_length() then
        /// olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_pickle_account")]
        public static extern long OlmPickleAccount(
            OlmAccountPtr account,
            KeyPtr key, long keyLength,
            StrPtr pickled, long pickledLength
        );

        /// <summary>
        /// Stores a session as a base64 string. Encrypts the session using the
        /// supplied key. Returns the length of the pickled session on success.
        /// Returns olm_error() on failure. If the pickle output buffer
        /// is smaller than olm_pickle_session_length() then
        /// olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_pickle_session")]
        public static extern long OlmPickleSession(
            OlmSessionPtr session,
            KeyPtr key, long keyLength,
            StrPtr pickled, long pickledLength
        );

        /// <summary>
        /// Loads an account from a pickled base64 string. Decrypts the account using
        /// the supplied key. Returns olm_error() on failure. If the key doesn't
        /// match the one used to encrypt the account then olm_account_last_error()
        /// will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
        /// olm_account_last_error() will be "INVALID_BASE64". The input pickled
        /// buffer is destroyed
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_unpickle_account")]
        public static extern long OlmUnpickleAccount(
            OlmAccountPtr account,
            KeyPtr key, long keyLength,
            StrPtr pickled, long pickledLength
        );

        /// <summary>
        /// Loads a session from a pickled base64 string. Decrypts the session using
        /// the supplied key. Returns olm_error() on failure. If the key doesn't
        /// match the one used to encrypt the account then olm_session_last_error()
        /// will be "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
        /// olm_session_last_error() will be "INVALID_BASE64". The input pickled
        /// buffer is destroyed
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_unpickle_session")]
        public static extern long OlmUnpickleSession(
            OlmSessionPtr session,
            KeyPtr key, long keyLength,
            StrPtr pickled, long pickledLength
        );

        /// <summary>
        /// The number of random bytes needed to create an account.*/
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_create_account_random_length")]
        public static extern long OlmCreateAccountRandomLength(
            OlmAccountPtr account
        );

        /// <summary>
        /// Creates a new account. Returns olm_error() on failure. If weren't
        /// enough random bytes then olm_account_last_error() will be
        /// "NOT_ENOUGH_RANDOM"
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_create_account")]
        public static extern long OlmCreateAccount(
            OlmAccountPtr account,
            MemPtr random, long random_length
        );

        /// <summary>
        /// The size of the output buffer needed to hold the identity keys
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_identity_keys_length")]
        public static extern long OlmAccountIdentityKeysLength(
            OlmAccountPtr account
        );

        /// <summary>
        /// Writes the public parts of the identity keys for the account into the
        /// identity_keys output buffer. Returns olm_error() on failure. If the
        /// identity_keys buffer was too small then olm_account_last_error() will be
        /// "OUTPUT_BUFFER_TOO_SMALL".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_identity_keys")]
        public static extern long OlmAccountIdentityKeys(
            OlmAccountPtr account,
            StrPtr identity_keys, long identity_keyLength
        );

        /// <summary>
        /// The length of an ed25519 signature encoded as base64.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_signature_length")]
        public static extern long OlmAccountSignatureLength(
            OlmAccountPtr account
        );

        /// <summary>
        /// Signs a message with the ed25519 key for this account. Returns olm_error()
        /// on failure. If the signature buffer was too small then
        /// olm_account_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_sign")]
        public static extern long OlmAccountSign(
            OlmAccountPtr account,
            MemPtr message, long message_length,
            MemPtr signature, long signature_length
        );

        /// <summary>
        /// The size of the output buffer needed to hold the one time keys
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_one_time_keys_length")]
        public static extern long OlmAccountOneTimeKeysLength(
            OlmAccountPtr account
        );

        /// <summary>
        /// Writes the public parts of the unpublished one time keys for the account
        /// into the one_time_keys output buffer.
        /// <p>
        /// The returned data is a JSON-formatted object with the single property
        /// <tt>curve25519</tt>, which is itself an object mapping key id to
        /// base64-encoded Curve25519 key. For example:
        /// <pre>
        /// {
        ///     curve25519: {
        ///         "AAAAAA": "wo76WcYtb0Vk/pBOdmduiGJ0wIEjW4IBMbbQn7aSnTo",
        ///         "AAAAAB": "LRvjo46L1X2vx69sS9QNFD29HWulxrmW11Up5AfAjgU"
        ///     }
        /// }
        /// </pre>
        /// Returns olm_error() on failure.
        /// <p>
        /// If the one_time_keys buffer was too small then olm_account_last_error()
        /// will be "OUTPUT_BUFFER_TOO_SMALL".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_one_time_keys")]
        public static extern long OlmAccountOneTimeKeys(
            OlmAccountPtr account,
            StrPtr one_time_keys, long one_time_keys_length
        );

        /// <summary>
        /// Marks the current set of one time keys as being published.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_mark_keys_as_published")]
        public static extern long OlmAccountMarkKeysAsPublished(
            OlmAccountPtr account
        );

        /// <summary>
        /// The largest number of one time keys this account can store.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_max_number_of_one_time_keys")]
        public static extern long OlmAccountMaxNumberOfOneTimeKeys(
            OlmAccountPtr account
        );

        /// <summary>
        /// The number of random bytes needed to generate a given number of new one
        /// time keys.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_generate_one_time_keys_random_length")]
        public static extern long OlmAccountGenerateOneTimeKeysRandomLength(
            OlmAccountPtr account,
            long number_of_keys
        );

        /// <summary>
        /// Generates a number of new one time keys. If the total number of keys stored
        /// by this account exceeds max_number_of_one_time_keys() then the old keys are
        /// discarded. Returns olm_error() on error. If the number of random bytes is
        /// too small then olm_account_last_error() will be "NOT_ENOUGH_RANDOM".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_account_generate_one_time_keys")]
        public static extern long OlmAccountGenerateOneTimeKeys(
            OlmAccountPtr account,
            long number_of_keys,
            MemPtr random, long random_length
        );

        /// <summary>
        /// The number of random bytes needed to create an outbound session
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_create_outbound_session_random_length")]
        public static extern long OlmCreateOutboundSessionRandomLength(
            OlmSessionPtr session
        );

        /// <summary>
        /// Creates a new out-bound session for sending messages to a given identity_key
        /// and one_time_key. Returns olm_error() on failure. If the keys couldn't be
        /// decoded as base64 then olm_session_last_error() will be "INVALID_BASE64"
        /// If there weren't enough random bytes then olm_session_last_error() will
        /// be "NOT_ENOUGH_RANDOM".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_create_outbound_session")]
        public static extern long OlmCreateOutboundSession(
            OlmSessionPtr session,
            OlmAccountPtr account,
            StrPtr theirIdentityKey, long theirIdentityKeyLength,
            StrPtr theirOneTimeKey, long theirOneTimeKeyLength,
            MemPtr random, long randomLength
        );

        /// <summary>
        /// Create a new in-bound session for sending/receiving messages from an
        /// incoming PRE_KEY message. Returns olm_error() on failure. If the base64
        /// couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
        /// If the message was for an unsupported protocol version then
        /// olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
        /// couldn't be decoded then then olm_session_last_error() will be
        /// "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
        /// key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_create_inbound_session")]
        public static extern long OlmCreateInboundSession(
            OlmSessionPtr session,
            OlmAccountPtr account,
            StrPtr one_time_key_message, long message_length
        );

        /// <summary>
        /// Create a new in-bound session for sending/receiving messages from an
        /// incoming PRE_KEY message. Returns olm_error() on failure. If the base64
        /// couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
        /// If the message was for an unsupported protocol version then
        /// olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
        /// couldn't be decoded then then olm_session_last_error() will be
        /// "BAD_MESSAGE_FORMAT". If the message refers to an unknown one time
        /// key then olm_session_last_error() will be "BAD_MESSAGE_KEY_ID".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_create_inbound_session_from")]
        public static extern long OlmCreateInboundSessionFrom(
            OlmSessionPtr session,
            OlmAccountPtr account,
            StrPtr their_identity_key, long their_identity_keyLength,
            StrPtr one_time_key_message, long message_length
        );

        /// <summary>
        /// The length of the buffer needed to return the id for this session.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_session_id_length")]
        public static extern long OlmSessionIdLength(
            OlmSessionPtr session
        );

        /// <summary>
        /// An identifier for this session. Will be the same for both ends of the
        /// conversation. If the id buffer is too small then olm_session_last_error()
        /// will be "OUTPUT_BUFFER_TOO_SMALL".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_session_id")]
        public static extern long OlmSessionId(
            OlmSessionPtr session,
            MemPtr id, long id_length
        );

        [DllImport(LibraryName, EntryPoint = "olm_session_has_received_message")]
        public static extern int OlmSessionHasReceivedMessage(
            OlmSessionPtr session
        );

        /// <summary>
        /// Checks if the PRE_KEY message is for this in-bound session. This can happen
        /// if multiple messages are sent to this account before this account sends a
        /// message in reply. Returns 1 if the session matches. Returns 0 if the session
        /// does not match. Returns olm_error() on failure. If the base64
        /// couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
        /// If the message was for an unsupported protocol version then
        /// olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
        /// couldn't be decoded then then olm_session_last_error() will be
        /// "BAD_MESSAGE_FORMAT".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_matches_inbound_session")]
        public static extern long OlmMatchesInboundSession(
            OlmSessionPtr session,
            StrPtr one_time_key_message, long message_length
        );

        /// <summary>
        /// Checks if the PRE_KEY message is for this in-bound session. This can happen
        /// if multiple messages are sent to this account before this account sends a
        /// message in reply. Returns 1 if the session matches. Returns 0 if the session
        /// does not match. Returns olm_error() on failure. If the base64
        /// couldn't be decoded then olm_session_last_error will be "INVALID_BASE64".
        /// If the message was for an unsupported protocol version then
        /// olm_session_last_error() will be "BAD_MESSAGE_VERSION". If the message
        /// couldn't be decoded then then olm_session_last_error() will be
        /// "BAD_MESSAGE_FORMAT".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_matches_inbound_session_from")]
        public static extern long OlmMatchesInboundSessionFrom(
            OlmSessionPtr session,
            StrPtr their_identity_key, long their_identity_keyLength,
            StrPtr one_time_key_message, long message_length
        );

        /// <summary>
        /// Removes the one time keys that the session used from the account. Returns
        /// olm_error() on failure. If the account doesn't have any matching one time
        /// keys then olm_account_last_error() will be "BAD_MESSAGE_KEY_ID".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_remove_one_time_keys")]
        public static extern long OlmRemoveOneTimeKeys(
            OlmAccountPtr account,
            OlmSessionPtr session
        );

        /// <summary>
        /// </summary>
        /// The type of the next message that olm_encrypt() will return. Returns
        /// OLM_MESSAGE_TYPE_PRE_KEY if the message will be a PRE_KEY message.
        /// Returns OLM_MESSAGE_TYPE_MESSAGE if the message will be a normal message.
        /// Returns olm_error on failure.
        [DllImport(LibraryName, EntryPoint = "olm_encrypt_message_type")]
        public static extern long OlmEncryptMessageType(
            OlmSessionPtr session
        );

        /// <summary>
        /// The number of random bytes needed to encrypt the next message.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_encrypt_random_length")]
        public static extern long OlmEncryptRandomLength(
            OlmSessionPtr session
        );

        /// <summary>
        /// The size of the next message in bytes for the given number of plain-text
        /// bytes.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_encrypt_message_length")]
        public static extern long OlmEncryptMessageLength(
            OlmSessionPtr session,
            long plaintext_length
        );

        /// <summary>
        /// Encrypts a message using the session. Returns the length of the message in
        /// bytes on success. Writes the message as base64 into the message buffer.
        /// Returns olm_error() on failure. If the message buffer is too small then
        /// olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL". If there
        /// weren't enough random bytes then olm_session_last_error() will be
        /// "NOT_ENOUGH_RANDOM".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_encrypt")]
        public static extern long OlmEncrypt(
            OlmSessionPtr session,
            StrPtr plaintext, long plaintext_length,
            MemPtr random, long random_length,
            StrPtr message, long message_length
        );

        /// <summary>
        /// The maximum number of bytes of plain-text a given message could decode to.
        /// The actual size could be different due to padding. The input message buffer
        /// is destroyed. Returns olm_error() on failure. If the message base64
        /// couldn't be decoded then olm_session_last_error() will be
        /// "INVALID_BASE64". If the message is for an unsupported version of the
        /// protocol then olm_session_last_error() will be "BAD_MESSAGE_VERSION".
        /// If the message couldn't be decoded then olm_session_last_error() will be
        /// "BAD_MESSAGE_FORMAT".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_decrypt_max_plaintext_length")]
        public static extern long OlmDecryptMaxPlaintextLength(
            OlmSessionPtr session,
            long message_type,
            StrPtr message, long message_length
        );

        /// <summary>
        /// Decrypts a message using the session. The input message buffer is destroyed.
        /// Returns the length of the plain-text on success. Returns olm_error() on
        /// failure. If the plain-text buffer is smaller than
        /// olm_decrypt_max_plaintext_length() then olm_session_last_error()
        /// will be "OUTPUT_BUFFER_TOO_SMALL". If the base64 couldn't be decoded then
        /// olm_session_last_error() will be "INVALID_BASE64". If the message is for
        /// an unsupported version of the protocol then olm_session_last_error() will
        ///  be "BAD_MESSAGE_VERSION". If the message couldn't be decoded then
        ///  olm_session_last_error() will be BAD_MESSAGE_FORMAT".
        ///  If the MAC on the message was invalid then olm_session_last_error() will
        ///  be "BAD_MESSAGE_MAC".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_decrypt")]
        public static extern long OlmDecrypt(
            OlmSessionPtr session,
            long message_type,
            StrPtr message, long message_length,
            StrPtr plaintext, long max_plaintext_length
        );

        /// <summary>
        /// The length of the buffer needed to hold the SHA-256 hash.
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_sha256_length")]
        public static extern long OlmSha256Length(
           OlmUtilityPtr utility
        );

        /// <summary>
        /// Calculates the SHA-256 hash of the input and encodes it as base64. If the
        /// output buffer is smaller than olm_sha256_length() then
        /// olm_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_sha256")]
        public static extern long OlmSha256(
            OlmUtilityPtr utility,
            MemPtr input, long inputLength,
            StrPtr output, long outputLength
        );

        /// <summary>
        /// Verify an ed25519 signature. If the key was too small then
        /// olm_session_last_error will be "INVALID_BASE64". If the signature was invalid
        /// then olm_session_last_error() will be "BAD_MESSAGE_MAC".
        /// </summary>
        [DllImport(LibraryName, EntryPoint = "olm_ed25519_verify")]
        public static extern long OlmEd25519Verify(
            OlmUtilityPtr utility,
            StrPtr key, long keyLength,
            StrPtr message, long messageLength,
            StrPtr signature, long signatureLength
        );

        /** get the size of an outbound group session, in bytes. */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_size")]
        public static extern long OlmOutboundGroupSessionSize();

        /**
         * Initialise an outbound group session object using the supplied memory
         * The supplied memory should be at least olm_outbound_group_session_size()
         * bytes.
         */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session")]
        public static extern OlmOutboundGroupSessionPtr OlmOutboundGroupSession(
            MemPtr memory
        );

        /**
         * A null terminated string describing the most recent error to happen to a
         * group session */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_last_error")]
        public static extern StrPtr OlmOutboundGroupSessionLastError(
            OlmOutboundGroupSessionPtr session
        );

        /** Clears the memory used to back this group session */
        [DllImport(LibraryName, EntryPoint = "olm_clear_outbound_group_session")]
        public static extern long OlmClearOutboundGroupSession(
            OlmOutboundGroupSessionPtr session
        );

        /** Returns the number of bytes needed to store an outbound group session */
        [DllImport(LibraryName, EntryPoint = "olm_pickle_outbound_group_session_length")]
        public static extern long OlmPickleOutboundGroupSessionLength(
            OlmOutboundGroupSessionPtr session
        );

        /**
         * Stores a group session as a base64 string. Encrypts the session using the
         * supplied key. Returns the length of the session on success.
         *
         * Returns olm_error() on failure. If the pickle output buffer
         * is smaller than olm_pickle_outbound_group_session_length() then
         * olm_outbound_group_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
         */
        [DllImport(LibraryName, EntryPoint = "olm_pickle_outbound_group_session")]
        public static extern long OlmPickleOutboundGroupSession(
            OlmOutboundGroupSessionPtr session,
            KeyPtr key, long keyLength,
            StrPtr pickled, long pickledLength
        );

        /**
         * Loads a group session from a pickled base64 string. Decrypts the session
         * using the supplied key.
         *
         * Returns olm_error() on failure. If the key doesn't match the one used to
         * encrypt the account then olm_outbound_group_session_last_error() will be
         * "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
         * olm_outbound_group_session_last_error() will be "INVALID_BASE64". The input
         * pickled buffer is destroyed
         */
        [DllImport(LibraryName, EntryPoint = "olm_unpickle_outbound_group_session")]
        public static extern long OlmUnpickleOutboundGroupSession(
            OlmOutboundGroupSessionPtr session,
            KeyPtr key, long keyLength,
            StrPtr pickled, long pickledLength
        );


        /** The number of random bytes needed to create an outbound group session */
        [DllImport(LibraryName, EntryPoint = "olm_init_outbound_group_session_random_length")]
        public static extern long OlmInitOutboundGroupSessionRandomLength(
            OlmOutboundGroupSessionPtr session
        );

        /**
         * Start a new outbound group session. Returns olm_error() on failure. On
         * failure last_error will be set with an error code. The last_error will be
         * NOT_ENOUGH_RANDOM if the number of random bytes was too small.
         */
        [DllImport(LibraryName, EntryPoint = "olm_init_outbound_group_session")]
        public static extern long OlmInitOutboundGroupSession(
            OlmOutboundGroupSessionPtr session,
            MemPtr random, long random_length
        );

        /**
         * The number of bytes that will be created by encrypting a message
         */
        [DllImport(LibraryName, EntryPoint = "olm_group_encrypt_message_length")]
        public static extern long OlmGroupEncryptMessageLength(
            OlmOutboundGroupSessionPtr session,
            long plaintextlength
        );

        /**
         * Encrypt some plain-text. Returns the length of the encrypted message or
         * olm_error() on failure. On failure last_error will be set with an
         * error code. The last_error will be OUTPUT_BUFFER_TOO_SMALL if the output
         * buffer is too small.
         */
        [DllImport(LibraryName, EntryPoint = "olm_group_encrypt")]
        public static extern long OlmGroupEncrypt(
            OlmOutboundGroupSessionPtr session,
            MemPtr plaintext, long plaintextlength,
            MemPtr message, long messageLength
        );


        /**
         * Get the number of bytes returned by olm_outbound_group_session_id()
         */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_id_length")]
        public static extern long OlmOutboundGroupSessionIdLength(
            OlmOutboundGroupSessionPtr session
        );

        /**
         * Get a base64-encoded identifier for this session.
         *
         * Returns the length of the session id on success or olm_error() on
         * failure. On failure last_error will be set with an error code. The
         * last_error will be OUTPUT_BUFFER_TOO_SMALL if the id buffer was too
         * small.
         */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_id")]
        public static extern long OlmOutboundGroupSessionId(
            OlmOutboundGroupSessionPtr session,
            MemPtr id, long idLength
        );

        /**
         * Get the current message index for this session.
         *
         * Each message is sent with an increasing index; this returns the index for
         * the next message.
         */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_message_index")]
        public static extern uint OlmOutboundGroupSessionMessageIndex(
            OlmOutboundGroupSessionPtr session
        );

        /**
         * Get the number of bytes returned by olm_outbound_group_session_key()
         */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_key_length")]
        public static extern long OlmOutboundGroupSessionKeyLength(
            OlmOutboundGroupSessionPtr session
        );

        /**
         * Get the base64-encoded current ratchet key for this session.
         *
         * Each message is sent with a different ratchet key. This function returns the
         * ratchet key that will be used for the next message.
         *
         * Returns the length of the ratchet key on success or olm_error() on
         * failure. On failure last_error will be set with an error code. The
         * last_error will be OUTPUT_BUFFER_TOO_SMALL if the buffer was too small.
         */
        [DllImport(LibraryName, EntryPoint = "olm_outbound_group_session_key")]
        public static extern long OlmOutboundGroupSessionKey(
            OlmOutboundGroupSessionPtr session,
            MemPtr key, long keyLength
        );

        /** get the size of an inbound group session, in bytes. */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session_size")]
        public static extern long OlmInboundGroupSessionSize();

        /**
         * Initialise an inbound group session object using the supplied memory
         * The supplied memory should be at least olm_inbound_group_session_size()
         * bytes.
         */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session")]
        public static extern OlmInboundGroupSessionPtr OlmInboundGroupSession(
            MemPtr memory
        );

        /**
         * A null terminated string describing the most recent error to happen to a
         * group session */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session_last_error")]
        public static extern StrPtr OlmInboundGroupSessionLastError(
            OlmInboundGroupSessionPtr session
        );

        /** Clears the memory used to back this group session */
        [DllImport(LibraryName, EntryPoint = "olm_clear_inbound_group_session")]
        public static extern long OlmClearInboundGroupSession(
            OlmInboundGroupSessionPtr session
        );

        /** Returns the number of bytes needed to store an inbound group session */
        [DllImport(LibraryName, EntryPoint = "olm_pickle_inbound_group_session_length")]
        public static extern long OlmPickleInboundGroupSessionLength(
            OlmInboundGroupSessionPtr session
        );

        /**
         * Stores a group session as a base64 string. Encrypts the session using the
         * supplied key. Returns the length of the session on success.
         *
         * Returns olm_error() on failure. If the pickle output buffer
         * is smaller than olm_pickle_inbound_group_session_length() then
         * olm_inbound_group_session_last_error() will be "OUTPUT_BUFFER_TOO_SMALL"
         */
        [DllImport(LibraryName, EntryPoint = "olm_pickle_inbound_group_session")]
        public static extern long OlmPickleInboundGroupSession(
            OlmInboundGroupSessionPtr session,
            MemPtr key, long keyLength,
            MemPtr pickled, long pickledLength
        );

        /**
         * Loads a group session from a pickled base64 string. Decrypts the session
         * using the supplied key.
         *
         * Returns olm_error() on failure. If the key doesn't match the one used to
         * encrypt the account then olm_inbound_group_session_last_error() will be
         * "BAD_ACCOUNT_KEY". If the base64 couldn't be decoded then
         * olm_inbound_group_session_last_error() will be "INVALID_BASE64". The input
         * pickled buffer is destroyed
         */
        [DllImport(LibraryName, EntryPoint = "olm_unpickle_inbound_group_session")]
        public static extern long OlmUnpickleInboundGroupSession(
            OlmInboundGroupSessionPtr session,
            MemPtr key, long keyLength,
            MemPtr pickled, long pickledLength
        );

        /**
         * Start a new inbound group session, from a key exported from
         * olm_outbound_group_session_key
         *
         * Returns olm_error() on failure. On failure last_error will be set with an
         * error code. The last_error will be:
         *
         *  * OLM_INVALID_BASE64  if the session_key is not valid base64
         *  * OLM_BAD_SESSION_KEY if the session_key is invalid
         */
        [DllImport(LibraryName, EntryPoint = "olm_init_inbound_group_session")]
        public static extern long OlmInitInboundGroupSession(
            OlmInboundGroupSessionPtr session,
            /* base64-encoded keys */
            MemPtr sessionKey, long sessionKeyLength
        );

        /**
         * Import an inbound group session, from a previous export.
         *
         * Returns olm_error() on failure. On failure last_error will be set with an
         * error code. The last_error will be:
         *
         *  * OLM_INVALID_BASE64  if the session_key is not valid base64
         *  * OLM_BAD_SESSION_KEY if the session_key is invalid
         */
        [DllImport(LibraryName, EntryPoint = "olm_import_inbound_group_session")]
        public static extern long OlmImportInboundGroupSession(
            OlmInboundGroupSessionPtr session,
            /* base64-encoded keys; note that it will be overwritten with the base64-decoded
            data. */
            MemPtr sessionKey, long sessionKeyLength
        );

        /**
         * Get an upper bound on the number of bytes of plain-text the decrypt method
         * will write for a given input message length. The actual size could be
         * different due to padding.
         *
         * The input message buffer is destroyed.
         *
         * Returns olm_error() on failure.
         */
        [DllImport(LibraryName, EntryPoint = "olm_group_decrypt_max_plaintext_length")]
        public static extern long OlmGroupDecryptMaxPlaintextLength(
            OlmInboundGroupSessionPtr session,
            MemPtr message, long messageLength
        );

        /**
         * Decrypt a message.
         *
         * The input message buffer is destroyed.
         *
         * Returns the length of the decrypted plain-text, or olm_error() on failure.
         *
         * On failure last_error will be set with an error code. The last_error will
         * be:
         *   * OLM_OUTPUT_BUFFER_TOO_SMALL if the plain-text buffer is too small
         *   * OLM_INVALID_BASE64 if the message is not valid base-64
         *   * OLM_BAD_MESSAGE_VERSION if the message was encrypted with an unsupported
         *     version of the protocol
         *   * OLM_BAD_MESSAGE_FORMAT if the message headers could not be decoded
         *   * OLM_BAD_MESSAGE_MAC    if the message could not be verified
         *   * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key corresponding to the
         *     message's index (ie, it was sent before the session key was shared with
         *     us)
         */
        [DllImport(LibraryName, EntryPoint = "olm_group_decrypt")]
        public static extern long OlmGroupDecrypt(
            OlmInboundGroupSessionPtr session,

            /* input; note that it will be overwritten with the base64-decoded
               message. */
            MemPtr message, long messageLength,

            /* output */
            MemPtr plaintext, long maxPlaintextLength,
            out uint messageIndex
        );


        /**
         * Get the number of bytes returned by olm_inbound_group_session_id()
         */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session_id_length")]
        public static extern long OlmInboundGroupSessionIdLength(
            OlmInboundGroupSessionPtr session
        );

        /**
         * Get a base64-encoded identifier for this session.
         *
         * Returns the length of the session id on success or olm_error() on
         * failure. On failure last_error will be set with an error code. The
         * last_error will be OUTPUT_BUFFER_TOO_SMALL if the id buffer was too
         * small.
         */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session_id")]
        public static extern long OlmInboundGroupSessionId(
            OlmInboundGroupSessionPtr session,
            MemPtr id, long idLength
        );

        /**
         * Get the first message index we know how to decrypt.
         */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session_first_known_index")]
        public static extern int OlmInboundGroupSessionFirstKnownIndex(
            OlmInboundGroupSessionPtr session
        );

        /**
         * Check if the session has been verified as a valid session.
         *
         * (A session is verified either because the original session share was signed,
         * or because we have subsequently successfully decrypted a message.)
         *
         * This is mainly intended for the unit tests, currently.
         */
        [DllImport(LibraryName, EntryPoint = "olm_inbound_group_session_is_verified")]
        public static extern int OlmInboundGroupSessionIsVerified(
            OlmInboundGroupSessionPtr session
        );

        /**
         * Get the number of bytes returned by olm_export_inbound_group_session()
         */
        [DllImport(LibraryName, EntryPoint = "olm_export_inbound_group_session_length")]
        public static extern long OlmExportInboundGroupSessionLength(
            OlmInboundGroupSessionPtr session
        );

        /**
         * Export the base64-encoded ratchet key for this session, at the given index,
         * in a format which can be used by olm_import_inbound_group_session
         *
         * Returns the length of the ratchet key on success or olm_error() on
         * failure. On failure last_error will be set with an error code. The
         * last_error will be:
         *   * OUTPUT_BUFFER_TOO_SMALL if the buffer was too small
         *   * OLM_UNKNOWN_MESSAGE_INDEX  if we do not have a session key corresponding to the
         *     given index (ie, it was sent before the session key was shared with
         *     us)
         */
        [DllImport(LibraryName, EntryPoint = "olm_export_inbound_group_session")]
        public static extern long OlmExportInboundGroupSession(
            OlmInboundGroupSessionPtr session,
            MemPtr key, long keyLength, int messageIndex
        );
    }
}
