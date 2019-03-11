/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

namespace Virgil.PureKit.Phe
{
    using System;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Engines;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Modes;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Security;
    using Virgil.PureKit.Utils;

    internal class EncryptionService
    {
        public static readonly int SymKeyLen = 32;
        public static readonly int SymSaltLen = 32;
        public static readonly int SymNonceLen = 12;
        public static readonly int SymTagLen = 16;
        private byte[] key;
        private byte[] domain;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptionService"/> class.
        /// </summary>
        /// <param name="key">Key to be used in HKDF.</param>
        public EncryptionService(byte[] key)
        {
            Validation.NotNullOrEmptyByteArray(key);
            if (key.Length != SymKeyLen)
            {
                throw new ArgumentException(string.Format("key must be exactly {0} bytes", SymKeyLen));
            }

            this.key = key;
            this.domain = Domains.Encrypt;
        }

        /// <summary>
        /// Encrypt the specified data.
        ///Encrypt generates 32 byte salt, uses master key
        ///& salt to generate per-data key & nonce with the help of HKDF
        ///Salt is concatenated to the ciphertext
        /// </summary>
        /// <returns>The encrypted data bytes.</returns>
        /// <param name="data">Data to be encrypted.</param>
        public byte[] Encrypt(byte[] data)
        {
            Validation.NotNull(data);
            var rng = new SecureRandom();
            var salt = new byte[SymSaltLen];
            rng.NextBytes(salt);

            return this.EncryptWithSalt(data, salt);
        }

        /// <summary>
        /// Encrypt the specified data using the specified salt.
        ///Encrypt uses provided salt, uses master key
        ///& salt to generate per-data key & nonce with the help of HKDF
        ///Salt is concatenated to the ciphertext
        /// </summary>
        /// <returns>The encrypted data bytes.</returns>
        /// <param name="data">Data to be encrypted.</param>
        public byte[] EncryptWithSalt(byte[] data, byte[] salt)
        {
            Validation.NotNull(data);
            Validation.NotNullOrEmptyByteArray(salt);

            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(this.key, salt, this.domain));

            var keyNonce = new byte[SymKeyLen + SymNonceLen];
            hkdf.GenerateBytes(keyNonce, 0, keyNonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var keyNonceSlice1 = ((Span<byte>)keyNonce).Slice(0, SymKeyLen);
            var keyNonceSlice2 = ((Span<byte>)keyNonce).Slice(SymKeyLen);

            var parameters = new AeadParameters(
                new KeyParameter(keyNonceSlice1.ToArray()),
                SymTagLen * 8,
                keyNonceSlice2.ToArray());
            
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            return Bytes.Combine(salt, cipherText);
        }

        /// <summary>
        /// Decrypt the specified cipherText.
        ///Decrypt extracts 32 byte salt, derives key & nonce and
        ///decrypts ciphertext with the help of HKDF
        /// </summary>
        /// <returns>The decrypted data bytes.</returns>
        /// <param name="cipherText">Encrypted data to be decrypted.</param>
        public byte[] Decrypt(byte[] cipherText)
        {
            Validation.NotNullOrEmptyByteArray(cipherText);

            if (cipherText.Length < (SymSaltLen + SymTagLen))
            {
                throw new ArgumentException("Invalid ciphertext length.");
            }

            var salt = ((Span<byte>)cipherText).Slice(0, SymSaltLen).ToArray();

            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(this.key, salt, this.domain));

            var keyNonce = new byte[SymKeyLen + SymNonceLen];
            hkdf.GenerateBytes(keyNonce, 0, keyNonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var keyNonceSlice1 = ((Span<byte>)keyNonce).Slice(0, SymKeyLen);
            var keyNonceSlice2 = ((Span<byte>)keyNonce).Slice(SymKeyLen);

            var parameters = new AeadParameters(new KeyParameter(keyNonceSlice1.ToArray()), SymTagLen * 8, keyNonceSlice2.ToArray());
            cipher.Init(false, parameters);

            var cipherTextExceptSalt = ((Span<byte>)cipherText).Slice(SymSaltLen).ToArray();
            var plainText = new byte[cipher.GetOutputSize(cipherTextExceptSalt.Length)];

            var len = cipher.ProcessBytes(cipherTextExceptSalt, 0, cipherTextExceptSalt.Length, plainText, 0);
            cipher.DoFinal(plainText, len);

            return plainText;
        }
    }
}
