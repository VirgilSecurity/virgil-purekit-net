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

namespace Passw0rd.Utils
{
    using System;
    using Passw0rd.Phe;

    internal class StringKeyParser
    {
        private const string PublicKeyPref = "PK";
        private const string SecretKeyPref = "SK";
        private readonly PheCrypto crypto;

        public StringKeyParser()
        {
            this.crypto = new PheCrypto();
        }

        public (uint, PublicKey) ParsePublicKey(string servicePublicKey)
        {
            Validation.NotNullOrWhiteSpace(servicePublicKey);
            var (version, keyBytes) = this.ParseKeyBytesByPrefix(servicePublicKey, PublicKeyPref);

            if (keyBytes.Length != 65)
            {
                throw new ArgumentException("has incorrect length", nameof(servicePublicKey));
            }

            PublicKey publicKey;
            try
            {
                publicKey = this.crypto.DecodePublicKey(keyBytes);
            }
            catch (Exception e)
            {
                throw new WrongServiceKeyException(e.ToString());
            }

            return (version, publicKey);
        }

        public (uint, SecretKey) ParseSecretKey(string clientSecretKey)
        {
            Validation.NotNullOrWhiteSpace(clientSecretKey);
            var (version, keyBytes) = this.ParseKeyBytesByPrefix(clientSecretKey, SecretKeyPref);

            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("has incorrect length", nameof(clientSecretKey));
            }

            SecretKey secretKey;
            try
            {
                secretKey = this.crypto.DecodeSecretKey(keyBytes);
            }
            catch (Exception e)
            {
                throw new WrongClientSecretKeyException(e.ToString());
            }

            return (version, secretKey);
        }

        private (uint, byte[]) ParseKeyBytesByPrefix(string key, string keyFlag)
        {
            Validation.NotNullOrWhiteSpace(key);

            var keyParts = key.Split(".");
            if (keyParts.Length != 3 ||
                !uint.TryParse(keyParts[1], out uint version) ||
                !keyParts[0].ToUpper().Equals(keyFlag))
            {
                throw new ArgumentException("has incorrect format", nameof(key));
            }

            var keyBytes = Bytes.FromString(keyParts[2], StringEncoding.BASE64);

            return (version, keyBytes);
        }
    }
}
