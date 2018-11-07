/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

namespace Passw0rd
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Passw0rd.Client;
    using Passw0rd.Client.Connection;
    using Passw0rd.Phe;
    using Passw0rd.Utils;

    public class ProtocolContext
    {
        private IDictionary<int, SecretKey> clientSecretKeys;
        private IDictionary<int, PublicKey> serverPublicKeys;

        private ProtocolContext()
        {
        }

        /// <summary>
        /// Gets the app identifier.
        /// </summary>
        public string AppId { get; private set; }

        /// <summary>
        /// Gets the client instance.
        /// </summary> 
        public IPheClient Client { get; private set; }

        /// <summary>
        /// Gets the PHE Crypto instanse.
        /// </summary>
        public PheCrypto Crypto { get; private set; }

        /// <summary>
        /// Gets the update tokens.
        /// </summary>
        public IEnumerable<UpdateToken> UpdateTokens { get; private set; } 

        public int ActualVersion 
        {
            get 
            {
                return this.clientSecretKeys.Max(it => it.Key);
            }
        }

        public SecretKey GetActualClientSecretKey()
        {
            return this.clientSecretKeys[this.ActualVersion];
        }

        public PublicKey GetActualServerPublicKey()
        {
            return this.serverPublicKeys[this.ActualVersion];
        }

        public SecretKey GetClientSecretKeyForVersion(int version)
        {
            return this.clientSecretKeys[version];
        }

        public PublicKey GetServerPublicKeyForVersion(int version)
        {
            return this.serverPublicKeys[version];
        }

        public static ProtocolContext Create(string appId, string accessToken, 
            string serverPublicKey, string clientSecretKey, string[] updateTokens = null)
        {
            var phe = new PheCrypto();
            var (pkSVer, pkS) = EnsureServerPublicKey(serverPublicKey, phe);
            var (skCVer, skC) = EnsureClientSecretKey(clientSecretKey, phe);

            if (pkSVer != skCVer) 
            {
                throw new ArgumentException("Incorrect versions for Server/Client keys.");
            }

            var serializer = new HttpBodySerializer();
            var client = new PheClient(serializer)
            {
                AccessToken = accessToken,
                BaseUri = new Uri("https://api.passw0rd.io/")
            };

            var ctx = new ProtocolContext
            {
                AppId = appId,
                Client = client,
                Crypto = phe
            };

            var serverPksDictionary = new Dictionary<int, PublicKey> { [pkSVer] = pkS };
            var clientSksDictionary = new Dictionary<int, SecretKey> { [skCVer] = skC };

            if (updateTokens != null && updateTokens.Length > 0)
            {
                var updateTokenList = updateTokens.Select(UpdateToken.Decode)
                    .Where(it => it.Version > skCVer)
                    .OrderBy(it => it.Version)
                    .ToList();

                ctx.UpdateTokens = updateTokenList;

                foreach (var token in updateTokenList)
                {
                    pkS = phe.RotatePublicKey(pkS, token.A, token.B);
                    skC = phe.RotateSecretKey(skC, token.A, token.B);

                    serverPksDictionary.Add(token.Version, pkS);
                    clientSksDictionary.Add(token.Version, skC);
                }
            }

            ctx.clientSecretKeys = clientSksDictionary;
            ctx.serverPublicKeys = serverPksDictionary;

            return ctx;
        }

        private static (int, PublicKey) EnsureServerPublicKey(string serverPublicKey, PheCrypto phe)
        {
            var keyParts = serverPublicKey.Split(".");
            if (keyParts.Length != 3 ||
                !Int32.TryParse(keyParts[1], out int version) ||
                !keyParts[0].ToUpper().Equals("PK"))
            {
                throw new ArgumentException("has incorrect format", nameof(serverPublicKey));
            }

            var keyBytes = Bytes.FromString(keyParts[2], StringEncoding.BASE64);
            if (keyBytes.Length != 65)
            {
                throw new ArgumentException("has incorrect length", nameof(serverPublicKey));
            }

            var publicKey = phe.DecodePublicKey(keyBytes);
            return (version, publicKey); 
        }

        private static (int, SecretKey) EnsureClientSecretKey(string clientSecretKey, PheCrypto phe)
        {
            var keyParts = clientSecretKey.Split(".");
            if (keyParts.Length != 3 ||
                !Int32.TryParse(keyParts[1], out int version) ||
                !keyParts[0].ToUpper().Equals("SK"))
            {
                throw new ArgumentException("has incorrect format", nameof(clientSecretKey));
            }

            var keyBytes = Bytes.FromString(keyParts[2], StringEncoding.BASE64);
            if (keyBytes.Length != 32)
            {
                throw new ArgumentException("has incorrect length", nameof(clientSecretKey));
            }

            var secretKey = phe.DecodeSecretKey(keyBytes);
            return (version, secretKey); 
        }
    }
}
