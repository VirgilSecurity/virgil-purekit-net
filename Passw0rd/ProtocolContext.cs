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
    using global::Phe;
    using Google.Protobuf;
    using Passw0rd.Client;
    using Passw0rd.Client.Connection;
    using Passw0rd.Phe;
    using Passw0rd.Utils;
    using Passw0Rd;

    public class ProtocolContext
    {
        
        public SecretKey ClientSecretKey { get; private set; }
        public PublicKey ServerPublicKey { get; private set; }
        public Dictionary<uint, PheKeys> VersionedPheKeys { get; private set; }
        private ProtocolContext()
        {
            VersionedPheKeys = new Dictionary<uint, PheKeys>();
        }

        /// <summary>
        /// Gets the app identifier.
        /// </summary>
        public string AppToken { get; private set; }

        /// <summary>
        /// Gets the client instance.
        /// </summary> 
        public IPheClient Client { get; private set; }

        /// <summary>
        /// Gets the PHE Crypto instanse.
        /// </summary>
        public PheCrypto Crypto { get; private set; }


        /// <summary>
        /// Gets the PHE Crypto instanse.
        /// </summary>
        public uint CurrentVersion { get; private set; }

        /// <summary>
        /// Gets the update tokens.
        /// </summary>
        public VersionedUpdateToken VersionedUpdateToken { get; private set; } 

     
        public static ProtocolContext Create(string appToken, string accessToken, 
            string serverPublicKey, string clientSecretKey, string updateToken = null)
        {
            // todo: validate params
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
                AppToken = appToken,
                Client = client,
                Crypto = phe,
                CurrentVersion = pkSVer
            };
            ctx.VersionedPheKeys.Add(pkSVer, new PheKeys(skC, pkS));

            if (!String.IsNullOrWhiteSpace(updateToken))
            {

                ctx.VersionedUpdateToken = VersionedUpdateTokenExtension.ParseFromString(updateToken);
                if (ctx.VersionedUpdateToken.Version != pkSVer)
                {
                    if (ctx.VersionedUpdateToken.Version != ctx.CurrentVersion + 1){
                        throw new Exception("incorrect token version");
                    } 

                    pkS = phe.RotatePublicKey(pkS, ctx.VersionedUpdateToken.UpdateToken.ToByteArray());
                    skC = phe.RotateSecretKey(skC, ctx.VersionedUpdateToken.UpdateToken.ToByteArray());
                    ctx.VersionedPheKeys.Add(ctx.VersionedUpdateToken.Version, new PheKeys(skC, pkS));
                    ctx.CurrentVersion = ctx.VersionedUpdateToken.Version;
                }
            }

            ctx.ClientSecretKey = skC;
            ctx.ServerPublicKey = pkS;

            return ctx;
        }
     

        //todo: refactoring
        private static (uint, PublicKey) EnsureServerPublicKey(string serverPublicKey, PheCrypto phe)
        {
            var keyParts = serverPublicKey.Split(".");
            if (keyParts.Length != 3 ||
                !UInt32.TryParse(keyParts[1], out uint version) ||
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

        //todo: refactoring
        private static (uint, SecretKey) EnsureClientSecretKey(string clientSecretKey, PheCrypto phe)
        {
            var keyParts = clientSecretKey.Split(".");
            if (keyParts.Length != 3 ||
                !UInt32.TryParse(keyParts[1], out uint version) ||
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
