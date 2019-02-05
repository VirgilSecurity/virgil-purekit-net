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

namespace Passw0rd
{
    using System;
    using System.Collections.Generic;
    using Passw0rd.Client;
    using Passw0rd.Client.Connection;
    using Passw0rd.Utils;
    using Passw0Rd;

    public class ProtocolContext
    {
        private ProtocolContext()
        {
            PheClients = new Dictionary<uint, PheClient>();
        }

        /// <summary>
        /// Gets the app identifier.
        /// </summary>
        public string AppToken { get; private set; }

        /// <summary>
        /// Gets the client instance.
        /// </summary> 
        public IPheHttpClient Client { get; private set; }

     
        /// <summary>
        /// Gets the client instance.
        /// </summary> 
        public Dictionary<uint, PheClient> PheClients { get; private set; }

        /// <summary>
        /// Gets the Current Version.
        /// </summary>
        public uint CurrentVersion { get; private set; }

        /// <summary>
        /// Gets the update token.
        /// </summary>
        public VersionedUpdateToken VersionedUpdateToken { get; private set; }

        /// <summary>
        /// Create the context with passw0rd's application credentials.
        /// How to get passw0rd's application credentials
        /// you will find <see href="https://github.com/passw0rd/cli">here</see>.
        /// </summary>
        /// <returns>The new instance of the <see cref="ProtocolContext"/>
        ///  which contains application credentials.</returns>
        /// <param name="appToken">Application token.</param>
        /// <param name="servicePublicKey">Service public key.</param>
        /// <param name="appSecretKey">Application Secret Key.</param>
        /// <param name="updateToken">Update token.
        /// How to generate Update Token you will find 
        /// <see href="https://github.com/passw0rd/cli#get-an-update-token">here</see>.</param>
        public static ProtocolContext Create(string appToken,
            string servicePublicKey,
            string appSecretKey,
            string updateToken = null,
            string apiUrl = null)
        {
            Validation.NotNullOrWhiteSpace(appToken, "Application token isn't provided.");
            Validation.NotNullOrWhiteSpace(servicePublicKey, "Service Public Key isn't provided.");
            Validation.NotNullOrWhiteSpace(appSecretKey, "Application Secret Key isn't provided.");

            var keyParser = new StringKeyParser();
            var (pkSVer, pkS) = keyParser.ParsePublicKey(servicePublicKey);
            var (skCVer, skC) = keyParser.ParseSecretKey(appSecretKey);

            if (pkSVer != skCVer) 
            {
                throw new WrongVersionException("Incorrect versions for Server/Client keys.");
            }

            var serializer = new HttpBodySerializer();
            var url = String.IsNullOrWhiteSpace(apiUrl) ? "https://api.passw0rd.io/"
                            : apiUrl;
            var client = new PheHttpClient(serializer)
            {
                AppToken = appToken,
                BaseUri = new Uri(url)
            };

            var ctx = new ProtocolContext
            {
                AppToken = appToken,
                Client = client,
                CurrentVersion = pkSVer
            };

            var pheClient = new PheClient(skC, pkS);
            ctx.PheClients.Add(pkSVer, pheClient);

            if (!String.IsNullOrWhiteSpace(updateToken))
            {
                ctx.VersionedUpdateToken = StringUpdateTokenParser.Parse(updateToken);
                    if (ctx.VersionedUpdateToken.Version != ctx.CurrentVersion + 1){
                        throw new WrongVersionException("Incorrect token version.");
                    }
                    var (newSecretKey, newPublicKey) = pheClient.RotateKeys(ctx.VersionedUpdateToken.UpdateToken.ToByteArray());
                    ctx.PheClients.Add(ctx.VersionedUpdateToken.Version, new PheClient(newSecretKey, newPublicKey));
                    ctx.CurrentVersion = ctx.VersionedUpdateToken.Version;
            }
            return ctx;
        }
    }
}
