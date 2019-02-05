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
    using System.Threading.Tasks;
    using Passw0rd.Phe;
    using Passw0rd.Utils;
    using Passw0Rd;
    using Google.Protobuf;

    /// <summary>
    /// The <see cref="Protocol"/> provides an implementation of PHE (Password 
    /// Hardened Encryption) scheme.
    /// </summary>
    /// <remarks>
    /// With the help of an external crypto server, a service provider can recover 
    /// the user data encrypted by PHE only when an end user supplied a correct password. 
    /// PHE inherits the security features of password-hardening, adding protection
    /// for the user data. In particular, the crypto server does not learn any 
    /// information about any user data. More importantly, both the crypto server 
    /// and the service provider can rotate their secret keys, a proactive security 
    /// mechanism mandated by the Payment Card Industry Data Security Standard (PCI DSS).
    /// </remarks>
    public class Protocol
    {
        private readonly ProtocolContext ctx;

        /// <summary>
        /// Initializes a new instance of the <see cref="Protocol"/> class.
        /// </summary>
        /// <param name="context">The instance of the <see cref="ProtocolContext"/>
        /// which contains application credentials.
        /// How to get passw0rd's application credentials
        /// you will find <see href="https://github.com/passw0rd/cli">here</see>.</param>
        public Protocol(ProtocolContext context)
        {
            Validation.NotNull(context,
                               "Context with Application token, Service Public" +
                               " Key and Application Secret Key isn't provided.");
            this.ctx = context;
        }

       /// <summary>
        /// Creates a new encrypted password record using user's password. 
       /// </summary>
        /// <returns>
        /// Encrypted Passw0rd's record.(Is associated with the user. You can keep it in your database.)
        /// Secret key, that can be used to encrypt user's data. 
        /// </returns>
       /// <param name="password">User's Password.</param>
        public async Task<(byte[], byte[])> EnrollAccountAsync(string password)
        {
            Validation.NotNullOrWhiteSpace(password, "User's password isn't provided.");

            var enrollmentResp = await ctx.Client.GetEnrollment(
                new EnrollmentRequest() { Version = ctx.CurrentVersion })
                .ConfigureAwait(false);
            var pwdBytes = Bytes.FromString(password);
            var pheClient = ctx.PheClients[ctx.CurrentVersion];
            var (enrollmentRecord, key) = pheClient.EnrollAccount(pwdBytes,
                                                                  enrollmentResp.Response.ToByteArray());
            var record = new DatabaseRecord
            {
                Version = ctx.CurrentVersion,
                Record = ByteString.CopyFrom(enrollmentRecord)
                                   
            };
            return (record.ToByteArray(), key);
        }

        /// <summary>
        /// Verifies encrypted password record using user's password.
        /// </summary>
        /// <returns>EncryptionKey wich you can use for decrypting user's data.</returns>
        /// <param name="password">User's password.</param>
        /// <param name="pwdRecord">Encrypted password record to be verified.</param>
        public async Task<byte[]> VerifyPasswordAsync(string password, byte[] pwdRecord)
        {
            Validation.NotNullOrWhiteSpace(password, "User's password isn't provided.");
            Validation.NotNullOrEmptyByteArray(pwdRecord, "User's record isn't provided.");

            var pwdBytes = Bytes.FromString(password);
            var databaseRecord = DatabaseRecord.Parser.ParseFrom(pwdRecord);
            if (databaseRecord.Version < 1)
            {
                throw new WrongVersionException("Invalid record version");
            }

            if (!ctx.PheClients.ContainsKey(databaseRecord.Version)){
                throw new WrongVersionException("unable to find keys corresponding to this record's version");
            }
           
            var pheClient = ctx.PheClients[databaseRecord.Version];
            var pheVerifyPasswordRequest = pheClient.CreateVerifyPasswordRequest(pwdBytes,
                                                                                 databaseRecord.Record.ToByteArray());

            var versionedPasswordRequest = new Passw0Rd.VerifyPasswordRequest()
            {
                Version = databaseRecord.Version,
                Request = ByteString.CopyFrom(pheVerifyPasswordRequest)
            };

            var serverResponse = await ctx.Client.VerifyAsync(versionedPasswordRequest).ConfigureAwait(false);

            return pheClient.CheckResponseAndDecrypt(pwdBytes,
                                                     databaseRecord.Record.ToByteArray(),
                                                     serverResponse.Response.ToByteArray());
        }
    }
}
