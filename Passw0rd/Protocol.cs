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
    using System.Threading.Tasks;

    using Passw0rd.Phe;
    using Passw0rd.Client;
    using Passw0rd.Utils;

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
        private readonly PheCrypto phe;
        private readonly IClient client;
        private readonly SecretKey skC;
        private readonly PublicKey pkS;

        /// <summary>
        /// Initializes a new instance of the <see cref="Protocol"/> class.
        /// </summary>
        public Protocol(IClient client, PheCrypto phe, SecretKey clientSecretKey, PublicKey serverPublicKey)
        {
            this.phe = phe;
            this.client = client;
            this.skC = clientSecretKey;
            this.pkS = serverPublicKey;
        }

        /// <summary>
        /// Enrolls a new <see cref="PasswordRecord"/> for specified password.
        /// </summary>
        public async Task<PasswordRecord> EnrollAsync(string password)
        {
            var enrollment  = await this.client.EnrollAsync().ConfigureAwait(false);

            var nS = enrollment.Nonce;
            var nC = this.phe.GenerateNonce();
            var pwdBytes = Bytes.FromString(password);

            var (t0, t1) = this.phe.ComputeT(skC, pwdBytes, nC, enrollment.C0, enrollment.C1);

            var recordT = new PasswordRecord
            {
                ClientNonce = nC,
                ServerNonce = nS,
                RecordT0 = t0,
                RecordT1 = t1
            };

            return recordT;
        }

        /// <summary>
        /// Verifies a <see cref="PasswordRecord"/> by specified password.
        /// </summary>
        public async Task<VerificationResult> VerifyAsync(PasswordRecord pwdRecord, string password)
        {
            var pwdBytes = Bytes.FromString(password);
            var c0 = this.phe.ComputeC0(this.skC, pwdBytes, pwdRecord.ClientNonce, pwdRecord.RecordT0);

            var parameters = new VerificationModel 
            { 
                C0 = c0, 
                Ns = pwdRecord.ServerNonce 
            };

            byte[] m = null;

            var serverResult = await this.client.VerifyAsync(parameters).ConfigureAwait(false);
            if (serverResult.IsSuccess)
            {
                var proof = serverResult.ProofOfSuccess ?? throw new ProofNotProvidedException();
           
                var isValid = this.phe.ValidateProofOfSuccess(this.pkS, pwdRecord.ServerNonce, 
                    c0, serverResult.C1, proof.Term1, proof.Term2, proof.Term3, proof.BlindX);

                if (!isValid)
                {
                    throw new ProofOfSuccessNotValidException();
                }

                m = this.phe.DecryptM(this.skC, pwdBytes, pwdRecord.ClientNonce, pwdRecord.RecordT1, serverResult.C1);
            }
            else
            {
                var proof = serverResult.ProofOfFail ?? throw new ProofNotProvidedException();

                // TODO: verify the proof of fail
            }

            var result = new VerificationResult
            {
                IsSuccess = serverResult.IsSuccess,
                Key = m
            };

            return result;
        }

        /// <summary>
        /// Updates a <see cref="PasswordRecord"/> with an specified <see cref="UpdateToken"/>.
        /// </summary>
        public PasswordRecord Update(PasswordRecord pwdRecord, UpdateToken updateToken)
        {
            if (pwdRecord == null)
            {
                throw new ArgumentNullException(nameof(pwdRecord));
            }

            if (updateToken == null)
            {
                throw new ArgumentNullException(nameof(updateToken));
            }

            var (t0, t1) = this.phe.UpdateT(pwdRecord.ServerNonce, pwdRecord.RecordT0, 
                pwdRecord.RecordT1, updateToken.A, updateToken.B);

            var newRecord = new PasswordRecord
            {
                ClientNonce = pwdRecord.ClientNonce,
                ServerNonce = pwdRecord.ServerNonce,
                RecordT0 = t0,
                RecordT1 = t1
            };

            return newRecord;
        }
    }
}
