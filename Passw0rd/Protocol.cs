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
    using System.Linq;

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
        public Protocol(ProtocolContext context)
        {
            this.ctx = context;
        }

        /// <summary>
        /// Enrolls a new <see cref="PasswordRecord"/> for specified password.
        /// </summary>
        public async Task<PasswordRecord> EnrollAsync(string password)
        {
            var version = this.ctx.ActualVersion;
            var skC = this.ctx.GetActualClientSecretKey();

            var model = await this.ctx.Client.EnrollAsync(
                new EnrollmentRequestModel{ AppId = this.ctx.AppId, Version = version })
                .ConfigureAwait(false);

            var enrollment = model.Enrollment;
            var nS = enrollment.Nonce;
            var nC = this.ctx.Crypto.GenerateNonce();
            var pwdBytes = Bytes.FromString(password);

            var (t0, t1) = this.ctx.Crypto.ComputeT(skC, pwdBytes, nC, enrollment.C0, enrollment.C1);

            var recordT = new PasswordRecord
            {
                ClientNonce = nC,
                ServerNonce = nS,
                RecordT0 = t0,
                RecordT1 = t1,
                Version = version
            };

            return recordT;
        }

        /// <summary>
        /// Verifies a <see cref="PasswordRecord"/> by specified password.
        /// </summary>
        public async Task<VerificationResult> VerifyAsync(PasswordRecord pwdRecord, string password)
        {
            var pwdBytes = Bytes.FromString(password);
            var skC = this.ctx.GetClientSecretKeyForVersion(pwdRecord.Version);
            var pkS = this.ctx.GetServerPublicKeyForVersion(pwdRecord.Version);
            var c0 = this.ctx.Crypto.ComputeC0(skC, pwdBytes, pwdRecord.ClientNonce, pwdRecord.RecordT0);

            var parameters = new VerificationRequestModel 
            { 
                AppId = this.ctx.AppId,
                C0 = c0, 
                Ns = pwdRecord.ServerNonce 
            };

            byte[] m = null;

            var serverResult = await this.ctx.Client.VerifyAsync(parameters).ConfigureAwait(false);
            if (serverResult.IsSuccess)
            {
                var proofModel = serverResult.ProofOfSuccess ?? throw new ProofNotProvidedException();

                var proof = new ProofOfSuccess
                {
                    Term1  = proofModel.Term1,
                    Term2  = proofModel.Term2,
                    Term3  = proofModel.Term3,
                    BlindX = proofModel.BlindX,
                };
           
                var isValid = this.ctx.Crypto.ValidateProofOfSuccess(proof, pkS, pwdRecord.ServerNonce, c0, serverResult.C1);
                if (!isValid)
                {
                    throw new ProofOfSuccessNotValidException();
                }

                m = this.ctx.Crypto.DecryptM(skC, pwdBytes, pwdRecord.ClientNonce, pwdRecord.RecordT1, serverResult.C1);
            }
            else
            {
                var proofModel = serverResult.ProofOfFail ?? throw new ProofNotProvidedException();

                var proof = new ProofOfFail
                {
                    Term1  = proofModel.Term1,
                    Term2  = proofModel.Term2,
                    Term3  = proofModel.Term3,
                    Term4  = proofModel.Term4,
                    BlindA = proofModel.BlindA,
                    BlindB = proofModel.BlindB,
                };

                var isValid = this.ctx.Crypto.ValidateProofOfFail(proof, pkS, pwdRecord.ServerNonce, c0, serverResult.C1);

                if (!isValid)
                {
                    throw new ProofOfFailNotValidException();
                }
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
        public PasswordRecord Update(PasswordRecord record)
        {
            if (record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }

            if (this.ctx.UpdateTokens == null || !this.ctx.UpdateTokens.Any())
            {
                throw new Passw0rdProtocolException("UpdateToken is not provided in context");
            }

            var tokensForRotate = this.ctx.UpdateTokens
                                      .Where(it => it.Version > record.Version)
                                      .OrderBy(it => it.Version)
                                      .ToList();

            if (!tokensForRotate.Any())
            {
                throw new Passw0rdProtocolException("It's up to date record.");
            }

            var t0 = record.RecordT0;
            var t1 = record.RecordT1;
            var version = record.Version;

            foreach (var token in tokensForRotate)
            {
                (t0, t1) = this.ctx.Crypto.UpdateT(record.ServerNonce, t0, t1, token.A, token.B);
                version = token.Version;
            }

            var newRecord = new PasswordRecord
            {
                ClientNonce = record.ClientNonce,
                ServerNonce = record.ServerNonce,
                RecordT0 = t0,
                RecordT1 = t1,
                Version = version
            };

            return newRecord;
        }
    }
}
