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
    using Google.Protobuf;
    using Passw0rd.Phe;
    using Passw0rd.Utils;

    public class PheClient
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="T:Passw0rd.PheClient"/> class.
        /// </summary>
        /// <param name="secretKey">Application Secret Key.</param>
        /// <param name="publicKey">Service public key.</param>
        public PheClient(SecretKey secretKey, PublicKey publicKey)
        {
            Validation.NotNull(secretKey);
            Validation.NotNull(publicKey);

            this.Crypto = new PheCrypto();
            this.AppSecretKey = secretKey;
            this.ServicePublicKey = publicKey;
        }

        internal PheClient()
        {
            this.Crypto = new PheCrypto();
        }

        /// <summary>
        /// Gets the PHE Crypto instanse.
        /// </summary>
        public PheCrypto Crypto { get; internal set; }

        /// <summary>
        /// Gets the app secret key.
        /// </summary>
        public SecretKey AppSecretKey { get; private set; }

        /// <summary>
        /// Gets the service public key.
        /// </summary>
        /// <value>The service public key.</value>
        public PublicKey ServicePublicKey { get; private set; }

        /// <summary>
        /// Rotates the keys.
        /// </summary>
        /// <returns>The rotated AppSecretKey and rotated ServicePublicKey.</returns>
        /// <param name="updateTokenData">Update token data.</param>
        public (SecretKey, PublicKey) RotateKeys(byte[] updateTokenData)
        {
            Validation.NotNullOrEmptyByteArray(updateTokenData);

            var secretKey = this.Crypto.RotateSecretKey(this.AppSecretKey, updateTokenData);
            var publicKey = this.Crypto.RotatePublicKey(this.ServicePublicKey, updateTokenData);
            return (secretKey, publicKey);
        }

        /// <summary>
        /// Creates EnrollmentRecord which is then supposed to be stored in  database for further authentication
        /// Also generates a key which then can be used to protect user's data.
        /// </summary>
        /// <returns>The account.</returns>
        /// <param name="pwdBytes">Password bytes.</param>
        /// <param name="pheRespData">Phe resp data.</param>
        public (byte[], byte[]) EnrollAccount(byte[] pwdBytes, byte[] pheRespData)
        {
            Validation.NotNullOrEmptyByteArray(pwdBytes);
            Validation.NotNullOrEmptyByteArray(pheRespData);

            var pheResp = Phe.EnrollmentResponse.Parser.ParseFrom(ByteString.CopyFrom(pheRespData));

            var isValid = this.Crypto.ValidateProofOfSuccess(
                pheResp.Proof,
                this.ServicePublicKey,
                pheResp.Ns.ToByteArray(),
                pheResp.C0.ToByteArray(),
                pheResp.C1.ToByteArray());
            if (!isValid)
            {
                throw new ProofOfSuccessNotValidException();
            }

            var nS = pheResp.Ns;
            var nC = this.Crypto.GenerateNonce();

            var (t0, t1, key) = this.Crypto.ComputeT(
                this.AppSecretKey,
                pwdBytes,
                nC,
                pheResp.C0.ToByteArray(),
                pheResp.C1.ToByteArray());

            var enrollmentRecord = new EnrollmentRecord
            {
                Nc = ByteString.CopyFrom(nC),
                Ns = nS,
                T0 = ByteString.CopyFrom(t0),
                T1 = ByteString.CopyFrom(t1),
            };

            return (enrollmentRecord.ToByteArray(), key);
        }

        /// <summary>
        /// Creates a request for further password verification at the PHE server side.
        /// </summary>
        /// <returns>The verify password request.</returns>
        /// <param name="pwdBytes">Password bytes.</param>
        /// <param name="enrollmentRecordData">Enrollment record data.</param>
        public byte[] CreateVerifyPasswordRequest(byte[] pwdBytes, byte[] enrollmentRecordData)
        {
            Validation.NotNullOrEmptyByteArray(pwdBytes);
            Validation.NotNullOrEmptyByteArray(enrollmentRecordData);

            var enrollmentRecord = EnrollmentRecord.Parser.ParseFrom(
                ByteString.CopyFrom(enrollmentRecordData));

            if (enrollmentRecord.Nc.Length != this.Crypto.NonceLength() ||
                enrollmentRecord.Ns.Length != this.Crypto.NonceLength())
            {
                throw new Passw0rdProtocolException("Invalid record.");
            }

            var c0 = this.Crypto.ComputeC0(
                this.AppSecretKey,
                pwdBytes,
                enrollmentRecord.Nc.ToByteArray(),
                enrollmentRecord.T0.ToByteArray());

            var pheVerifyPasswordRequest = new Phe.VerifyPasswordRequest()
            {
                Ns = enrollmentRecord.Ns,
                C0 = ByteString.CopyFrom(c0),
            };

            return pheVerifyPasswordRequest.ToByteArray();
        }

        /// <summary>
        /// Update the specified EnrollmentRecord record.
        /// </summary>
        /// <returns>The updated Encrypted EnrollmentRecord.</returns>
        public byte[] UpdateEnrollmentRecord(byte[] token, byte[] enrollmentRecordData)
        {
            Validation.NotNullOrEmptyByteArray(token);
            Validation.NotNullOrEmptyByteArray(enrollmentRecordData);

            var enrollmentRecord = EnrollmentRecord.Parser.ParseFrom(ByteString.CopyFrom(enrollmentRecordData));

            var (t0, t1) = this.Crypto.UpdateT(
                enrollmentRecord.Ns.ToByteArray(),
                enrollmentRecord.T0.ToByteArray(),
                enrollmentRecord.T1.ToByteArray(),
                token);

            var updatedEnrollmentRecord = new EnrollmentRecord
            {
                Nc = enrollmentRecord.Nc,
                Ns = enrollmentRecord.Ns,
                T0 = ByteString.CopyFrom(t0),
                T1 = ByteString.CopyFrom(t1),
            };
            return updatedEnrollmentRecord.ToByteArray();
        }

        /// <summary>
        /// Checks the response and decrypt.
        /// </summary>
        /// <returns>Secret key, that can be used to encrypt user's data. </returns>
        /// <param name="pwdBytes">Password bytes.</param>
        /// <param name="enrollmentRecordData">Enrollment record data.</param>
        /// <param name="responseData">Response data.</param>
        public byte[] CheckResponseAndDecrypt(byte[] pwdBytes, byte[] enrollmentRecordData, byte[] responseData)
        {
            Validation.NotNullOrEmptyByteArray(pwdBytes);
            Validation.NotNullOrEmptyByteArray(enrollmentRecordData);
            Validation.NotNullOrEmptyByteArray(responseData);

            var enrollmentRecord = EnrollmentRecord.Parser.ParseFrom(
                ByteString.CopyFrom(enrollmentRecordData));

            var pheServerResponse = Phe.VerifyPasswordResponse.Parser.ParseFrom(
                ByteString.CopyFrom(responseData));
            byte[] key = null;

            var c0 = this.Crypto.ComputeC0(
                this.AppSecretKey,
                pwdBytes,
                enrollmentRecord.Nc.ToByteArray(),
                enrollmentRecord.T0.ToByteArray());

            if (pheServerResponse.Res)
            {
                this.ValidateProofOfSuccess(
                    pheServerResponse.Success,
                    enrollmentRecord.Ns.ToByteArray(),
                    c0,
                    pheServerResponse.C1.ToByteArray());

                key = this.Crypto.DecryptM(
                    this.AppSecretKey,
                    pwdBytes,
                    enrollmentRecord.Nc.ToByteArray(),
                    enrollmentRecord.T1.ToByteArray(),
                    pheServerResponse.C1.ToByteArray());
            }
            else
            {
                this.ValidateProofOfFail(
                    pheServerResponse.Fail,
                    enrollmentRecord.Ns.ToByteArray(),
                    c0,
                    pheServerResponse.C1.ToByteArray());
            }

            return key;
        }

        private void ValidateProofOfFail(ProofOfFail proofOfFail, byte[] ns, byte[] c0, byte[] c1)
        {
            if (proofOfFail == null)
            {
                throw new ProofNotProvidedException();
            }

            var isValid = this.Crypto.ValidateProofOfFail(
                proofOfFail,
                this.ServicePublicKey,
                ns,
                c0,
                c1);

            if (!isValid)
            {
                throw new ProofOfFailNotValidException();
            }

            throw new WrongPasswordException("You provide wrong password.");
        }

        private void ValidateProofOfSuccess(ProofOfSuccess proofOfSuccess, byte[] ns, byte[] c0, byte[] c1)
        {
            if (proofOfSuccess == null)
            {
                throw new ProofNotProvidedException();
            }

            var isValid = this.Crypto.ValidateProofOfSuccess(
                proofOfSuccess,
                this.ServicePublicKey,
                ns,
                c0,
                c1);
            if (!isValid)
            {
                throw new ProofOfSuccessNotValidException();
            }
        }
    }
}
