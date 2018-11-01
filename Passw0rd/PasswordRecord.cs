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
    using System.Linq;
    using Passw0rd.Utils;

    /// <summary>
    /// The <see cref="PasswordRecord"/> represents an encryption record and 
    /// server/client nonces for specified user/password. 
    /// </summary>
    public class PasswordRecord
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordRecord"/> class.
        /// </summary>
        internal PasswordRecord()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordRecord"/> class.
        /// </summary>
        public PasswordRecord(byte[] nS, byte[] nC, byte[] t0, byte[] t1)
        {
            this.ServerNonce = nS;
            this.ClientNonce = nC;
            this.RecordT0 = t0;
            this.RecordT1 = t1;
        }

        /// <summary>
        /// Gets a nonce that generated on the PHE Server for the user.
        /// </summary>
        public byte[] ServerNonce { get; internal set; }

        /// <summary>
        /// Gets or nonce that generated on the Client Server for the user.
        /// </summary>
        public byte[] ClientNonce { get; internal set; }

        /// <summary>
        /// Gets an encryption record T0.
        /// </summary>
        public byte[] RecordT0 { get; internal set; }

        /// <summary>
        /// Gets an encryption record T1.
        /// </summary>
        public byte[] RecordT1 { get; internal set; }

        public byte[] Encode()
        {
            return Asn1Helper.Encode(this.ServerNonce, this.ClientNonce, this.RecordT0, this.RecordT1);
        }

        public string EncodeToBase64()
        {
            var asn1Bytes = this.Encode();
            var asn1Base64 = Bytes.ToString(asn1Bytes, StringEncoding.BASE64);

            return asn1Base64;
        }

        public static PasswordRecord Decode(byte[] encodedRecord)
        {
            var arrays = Asn1Helper.Decode(encodedRecord);

            return new PasswordRecord(arrays.ElementAt(0), arrays.ElementAt(1), 
                arrays.ElementAt(2), arrays.ElementAt(3));
        }

        public static PasswordRecord DecodeFromBase64(string encodedRecordBase64)
        {
            var asn1Bytes = Bytes.FromString(encodedRecordBase64);
            var record = PasswordRecord.Decode(asn1Bytes);

            return record;
        }
    }
}
