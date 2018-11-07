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
    using System.Collections.Generic;
    using System.Linq;
    using Passw0rd.Utils;
    using Passw0rd.Utils.Asn1;

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
        public PasswordRecord(byte[] nS, byte[] nC, byte[] t0, byte[] t1, int version)
        {
            this.ServerNonce = nS;
            this.ClientNonce = nC;
            this.RecordT0 = t0;
            this.RecordT1 = t1;
            this.Version = version;
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

        /// <summary>
        /// Gets the version.
        /// </summary>
        public int Version { get; internal set; }

        public byte[] Encode()
        {
            var sequence = new ASN1Sequence
            {
                Elements = new List<IASN1Object>
                {
                    new ASN1Integer(this.Version),
                    new ASN1OctetString(this.ServerNonce),
                    new ASN1OctetString(this.ClientNonce),
                    new ASN1OctetString(this.RecordT0),
                    new ASN1OctetString(this.RecordT1)
                }
            };

            return sequence.Encode();
        }

        public string EncodeToBase64()
        {
            var asn1Bytes = this.Encode();
            var asn1Base64 = Bytes.ToString(asn1Bytes, StringEncoding.BASE64);

            return asn1Base64;
        }

        public static PasswordRecord Decode(byte[] encodedRecord)
        {
            var sequence = ASN1Sequence.Decode(encodedRecord);

            var version = sequence.GetIntegerFromElementAt(0);
            var nS  = sequence.GetOctetStringFromElementAt(1);
            var nC  = sequence.GetOctetStringFromElementAt(2);
            var t0  = sequence.GetOctetStringFromElementAt(3);
            var t1  = sequence.GetOctetStringFromElementAt(4);

            return new PasswordRecord(nS, nC, t0, t1, version);
        }

        public static PasswordRecord DecodeFromBase64(string encodedRecordBase64)
        {
            var asn1Bytes = Bytes.FromString(encodedRecordBase64, StringEncoding.BASE64);
            var record = Decode(asn1Bytes);

            return record;
        }
    }
}
