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
    using System.Linq;

    using Passw0rd.Utils;

    /// <summary>
    /// Update token.
    /// </summary>
    public class UpdateToken
    {
        /// <summary>
        /// Gets the a value.
        /// </summary>
        public byte[] A { get; internal set; }

        /// <summary>
        /// Gets the b value.
        /// </summary>
        public byte[] B { get; internal set; }

        /// <summary>
        /// Gets the version.
        /// </summary>
        public int Version { get; internal set; }

        /// <summary>
        /// Decodes an <see cref="UpdateToken"/> form specified string.
        /// </summary>
        public static UpdateToken Decode(string updateToken)
        {
            var tokenParts = updateToken.Split(".");
            if (tokenParts.Length != 3 ||
                !Int32.TryParse(tokenParts[1], out int version) || 
                !tokenParts[0].ToUpper().Equals("UT"))
            {
                throw new ArgumentException("has incorrect format", nameof(updateToken));
            }

            var asn1Bytes = Bytes.FromString(updateToken);
            var decodedAsn1Sequense = Asn1Helper.Decode(asn1Bytes);

            return new UpdateToken 
            {
                A = decodedAsn1Sequense.ElementAt(0), 
                B = decodedAsn1Sequense.ElementAt(1),
                Version = version
            };
        }
    }
}