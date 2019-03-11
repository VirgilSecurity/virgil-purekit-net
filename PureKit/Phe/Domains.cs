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

namespace Virgil.PureKit.Phe
{
    using Virgil.PureKit.Utils;

    /// <summary>
    /// Constants wich are used in implementation of the  Password-Hardened Encryption(PHE) protocol.
    /// </summary>
    internal static class Domains
    {
        public static readonly byte[] Dhc0;
        public static readonly byte[] Dhc1;
        public static readonly byte[] Dhs0;
        public static readonly byte[] Dhs1;
        public static readonly byte[] ProofOK;
        public static readonly byte[] ProofErr;
        public static readonly byte[] Encrypt;
        public static readonly byte[] KdfInfoZ;
        public static readonly byte[] KdfInfoClientKey;
        private static byte[] commonPrefix;

        static Domains()
        {
            commonPrefix = new byte[] { 0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45 }; // VRGLPHE
            Dhc0 = Bytes.Combine(commonPrefix, new byte[] { 0x31 });
            Dhc1 = Bytes.Combine(commonPrefix, new byte[] { 0x32 });
            Dhs0 = Bytes.Combine(commonPrefix, new byte[] { 0x33 });
            Dhs1 = Bytes.Combine(commonPrefix, new byte[] { 0x34 });
            ProofOK = Bytes.Combine(commonPrefix, new byte[] { 0x35 });
            ProofErr = Bytes.Combine(commonPrefix, new byte[] { 0x36 });
            Encrypt = Bytes.Combine(commonPrefix, new byte[] { 0x37 });
            KdfInfoZ = Bytes.Combine(commonPrefix, new byte[] { 0x38 });
            KdfInfoClientKey = Bytes.Combine(commonPrefix, new byte[] { 0x39 });
        }
    }
}
