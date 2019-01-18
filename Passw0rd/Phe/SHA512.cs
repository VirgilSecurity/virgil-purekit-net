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

namespace Passw0rd.Phe
{
    using System;
    using System.IO;

    using Org.BouncyCastle.Crypto.Digests;

    public class SHA512
    {
        /// <summary>
        /// Hashes a list of byte arrays, prefixing each one with its length.
        /// </summary>
        public byte[] ComputeHash(byte[] domain, params byte[][] datas)
        {
            using (var stream = new MemoryStream())
            {
                if (domain != null){
                    stream.Write(domain, 0, domain.Length);
                }

                foreach (var data in datas)
                {
                    stream.Write(data, 0, data.Length);
                }

                var result = stream.ToArray();

                byte[] hash;
                var sha = new Sha512Digest();

                try
                {
                    sha.BlockUpdate(result, 0, result.Length);
                    hash = new byte[sha.GetDigestSize()];
                    sha.DoFinal(hash, 0);
                }
                finally
                {
                    sha.Finish();
                }

                return hash;
            }
        }

        /// <summary>
        /// Converts UInt64 value into byte arraty with big endian bytes order.
        /// </summary>
        private byte[] UInt64ToBytes(ulong value)
        {
            var ulongBytes = BitConverter.GetBytes(value);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(ulongBytes);
            }

            return ulongBytes;
        }
    }
}