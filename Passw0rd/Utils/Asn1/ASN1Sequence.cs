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

namespace Passw0rd.Utils.Asn1
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Math;

    public class ASN1Sequence
    {
        public IEnumerable<IASN1Object> Elements { get; set; }

        public static ASN1Sequence Decode(byte[] asn1Bytes)
        {
            var sequense = Asn1Object.FromByteArray(asn1Bytes) as DerSequence;
            if (sequense == null)
            {
                throw new ArgumentException(nameof(asn1Bytes));
            }

            var asn1Objects = new List<IASN1Object>();

            for (var index = 0; index < sequense.Count; index++)
            {
                if (sequense[index].GetType() == typeof(DerOctetString))
                {
                    var octetString = sequense[index] as DerOctetString;
                    asn1Objects.Add(new ASN1OctetString(octetString.GetOctets()));
                }
                else if (sequense[index].GetType() == typeof(DerInteger))
                {
                    var asn1Integer = sequense[index] as DerInteger;
                    asn1Objects.Add(new ASN1Integer(asn1Integer.Value.IntValue));
                }
                else
                {
                    throw new ArgumentException("ASN1 sequense contains unsupported element type");
                }
            }

            return new ASN1Sequence { Elements = asn1Objects };
        }

        public byte[] Encode()
        {
            if (this.Elements == null || !this.Elements.Any())
            {
                throw new NotSupportedException("Sequence is null or contains no elements");
            }

            var asn1objs = new List<Asn1Object>();
            foreach (var element in this.Elements)
            {
                if (element.GetType() == typeof(ASN1OctetString))
                {
                    asn1objs.Add(new DerOctetString(element.GetBytes()));
                }
                else if (element.GetType() == typeof(ASN1Integer))
                {
                    asn1objs.Add(new DerInteger(((ASN1Integer)element).Value));
                }
                else
                {
                    throw new NotSupportedException("Sequence contains unsupported element type");
                }
            }

            var derSequence = new DerSequence(asn1objs.ToArray());
            return derSequence.GetDerEncoded(); // .GetDerEncoded();
        }

        public int GetIntegerFromElementAt(int elementIndex)
        {
            var asn1Int = this.Elements.ElementAt(elementIndex) as ASN1Integer;
            if (asn1Int == null)
            {
                throw new ASN1Exception($"Element at index ${elementIndex} is not integer");
            }

            return asn1Int.Value;
        }

        public byte[] GetOctetStringFromElementAt(int elementIndex)
        {
            var asn1OctetString = this.Elements.ElementAt(elementIndex) as ASN1OctetString;
            if (asn1OctetString == null)
            {
                throw new ASN1Exception($"Element at index ${elementIndex} is not octet string");
            }

            return asn1OctetString.GetBytes();
        }
    }
}
