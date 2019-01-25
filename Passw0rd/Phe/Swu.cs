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
    using Org.BouncyCastle.Math;

    /// <summary>
    /// Implementation of Shallue-Woestijne-Ulas algorithm
    /// </summary>
    public class Swu
    {
        private readonly BigInteger a;
        private readonly BigInteger b;
        private readonly BigInteger p;
        private readonly BigInteger p34;
        private readonly BigInteger p14;
        private readonly BigInteger mba;
        private readonly SHA512 sha512;
        public readonly int PointHashLen = 32;
        /// <summary>
        /// Initializes a new instance of the <see cref="Swu"/> class.
        /// </summary>
        public Swu(BigInteger p, BigInteger b)
        {
            this.p   = p; 
            this.b   = b; 
            this.a   = p.Neg(BigInteger.Three);
            this.mba = p.Neg(p.Div(this.b, a));
            this.p34 = p.Div(p.Sub(p, BigInteger.Three), BigInteger.ValueOf(4));
            this.p14 = p.Div(p.Add(p, BigInteger.One), BigInteger.ValueOf(4));
            this.sha512 = new SHA512();
        }

        //DataToPoint hashes data using SHA-256 and maps it to a point on curve
        public (BigInteger x, BigInteger y) DataToPoint(byte[] data)
        {
            var hash = sha512.ComputeHash(null, data);
            var hash256 = ((Span<byte>)hash).Slice(0, PointHashLen).ToArray();
            return HashToPoint(hash256);
        }

        /// <summary>
        /// Maps 32 byte hash to a point on curve.
        /// </summary>
        public (BigInteger x, BigInteger y) HashToPoint(byte[] hash)
        {
            if (hash.Length != PointHashLen) {
                throw new Exception("invalid hash length"); //todo unify exceptions
            }
            var t = new BigInteger(1, hash, 0, hash.Length);
            t = t.Mod(p);

            var tt = p.Square(t);
            var alpha = p.Neg(tt);
            var asq = p.Square(alpha);
            var asqa = p.Add(asq, alpha);
            var asqa1 = p.Add(BigInteger.One, p.Inv(asqa));

            // x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
            var x2 = p.Mul(mba, asqa1);

            // x3 = alpha * x2
            var x3 = p.Mul(alpha, x2);
            var ax2 = p.Mul(a, x2);
            var x23 = p.Cube(x2);
            var x23ax2 = p.Add(x23, ax2);

            // h2 = x2^3 + a*x2 + b
            var h2 = p.Add(x23ax2, b);
            var ax3 = p.Mul(a, x3);
            var x33 = p.Cube(x3);
            var x33ax3 = p.Add(x33, ax3);
            var h3 = p.Add(x33ax3, b);

            // tmp = h2 ^ ((p - 3) // 4)
            var tmp = p.Pow(h2, p34);
            var tmp2 = p.Square(tmp);
            var tmp2h2 = p.Mul(tmp2, h2);

            // if tmp^2 * h2 == 1:
            return tmp2h2.Equals(BigInteger.One)
                ? (x2, p.Mul(tmp, h2))
                : (x3, p.Pow(h3, p14));
        }
    
    }
}
