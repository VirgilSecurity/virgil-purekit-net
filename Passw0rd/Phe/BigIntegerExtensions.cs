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

namespace Passw0rd.Phe
{
    using Org.BouncyCastle.Math;

    internal static class BigIntegerExtensions
    {
        public static BigInteger Neg(this BigInteger bigInt, BigInteger i)
        {
            return bigInt.Subtract(i);
        }

        public static BigInteger NegBytes(this BigInteger bigInt, byte[] bytes)
        {
            return bigInt.Subtract(new BigInteger(bytes));
        }

        public static BigInteger Inv(this BigInteger bigInt, BigInteger i)
        {
            return i.ModInverse(bigInt);
        }

        public static BigInteger Mul(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            return i.Multiply(j).Mod(bigInt);
        }

        public static BigInteger Square(this BigInteger bigInt, BigInteger i)
        {
            return i.ModPow(BigInteger.Two, bigInt);
        }

        public static BigInteger Cube(this BigInteger bigInt, BigInteger i)
        {
            return i.ModPow(BigInteger.Three, bigInt);
        }

        public static BigInteger Pow(this BigInteger bigInt, BigInteger n, BigInteger e)
        {
            return n.ModPow(e, bigInt);
        }

        public static BigInteger Sub(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            var negB = i.Subtract(j);
            return negB.Mod(bigInt);
        }

        public static BigInteger Add(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            return i.Add(j).Mod(bigInt);
        }

        public static BigInteger Div(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            var invB = bigInt.Inv(j);
            return bigInt.Mul(i, invB);
        }
    }
}
