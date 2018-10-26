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
    using System.Text;

    using Passw0rd.Utils;

    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Math.EC;
    using Org.BouncyCastle.Math.EC.Multiplier;
    using Org.BouncyCastle.Security;

    /// <summary>
    /// Phe crypto.
    /// </summary>
    public class PheCrypto
    {
        private X9ECParameters curveParams;
        private FpCurve curve;
        private SecureRandom rng;
        private TupleHash tupleHash;
        private Swu swu;
        private MixedNafR2LMultiplier multiplier;

        private byte[] dhc0 = Encoding.UTF8.GetBytes("hc0");
        private byte[] dhc1 = Encoding.UTF8.GetBytes("hc1");
        private byte[] dm   = Encoding.UTF8.GetBytes("dm");
        private byte[] dhs0 = Encoding.UTF8.GetBytes("hs0");
        private byte[] dhs1 = Encoding.UTF8.GetBytes("hs1");
        private byte[] proofOK = Bytes.FromString("ProofOk");
        private byte[] proofErr = Bytes.FromString("ProofError");

        public PheCrypto()
        {
            this.curveParams = NistNamedCurves.GetByName("P-256");
            this.curve = (FpCurve)curveParams.Curve;
            this.rng = new SecureRandom();
            this.tupleHash = new TupleHash();
            this.swu = new Swu(curve.Q, curve.B.ToBigInteger()); ;
            this.multiplier = new MixedNafR2LMultiplier();
        }

        /// <summary>
        /// Generates a random nonce.
        /// </summary>
        public byte[] GenerateNonce()
        {
            var nonce = new byte[32];
            this.rng.NextBytes(nonce);

            return nonce;
        }

        /// <summary>
        /// Generates a new random secret key.
        /// </summary>
        public SecretKey GenerateSecretKey()
        {
            var randomZ = this.RandomZ();
            var point   = this.multiplier.Multiply(this.curveParams.G, randomZ);

            return new SecretKey(randomZ, (FpPoint)point);
        }

        /// <summary>
        /// Decodes <see cref="SecretKey"/> from specified byte array.
        /// </summary>
        public SecretKey DecodeSecretKey(byte[] encodedSecretKey)
        {
            var secretKeyInt = new BigInteger(1, encodedSecretKey);

            Console.WriteLine(secretKeyInt);
            var point = this.multiplier.Multiply(this.curveParams.G, secretKeyInt);

            return new SecretKey(secretKeyInt, (FpPoint)point);
        }

        /// <summary>
        /// Decodes <see cref="PublicKey"/> from specified byte array.
        /// </summary>
        public PublicKey DecodePublicKey(byte[] encodedPublicKey)
        {
            var point = (FpPoint)this.curve.DecodePoint(encodedPublicKey);
            return new PublicKey(point);
        }

        /// <summary>
        /// Computes the record T for specified password.
        /// </summary>
        public Tuple<byte[], byte[]> ComputeT(SecretKey skC, byte[] pwd, byte[] nC, byte[] c0, byte[] c1)
        {
            // TODO: validation
            var c0Point  = this.curve.DecodePoint(c0);
            var c1Point  = this.curve.DecodePoint(c1);

            var mbuf = new byte[32];
            this.rng.NextBytes(mbuf);

            var mPoint   = this.HashToPoint(dm, mbuf);
            var hc0Point = this.HashToPoint(dhc0, nC, pwd);
            var hc1Point = this.HashToPoint(dhc1, nC, pwd);
            var t0Point  = c0Point.Add(this.multiplier.Multiply(hc0Point, skC.Value));
            var t1Point  = c1Point.Add(this.multiplier.Multiply(hc1Point, skC.Value)
                .Add(this.multiplier.Multiply(mPoint, skC.Value)));

            return new Tuple<byte[], byte[]>(t0Point.GetEncoded(), t1Point.GetEncoded());
        }

        /// <summary>
        /// Computes the c.
        /// </summary>
        public Tuple<byte[], byte[]> ComputeC(SecretKey skS, byte[] nS)
        {
            var hs0 = this.HashToPoint(dhs0, nS);
            var hs1 = this.HashToPoint(dhs1, nS);

            var c0 = this.multiplier.Multiply(hs0, skS.Value);
            var c1 = this.multiplier.Multiply(hs1, skS.Value);

            return new Tuple<byte[], byte[]>(c0.GetEncoded(), c1.GetEncoded());
        }

        /// <summary>
        /// Decrypts the M value for specified password.
        /// </summary>
        public byte[] DecryptM(SecretKey skC, byte[] pwd, byte[] nC, byte[] t1, byte[] c1)
        {
            var t1Point  = this.curve.DecodePoint(t1);
            var c1Point  = this.curve.DecodePoint(c1);
            var hc1Point = this.HashToPoint(dhc1, nC, pwd);
            var minusY   = this.curveParams.N.Neg(skC.Value);

            var mPoint = this.multiplier.Multiply(t1Point.Add(c1Point.Negate())
                .Add(this.multiplier.Multiply(hc1Point, minusY)), skC.Value.ModInverse(this.curveParams.N));

            var hkdf = new HkdfBytesGenerator(new Sha512tDigest(256));
            hkdf.Init(new HkdfParameters(mPoint.GetEncoded(), null, Encoding.UTF8.GetBytes("Secret")));
            var key = new byte[32];
            hkdf.GenerateBytes(key, 0, key.Length);

            return key;
        }

        /// <summary>
        /// Computes the c0 point for specified T record and password.
        /// </summary>
        public byte[] ComputeC0(SecretKey skC, byte[] pwd, byte[] nc, byte[] t0)
        {
            var hc0Point = this.HashToPoint(dhc0, nc, pwd);
            var minusY = skC.Value.Negate();

            var t0Point = this.curve.DecodePoint(t0);
            var c0Point = t0Point.Add(this.multiplier.Multiply(hc0Point, minusY));

            return c0Point.GetEncoded();
        }

        /// <summary>
        /// Updates an encryption record T with the specified update token parameters.
        /// </summary>
        public Tuple<byte[], byte[]> UpdateT(byte[] nS, byte[] t0, byte[] t1, byte[] a, byte[] b)
        {
            var hs0Point = this.HashToPoint(dhs0, nS);
            var hs1Point = this.HashToPoint(dhs1, nS);

            var t0Point = this.curve.DecodePoint(t0);
            var t1Point = this.curve.DecodePoint(t1);

            var aInt = new BigInteger(1, a);
            var bInt = new BigInteger(1, b);

            var t00Point = this.multiplier.Multiply(t0Point, aInt).Add(this.multiplier.Multiply(hs0Point, bInt));
            var t11Point = this.multiplier.Multiply(t1Point, aInt).Add(this.multiplier.Multiply(hs1Point, bInt));

            return new Tuple<byte[], byte[]>(t00Point.GetEncoded(), t11Point.GetEncoded());
        }

        /// <summary>
        /// Proves the success.
        /// </summary>
        public ProofOfSuccess ProveSuccess(SecretKey skS, byte[] nS, byte[] c0, byte[] c1)
        {
            var blindX    = this.RandomZ();
            var hs0Point  = this.HashToPoint(dhs0, nS);
            var hs1Point  = this.HashToPoint(dhs1, nS);
            var term1     = this.multiplier.Multiply(hs0Point, blindX).GetEncoded();
            var term2     = this.multiplier.Multiply(hs1Point, blindX).GetEncoded();
            var term3     = this.multiplier.Multiply(this.curveParams.G, blindX).GetEncoded();
            var pubKey    = skS.PublicKey.Encode();
            var curveG    = this.multiplier.Multiply(this.curveParams.G, BigInteger.ValueOf(1));
            var challenge = this.HashZ(proofOK, pubKey, curveG.GetEncoded(), c0, c1, term1, term2, term3);

            var result    = blindX.Add(skS.Value.Multiply(challenge)).ToByteArray();

            return new ProofOfSuccess 
            {
                Term1 = term1, 
                Term2 = term2, 
                Term3 = term3,
                BlindX = result
            };
        }

        /// <summary>
        /// Validates the proof of success.
        /// </summary>
        public bool ValidateProofOfSuccess(ProofOfSuccess proof, PublicKey pkS, byte[] nS, byte[] c0, byte[] c1)
        {
            var trm1Point = this.curve.DecodePoint(proof.Term1);
            var trm2Point = this.curve.DecodePoint(proof.Term2);
            var trm3Point = this.curve.DecodePoint(proof.Term3);
            var blindXInt = new BigInteger(1, proof.BlindX);

            var c0Point   = this.curve.DecodePoint(c0);
            var c1Point   = this.curve.DecodePoint(c1);

            var hs0Point  = this.HashToPoint(dhs0, nS);
            var hs1Point  = this.HashToPoint(dhs1, nS);

            var curveG    = this.multiplier.Multiply(this.curveParams.G, BigInteger.ValueOf(1));
            var challenge = this.HashZ(proofOK, pkS.Encode(), curveG.GetEncoded(), c0, c1, proof.Term1, proof.Term2, proof.Term3);

            var t1Point   = trm1Point.Add(this.multiplier.Multiply(c0Point, challenge));
            var t2Point   = this.multiplier.Multiply(hs0Point, blindXInt);

            if (!t1Point.Equals(t2Point)) 
            {
                return false;
            }

            t1Point = trm2Point.Add(this.multiplier.Multiply(c1Point, challenge));
            t2Point = this.multiplier.Multiply(hs1Point, blindXInt);

            if (!t1Point.Equals(t2Point))
            {
                return false;
            }

            t1Point = trm3Point.Add(this.multiplier.Multiply(pkS.Point, challenge));
            t2Point = this.multiplier.Multiply(this.curveParams.G, blindXInt);

            if (!t1Point.Equals(t2Point))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates the proof of fail.
        /// </summary>
        public bool ValidateProofOfFail(ProofOfFail proof, PublicKey pkS,  byte[] nS, byte[] c0, byte[] c1)
        {
            var curveG = this.multiplier.Multiply(this.curveParams.G, BigInteger.ValueOf(1));

            var challenge = this.HashZ(this.proofErr, pkS.Encode(), curveG.GetEncoded(), c0, c1,
                proof.Term1, proof.Term2, proof.Term3, proof.Term4);

            var hs0Point = this.HashToPoint(dhs0, nS);

            var term1Point = this.curve.DecodePoint(proof.Term1);
            var term2Point = this.curve.DecodePoint(proof.Term2);
            var term3Point = this.curve.DecodePoint(proof.Term3);
            var term4Point = this.curve.DecodePoint(proof.Term4);

            var blindAInt = new BigInteger(1, proof.BlindA);
            var blindBInt = new BigInteger(1, proof.BlindB);

            var c0Point = this.curve.DecodePoint(c0);
            var c1Point = this.curve.DecodePoint(c1);

            var t1Point = term1Point.Add(term2Point).Add(this.multiplier.Multiply(c1Point, challenge));
            var t2Point = this.multiplier.Multiply(c0Point, blindAInt).Add(this.multiplier.Multiply(hs0Point, blindBInt));

            if (!t1Point.Equals(t2Point)) 
            {
                return false;
            }

            t1Point = term3Point.Add(term4Point);
            t2Point = this.multiplier.Multiply(pkS.Point, blindAInt)
                          .Add(this.multiplier.Multiply(this.curveParams.G, blindBInt));

            if (!t1Point.Equals(t2Point))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Generates big random 256 bit integer which must be less than 
        /// curve's N parameter.
        /// </summary>
        private BigInteger RandomZ()
        {
            BigInteger z;
            byte[] zBytes = new byte[32];

            do
            {
                this.rng.NextBytes(zBytes);
                z = new BigInteger(1, zBytes);
            }
            while (z.CompareTo(this.curveParams.N) >= 0);

            return z;
        }

        /// <summary>
        /// Maps arrays of bytes to an integer less than curve's N parameter
        /// </summary>
        private BigInteger HashZ(byte[] domain, params byte[][] datas)
        {
            var hash = this.tupleHash.Sum(domain, datas);

            Console.WriteLine("Th  : " + Bytes.ToString(hash, StringEncoding.BASE64));

            var hkdf = new HkdfBytesGenerator(new Sha512tDigest(256));
            hkdf.Init(new HkdfParameters(hash, domain, Encoding.UTF8.GetBytes("TupleKDF")));
            var result = new byte[32];

            BigInteger z;

            do
            {
                hkdf.GenerateBytes(result, 0, result.Length);
                z = new BigInteger(1, result);
            }
            while (z.CompareTo(this.curveParams.N) >= 0);

            return z;
        }

        /// <summary>
        /// Maps arrays of bytes to a valid curve point.
        /// </summary>
        private FpPoint HashToPoint(byte[] domain, params byte[][] datas)
        {
            var hash   = this.tupleHash.Sum(domain, datas);
            var (x, y) = this.swu.HashToPoint(hash);

            var xField = this.curve.FromBigInteger(x);
            var yField = this.curve.FromBigInteger(y);

            return (FpPoint)this.curve.CreatePoint(x, y);
        }
    }
}
