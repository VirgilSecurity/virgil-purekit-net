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
    using Org.BouncyCastle.Security;

    /// <summary>
    /// Phe crypto.
    /// </summary>
    public class PheCrypto
    {
        private X9ECParameters curveParams;
        private FpCurve curve;
        private SecureRandom rng;
        private SHA512 sha512;
        private Swu swu;

        private byte[] dhc0     = Bytes.FromString("hc0");
        private byte[] dhc1     = Bytes.FromString("hc1");
        private byte[] dm       = Bytes.FromString("dm");
        private byte[] dhs0     = Bytes.FromString("hs0");
        private byte[] dhs1     = Bytes.FromString("hs1");
        private byte[] proofOK  = Bytes.FromString("ProofOk");
        private byte[] proofErr = Bytes.FromString("ProofError");
        private byte[] kdfInfoZ = Bytes.FromString("VIRGIL_PHE_KDF_INFO_Z");
        private byte[] encrypt = Bytes.FromString("PheEncrypt");



       
        //kdfInfoClientKey = [] byte ("VIRGIL_PHE_KDF_INFO_AK")

        public PheCrypto()
        {
            this.curveParams = NistNamedCurves.GetByName("P-256");
            this.curve = (FpCurve)curveParams.Curve;
            this.rng = new SecureRandom();
            this.sha512 = new SHA512();
            this.swu = new Swu(curve.Q, curve.B.ToBigInteger());
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
            // var point   = this.curveParams.G.Multiply(randomZ);

            return new SecretKey(randomZ);
        }

        /// <summary>
        /// Decodes <see cref="SecretKey"/> from specified byte array.
        /// </summary>
        public SecretKey DecodeSecretKey(byte[] encodedSecretKey)
        {
            var secretKeyInt = new BigInteger(1, encodedSecretKey);
            var point = this.curveParams.G.Multiply(secretKeyInt);

            return new SecretKey(secretKeyInt);
        }

        public PublicKey ExtractPublicKey(SecretKey secretKey)
        {
            var point = (FpPoint)this.curveParams.G.Multiply(secretKey.Value);
            return new PublicKey(point);
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
            var t0Point  = c0Point.Add(hc0Point.Multiply(skC.Value));
            var t1Point  = c1Point.Add(hc1Point.Multiply(skC.Value).Add(mPoint.Multiply(skC.Value)));

            return new Tuple<byte[], byte[]>(t0Point.GetEncoded(), t1Point.GetEncoded());
        }

        /// <summary>
        /// Computes the c.
        /// </summary>
        public Tuple<byte[], byte[]> ComputeC(SecretKey skS, byte[] nS)
        {
            var hs0 = this.HashToPoint(dhs0, nS);
            var hs1 = this.HashToPoint(dhs1, nS);

            var c0 = hs0.Multiply(skS.Value);
            var c1 = hs1.Multiply(skS.Value);

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

            var mPoint = t1Point.Add(c1Point.Negate()).Add(hc1Point.Multiply(minusY)).Multiply(skC.Value.ModInverse(this.curveParams.N));


            var hkdf = new HkdfBytesGenerator(new Sha512tDigest(256));
            hkdf.Init(new HkdfParameters(mPoint.GetEncoded(), null, encrypt));
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
            var c0Point = t0Point.Add(hc0Point.Multiply(minusY));

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

            var t00Point = t0Point.Multiply(aInt).Add(hs0Point.Multiply(bInt));
            var t11Point = t1Point.Multiply(aInt).Add(hs1Point.Multiply(bInt));

            return new Tuple<byte[], byte[]>(t00Point.GetEncoded(), t11Point.GetEncoded());
        }

        /// <summary>
        /// Proves the success.
        /// </summary>
        public ProofOfSuccess ProveSuccess(SecretKey skS, byte[] nS, byte[] c0, byte[] c1)
        {
            var pkSPoint = this.curveParams.G.Multiply(skS.Value);

            var blindX    = this.RandomZ();
            var hs0Point  = this.HashToPoint(dhs0, nS);
            var hs1Point  = this.HashToPoint(dhs1, nS);
            var term1     = hs0Point.Multiply(blindX).GetEncoded();
            var term2     = hs1Point.Multiply(blindX).GetEncoded();
            var term3     = this.curveParams.G.Multiply(blindX).GetEncoded();
            var pubKey    = pkSPoint.GetEncoded();
            var curveG    = this.curveParams.G.Multiply(BigInteger.ValueOf(1));
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

            var curveG    = this.curveParams.G.Multiply(BigInteger.ValueOf(1));
            var challenge = this.HashZ(proofOK, pkS.Encode(), curveG.GetEncoded(), c0, c1, proof.Term1, proof.Term2, proof.Term3);

            var t1Point   = trm1Point.Add(c0Point.Multiply(challenge));
            var t2Point   = hs0Point.Multiply(blindXInt);

            if (!t1Point.Equals(t2Point)) 
            {
                return false;
            }

            t1Point = trm2Point.Add(c1Point.Multiply(challenge));
            t2Point = hs1Point.Multiply(blindXInt);

            if (!t1Point.Equals(t2Point))
            {
                return false;
            }

            t1Point = trm3Point.Add(pkS.Point.Multiply(challenge));
            t2Point = this.curveParams.G.Multiply(blindXInt);

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
            var curveG = this.curveParams.G.Multiply(BigInteger.ValueOf(1));

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

            var t1Point = term1Point.Add(term2Point).Add(c1Point.Multiply(challenge));
            var t2Point = c0Point.Multiply(blindAInt).Add(hs0Point.Multiply(blindBInt));

            if (!t1Point.Equals(t2Point)) 
            {
                return false;
            }

            t1Point = term3Point.Add(term4Point);
            t2Point = pkS.Point.Multiply(blindAInt).Add(this.curveParams.G.Multiply(blindBInt));

            if (!t1Point.Equals(t2Point))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Rotates the secret key.
        /// </summary>
        public SecretKey RotateSecretKey(SecretKey secretKey, byte[] a, byte[] b)
        {
            var aInt = new BigInteger(1, a);
            var bInt = new BigInteger(1, b);

            var newSecretKey = new SecretKey(curveParams.N.Mul(secretKey.Value, aInt));
            return newSecretKey;
        }

        /// <summary>
        /// Rotates the public key.
        /// </summary>
        public PublicKey RotatePublicKey(PublicKey publicKey, byte[] a, byte[] b)
        {
            var aInt = new BigInteger(1, a);
            var bInt = new BigInteger(1, b);

            var newPoint = (FpPoint)publicKey.Point.Multiply(aInt).Add(this.curveParams.G.Multiply(bInt));

            var newPublicKey = new PublicKey(newPoint);
            return newPublicKey;
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
            var hash = this.sha512.ComputeHash(domain, datas);

            var hkdf = new HkdfBytesGenerator(new Sha512tDigest(256));
            hkdf.Init(new HkdfParameters(hash, domain, kdfInfoZ));
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
            var hash = this.sha512.ComputeHash(domain, datas);
            var (x, y) = this.swu.HashToPoint(hash);

            var xField = this.curve.FromBigInteger(x);
            var yField = this.curve.FromBigInteger(y);

            return (FpPoint)this.curve.CreatePoint(x, y);
        }
    }
}
