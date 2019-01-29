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

[assembly: System.Runtime.CompilerServices.InternalsVisibleToAttribute("Passw0rd.Tests")]

namespace Passw0rd.Phe
{
    using System;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Math.EC;
    using Google.Protobuf;

    /// <summary>
    /// Phe crypto.
    /// </summary>
    public class PheCrypto
    {
        private X9ECParameters curveParams;
        internal FpCurve Curve { get; private set; }
        internal ECPoint CurveG { get; private set; }
        internal PheRandomGenerator Rng{ get; set; }
       
        private SHA512 sha512;
        private Swu swu;
        private const int pheClientKeyLen = 32;
        private const int pheNonceLen = 32;
        private const int zLen = 32;
        public PheCrypto()
        {
            this.curveParams = NistNamedCurves.GetByName("P-256");
            this.Curve = (FpCurve)curveParams.Curve;
            this.CurveG = this.curveParams.G.Multiply(BigInteger.ValueOf(1));
            this.Rng = new PheRandomGenerator(); 
            this.sha512 = new SHA512();
            this.swu = new Swu(Curve.Q, Curve.B.ToBigInteger());
        }

        /// <summary>
        /// Generates a random default length nonce.
        /// </summary>
        public byte[] GenerateNonce()
        {
            return GenerateNonce(pheNonceLen);
        }

        /// <summary>
        /// Generates a random nonce.
        /// </summary>
        private byte[] GenerateNonce(int length)
        {
            return Rng.GenerateNonce(length);
        }

        /// <summary>
        /// Generates a new random secret key.
        /// </summary>
        public SecretKey GenerateSecretKey()
        {
            var randomZ = this.RandomZ();
            return new SecretKey(randomZ);
        }

        /// <summary>
        /// Decodes <see cref="SecretKey"/> from specified byte array.
        /// </summary>
        public SecretKey DecodeSecretKey(byte[] encodedSecretKey)
        {
            Validation.NotNullOrEmptyByteArray(encodedSecretKey);

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
            Validation.NotNullOrEmptyByteArray(encodedPublicKey);

            var point = (FpPoint)this.Curve.DecodePoint(encodedPublicKey);
            return new PublicKey(point);
        }

        /// <summary>
        /// Computes the record T for specified password.
        /// </summary>
        internal (byte[], byte[], byte[]) ComputeT(SecretKey skC, byte[] pwd, byte[] nC, byte[] c0, byte[] c1)
        {
            Validation.NotNull(skC);
            Validation.NotNullOrEmptyByteArray(pwd);
            Validation.NotNullOrEmptyByteArray(nC);
            Validation.NotNullOrEmptyByteArray(c0);
            Validation.NotNullOrEmptyByteArray(c1);

            var c0Point  = this.Curve.DecodePoint(c0);
            var c1Point  = this.Curve.DecodePoint(c1);

            var mPoint   = this.HashToPoint(GenerateNonce(swu.PointHashLen));
            var hc0Point = this.HashToPoint(Domains.Dhc0, nC, pwd);
            var hc1Point = this.HashToPoint(Domains.Dhc1, nC, pwd);

            // encryption key in a form of a random point
            var hkdf = InitHkdf(mPoint.GetEncoded(), null, Domains.KdfInfoClientKey);
            var key = new byte[pheClientKeyLen];
            hkdf.GenerateBytes(key, 0, key.Length);

            var t0Point  = c0Point.Add(hc0Point.Multiply(skC.Value));
            var t1Point  = c1Point.Add(hc1Point.Multiply(skC.Value).Add(mPoint.Multiply(skC.Value)));

            return (t0Point.GetEncoded(), t1Point.GetEncoded(), key);
        }

        /// <summary>
        /// Computes the c.
        /// </summary>
        internal Tuple<byte[], byte[]> ComputeC(SecretKey skS, byte[] nS)
        {
            Validation.NotNull(skS);
            Validation.NotNullOrEmptyByteArray(nS);

            var hs0 = this.HashToPoint(Domains.Dhs0, nS);
            var hs1 = this.HashToPoint(Domains.Dhs1, nS);

            var c0 = hs0.Multiply(skS.Value);
            var c1 = hs1.Multiply(skS.Value);

            return new Tuple<byte[], byte[]>(c0.GetEncoded(), c1.GetEncoded());
        }

        /// <summary>
        /// Decrypts the M value for specified password.
        /// </summary>
        internal byte[] DecryptM(SecretKey skC, byte[] pwd, byte[] nC, byte[] t1, byte[] c1)
        {
            Validation.NotNull(skC);
            Validation.NotNullOrEmptyByteArray(pwd);
            Validation.NotNullOrEmptyByteArray(nC);
            Validation.NotNullOrEmptyByteArray(t1);
            Validation.NotNullOrEmptyByteArray(c1);

            var t1Point  = this.Curve.DecodePoint(t1);
            var c1Point  = this.Curve.DecodePoint(c1);
            var hc1Point = this.HashToPoint(Domains.Dhc1, nC, pwd);
            var minusY   = this.curveParams.N.Neg(skC.Value);

            var mPoint = t1Point.Add(c1Point.Negate()).Add(hc1Point.Multiply(minusY)).Multiply(skC.Value.ModInverse(this.curveParams.N));

            var hkdf = InitHkdf(mPoint.GetEncoded(), null, Domains.KdfInfoClientKey);
            var key = new byte[pheClientKeyLen];
            hkdf.GenerateBytes(key, 0, key.Length);

            return key;
        }

        /// <summary>
        /// Encrypt the specified data using the specified key.
        /// Encrypt generates 32 byte salt, uses master key 
        /// & salt to generate per-data key & nonce with the help of HKDF
        /// Salt is concatenated to the ciphertext
        /// </summary>
        /// <returns>The encrypted data bytes.</returns>
        /// <param name="data">Data to be encrypted.</param>
        /// <param name="key">Key to be used for encryption.</param>
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            Validation.NotNull(data);
            Validation.NotNullOrEmptyByteArray(key);
           
            var encryptionService = new EncryptionService(key);
            return encryptionService.Encrypt(data);
        }

        private HkdfBytesGenerator InitHkdf(byte[] key, byte[] salt, byte[] info)
        {
            Validation.NotNullOrEmptyByteArray(key);
            Validation.NotNullOrEmptyByteArray(info);

            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(key, salt, info));
            return hkdf;
        }

        /// <summary>
        /// Decrypt the specified cipherText using the specified key.
        /// Decrypt extracts 32 byte salt, derives key & nonce and decrypts
        /// ciphertext with the help of HKDF 
        /// </summary>
        /// <returns>The decrypted data bytes.</returns>
        /// <param name="cipherText">Encrypted data to be decrypted.</param>
        /// <param name="key">Key to be used for decryption.</param>
        public byte[] Decrypt(byte[] cipherText, byte[] key)
        {
            Validation.NotNullOrEmptyByteArray(cipherText);
            Validation.NotNullOrEmptyByteArray(key);

            var encryptionService = new EncryptionService(key);
            return encryptionService.Decrypt(cipherText);
        }

        /// <summary>
        /// Computes the c0 point for specified T record and password.
        /// </summary>
        public byte[] ComputeC0(SecretKey skC, byte[] pwd, byte[] nc, byte[] t0)
        {
            Validation.NotNull(skC);
            Validation.NotNullOrEmptyByteArray(pwd);
            Validation.NotNullOrEmptyByteArray(nc);
            Validation.NotNullOrEmptyByteArray(t0);

            var hc0Point = this.HashToPoint(Domains.Dhc0, nc, pwd);
            var minusY = skC.Value.Negate();

            var t0Point = this.Curve.DecodePoint(t0);
            var c0Point = t0Point.Add(hc0Point.Multiply(minusY));

            return c0Point.GetEncoded();
        }

        /// <summary>
        /// Updates an encryption record T with the specified update token parameters.
        /// </summary>
        internal Tuple<byte[], byte[]> UpdateT(byte[] nS, byte[] t0, byte[] t1, byte[] tokenBytes)
        {
            Validation.NotNullOrEmptyByteArray(nS);
            Validation.NotNullOrEmptyByteArray(t0);
            Validation.NotNullOrEmptyByteArray(t1);
            Validation.NotNullOrEmptyByteArray(tokenBytes);

            var token = UpdateToken.Parser.ParseFrom(tokenBytes);

            var hs0Point = this.HashToPoint(Domains.Dhs0, nS);
            var hs1Point = this.HashToPoint(Domains.Dhs1, nS);

            var t0Point = this.Curve.DecodePoint(t0);
            var t1Point = this.Curve.DecodePoint(t1);

            var aInt = new BigInteger(1, token.A.ToByteArray());
            var bInt = new BigInteger(1, token.B.ToByteArray());

            var t00Point = t0Point.Multiply(aInt).Add(hs0Point.Multiply(bInt));
            var t11Point = t1Point.Multiply(aInt).Add(hs1Point.Multiply(bInt));

            return new Tuple<byte[], byte[]>(t00Point.GetEncoded(), t11Point.GetEncoded());
        }

        /// <summary>
        /// Proves the success.
        /// </summary>
        internal ProofOfSuccess ProveSuccess(SecretKey skS, byte[] nS, byte[] c0, byte[] c1)
        {
            Validation.NotNull(skS);
            Validation.NotNullOrEmptyByteArray(nS);
            Validation.NotNullOrEmptyByteArray(c0);
            Validation.NotNullOrEmptyByteArray(c1);

            var pkSPoint = this.curveParams.G.Multiply(skS.Value);

            var blindX    = this.RandomZ();
            var hs0Point  = this.HashToPoint(Domains.Dhs0, nS);
            var hs1Point  = this.HashToPoint(Domains.Dhs1, nS);
            var term1     = hs0Point.Multiply(blindX).GetEncoded();
            var term2     = hs1Point.Multiply(blindX).GetEncoded();
            var term3     = this.curveParams.G.Multiply(blindX).GetEncoded();
            var pubKey    = pkSPoint.GetEncoded();
            var challenge = this.HashZ(Domains.ProofOK, pubKey, CurveG.GetEncoded(), c0, c1, term1, term2, term3);

            var result    = blindX.Add(skS.Value.Multiply(challenge)).ToByteArray();

            return new ProofOfSuccess 
            {
                Term1 = ByteString.CopyFrom(term1), 
                Term2 = ByteString.CopyFrom(term2), 
                Term3 = ByteString.CopyFrom(term3),
                BlindX = ByteString.CopyFrom(result)
            };
        }

        /// <summary>
        /// Validates the proof of success.
        /// </summary>
        internal bool ValidateProofOfSuccess(ProofOfSuccess proof, PublicKey pkS, byte[] nS, byte[] c0, byte[] c1)
        {
            Validation.NotNull(proof);
            Validation.NotNull(pkS);
            Validation.NotNullOrEmptyByteArray(nS);
            Validation.NotNullOrEmptyByteArray(c0);
            Validation.NotNullOrEmptyByteArray(c1);

            var term1 = proof.Term1.ToByteArray();
            var term2 = proof.Term2.ToByteArray();
            var term3 = proof.Term3.ToByteArray();
            var trm1Point = this.Curve.DecodePoint(term1);
            var trm2Point = this.Curve.DecodePoint(term2);
            var trm3Point = this.Curve.DecodePoint(term3);
            var blindXInt = new BigInteger(1, proof.BlindX.ToByteArray());

            var c0Point   = this.Curve.DecodePoint(c0);
            var c1Point   = this.Curve.DecodePoint(c1);

            var hs0Point  = this.HashToPoint(Domains.Dhs0, nS);
            var hs1Point  = this.HashToPoint(Domains.Dhs1, nS);

            var challenge = this.HashZ(Domains.ProofOK, 
                                       pkS.Encode(), 
                                       CurveG.GetEncoded(), 
                                       c0, 
                                       c1, 
                                       term1,
                                       term2, 
                                       term3);

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
        internal bool ValidateProofOfFail(ProofOfFail proof, PublicKey pkS,  byte[] nS, byte[] c0, byte[] c1)
        {
            Validation.NotNull(proof);
            Validation.NotNull(pkS);
            Validation.NotNullOrEmptyByteArray(nS);
            Validation.NotNullOrEmptyByteArray(c0);
            Validation.NotNullOrEmptyByteArray(c1);

            var term1 = proof.Term1.ToByteArray();
            var term2 = proof.Term2.ToByteArray();
            var term3 = proof.Term3.ToByteArray();
            var term4 = proof.Term4.ToByteArray();

            var challenge = this.HashZ(Domains.ProofErr, 
                                       pkS.Encode(),
                                       CurveG.GetEncoded(), 
                                       c0, c1,
                                       term1, term2, term3, term4);

            var hs0Point = this.HashToPoint(Domains.Dhs0, nS);

            var term1Point = this.Curve.DecodePoint(term1);
            var term2Point = this.Curve.DecodePoint(term2);
            var term3Point = this.Curve.DecodePoint(term3);
            var term4Point = this.Curve.DecodePoint(term4);

            var blindAInt = new BigInteger(1, proof.BlindA.ToByteArray());
            var blindBInt = new BigInteger(1, proof.BlindB.ToByteArray());

            var c0Point = this.Curve.DecodePoint(c0);
            var c1Point = this.Curve.DecodePoint(c1);

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
        public SecretKey RotateSecretKey(SecretKey secretKey, byte[] tokenBytes)
        {
            Validation.NotNull(secretKey);
            Validation.NotNullOrEmptyByteArray(tokenBytes);

            var token = UpdateToken.Parser.ParseFrom(tokenBytes);

            var aInt = new BigInteger(1, token.A.ToByteArray());
            var bInt = new BigInteger(1, token.B.ToByteArray());

            var newSecretKey = new SecretKey(curveParams.N.Mul(secretKey.Value, aInt));
            return newSecretKey;
        }

        /// <summary>
        /// Rotates the public key.
        /// </summary>
        public PublicKey RotatePublicKey(PublicKey publicKey, byte[] tokenBytes)
        {
            Validation.NotNull(publicKey);
            Validation.NotNullOrEmptyByteArray(tokenBytes);

            var token = UpdateToken.Parser.ParseFrom(tokenBytes);

            var aInt = new BigInteger(1, token.A.ToByteArray());
            var bInt = new BigInteger(1, token.B.ToByteArray());

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
            do
            {
                z = new BigInteger(1, GenerateNonce(zLen));
            }
            while (z.CompareTo(this.curveParams.N) >= 0);

            return z;
        }

        /// <summary>
        /// Maps arrays of bytes to an integer less than curve's N parameter
        /// </summary>
        internal BigInteger HashZ(byte[] domain, params byte[][] datas)
        {
            Validation.NotNullOrEmptyByteArray(domain);
            Validation.NotNullOrEmptyByteArray(datas);

            var key = this.sha512.ComputeHash(null, datas);

            var hkdf = InitHkdf(key, domain, Domains.KdfInfoZ);
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
        internal FpPoint HashToPoint(byte[] domain, params byte[][] datas)
        {
            var hash = this.sha512.ComputeHash(domain, datas);
            var hash256 = ((Span<byte>)hash).Slice(0, this.swu.PointHashLen).ToArray();

            var (x, y) = this.swu.HashToPoint(hash256);

            var xField = this.Curve.FromBigInteger(x);
            var yField = this.Curve.FromBigInteger(y); 

            return (FpPoint)this.Curve.CreatePoint(x, y);
        }

        internal int NonceLength(){
            return pheNonceLen;
        }
    }
}
