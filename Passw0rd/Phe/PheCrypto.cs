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
[assembly: System.Runtime.CompilerServices.InternalsVisibleToAttribute("Passw0rd.Tests")]

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
    using global::Phe;
    using Google.Protobuf;
    using Org.BouncyCastle.Crypto.Modes;
    using Org.BouncyCastle.Crypto.Engines;

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
        private byte[] commonPrefix = new byte[]{0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45}; //VRGLPHE
        private byte[] dhc0;
        private byte[] dhc1;
        private byte[] dhs0;
        private byte[] dhs1;
        private byte[] proofOK;
        private byte[] proofErr;
        private byte[] kdfInfoZ ;
        private byte[] encrypt;
        private byte[] kdfInfoClientKey;


        private const int symKeyLen = 32;
        private const int symSaltLen = 32;
        private const int symNonceLen = 12;
        private const int symTagLen = 16;
        private const int pheClientKeyLen = 32;
        private const int pheNonceLen = 32;
        public PheCrypto()
        {
            this.dhc0 = Bytes.Combine(commonPrefix, new byte[] { 0x31 });
            this.dhc1 = Bytes.Combine(commonPrefix, new byte[] { 0x32 });
            this.dhs0 = Bytes.Combine(commonPrefix, new byte[] { 0x33 });
            this.dhs1 = Bytes.Combine(commonPrefix, new byte[] { 0x34 });
            this.proofOK = Bytes.Combine(commonPrefix, new byte[] { 0x35 });
            this.proofErr = Bytes.Combine(commonPrefix, new byte[] { 0x36 });
            this.encrypt = Bytes.Combine(commonPrefix, new byte[] { 0x37 });
            this.kdfInfoZ = Bytes.Combine(commonPrefix, new byte[] { 0x38 });
            this.kdfInfoClientKey = Bytes.Combine(commonPrefix, new byte[] { 0x39 });

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
            var nonce = new byte[pheNonceLen];
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
        public (byte[], byte[], byte[]) ComputeT(SecretKey skC, byte[] pwd, byte[] nC, byte[] c0, byte[] c1)
        {
            // TODO: validation, doc
            var c0Point  = this.curve.DecodePoint(c0);
            var c1Point  = this.curve.DecodePoint(c1);

            //todo ==swu.PointHashLen
            var mbuf = new byte[32];
            this.rng.NextBytes(mbuf);

            var mPoint   = this.HashToPoint(mbuf);
            var hc0Point = this.HashToPoint(dhc0, nC, pwd);
            var hc1Point = this.HashToPoint(dhc1, nC, pwd);

            var hkdf = InitHkdf(mPoint.GetEncoded(), null, kdfInfoClientKey);
            var key = new byte[pheClientKeyLen];
            hkdf.GenerateBytes(key, 0, key.Length);


            var t0Point  = c0Point.Add(hc0Point.Multiply(skC.Value));
            var t1Point  = c1Point.Add(hc1Point.Multiply(skC.Value).Add(mPoint.Multiply(skC.Value)));

            return (t0Point.GetEncoded(), t1Point.GetEncoded(), key);
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

            var hkdf = InitHkdf(mPoint.GetEncoded(), null, kdfInfoClientKey);
            var key = new byte[pheClientKeyLen];
            hkdf.GenerateBytes(key, 0, key.Length);

            return key;
        }

        // Encrypt generates 32 byte salt, uses master key & salt to generate per-data key & nonce with the help of HKDF
        // Salt is concatenated to the ciphertext
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            if (key.Length != symKeyLen)
            {
                throw new Exception(String.Format("key must be exactly {0} bytes", symKeyLen)); //todo
            }
            var salt = new byte[symSaltLen];
            this.rng.NextBytes(salt);

            var hkdf = InitHkdf(key, salt, encrypt);

            var keyNonce = new byte[symKeyLen + symNonceLen];
            hkdf.GenerateBytes(keyNonce, 0, keyNonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var keyNonceSlice1 = ((Span<byte>)keyNonce).Slice(0, symKeyLen);
            var keyNonceSlice2 = ((Span<byte>)keyNonce).Slice(symKeyLen);

            var parameters = new AeadParameters(new KeyParameter(keyNonceSlice1.ToArray()), symTagLen * 8, keyNonceSlice2.ToArray());
            cipher.Init(true, parameters);

            var cipherText = new byte[] { };
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            return Bytes.Combine(salt, cipherText);
        }

        private HkdfBytesGenerator InitHkdf(byte[] key, byte[] salt, byte[] info)
        {
            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(key, salt, info));
            return hkdf;
        }

        // Decrypt extracts 32 byte salt, derives key & nonce and decrypts ciphertext
        public byte[] Decrypt(byte[] cipherText, byte[] key)
        {
            if (key.Length != symKeyLen)
            {
                throw new Exception(String.Format("key must be exactly {0} bytes", symKeyLen)); //todo
            }

            if (cipherText.Length < (symSaltLen + symTagLen))
            {
                throw new Exception(String.Format("key must be exactly {0} bytes", symKeyLen)); //todo
            }

            var salt = ((Span<byte>)cipherText).Slice(0, symSaltLen).ToArray();

            var hkdf = InitHkdf(key, salt, encrypt);

            var keyNonce = new byte[symKeyLen + symNonceLen];
            hkdf.GenerateBytes(keyNonce, 0, keyNonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var keyNonceSlice1 = ((Span<byte>)keyNonce).Slice(0, symKeyLen);
            var keyNonceSlice2 = ((Span<byte>)keyNonce).Slice(symKeyLen);

            var parameters = new AeadParameters(new KeyParameter(keyNonceSlice1.ToArray()), symTagLen * 8, keyNonceSlice2.ToArray());
            cipher.Init(false, parameters);

            var data = new byte[] { };
            var cipherTextExceptSalt = ((Span<byte>)cipherText).Slice(symSaltLen).ToArray();
            var len = cipher.ProcessBytes(cipherTextExceptSalt, 0, cipherTextExceptSalt.Length, data, 0);
            cipher.DoFinal(cipherText, len);

            return Bytes.Combine(salt, cipherText);
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
        public Tuple<byte[], byte[]> UpdateT(byte[] nS, byte[] t0, byte[] t1, byte[] tokenBytes)
        {
            var token = UpdateToken.Parser.ParseFrom(tokenBytes);

            var hs0Point = this.HashToPoint(dhs0, nS);
            var hs1Point = this.HashToPoint(dhs1, nS);

            var t0Point = this.curve.DecodePoint(t0);
            var t1Point = this.curve.DecodePoint(t1);

            var aInt = new BigInteger(1, token.A.ToByteArray());
            var bInt = new BigInteger(1, token.B.ToByteArray());

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
                Term1 = ByteString.CopyFrom(term1), 
                Term2 = ByteString.CopyFrom(term2), 
                Term3 = ByteString.CopyFrom(term3),
                BlindX = ByteString.CopyFrom(result)
            };
        }

        /// <summary>
        /// Validates the proof of success.
        /// </summary>
        public bool ValidateProofOfSuccess(ProofOfSuccess proof, PublicKey pkS, byte[] nS, byte[] c0, byte[] c1)
        {
            var term1 = proof.Term1.ToByteArray();
            var term2 = proof.Term2.ToByteArray();
            var term3 = proof.Term3.ToByteArray();
            var trm1Point = this.curve.DecodePoint(term1);
            var trm2Point = this.curve.DecodePoint(term2);
            var trm3Point = this.curve.DecodePoint(term3);
            var blindXInt = new BigInteger(1, proof.BlindX.ToByteArray());

            var c0Point   = this.curve.DecodePoint(c0);
            var c1Point   = this.curve.DecodePoint(c1);

            var hs0Point  = this.HashToPoint(dhs0, nS);
            var hs1Point  = this.HashToPoint(dhs1, nS);

            var curveG    = this.curveParams.G.Multiply(BigInteger.ValueOf(1));
            var challenge = this.HashZ(proofOK, 
                                       pkS.Encode(), 
                                       curveG.GetEncoded(), 
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
        public bool ValidateProofOfFail(ProofOfFail proof, PublicKey pkS,  byte[] nS, byte[] c0, byte[] c1)
        {
            var term1 = proof.Term1.ToByteArray();
            var term2 = proof.Term2.ToByteArray();
            var term3 = proof.Term3.ToByteArray();
            var term4 = proof.Term4.ToByteArray();

            var curveG = this.curveParams.G.Multiply(BigInteger.ValueOf(1));

            var challenge = this.HashZ(this.proofErr, 
                                       pkS.Encode(),
                                       curveG.GetEncoded(), 
                                       c0, c1,
                                       term1, term2, term3, term4);

            var hs0Point = this.HashToPoint(dhs0, nS);

            var term1Point = this.curve.DecodePoint(term1);
            var term2Point = this.curve.DecodePoint(term2);
            var term3Point = this.curve.DecodePoint(term3);
            var term4Point = this.curve.DecodePoint(term4);

            var blindAInt = new BigInteger(1, proof.BlindA.ToByteArray());
            var blindBInt = new BigInteger(1, proof.BlindB.ToByteArray());

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
        public SecretKey RotateSecretKey(SecretKey secretKey, byte[] tokenBytes)
        {
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

            var hkdf = InitHkdf(hash, domain, kdfInfoZ);
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

        internal byte[] KdfInfoZ(){
            return kdfInfoZ;
        }

      
    }
}
