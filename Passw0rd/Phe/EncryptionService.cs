using System;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Passw0rd.Utils;

namespace Passw0rd.Phe
{
    public class EncryptionService
    {
        public static readonly int SymKeyLen = 32;
        public static readonly int SymSaltLen = 32;
        public static readonly int SymNonceLen = 12;
        public static readonly int SymTagLen = 16;

       // public byte[] Salt { get; private set; }
       // private HkdfBytesGenerator hkdf;
        private byte[] key;
        private byte[] domain;


        public EncryptionService(byte[] key)
        {
            if (key.Length != SymKeyLen)
            {
                throw new ArgumentException(String.Format("key must be exactly {0} bytes", SymKeyLen));
            }
            this.key = key;
            this.domain = Domains.Encrypt;
        }

        public byte[] Encrypt(byte[] data)
        {
            var rng = new SecureRandom();
            var salt = new byte[SymSaltLen];
            rng.NextBytes(salt);

            return EncryptWithSalt(data, salt);
        }

        public byte[] EncryptWithSalt(byte[] data, byte[] salt)
        {
            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(key, salt, domain));

            var keyNonce = new byte[SymKeyLen + SymNonceLen];
            hkdf.GenerateBytes(keyNonce, 0, keyNonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var keyNonceSlice1 = ((Span<byte>)keyNonce).Slice(0, SymKeyLen);
            var keyNonceSlice2 = ((Span<byte>)keyNonce).Slice(SymKeyLen);

            var parameters = new AeadParameters(new KeyParameter(keyNonceSlice1.ToArray()),
                                                SymTagLen * 8, keyNonceSlice2.ToArray());
            cipher.Init(true, parameters);

            var cipherText = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            return Bytes.Combine(salt, cipherText);
        }

        // Decrypt extracts 32 byte salt, derives key & nonce and decrypts ciphertext
        public byte[] Decrypt(byte[] cipherText)
        {
            if (cipherText == null)
            {
                throw new ArgumentNullException(nameof(cipherText));
            }

            if (cipherText.Length < (SymSaltLen + SymTagLen))
            {
                throw new ArgumentException("Invalid ciphertext length.");
            }

            var salt = ((Span<byte>)cipherText).Slice(0, SymSaltLen).ToArray();

            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            hkdf.Init(new HkdfParameters(key, salt, domain));

            var keyNonce = new byte[SymKeyLen + SymNonceLen];
            hkdf.GenerateBytes(keyNonce, 0, keyNonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var keyNonceSlice1 = ((Span<byte>)keyNonce).Slice(0, SymKeyLen);
            var keyNonceSlice2 = ((Span<byte>)keyNonce).Slice(SymKeyLen);

            var parameters = new AeadParameters(new KeyParameter(keyNonceSlice1.ToArray()), SymTagLen * 8, keyNonceSlice2.ToArray());
            cipher.Init(false, parameters);

            var cipherTextExceptSalt = ((Span<byte>)cipherText).Slice(SymSaltLen).ToArray();
            var plainText = new byte[cipher.GetOutputSize(cipherTextExceptSalt.Length)];

            var len = cipher.ProcessBytes(cipherTextExceptSalt, 0, cipherTextExceptSalt.Length, plainText, 0);
            cipher.DoFinal(plainText, len);

            return plainText;
        }

    }
}
