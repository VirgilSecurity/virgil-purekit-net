namespace Virgil.PureKit.Tests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using Google.Protobuf;
    using NSubstitute;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Math.EC;
    using Org.BouncyCastle.Security;
    using Virgil.PureKit.Phe;
    using Virgil.PureKit.Utils;

    using Xunit;
    using Xunit.Abstractions;

    public class PheCryptoTests
    {
        private readonly ITestOutputHelper output;
        private byte[] serverPublic = Bytes.FromString("04464173c0589a4dd70760f0fd8ddccf99ec829098d194e9c925403a35245d44f2acf6784fe4d7a5eb76ba0d23227625e0f264051c8ed36fe9088f210faa160a45", StringEncoding.HEX);
        private byte[] serverPrivate = Bytes.FromString("403cde159ac7bafa8e04a88e3dcbaae06c3c2f46699c0a28344e5e54e3c460ca", StringEncoding.HEX);
        private byte[] clientPrivate = Bytes.FromString("f587c094be766cf7d33120717bdf7e448cfea9c7ea69d4cae49f145e1f967b6c", StringEncoding.HEX);
        private byte[] enrollmentResponse = Bytes.FromString("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d124104a623af89752c65f091ee3a1bad2101fa1fd07af69630ff1b4362d48f6209ec2d46583eefe98e92b5101eac9627da22cf70ef1f0ca5f5bcb9a2b2868ee746e5e71a410446bfd5f5087e274ff9047d0afdf78f41f7984338e0285ab009eda24c347e5708346c30dfff0581c5086d9d9e348a54a361f5f0ed3f0f8627fe52c8694e592c9622eb010a4104eba8f5f434ab5e9e1d29b01dd6c90a4921b01bc3c27f508f4c750c1a3156ee32e89e336f96f5883cd03441b03d5543c3d869a71b8ed8ae43c12fe03cd67aeefd124104df22dc8b1ce0d11fe23e2b7a5efaa7e1881cf7d0a66bf25ad5979bc8b0b33876c20fbdb2dcf90f4bcb168bbb1cd5ece1217cad813a4b4a9774503b4ffbf6b9e21a4104e6dcadc5be875aafeb95e97bfd52b02560d30be3d1ba12662e44a408310a900bc14e79a70912329e0e58a5db5e6b54f2d674751a90544c1b171cde64481fc77c2220f09dbd69f7886dbba4b5527b52479cde3de8b2737641727d5e2476846e26ec2d", StringEncoding.HEX);
        private byte[] password = Bytes.FromString("7061737377307264", StringEncoding.HEX);
        private byte[] enrollmentRecord = Bytes.FromString("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1220fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1a41041cc2fc1243a1e6af99c6099c2bde1c1bc866a6072975f87c6bfce11db719b09f4832ac49db8ea7dc811f3239fee5b531a530e9a9915eb7be7ac51decb3cf7753224104bf0d5ccbc453fb0149c1c9789511ec6f0a85e07a1f9e3943b7826f23f53dfe61aa040abc0e41686702690ea496344a528be4e862da1786482db29631e634068c", StringEncoding.HEX);
        private byte[] recordKey = Bytes.FromString("ffa2b491260f2b4ae5cf0849371fc521c3aa06a7f359bd1d30ad4b7de38ba316", StringEncoding.HEX);
        private byte[] verifyPasswordReq = Bytes.FromString("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d124104a623af89752c65f091ee3a1bad2101fa1fd07af69630ff1b4362d48f6209ec2d46583eefe98e92b5101eac9627da22cf70ef1f0ca5f5bcb9a2b2868ee746e5e7", StringEncoding.HEX);
        private byte[] verifyPasswordResp = Bytes.FromString("080112410446bfd5f5087e274ff9047d0afdf78f41f7984338e0285ab009eda24c347e5708346c30dfff0581c5086d9d9e348a54a361f5f0ed3f0f8627fe52c8694e592c961aeb010a4104684ab1bdffa84453ebd6a1ec23cc7b4ae2ce6ebbe5a21b16856fd3847dad4559a312525ba0ab53d24a41fa5192ccdc742767d61a04318cd7b5b332d6741287af12410461c82f541a04b37e40545b4756325e4de1e8ba542d97dda356016694d87ae4cc6b3f25844d6504c1316e5c5442ce098d04a103257ac15b9ff16d4994d2af59cd1a410401d217f6d2ca53a85562cf36d13cf17f4db5c2737d8027afdad2bbfc8dcf0d9986c06e144c7ac5032d9fac36815be395ad9f343c3229a78e8a5e9c806181230e2220f90282dccb78ac4f14487ac00df7c736eee55e6d63e53d4e0e7679a2e1b3c8a1", StringEncoding.HEX);
        private byte[] badPassword = Bytes.FromString("7040737377307264", StringEncoding.HEX);
        private byte[] verifyBadPasswordReq = Bytes.FromString("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1241045950d1b2c56d8a77645fc784ddaa080066c20e19cbcc4805df27cfde4c88b744b01531b76d6be98f514870a2e4d2f7fa5139e20c7b517c7e8e56120f6dd0f6d3", StringEncoding.HEX);
        private byte[] verifyBadPasswordResp = Bytes.FromString("1241041a83e2221aa9796f5a5022c35f8bc764503c0cfb992bbd4eefb22bcd3186d280cf2783030316a538919abe2d697370a31bfba5133c2d679a22aed3327fc1da4722d0020a4104434fd3eb8d9df8ffc12667f09696ead6194ad7a197817bca53670852a4e32c0197dfeb50367622a88969d448daf8a1adf1416b884d2a6ae430820bd8bc36b9e3124104a773a99986143acf4698a2bcf93fa1ad02a8565f0231604d5f655ff70999ff55e4e5b6ef498d52342abf3b3ff72164017e52471abb06011392112058e36a14351a41049afb7fc9904b4fa45ab9993f91af369a6854b0f44d9048792be7327c2f9878172d0d64f9991fbcf6054bd463bf05e16b2e52d07671ad6e9f8c146605b21f61e3224104ea343565b7b2a6b8248e09ed2a3e4c32dbd7af391369be67387d6ccc4ab5baff7486ce95bf34cbaaec2a37ca380c33b10014450ffeec70dfde4a5eeaac5090cc2a2077e964767b16707315626307386c2a9d139dfa54de87a70e998124311d76a1743220f7dff81df7cc0582277944a89a75979766c89ba8e0ff5040fa85707c350521fe", StringEncoding.HEX);
        private byte[] token = Bytes.FromString("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d122080390531494470be0b296501586bfcd9e131c39e2decc753d4f25fefd2281eea", StringEncoding.HEX);
        private byte[] rotatedServerPub = Bytes.FromString("04c3b315ac3bbc101d7f71d31899fa44aecef0b1b879fab84c7f623d1113e6f7228b3399c246b345c6df0fa7af07cf39b558b13af502910d6c3b42d690468c2f1b", StringEncoding.HEX);
        private byte[] rotatedServerSk = Bytes.FromString("001e0d5c37a3627a53fed34b9f3a4236d3f5b6faa72696998a1239903a4bd12b", StringEncoding.HEX);
        private byte[] rotatedClientSk = Bytes.FromString("ceb6e27585f969f5d5c5bfb8bdc8337f369f381cc5e32efdc123ab74b06a441e", StringEncoding.HEX);
        private byte[] updatedRecord = Bytes.FromString("0a20fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1220fc9e1d89fa8b15e391f62b3de357b0f56fe4dec54a008c7556c477bc9679f83d1a4104b1dba4fc25dbe850c14278188adad7f39eb8977db5b364d2fb851f2238bf03ab473cdae0c20de7d528ba8de5043c2eb3eed3d9d45b2e99290ef97af147692aa02241044971b0118442b7dd7fc3b0d098a3afb4c33c62768da00814224eeea77e9bf539fa0bc4279e2fcaff63aac3cbae33050c4d6626fdf04373c2bbbdc7bc609f3a1f", StringEncoding.HEX);

        public PheCryptoTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void Should_ComputeIdenticalC0AndC1Values_When_TheSameKeyAndNonceArePassed()
        {
            var phe = new PheCrypto();
            var skS = phe.DecodeSecretKey(this.clientPrivate);
            var nonce = phe.GenerateNonce();

            var (c0, c1) = phe.ComputeC(skS, nonce);
            var (c00, c11) = phe.ComputeC(skS, nonce);

            Assert.Equal(Bytes.ToString(c0, StringEncoding.HEX), Bytes.ToString(c00, StringEncoding.HEX));
            Assert.Equal(Bytes.ToString(c1, StringEncoding.HEX), Bytes.ToString(c11, StringEncoding.HEX));
        }

        [Fact]
        public void Should_ComputeTheSameC0Value_For_SpecifiedListOfParameters()
        {
            var phe = new PheCrypto();
            var ns = new byte[]
            {
                0x04, 0x60, 0x41, 0x90, 0xea, 0xe3, 0x03, 0x48,
                0xc4, 0x67, 0xa2, 0x56, 0xaa, 0x20, 0xf0, 0xe1,
                0x22, 0xfd, 0x4c, 0x54, 0xb0, 0x2a, 0x03, 0x26,
                0x84, 0xf1, 0x22, 0x11, 0xfc, 0x9a, 0x8e, 0xe3,
            };
            var pwd = Bytes.FromString("passw0rd");
            var skC = phe.DecodeSecretKey(this.clientPrivate);
            var hash = new Dictionary<string, int>();
            var expectedC0 = Bytes.FromString("047062653b3a156a0a211686506f86427f13cdbe3825ca4ee820a8f202b91cf76cd276cc2f506191b491e85f5ac412cc36b2502cfbf23b130b0808d93c37271651", StringEncoding.HEX);
            var t0 = Bytes.FromString("04f1b0aef2e5dc2028955a35448a0d4fb4ea4c2dd3eba78bca4c5afd5c35832a1ffb7b1c7da8aa4c00105d0e7babacc49047891e3365e0606085071e23f50d97b7", StringEncoding.HEX);

            var c0 = phe.ComputeC0(skC, pwd, ns, t0);

            Assert.Equal(expectedC0, c0);
        }

        [Fact]
        public void Should_RotateTheSameSecretKey_When_OldSecretKeyAndUpdateTokenAreGiven()
        {
            var a = ByteString.CopyFrom(Bytes.FromString("T20buheJjFOg+rsxP5ADIS7G3htdY/MUt9VozMOgEfA=", StringEncoding.BASE64));
            var b = ByteString.CopyFrom(Bytes.FromString("UbXPXPtmKuudthZXXjJTE9AxBEgZB7mTFD+TGViCgHU=", StringEncoding.BASE64));
            var skC = Bytes.FromString("YOCs/LOx6hll3nUBC29xpNJuLXofpKaBUNHPDBMA7JI=", StringEncoding.BASE64);
            var skC1 = Bytes.FromString("Zd+YJUvpXKQIjMaeZiad4vFOoU+mH2Qldx/yqwmGg2I=", StringEncoding.BASE64);

            var phe = new PheCrypto();
            var pheSkC = phe.DecodeSecretKey(skC);
            var token1 = new UpdateToken()
            {
                A = a,
                B = b,
            };
            var pheSkC1 = phe.RotateSecretKey(pheSkC, token1.ToByteArray());

            Assert.Equal(skC1, pheSkC1.Encode());
        }

        /*
        [Fact]
        public void Should_RotateTheSamePublicKey_When_OldPublicKeyAndUpdateTokenAreGiven()
        {
            var a = Bytes.FromString("T20buheJjFOg+rsxP5ADIS7G3htdY/MUt9VozMOgEfA=", StringEncoding.BASE64);
            var b = Bytes.FromString("UbXPXPtmKuudthZXXjJTE9AxBEgZB7mTFD+TGViCgHU=", StringEncoding.BASE64);
            var pkS = Bytes.FromString("BBqqpApF8EsvQtLQlcR1sBon9RbKDcrsNypYDGatbx5JxvdQfGaszDwen01xQVWxL0UvrLfmzTBJHpL+q5+kyWw=", StringEncoding.BASE64);
            var pkS1 = Bytes.FromString("BMiu/KcLEom9PwAeEeN9gYJZ45kdlYdo1bYPsd8YjWvRVgqJY2MzJlu2OR1d7ynxZvsdXbVY68pxG/oK3k+3xX0=", StringEncoding.BASE64);

            var phe = new PheCrypto();
            var phePkC = phe.DecodePublicKey(pkS);

            var phePkC1 = phe.RotatePublicKey(phePkC, a, b);

            Assert.Equal(pkS1, phePkC1.Encode());
        }*/

        [Fact]
        public void TestRotatePrivateClientKey()
        {
            var phe = new PheCrypto();
            var oldClientPrivateKey = phe.DecodeSecretKey(this.clientPrivate);
            var newClientSecretKey = phe.RotateSecretKey(oldClientPrivateKey, this.token);
            Assert.Equal(this.rotatedClientSk, newClientSecretKey.Encode());
        }

        [Fact]
        public void TestRotatePublicServerKey()
        {
            var phe = new PheCrypto();
            var oldPublicServerKey = phe.DecodePublicKey(this.serverPublic);
            var newPublicServerKey = phe.RotatePublicKey(oldPublicServerKey, this.token);
            Assert.Equal(this.rotatedServerPub, newPublicServerKey.Encode());
        }

        [Fact]
        public void TestEncrypt()
        {
            var phe = new PheCrypto();
            var rng = new SecureRandom();
            var key = new byte[EncryptionService.SymKeyLen];
            rng.NextBytes(key);

            var plainText = new byte[365];
            rng.NextBytes(plainText);
            var cipherText = phe.Encrypt(plainText, key);
            var decyptedText = phe.Decrypt(cipherText, key);
            Assert.Equal(decyptedText, plainText);
        }

        [Fact]
        public void TestEncrypt_empty()
        {
            var phe = new PheCrypto();
            var rng = new SecureRandom();
            var key = new byte[EncryptionService.SymKeyLen];
            rng.NextBytes(key);

            var plainText = new byte[0];
            var cipherText = phe.Encrypt(plainText, key);
            var decyptedText = phe.Decrypt(cipherText, key);
            Assert.Equal(decyptedText, plainText);
        }

        [Fact]
        public void TestEncrypt_badKey()
        {
            var phe = new PheCrypto();
            var rng = new SecureRandom();
            var key = new byte[EncryptionService.SymKeyLen];
            rng.NextBytes(key);

            var plainText = new byte[365];
            rng.NextBytes(plainText);

            var cipherText = phe.Encrypt(plainText, key);

            key[0]++;

            var ex = Record.Exception(() => { phe.Decrypt(cipherText, key); });

            Assert.NotNull(ex);
            Assert.IsType<InvalidCipherTextException>(ex);
        }

        [Fact]
        public void TestDecrypt_badLength()
        {
            var phe = new PheCrypto();
            var rng = new SecureRandom();
            var key = new byte[EncryptionService.SymKeyLen];
            rng.NextBytes(key);

            var cipherText = new byte[EncryptionService.SymSaltLen + 15];
            rng.NextBytes(cipherText);

            var ex = Record.Exception(() => { phe.Decrypt(cipherText, key); });

            Assert.NotNull(ex);
            Assert.IsType<ArgumentException>(ex);
        }

        [Fact]
        public void TestEncryptVector()
        {
            var rnd = new byte[]
            {
                0x2b, 0x1a, 0x49, 0xe2, 0x6c, 0xcc, 0x33, 0xfe,
                0x5e, 0x7d, 0x0e, 0x57, 0x3b, 0xc4, 0x02, 0xf0,
                0x04, 0xa0, 0x1c, 0x60, 0x35, 0xaf, 0x42, 0x16,
                0xcb, 0xd0, 0x1f, 0x1a, 0x98, 0x24, 0x7a, 0xaa,
            };

            var key = new byte[]
            {
                0x87, 0xeb, 0x2b, 0xc9, 0x09, 0xac, 0x86, 0x9a,
                0xdc, 0xb2, 0x17, 0x72, 0x2f, 0x3f, 0x56, 0xa6,
                0xf7, 0x0f, 0xb7, 0x47, 0x3b, 0x1b, 0x6b, 0x36,
                0xf0, 0xae, 0x0a, 0x14, 0x5b, 0x45, 0xae, 0xe2,
            };

            var plainText = new byte[]
            {
                0x05, 0xa1, 0x06, 0x74, 0xa5, 0xba, 0xd0, 0x38,
                0x50, 0x7b, 0x2d, 0x9f, 0x80, 0x06, 0x45, 0x4b,
                0x0f, 0xbe, 0xf0, 0xd4, 0x0f, 0x62, 0x1b, 0x3c,
                0x35, 0x16, 0xef, 0xdd, 0x70, 0xd1, 0xef, 0x1d,
                0x3a, 0x6b, 0x8d, 0x50, 0xbe, 0xdb, 0x25, 0x57,
                0x3c, 0x26, 0x86, 0x43, 0x86, 0xa1, 0x39, 0x69,
                0xf7, 0xe9, 0x40, 0x00, 0xf0, 0x02, 0xd0, 0x0f,
                0xae, 0x86, 0x84, 0x37, 0x77, 0x0d, 0x9a, 0xfa,
            };

            var expectedCipherText = new byte[]
            {
                0x2b, 0x1a, 0x49, 0xe2, 0x6c, 0xcc, 0x33, 0xfe,
                0x5e, 0x7d, 0x0e, 0x57, 0x3b, 0xc4, 0x02, 0xf0,
                0x04, 0xa0, 0x1c, 0x60, 0x35, 0xaf, 0x42, 0x16,
                0xcb, 0xd0, 0x1f, 0x1a, 0x98, 0x24, 0x7a, 0xaa,
                0x61, 0x95, 0x05, 0xda, 0x9c, 0xbf, 0x32, 0x5b,
                0x79, 0x2a, 0x31, 0xce, 0x87, 0x71, 0x6e, 0x89,
                0xc0, 0x0c, 0xe9, 0x32, 0x14, 0xb1, 0x5c, 0x59,
                0x6b, 0x30, 0xe6, 0xe5, 0x1a, 0xed, 0x8a, 0x3c,
                0xdd, 0x83, 0x1e, 0xbf, 0x0e, 0xa7, 0x7f, 0x59,
                0x4d, 0xae, 0xed, 0x9c, 0xa0, 0xb8, 0xe6, 0x28,
                0x0c, 0x73, 0x60, 0xbc, 0x8c, 0x0f, 0xd7, 0xb9,
                0x2d, 0x09, 0x40, 0x0c, 0x8d, 0x63, 0x36, 0x19,
                0x32, 0x04, 0xac, 0xd4, 0x45, 0xa0, 0xa4, 0x5e,
                0xab, 0x08, 0x2c, 0xb1, 0xa7, 0x36, 0x04, 0xf4,
            };

            var phe = new PheCrypto();
            var rng = new SecureRandom();
            var encrService = new EncryptionService(key);
            var cipherText = encrService.EncryptWithSalt(plainText, rnd);
            Assert.Equal(cipherText, expectedCipherText);

            var decyptedText = phe.Decrypt(cipherText, key);
            Assert.Equal(plainText, decyptedText);
        }

        [Fact]
        public void TestHashZVector1()
        {
            var pub = new byte[]
            {
                0x04, 0x21, 0xc3, 0x71, 0x95, 0x74, 0xaf, 0xce,
                0xc6, 0x5e, 0x35, 0xbd, 0x77, 0x5a, 0x5b, 0xe3,
                0x6c, 0x77, 0xc0, 0xbe, 0x45, 0x01, 0xf5, 0xd7,
                0x0f, 0xf0, 0x70, 0xd5, 0x1a, 0x89, 0x3a, 0xd8,
                0xe0, 0x0c, 0xe6, 0xb8, 0x9b, 0x17, 0x88, 0xe6,
                0xc1, 0x27, 0xa0, 0xe1, 0x25, 0xd9, 0xde, 0x6a,
                0x71, 0x16, 0x46, 0xa0, 0x38, 0x0f, 0xc4, 0xe9,
                0x5a, 0x74, 0xe5, 0x2c, 0x89, 0xf1, 0x12, 0x2a,
                0x7c,
            };

            var c0X = "97803661066250274657510595696566855164534492744724548093309723513248461995097";
            var c0Y = "32563640650805051226489658838020042684659728733816530715089727234214066735908";
            var c1X = "83901588226167680046300869772314554609808129217097458603677198943293551162597";
            var c1Y = "69578797673242144759724361924884259223786981560985539034793627438888366836078";
            var t1X = "34051691470374495568913340263568595354597873005782528499014802063444122859583";
            var t1Y = "55902370943165854960816059167184401667567213725158022607170263924097403943290";
            var t2X = "101861885104337123215820986653465602199317278936192518417111183141791463240617";
            var t2Y = "40785451420258280256125533532563267231769863378114083364571107590767796025737";
            var t3X = "79689595215343344259388135277552904427007069090288122793121340067386243614518";
            var t3Y = "63043970895569149637126206639504503565389755448934804609068720159153015056302";
            var chlng = "93919747365284119397236447539917482315419780885577135068398876525953972539838";

            var phe = new PheCrypto();
            var c0 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(c0X, 10), new BigInteger(c0Y, 10));
            var c1 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(c1X, 10), new BigInteger(c1Y, 10));
            var t1 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t1X, 10), new BigInteger(t1Y, 10));
            var t2 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t2X, 10), new BigInteger(t2Y, 10));
            var t3 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t3X, 10), new BigInteger(t3Y, 10));

            var hashZ = phe.HashZ(Domains.ProofOK, pub, phe.CurveG.GetEncoded(), c0.GetEncoded(), c1.GetEncoded(), t1.GetEncoded(), t2.GetEncoded(), t3.GetEncoded());
            Assert.Equal(new BigInteger(chlng, 10), hashZ);
        }

        [Fact]
        public void TestHashZVector2()
        {
            var pub = new byte[]
            {
                0x04, 0x39, 0x01, 0x9b, 0x9e, 0x2f, 0x1b, 0xae,
                0x60, 0x65, 0xcd, 0x9b, 0x85, 0x94, 0xfe, 0xa6,
                0xe3, 0x5a, 0x9a, 0xfd, 0xd3, 0x15, 0x96, 0xca,
                0xd8, 0xf8, 0xa4, 0xb1, 0xbd, 0xcd, 0x9b, 0x24,
                0x40, 0x5b, 0x8b, 0x13, 0x23, 0xf2, 0xdd, 0x6b,
                0x1b, 0x1d, 0x3f, 0x57, 0x5d, 0x00, 0xf4, 0xa8,
                0x5f, 0xb8, 0x67, 0x90, 0x69, 0x74, 0xea, 0x16,
                0x4b, 0x41, 0x9e, 0x93, 0x66, 0x47, 0xd8, 0xfb,
                0x7b,
            };

            var c0X = "66305582120524875023859689648303664817335268054431490163250455437389177295478";
            var c0Y = "19615011428787373705295950431517815162915845805720956004550495681707511034851";
            var c1X = "11237049376971579382843942757546874380042467137583453135179008882019225463739";
            var c1Y = "80961525191994723690800208523971748057046695876178833586656397502847317233228";
            var t1X = "39244241269455735193598520026736537476566784866134072628798326598844377151651";
            var t1Y = "10612278657611837393693400625940452527356993857624739575347941960949401758261";
            var t2X = "108016526337105983792792579967716341976396349948643843073602635679441433077833";
            var t2Y = "90379537067318020066230942533439624193620174277378193732900885672181004096656";
            var t3X = "36913295823787819500630010367019659122715720420780370192192548665300728488299";
            var t3Y = "36547572032269541322937508337036635249923361457001752921238955135105574250650";
            var t4X = "49166285642990312777312778351013119878896537776050488997315166935690363463787";
            var t4Y = "66983832439067043864623691503721372978034854603698954939248898067109763920732";
            var chlng = "98801234524135497507777343590157351416109876307242902372535142932873423904771";

            var phe = new PheCrypto();
            var c0 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(c0X, 10), new BigInteger(c0Y, 10));
            var c1 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(c1X, 10), new BigInteger(c1Y, 10));
            var t1 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t1X, 10), new BigInteger(t1Y, 10));
            var t2 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t2X, 10), new BigInteger(t2Y, 10));
            var t3 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t3X, 10), new BigInteger(t3Y, 10));
            var t4 = (FpPoint)phe.Curve.CreatePoint(new BigInteger(t4X, 10), new BigInteger(t4Y, 10));
            var hashZ = phe.HashZ(
                Domains.ProofErr,
                pub,
                phe.CurveG.GetEncoded(),
                c0.GetEncoded(),
                c1.GetEncoded(),
                t1.GetEncoded(),
                t2.GetEncoded(),
                t3.GetEncoded(),
                t4.GetEncoded());
            Assert.Equal(new BigInteger(chlng, 10), hashZ);
        }

        [Fact]
        public void TestSimpleHashZ()
        {
            var expectedHashZ = "69727408650258925666157816894980607074870114162787023360036165814485426747693";
            var phe = new PheCrypto();
            var hashZ = phe.HashZ(Domains.ProofOK, phe.CurveG.GetEncoded());
            Assert.Equal(new BigInteger(expectedHashZ, 10), hashZ);
        }

        [Fact]
        public void TestHs0()
        {
            var ns = new byte[]
            {
                0x8e, 0x48, 0xac, 0x4b, 0x4a, 0x0c, 0x3f, 0x87,
                0x83, 0x69, 0x6f, 0x5d, 0x1f, 0x77, 0xd4, 0x25,
                0x64, 0x84, 0xd5, 0xb0, 0x7f, 0xd3, 0x8a, 0xf6,
                0xb2, 0xbf, 0x2d, 0x7b, 0x34, 0x57, 0x8a, 0x24,
            };

            var expectedX = "25300858746488398178355367558777222618482687866522608982770829435057272700048";
            var expectedY = "110446173948945874058011275277660983270153244227256872727234408438424462761061";
            var phe = new PheCrypto();
            var point = phe.HashToPoint(Domains.Dhs0, ns);

            Assert.Equal(new BigInteger(expectedX, 10), point.XCoord.ToBigInteger());
            Assert.Equal(new BigInteger(expectedY, 10), point.YCoord.ToBigInteger());
        }

        [Fact]
        public void TestHs1()
        {
            var ns = new byte[]
            {
                0x04, 0x60, 0x41, 0x90, 0xea, 0xe3, 0x03, 0x48,
                0xc4, 0x67, 0xa2, 0x56, 0xaa, 0x20, 0xf0, 0xe1,
                0x22, 0xfd, 0x4c, 0x54, 0xb0, 0x2a, 0x03, 0x26,
                0x84, 0xf1, 0x22, 0x11, 0xfc, 0x9a, 0x8e, 0xe3,
            };

            var expectedX = "17908376941582875772307252089828253420307082915473361881522058301944387204152";
            var expectedY = "33408333837140987002065754540391028444871058307081963101365044681462597430369";
            var phe = new PheCrypto();
            var point = phe.HashToPoint(Domains.Dhs1, ns);

            Assert.Equal(new BigInteger(expectedX, 10), point.XCoord.ToBigInteger());
            Assert.Equal(new BigInteger(expectedY, 10), point.YCoord.ToBigInteger());
        }

        [Fact]
        public void TestHc0()
        {
            var ns = new byte[]
            {
                0xdb, 0x59, 0x4e, 0x9a, 0x53, 0xeb, 0x35, 0x39,
                0x84, 0x63, 0x67, 0xf1, 0x4c, 0x15, 0xa1, 0x9b,
                0x4b, 0xee, 0x1d, 0x27, 0x13, 0xf3, 0xaa, 0xb5,
                0x3b, 0x11, 0x72, 0xd6, 0x02, 0x51, 0x63, 0x36,
            };

            var pwd = new byte[]
            {
                0x5a, 0xf6, 0xf9, 0x9a, 0xc2, 0x0d, 0x0d, 0x54,
                0x52, 0xa2,
            };

            var expectedX = "71581924212971445159021410682851786422010928474259399013091051697427945751880";
            var expectedY = "82599985433400511569162075253342037148256984798119669265653399740244502620726";
            var phe = new PheCrypto();
            var point = phe.HashToPoint(Domains.Dhc0, ns, pwd);

            Assert.Equal(new BigInteger(expectedX, 10), point.XCoord.ToBigInteger());
            Assert.Equal(new BigInteger(expectedY, 10), point.YCoord.ToBigInteger());
        }

        [Fact]
        public void TestHc1()
        {
            var ns = new byte[]
            {
                0x91, 0xd2, 0x04, 0x0b, 0x8e, 0x52, 0x7e, 0x8a,
                0xe3, 0x40, 0xf6, 0x89, 0xda, 0x01, 0x7c, 0xd6,
                0x1e, 0x20, 0x25, 0xd0, 0xbc, 0xc4, 0xd1, 0x24,
                0x92, 0x5c, 0x87, 0xc3, 0xe9, 0x59, 0xc7, 0x54,
            };

            var pwd = new byte[]
            {
                0xb8, 0xce, 0xc3, 0xde, 0xfd, 0xfc, 0x80, 0x3c, 0x18,
                0x5d,
            };

            var expectedX = "49501362177553120463897295920682327704465381738906627606535872853621035764254";
            var expectedY = "47270509952559745766619070899406283523267398868407265017727132307696482921539";
            var phe = new PheCrypto();
            var point = phe.HashToPoint(Domains.Dhc1, ns, pwd);

            Assert.Equal(new BigInteger(expectedX, 10), point.XCoord.ToBigInteger());
            Assert.Equal(new BigInteger(expectedY, 10), point.YCoord.ToBigInteger());
        }

        [Fact]
        public void TestHashToPoint()
        {
            byte[] mockedRandomBytes = new byte[]
            {
                0x80, 0x39, 0x05, 0x31, 0x49, 0x44, 0x70, 0xbe,
                0x0b, 0x29, 0x65, 0x01, 0x58, 0x6b, 0xfc, 0xd9,
                0xe1, 0x31, 0xc3, 0x9e, 0x2d, 0xec, 0xc7, 0x53,
                0xd4, 0xf2, 0x5f, 0xef, 0xd2, 0x28, 0x1e, 0xea,
                0xe0, 0x92, 0x7d, 0x0e, 0xd0, 0x57, 0x2e, 0x7f,
                0xe7, 0x7b, 0x60, 0x93, 0x15, 0xbc, 0x86, 0x5e,
                0xd4, 0x38, 0x92, 0xcd, 0x6c, 0xda, 0xf5, 0x65,
                0x18, 0x1a, 0x3d, 0xf9, 0x2b, 0x13, 0x80, 0xdc,
                0xc4, 0x08, 0x93, 0xc8, 0xdf, 0x19, 0x7b, 0x6b,
                0x8f, 0x74, 0x8f, 0x39, 0x23, 0xa1, 0x8a, 0x6d,
                0xd4, 0xdd, 0xb5, 0xc3, 0x01, 0x66, 0xa9, 0x5a,
                0xb8, 0xbc, 0x14, 0xde, 0x83, 0x26, 0xdb, 0x32,
                0xf3, 0x1d, 0xa8, 0xef, 0x0b, 0xdd, 0x38, 0x5f,
                0x83, 0xb3, 0x6c, 0xf8, 0x89, 0x48, 0xc3, 0xee,
                0xb3, 0x97, 0x4d, 0x04, 0x08, 0x12, 0x53, 0xf5,
                0x60, 0x44, 0x67, 0x91, 0xc1, 0x9e, 0x03, 0xab,
                0x4b, 0x70, 0x0b, 0xcb, 0x4e, 0x03, 0x81, 0x7d,
                0x40, 0x96, 0xa2, 0x60, 0x5a, 0x80, 0xb2, 0x23,
                0x6d, 0x62, 0x3c, 0x5a, 0x5e, 0xd2, 0x45, 0xdb,
                0x36, 0x56, 0xda, 0xb9, 0x2e, 0x6e, 0xe1, 0xe6,
                0x10, 0x27, 0x97, 0x3b, 0xbc, 0x2e, 0x04, 0x8d,
                0x21, 0xce, 0x4c, 0xf0, 0x29, 0x03, 0x7e, 0x17,
                0x0c, 0x34, 0x81, 0x8d, 0xaa, 0x25, 0x33, 0xe6,
                0xf8, 0x77, 0xe1, 0x59, 0x65, 0x89, 0x16, 0xa2,
            };

            var crypto = new PheCrypto();
            var m = crypto.HashToPoint(null, mockedRandomBytes.Take(32).ToArray());

            var expectedM = (FpPoint)crypto.Curve.CreatePoint(
                new BigInteger("47919986077532098346505903401676113443327441655946536745084881296990002308999", 10),
                new BigInteger("83980225500589559999287763767838231751053639306927585927546932471768986795515", 10));
            var xcoord = m.XCoord.ToBigInteger();
            var ycoord = m.YCoord.ToBigInteger();
            Assert.Equal(expectedM, m);
        }
    }
}