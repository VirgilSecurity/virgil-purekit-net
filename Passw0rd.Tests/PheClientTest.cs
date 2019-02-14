namespace Passw0rd.Tests
{
    using System;
    using System.Linq;
    using NSubstitute;
    using Passw0rd.Phe;
    using Passw0rd.Utils;
    using Xunit;

    public class PheClientTest
    {
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

        private byte[] mockedRandomBytes = new byte[]
        {
            0xfc, 0x9e, 0x1d, 0x89, 0xfa, 0x8b, 0x15, 0xe3,
            0x91, 0xf6, 0x2b, 0x3d, 0xe3, 0x57, 0xb0, 0xf5,
            0x6f, 0xe4, 0xde, 0xc5, 0x4a, 0x00, 0x8c, 0x75,
            0x56, 0xc4, 0x77, 0xbc, 0x96, 0x79, 0xf8, 0x3d,
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

        [Fact]
        public void Should_EnrollNewRecord_When_PasswordSpecified()
        {
            var rngMock = Substitute.For<IPheRandomGenerator>();
            var offset = 0;
            rngMock.GenerateNonce(16).Returns(x =>
            {
                offset += 16;
                return ((Span<byte>)this.mockedRandomBytes).Slice(offset - 16, 16).ToArray();
            });
            rngMock.GenerateNonce(32).Returns(x =>
            {
                offset += 32;
                return ((Span<byte>)this.mockedRandomBytes).Slice(offset - 32, 32).ToArray();
            });

            var crypto = new PheCrypto();
            crypto.Rng = rngMock;

            var enrollmentRecordRight = EnrollmentRecord.Parser.ParseFrom(Google.Protobuf.ByteString.CopyFrom(this.enrollmentRecord));
            var appSecretKey = crypto.DecodeSecretKey(this.clientPrivate);

            var servicePublicKey = crypto.DecodePublicKey(this.serverPublic);
            var pheClient = new PheClient(appSecretKey, servicePublicKey);
            pheClient.Crypto = crypto;

            var (enrollmentRec, key) = pheClient.EnrollAccount(this.password, this.enrollmentResponse);
            var enrollmentRecordGot = EnrollmentRecord.Parser.ParseFrom(Google.Protobuf.ByteString.CopyFrom(enrollmentRec));

            Assert.Equal(Bytes.ToString(this.enrollmentRecord, StringEncoding.BASE64), Bytes.ToString(enrollmentRec, StringEncoding.BASE64));
            Assert.Equal(Bytes.ToString(this.recordKey, StringEncoding.BASE64), Bytes.ToString(key, StringEncoding.BASE64));
        }

        [Fact]
        public void TestValidPasswordRequest()
        {
            var rngMock = Substitute.For<IPheRandomGenerator>();
            rngMock.GenerateNonce(16).Returns(this.mockedRandomBytes.Take(16).ToArray());
            rngMock.GenerateNonce(32).Returns(this.mockedRandomBytes.Take(32).ToArray());

            var crypto = new PheCrypto();
            crypto.Rng = rngMock;

            var appSecretKey = crypto.DecodeSecretKey(this.clientPrivate);

            var servicePublicKey = crypto.DecodePublicKey(this.serverPublic);
            var pheClient = new PheClient(appSecretKey, servicePublicKey);
            pheClient.Crypto = crypto;
            var req = pheClient.CreateVerifyPasswordRequest(this.password, this.enrollmentRecord);

            Assert.Equal(this.verifyPasswordReq, req);
        }

        [Fact]
        public void TestInvalidPasswordRequest()
        {
            var rngMock = Substitute.For<IPheRandomGenerator>();
            rngMock.GenerateNonce(16).Returns(this.mockedRandomBytes.Take(16).ToArray());
            rngMock.GenerateNonce(32).Returns(this.mockedRandomBytes.Take(32).ToArray());

            var crypto = new PheCrypto();
            crypto.Rng = rngMock;

            var appSecretKey = crypto.DecodeSecretKey(this.clientPrivate);

            var servicePublicKey = crypto.DecodePublicKey(this.serverPublic);
            var pheClient = new PheClient(appSecretKey, servicePublicKey);
            pheClient.Crypto = crypto;
            var req = pheClient.CreateVerifyPasswordRequest(this.badPassword, this.enrollmentRecord);

            Assert.Equal(this.verifyBadPasswordReq, req);
        }

        [Fact]
        public void TestRotateClientKey()
        {
            var rngMock = Substitute.For<IPheRandomGenerator>();
            rngMock.GenerateNonce(16).Returns(this.mockedRandomBytes.Take(16).ToArray());
            rngMock.GenerateNonce(32).Returns(this.mockedRandomBytes.Take(32).ToArray());

            var crypto = new PheCrypto();
            crypto.Rng = rngMock;

            var appSecretKey = crypto.DecodeSecretKey(this.clientPrivate);

            var servicePublicKey = crypto.DecodePublicKey(this.serverPublic);
            var pheClient = new PheClient(appSecretKey, servicePublicKey);
            pheClient.Crypto = crypto;
            var (rotatedAppSecretKey, rotatedServicePublicKey) = pheClient.RotateKeys(this.token);

            Assert.Equal(this.rotatedClientSk, rotatedAppSecretKey.Encode());
            Assert.Equal(this.rotatedServerPub, rotatedServicePublicKey.Encode());
        }

        [Fact]
        public void TestRotateEnrollmentRecord()
        {
            var rngMock = Substitute.For<IPheRandomGenerator>();
            rngMock.GenerateNonce(16).Returns(this.mockedRandomBytes.Take(16).ToArray());
            rngMock.GenerateNonce(32).Returns(this.mockedRandomBytes.Take(32).ToArray());

            var crypto = new PheCrypto();
            crypto.Rng = rngMock;

            var appSecretKey = crypto.DecodeSecretKey(this.clientPrivate);

            var servicePublicKey = crypto.DecodePublicKey(this.serverPublic);
            var pheClient = new PheClient();
            pheClient.Crypto = crypto;
            var updatedEnrollmentRecord = pheClient.UpdateEnrollmentRecord(this.token, this.enrollmentRecord);

            Assert.Equal(this.updatedRecord, updatedEnrollmentRecord);
        }
    }
}
