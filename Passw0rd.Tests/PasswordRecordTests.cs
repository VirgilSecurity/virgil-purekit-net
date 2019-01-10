namespace Passw0rd.Tests
{
    using Passw0rd.Utils;
    using Xunit;

    public class PasswordRecordTests
    {
        [Fact]
        public void Should_EncodeToBase64StringAndDecode_When_RecordWithGivenParametersAreSpecified()
        {
            int v  = 1;
            var nS = Bytes.FromString("7+t+vbhC1M1+TzgGJ1n4ZBWCyzuUXcz61nxTvDIWN7A=", StringEncoding.BASE64);
            var nC = Bytes.FromString("FB/nl1UbJwBI3hM80+N53vSljZGu0ZJ/y6PhOvcnd8U=", StringEncoding.BASE64);
            var t0 = Bytes.FromString("BFVFSh2DlZkRQRjl9kLZWRqAA6dSFXU1TVymEqcM06fIorhK0SeDVSbA1390FDp9btM0RgztQAeYvZuH3/2SEvw=", StringEncoding.BASE64);
            var t1 = Bytes.FromString("BEUyxTjawlSTQnms5yuJwvIgNJDlpC7X71S+x8aOIHmruHxNIk+8bW85Wk9Dh/5XidFgL5AB266k9tjs5dApm6w=", StringEncoding.BASE64);

            var record = new PasswordRecordOld(nS, nC, t0, t1, v);

            var str = record.EncodeToBase64();

            var decodedRecord = PasswordRecordOld.DecodeFromBase64(str);

            Assert.Equal(decodedRecord.Version, v);
            Assert.Equal(decodedRecord.ServerNonce, nS);
            Assert.Equal(decodedRecord.ClientNonce, nC);
            Assert.Equal(decodedRecord.RecordT0, t0);
            Assert.Equal(decodedRecord.RecordT1, t1);
        }

        [Fact]
        public void Should_DecodeFromGivenBase64String()
        {
            var str = "MIHNAgEBBCBflyzZDaDN0ww2fTrLO+THRSgAc3G+lq7dtFe/GNQaYAQ" +
                "gQjHih3UMR3exo3rL7WqZ0bqKT+InhzNCcobfZQvpSq0EQQRkcIpfJlCpOn3A" +
                "f/9gSup3/eb2Dvy8B4zLsIE3MHQH71Kw0B4AaTU19LJexnjub9KKhNSQGeYHR" +
                "KIFUBYviMktBEEETpeGtp1awNv9OaE73fqi73Iy4EcG9RVK7xI1XOAMJZpait" +
                "qRO/FEYbx05lrEtRN3E5HtOGt1cyD1mJX1q/8Prw==";

            var decodedRecord = PasswordRecordOld.DecodeFromBase64(str);

            var nS = Bytes.FromString("5f972cd90da0cdd30c367d3acb3be4c74528007371be96aeddb457bf18d41a60", StringEncoding.HEX);
            var nC = Bytes.FromString("4231e287750c4777b1a37acbed6a99d1ba8a4fe2278733427286df650be94aad", StringEncoding.HEX);
            var t0 = Bytes.FromString("0464708a5f2650a93a7dc07fff604aea77fde6f60efcbc078ccbb08137307407ef52b0d01e00693535f4b25ec678ee6fd28a84d49019e60744a20550162f88c92d", StringEncoding.HEX);
            var t1 = Bytes.FromString("044e9786b69d5ac0dbfd39a13bddfaa2ef7232e04706f5154aef12355ce00c259a5a8ada913bf14461bc74e65ac4b513771391ed386b757320f59895f5abff0faf", StringEncoding.HEX);

            Assert.Equal(1, decodedRecord.Version);
            Assert.Equal(nS, decodedRecord.ServerNonce);
            Assert.Equal(nC, decodedRecord.ClientNonce);
            Assert.Equal(t0, decodedRecord.RecordT0);
            Assert.Equal(t1, decodedRecord.RecordT1);
        }
    }
}
