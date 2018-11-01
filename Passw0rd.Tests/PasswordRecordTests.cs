namespace Passw0rd.Tests
{
    using System;
    using Passw0rd.Utils;
    using Xunit;

    public class PasswordRecordTests
    {
        [Fact]
        public void Should_EncodeAndDecodeWithTheSameValues_When_MethodForSpecifiedInstanceIsCalled()
        {
            var nS = Bytes.FromString("7+t+vbhC1M1+TzgGJ1n4ZBWCyzuUXcz61nxTvDIWN7A=", StringEncoding.BASE64);
            var nC = Bytes.FromString("FB/nl1UbJwBI3hM80+N53vSljZGu0ZJ/y6PhOvcnd8U=", StringEncoding.BASE64);
            var t0 = Bytes.FromString("BFVFSh2DlZkRQRjl9kLZWRqAA6dSFXU1TVymEqcM06fIorhK0SeDVSbA1390FDp9btM0RgztQAeYvZuH3/2SEvw=", StringEncoding.BASE64);
            var t1 = Bytes.FromString("BEUyxTjawlSTQnms5yuJwvIgNJDlpC7X71S+x8aOIHmruHxNIk+8bW85Wk9Dh/5XidFgL5AB266k9tjs5dApm6w=", StringEncoding.BASE64);

            var record = new PasswordRecord(nS, nC, t0, t1);
            var str = record.EncodeToBase64();
        }
    }
}
