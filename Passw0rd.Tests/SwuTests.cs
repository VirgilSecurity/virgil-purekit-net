namespace Passw0rd.Tests
{
    using System;
    using Org.BouncyCastle.Asn1.Nist;
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Math.EC;
    using Org.BouncyCastle.Security;
 
    using Passw0rd.Phe;

    using Xunit;

    public class SwuTests
    {
        [Fact]
        public void Should_GeneratePointOnCurve_When_RandomHashesArePassed()
        {
            var curveParams = NistNamedCurves.GetByName("P-256");

            var swu = new Swu(((FpCurve)curveParams.Curve).Q, curveParams.Curve.B.ToBigInteger());
            var rng = new SecureRandom();
            var sha = new Sha512tDigest(256);
            var random = new byte[32];

            for (int i = 0; i <= 10000; i++)
            {
                var hash = new byte[32];

                rng.NextBytes(random);
                sha.BlockUpdate(random, 0, random.Length);
                sha.DoFinal(hash, 0);

                var (x, y) = swu.HashToPoint(hash);
                Assert.True(curveParams.Curve.CreatePoint(x, y).IsValid());

                sha.Reset();
            }
        }
    }
}
