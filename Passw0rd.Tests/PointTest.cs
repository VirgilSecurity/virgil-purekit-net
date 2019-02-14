namespace Passw0rd.Tests
{
    using System;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Math.EC;
    using Org.BouncyCastle.Security;
    using Passw0rd.Phe;
    using Xunit;

    public class PointTest
    {
        [Fact]
        public void TestPoint_Add_Neg()
        {
            var p1 = this.MakePoint();
            var p2 = this.MakePoint();
            var p3 = this.MakePoint();

            var p12 = p1.Add(p2);
            var p123 = p12.Add(p3);

            p1 = (FpPoint)p1.Negate();
            p2 = (FpPoint)p2.Negate();

            p123 = p123.Add(p1);
            p123 = p123.Add(p2);
            Assert.Equal(p3, p123);
        }

        [Fact]
        public void TestPoint_Encoding()
        {
            var rng = new SecureRandom();
            var phe = new PheCrypto();
            var swu = new Swu(phe.Curve.Q, phe.Curve.B.ToBigInteger());
            var random = new byte[Swu.PointHashLen];
            rng.NextBytes(random);
            var (x, y) = swu.HashToPoint(random);
            var xField = phe.Curve.FromBigInteger(x);
            var yField = phe.Curve.FromBigInteger(y);
            var ecpoint = phe.Curve.CreatePoint(x, y);

            var encoded = ecpoint.GetEncoded();
            var decoded = phe.Curve.DecodePoint(encoded);

            Assert.Equal(ecpoint, decoded);
        }

        private FpPoint MakePoint()
        {
            var rng = new SecureRandom();
            var phe = new PheCrypto();
            var swu = new Swu(phe.Curve.Q, phe.Curve.B.ToBigInteger());
            var random = new byte[Swu.PointHashLen];
            rng.NextBytes(random);
            var (x, y) = swu.HashToPoint(random);
            var xField = phe.Curve.FromBigInteger(x);
            var yField = phe.Curve.FromBigInteger(y);
            var ecpoint = phe.Curve.CreatePoint(x, y);
            return (FpPoint)ecpoint;
        }
    }
}
