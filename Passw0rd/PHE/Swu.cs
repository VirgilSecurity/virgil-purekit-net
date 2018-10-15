namespace Passw0rd.PHE
{
    using System.Security.Cryptography;

    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.Math.EC;

    /// <summary>
    /// Implementation of Shallue-Woestijne-Ulas algorithm
    /// </summary>
    public class Swu
    {
        private readonly BigInteger a;
        private readonly BigInteger b;
        private readonly BigInteger p;
        private readonly BigInteger p34;
        private readonly BigInteger p14;
        private readonly BigInteger mba;

        public Swu()
        {
            var curve = (FpCurve)ECNamedCurveTable.GetByName("P-256").Curve;

            this.p = curve.Q;
            this.b = curve.B.ToBigInteger();

            this.a = p.Neg(BigInteger.Three);
            var ba = p.Div(this.b, a);
            this.mba = p.Neg(ba);
            var p3 = p.Sub(p, BigInteger.Three);
            this.p34 = p.Div(p3, BigInteger.ValueOf(4));
            var p1 = p.Add(p, BigInteger.One);
            this.p14 = p.Div(p1, BigInteger.ValueOf(4));
        }

        public (BigInteger x, BigInteger y) HashToPoint(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(data);

                var t = new BigInteger(1, hash, 0, hash.Length);
                t = t.Mod(p);

                var tt = p.Square(t);
                var alpha = p.Neg(tt);
                var asq = p.Square(alpha);
                var asqa = p.Add(asq, alpha);
                var asqa1 = p.Add(BigInteger.One, p.Inv(asqa));

                // x2 = -(b / a) * (1 + 1/(alpha^2+alpha))
                var x2 = p.Mul(mba, asqa1);

                // x3 = alpha * x2
                var x3 = p.Mul(alpha, x2);
                var ax2 = p.Mul(a, x2);
                var x23 = p.Cube(x2);
                var x23ax2 = p.Add(x23, ax2);

                // h2 = x2^3 + a*x2 + b
                var h2 = p.Add(x23ax2, b);
                var ax3 = p.Mul(a, x3);
                var x33 = p.Cube(x3);
                var x33ax3 = p.Add(x33, ax3);
                var h3 = p.Add(x33ax3, b);

                // tmp = h2 ^ ((p - 3) // 4)
                var tmp = p.Pow(h2, p34);
                var tmp2 = p.Square(tmp);
                var tmp2h2 = p.Mul(tmp2, h2);

                // if tmp^2 * h2 == 1:

                return tmp2h2.Equals(BigInteger.One)
                    ? (x2, p.Mul(tmp, h2))
                    : (x3, p.Pow(h3, p14));
            }
        }
    }
}
