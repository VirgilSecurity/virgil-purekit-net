namespace Passw0rd.PHE
{
    using Org.BouncyCastle.Math;

    public static class BigIntegerExtensions
    {
        public static BigInteger Neg(this BigInteger bigInt, BigInteger i)
        {
            return bigInt.Subtract(i);
        }

        public static BigInteger NegBytes(this BigInteger bigInt, byte[] bytes)
        {
            return bigInt.Subtract(new BigInteger(bytes));
        }

        public static BigInteger Inv(this BigInteger bigInt, BigInteger i)
        {
            return i.ModInverse(bigInt);
        }

        public static BigInteger Mul(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            return i.Multiply(j).Mod(bigInt);
        }

        public static BigInteger Square(this BigInteger bigInt, BigInteger i)
        {
            return i.ModPow(BigInteger.Two, bigInt);
        }

        public static BigInteger Cube(this BigInteger bigInt, BigInteger i)
        {
            return i.ModPow(BigInteger.Three, bigInt);
        }

        public static BigInteger Pow(this BigInteger bigInt, BigInteger n, BigInteger e)
        {
            return n.ModPow(e, bigInt);
        }

        public static BigInteger Sub(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            var negB = i.Subtract(j);
            return negB.Mod(bigInt);
        }

        public static BigInteger Add(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            return i.Add(j).Mod(bigInt);
        }

        public static BigInteger Div(this BigInteger bigInt, BigInteger i, BigInteger j)
        {
            var invB = bigInt.Inv(j);
            return bigInt.Mul(i, invB);
        }
    }
}
