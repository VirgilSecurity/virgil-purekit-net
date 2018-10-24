namespace Passw0rd.Tests
{
    using Passw0rd.Phe;
    using Passw0rd.Utils;

    using Xunit;

    public class TupleHashTests
    {
        [Fact]
        public void Compatibility_Test_1()
        {
            var rightHash = "BA3CA6BD5B2AEDCD8D139E9EC75672392095FB8698CD46B434ACC3911769D103";

            var arr1 = new byte[] { 0x00, 0x01, 0x02 };
            var arr2 = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
            var arr3 = new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };

            var domain = Bytes.FromString("My Tuple App");

            var tupleHash = new TupleHash();
            var hash = tupleHash.Sum(domain, arr1, arr2, arr3);

            Assert.Equal(rightHash, Bytes.ToString(hash, StringEncoding.HEX).ToUpper());
        }
    }
}
