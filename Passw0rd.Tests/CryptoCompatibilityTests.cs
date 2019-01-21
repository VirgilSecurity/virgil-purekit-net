
namespace Passw0rd.Tests
{
    using Org.BouncyCastle.Crypto.Digests;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Crypto.Parameters;
    using Passw0rd.Phe;
    using Passw0rd.Utils;

    using Xunit;

    public class CryptoCompatibilityTests
    {
        [Fact]
        public void TupleHashCompute_Should_GenerateExpectedHash()
        {
            var expectedHash = "3696FB515910C43033D7BE0DD1ABFA4F3F8D8354EEC017D41F9"+
                "3A344C9AAB02C006771824DC09C5040BEC8CE9C5FD3833D1301B62750726160098E9A1ED440E4";

            var arr1 = new byte[] { 0x00, 0x01, 0x02 };
            var arr2 = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
            var arr3 = new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };

            var domain = Bytes.FromString("My Tuple App");

            var tupleHash = new SHA512();
            var hash = tupleHash.ComputeHash(domain, arr1, arr2, arr3);
            Assert.Equal(expectedHash, Bytes.ToString(hash, StringEncoding.HEX).ToUpper());
        }

        [Fact]
        public void HkdfGenerateBytes_Should_GenerateExpectedValue()
        {
            var expectedValue = 
                "0F097707AAB66A4CD5FCC79CEB96FB4B99DE2E73DF09295E" +
                "CFF6F6CC7C1DCF169D51B62999BC206487800E8DD451518FA6C50F5C053B8B780208BE7164D3A7F2";
            var arr1 = new byte[] { 0x00, 0x01, 0x02 };
            var arr2 = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
            var arr3 = new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };

            var domain = Bytes.FromString("My Tuple App");
            var sha512 = new SHA512();
            var key = sha512.ComputeHash(null, arr1, arr2, arr3);

            var hkdf = new HkdfBytesGenerator(new Sha512Digest());
            var phe = new PheCrypto();
            hkdf.Init(new HkdfParameters(key, domain, Domains.KdfInfoZ));
            var resultValue = new byte[64];
            hkdf.GenerateBytes(resultValue, 0, resultValue.Length);

            Assert.Equal(expectedValue, Bytes.ToString(resultValue, StringEncoding.HEX).ToUpper());
        }
    }
}
