namespace Passw0rd.Utils.Asn1
{
    public class ASN1OctetString : IASN1Object
    {
        private readonly byte[] bytes;

        public ASN1OctetString(byte[] bytes)
        {
            this.bytes = bytes;
        }

        public byte[] GetBytes()
        {
            return this.bytes;
        }
    }
}
