namespace Passw0rd.Utils.Asn1
{
    using System;

    public class ASN1Integer : IASN1Object
    {
        public ASN1Integer(int value)
        {
            this.Value = value;
        }

        public int Value { get; private set; }

        public byte[] GetBytes()
        {
            return BitConverter.GetBytes(this.Value);
        }
    }
}
