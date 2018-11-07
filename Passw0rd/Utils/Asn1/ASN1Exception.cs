namespace Passw0rd.Utils.Asn1
{
    using System;
    using System.Runtime.Serialization;

    [Serializable]
    internal class ASN1Exception : Exception
    {
        public ASN1Exception(string message) : base(message)
        {
        }
    }
}