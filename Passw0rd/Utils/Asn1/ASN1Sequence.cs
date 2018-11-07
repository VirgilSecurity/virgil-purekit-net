namespace Passw0rd.Utils.Asn1
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Math;

    public class ASN1Sequence
    {
        public IEnumerable<IASN1Object> Elements { get; set; }

        public byte[] Encode()
        {
            if (this.Elements == null || !this.Elements.Any())
            {
                throw new NotSupportedException("Sequence is null or contains no elements");
            }

            var asn1objs = new List<Asn1Object>();
            foreach (var element in this.Elements)
            {
                if (element.GetType() == typeof(ASN1OctetString))
                {
                    asn1objs.Add(new DerOctetString(element.GetBytes()));
                }
                else if (element.GetType() == typeof(ASN1Integer))
                {
                    asn1objs.Add(new DerInteger(((ASN1Integer)element).Value));
                }
                else
                {
                    throw new NotSupportedException("Sequence contains unsupported element type");
                }
            }

            var derSequence = new DerSequence(asn1objs.ToArray());
            return derSequence.GetDerEncoded();// .GetDerEncoded();
        }

        public static ASN1Sequence Decode(byte[] asn1Bytes)
        {
            var sequense = Asn1Object.FromByteArray(asn1Bytes) as DerSequence;
            if (sequense == null)
            {
                throw new ArgumentException(nameof(asn1Bytes));
            }

            var asn1Objects = new List<IASN1Object>();

            for (var index = 0; index < sequense.Count; index++)
            {
                if (sequense[index].GetType() == typeof(DerOctetString))
                {
                    var octetString = sequense[index] as DerOctetString;
                    asn1Objects.Add(new ASN1OctetString(octetString.GetOctets()));
                }
                else if (sequense[index].GetType() == typeof(DerInteger))
                {
                    var asn1Integer = sequense[index] as DerInteger;
                    asn1Objects.Add(new ASN1Integer(asn1Integer.Value.IntValue));
                }
                else
                {
                    throw new ArgumentException("ASN1 sequense contains unsupported element type");
                }
            }

            return new ASN1Sequence { Elements = asn1Objects };
        }

        public int GetIntegerFromElementAt(int elementIndex)
        {
            var asn1Int = this.Elements.ElementAt(elementIndex) as ASN1Integer;
            if (asn1Int == null)
            {
                throw new ASN1Exception($"Element at index ${elementIndex} is not integer");
            }

            return asn1Int.Value;
        }

        public byte[] GetOctetStringFromElementAt(int elementIndex)
        {
            var asn1OctetString = this.Elements.ElementAt(elementIndex) as ASN1OctetString;
            if (asn1OctetString == null)
            {
                throw new ASN1Exception($"Element at index ${elementIndex} is not octet string");
            }

            return asn1OctetString.GetBytes();
        }
    }
}
