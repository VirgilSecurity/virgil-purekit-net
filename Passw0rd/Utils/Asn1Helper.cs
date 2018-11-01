namespace Passw0rd.Utils
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using Org.BouncyCastle.Asn1;

    public class Asn1Helper
    {
        public static byte[] Encode(params byte[][] parameters)
        {
            var octetStrings = parameters.Select(it => new DerOctetString(it)).ToArray();

            var sequence = new DerSequence(octetStrings);
            var asn1Obj = sequence.ToAsn1Object();

            return asn1Obj.GetDerEncoded();
        }

        public static IEnumerable<byte[]> Decode(byte[] arr)
        {
            var sequense = Asn1Object.FromByteArray(arr) as DerSequence;
            if (sequense == null)
            {
                throw new ArgumentException(nameof(arr));
            }

            for (var index = 0; index < sequense.Count; index++)
            {
                var octetString = sequense[index] as DerOctetString;
                yield return octetString.GetOctets();
            }
        }
    }
}
