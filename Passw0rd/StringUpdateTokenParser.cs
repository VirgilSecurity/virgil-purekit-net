using System;
using Google.Protobuf;
using Passw0rd.Utils;
using Passw0Rd;

namespace Passw0rd
{
    internal static class StringUpdateTokenParser
    {
        public static VersionedUpdateToken Parse(string token)
        {
            var keyParts = token.Split(".");
            if (keyParts.Length != 3 ||
                !UInt32.TryParse(keyParts[1], out uint version) ||
                !keyParts[0].ToUpper().Equals("UT"))
            {
                throw new ArgumentException("has incorrect format", nameof(token));
            }
            //todo: version validate
            var tokenBytes = Bytes.FromString(keyParts[2], StringEncoding.BASE64);

            return new VersionedUpdateToken
            {
                Version = version,
                UpdateToken = ByteString.CopyFrom(tokenBytes)
            };
        }
    }
}
