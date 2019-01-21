using System;
using Passw0rd.Utils;

namespace Passw0rd.Phe
{
    public static class Domains
    {
        private static byte[] commonPrefix = new byte[] { 0x56, 0x52, 0x47, 0x4c, 0x50, 0x48, 0x45 }; //VRGLPHE
        public static readonly byte[] Dhc0 = Bytes.Combine(commonPrefix, new byte[] { 0x31 });
        public static readonly byte[] Dhc1 = Bytes.Combine(commonPrefix, new byte[] { 0x32 });
        public static readonly byte[] Dhs0 = Bytes.Combine(commonPrefix, new byte[] { 0x33 });
        public static readonly byte[] Dhs1 = Bytes.Combine(commonPrefix, new byte[] { 0x34 });
        public static readonly byte[] ProofOK = Bytes.Combine(commonPrefix, new byte[] { 0x35 });
        public static readonly byte[] ProofErr = Bytes.Combine(commonPrefix, new byte[] { 0x36 });
        public static readonly byte[] Encrypt = Bytes.Combine(commonPrefix, new byte[] { 0x37 });
        public static readonly byte[] KdfInfoZ = Bytes.Combine(commonPrefix, new byte[] { 0x38 });
        public static readonly byte[] KdfInfoClientKey = Bytes.Combine(commonPrefix, new byte[] { 0x39 });
    }
}
