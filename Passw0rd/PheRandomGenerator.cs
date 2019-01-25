using System;
using Org.BouncyCastle.Security;

namespace Passw0rd
{
    internal class PheRandomGenerator
    {
        private SecureRandom rng;

        public PheRandomGenerator()
        {
            this.rng = new SecureRandom();
        }

        /// <summary>
        /// Generates a random nonce.
        /// </summary>
        public virtual byte[] GenerateNonce(int length)
        {
            var nonce = new byte[length];
            this.rng.NextBytes(nonce);
            return nonce;
        }
    }
}
