namespace Passw0rd
{
    using Passw0rd.Phe;

    public class ClientSecretKey
    {
        public ClientSecretKey(SecretKey publicKey, int version)
        {
            this.SecretKey = publicKey;
            this.Version = version;
        }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        public SecretKey SecretKey { get; private set; }

        /// <summary>
        /// Gets the version.
        /// </summary>
        public int Version { get; private set; }
    }
}
