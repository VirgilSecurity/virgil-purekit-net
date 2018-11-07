namespace Passw0rd
{
    using Passw0rd.Phe;

    /// <summary>
    /// Secret public key.
    /// </summary>
    public class ServerPublicKey
    {
        public ServerPublicKey(PublicKey publicKey, int version)
        {
            this.PublicKey = publicKey;
            this.Version = version;
        }

        /// <summary>
        /// Gets the public key.
        /// </summary>
        public PublicKey PublicKey { get; private set; }

        /// <summary>
        /// Gets the version.
        /// </summary>
        public int Version { get; private set; }
    }
}
