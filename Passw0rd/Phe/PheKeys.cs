using System;
namespace Passw0rd.Phe
{
    public class PheKeys
    {
        public SecretKey ClientSecretKey { get; private set; }
        public PublicKey ServerPublicKey { get; private set; } 

        public PheKeys(SecretKey secretKey, PublicKey publicKey)
        {
            this.ClientSecretKey = secretKey;
            this.ServerPublicKey = publicKey;
        }
    }
}
