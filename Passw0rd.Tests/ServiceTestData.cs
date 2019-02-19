namespace Passw0rd.Tests
{
    using System;
    using Microsoft.Extensions.Configuration;

    public class ServiceTestData
    {
        public ServiceTestData(string serviceName)
        {
            IConfigurationRoot configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json", optional: true).Build();
            this.AppToken = configuration[$"{serviceName}:AppToken"];
            this.ServicePublicKey = configuration[$"{serviceName}:ServicePublicKey"];
            this.ClientSecretKey = configuration[$"{serviceName}:ClientSecretKey"];
            this.ClientSecretKey2 = configuration[$"{serviceName}:ClientSecretKey2"];
            this.ServicePublicKey2 = configuration[$"{serviceName}:ServicePublicKey2"];
            this.UpdateTokenV2 = configuration[$"{serviceName}:UpdateTokenV2"];
            this.UpdateTokenV3 = configuration[$"{serviceName}:UpdateTokenV3"];
            this.ServiceAddress = configuration[$"{serviceName}:ServiceAddress"];
            this.ServiceSubdomain = configuration[$"{serviceName}:ServiceSubdomain"];
        }

        public string AppToken { get; private set; }

        public string ServicePublicKey { get; private set; }

        public string ClientSecretKey { get; private set; }

        public string ClientSecretKey2 { get; private set; }

        public string ServicePublicKey2 { get; private set; }

        public string UpdateTokenV2 { get; private set; }

        public string UpdateTokenV3 { get; private set; }

        public string ServiceAddress { get; private set; }

        public string ServiceSubdomain { get; private set; }
    }
}
