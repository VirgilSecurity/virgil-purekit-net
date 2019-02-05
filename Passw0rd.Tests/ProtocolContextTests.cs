namespace Passw0rd.Tests
{
    using System.Linq;
    using Microsoft.Extensions.Configuration;
    using Xunit;

    public class ProtocolContextTests
    {
        private string appToken;
        private string servicePublicKey;
        private string clientSecretKey;
        private string clientSecretKey2;
        private string servicePublicKey2;
        private string updateTokenV2;
        private string updateTokenV3;
        private string serviceAddress;

        public ProtocolContextTests()
        {
            IConfigurationRoot configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json", optional: true).Build();
            appToken = configuration["AppToken"];
            servicePublicKey = configuration["ServicePublicKey"];
            clientSecretKey = configuration["ClientSecretKey"];
            clientSecretKey2 = configuration["ClientSecretKey2"];
            servicePublicKey2 = configuration["ServicePublicKey2"];
            updateTokenV2 = configuration["UpdateTokenV2"];
            updateTokenV3 = configuration["UpdateTokenV3"];
            serviceAddress = configuration["ServiceAddress"];
        }

        [Fact] //HTC-8
        public void Create_Should_SetKeysVersionToCurrentVersion()
        {
            // if there is no updateToken, then
            // 1)current version is set up from keys' version
            // 2)context has only one pair of keys
            var contextWithUpdateToken = ProtocolContext.Create(
              appToken: appToken,
              servicePublicKey: servicePublicKey2,
              appSecretKey: clientSecretKey2,
              apiUrl: serviceAddress);
            
            Assert.Equal<uint>(2, contextWithUpdateToken.CurrentVersion);
            Assert.Equal<int>(1, contextWithUpdateToken.PheClients.Count);
            Assert.Equal<uint>(2, contextWithUpdateToken.PheClients.Keys.First<uint>());
        }


        [Fact] //HTC-9
        public void Create_Should_RotateKeysIfUpdateTokenIsBigger()
        {
            // if update token version == current version + 1, then 
            // 1)new keys are calculated
            // 2)current vesion == updateToken version
            // 3)context keeps keys for previous and current versions
            var contextWithUpdateToken = ProtocolContext.Create(
              appToken: appToken,
              servicePublicKey: servicePublicKey,
              appSecretKey: clientSecretKey,
              apiUrl: serviceAddress,
              updateToken: updateTokenV2);

            Assert.Equal<uint>(2, contextWithUpdateToken.CurrentVersion);
            Assert.Equal(2, contextWithUpdateToken.PheClients.Count);
            Assert.Equal<uint>(2, contextWithUpdateToken.PheClients.Keys.Last<uint>());
        }

        [Fact] //HTC-10
        public void Create_Should_RaiseExceptionIfUpdateTokenVersionIsIncorect()
        {
            // if update token version != current version + 1, then raise exception.
            var ex = Record.Exception(() =>
            {
                ProtocolContext.Create(
              appToken: appToken,
              servicePublicKey: servicePublicKey,
              appSecretKey: clientSecretKey,
              apiUrl: serviceAddress,
                    updateToken: updateTokenV3);
            });

            Assert.IsType<WrongVersionException>(ex);
        }
    }
}
