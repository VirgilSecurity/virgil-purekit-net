namespace Virgil.PureKit.Tests
{
    using System;
    using System.Linq;
    using Microsoft.Extensions.Configuration;
    using NSubstitute;
    using Virgil.PureKit.Client;
    using Virgil.PureKit.Client.Connection;
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
        private string passwordServiceUrl = "https://api.passw0rd.io/";
        private string virgilServiceUrl = "https://api.virgilsecurity.com/";

        public ProtocolContextTests()
        {
            var serviceTestData = new ServiceTestData("passw0rd");
            this.appToken = serviceTestData.AppToken;
            this.servicePublicKey = serviceTestData.ServicePublicKey;
            this.clientSecretKey = serviceTestData.ClientSecretKey;
            this.clientSecretKey2 = serviceTestData.ClientSecretKey2;
            this.servicePublicKey2 = serviceTestData.ServicePublicKey2;
            this.updateTokenV2 = serviceTestData.UpdateTokenV2;
            this.updateTokenV3 = serviceTestData.UpdateTokenV3;
            this.serviceAddress = serviceTestData.ServiceAddress;
        }

        [Fact] // HTC-8
        public void Create_Should_SetKeysVersionToCurrentVersion()
        {
            // if there is no updateToken, then
            // 1)current version is set up from keys' version
            // 2)context has only one pair of keys
            var contextWithUpdateToken = ProtocolContext.Create(
                appToken: this.appToken,
                servicePublicKey: this.servicePublicKey2,
                appSecretKey: this.clientSecretKey2);
            Assert.Equal<uint>(2, contextWithUpdateToken.CurrentVersion);
            Assert.True(contextWithUpdateToken.PheClients.Count == 1);
            Assert.Equal<uint>(2, contextWithUpdateToken.PheClients.Keys.First<uint>());
        }

        [Fact] // HTC-9
        public void Create_Should_RotateKeysIfUpdateTokenIsBigger()
        {
            // if update token version == current version + 1, then
            // 1)new keys are calculated
            // 2)current vesion == updateToken version
            // 3)context keeps keys for previous and current versions
            var contextWithUpdateToken = ProtocolContext.Create(
                appToken: this.appToken,
                servicePublicKey: this.servicePublicKey,
                appSecretKey: this.clientSecretKey,
                updateToken: this.updateTokenV2);

            Assert.Equal<uint>(2, contextWithUpdateToken.CurrentVersion);
            Assert.Equal(2, contextWithUpdateToken.PheClients.Count);
            Assert.Equal<uint>(2, contextWithUpdateToken.PheClients.Keys.Last<uint>());
        }

        [Fact] // HTC-10
        public void Create_Should_RaiseExceptionIfUpdateTokenVersionIsIncorect()
        {
            // if update token version != current version + 1, then raise exception.
            var ex = Record.Exception(() =>
            {
                ProtocolContext.Create(
                    appToken: this.appToken,
                    servicePublicKey: this.servicePublicKey,
                    appSecretKey: this.clientSecretKey,
                    updateToken: this.updateTokenV3);
            });

            Assert.IsType<WrongVersionException>(ex);
        }

        [Fact]
        public void Create_Should_UsePassw0rdService_AccordingToAppToken()
        {
            var context = ProtocolContext.Create(
                appToken: "PT.SOMETOKEN",
                servicePublicKey: this.servicePublicKey,
                appSecretKey: this.clientSecretKey);
            Assert.Equal(this.passwordServiceUrl, ((HttpClientBase)context.Client).BaseUri.AbsoluteUri);
        }

        [Fact]
        public void Create_Should_UseVirgilService_AccordingToAppToken()
        {
            var contextVirgil = ProtocolContext.Create(
                appToken: "AT.SOMETOKEN",
                servicePublicKey: this.servicePublicKey,
                appSecretKey: this.clientSecretKey);
            Assert.Equal(this.virgilServiceUrl, ((HttpClientBase)contextVirgil.Client).BaseUri.AbsoluteUri);
        }

        [Fact]
        public void Create_Should_RaiseException_IfTokenDoesnHaveCorrectPrefix()
        {
            var ex = Record.Exception(() =>
            {
                ProtocolContext.Create(
                    appToken: "OO.SOMETOKEN",
                    servicePublicKey: this.servicePublicKey,
                    appSecretKey: this.clientSecretKey);
            });

            Assert.IsType<ServiceClientException>(ex);
        }
    }
}
