namespace Passw0rd.Tests
{
    using System;
    using System.Threading.Tasks;
    using Google.Protobuf;
    using Microsoft.Extensions.Configuration;
    using Passw0Rd;
    using Passw0rd.Client;
    using Passw0rd.Client.Connection;
    using Xunit;

    public class ProtocolTests
    {
        private string appToken;
        private string servicePublicKey;
        private string clientSecretKey;
        private string clientSecretKey2;
        private string servicePublicKey2;
        private string myPassword = "passw9rd";
        private string updateTokenV2;
        private string updateTokenV3;
        private string serviceAddress;
        private string serviceSubdomain;

        public ProtocolTests()
        {
            IConfigurationRoot configuration = new ConfigurationBuilder().AddJsonFile("appsettings.json", optional: true).Build();
            this.appToken = configuration["AppToken"];
            this.servicePublicKey = configuration["ServicePublicKey"];
            this.clientSecretKey = configuration["ClientSecretKey"];
            this.clientSecretKey2 = configuration["ClientSecretKey2"];
            this.servicePublicKey2 = configuration["ServicePublicKey2"];
            this.updateTokenV2 = configuration["UpdateTokenV2"];
            this.updateTokenV3 = configuration["UpdateTokenV3"];
            this.serviceAddress = configuration["ServiceAddress"];
            this.serviceSubdomain = configuration["ServiceSubdomain"];
        }

        [Fact] // HTC-1
        public async Task EncrollAccount_Should_GenerateNewRecord()
        {
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);
            var rec = DatabaseRecord.Parser.ParseFrom(recBytes);
            Assert.Equal<uint>(2, rec.Version);
            Assert.NotNull(rec.Record);
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);

            System.Threading.Thread.Sleep(4000);

            var accountKey = await protocol.VerifyPasswordAsync(this.myPassword, recBytes);
            Assert.Equal(key, accountKey);
        }

        [Fact] // HTC-2
        public async Task EncrollAccountWithUpdateToken_Should_GenerateNewRecordWithTokenVersion()
        {
            // if token has version =  (keys' version + 1), then database record will have token version
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);
            context.UpdatePheClients(this.updateTokenV3);

            var protocol = new Protocol(context);

            System.Threading.Thread.Sleep(5000);

            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);
            var rec = DatabaseRecord.Parser.ParseFrom(recBytes);
            Assert.Equal<uint>(3, rec.Version);
            Assert.NotNull(rec.Record);
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);

            var accountKey = await protocol.VerifyPasswordAsync(this.myPassword, recBytes);
            Assert.Equal(key, accountKey);
        }

        [Fact] // HTC-3
        public async Task VerifyPasswordWithWrongPassword_Should_RaiseWrongPasswordException()
        {
            // you can't verify database record if provide wrong password
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);
            var ex = await Record.ExceptionAsync(async () =>
            {
                await protocol.VerifyPasswordAsync("wrong password", recBytes);
            });

            Assert.IsType<WrongPasswordException>(ex);
        }

        [Fact] // HTC-4
        public async Task ProtocolWithWrongServiceKey_Should_RaiseProofOfSuccessNotValidException()
        {
            // you will get ProofOfSuccessNotValidException if try to enroll with wrong servicePublicKey
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);

            var contextWithWrongServerKey = this.InitContext(this.appToken, "PK.2.BK6oQNcAEyMc0fmc7coHbaQHqwoYPTiIM6A4393wEE9vRbCeUjKZSHzluHI80bGhJ61/eg1SUZNtgmMie4U80gI=", this.clientSecretKey2);

            System.Threading.Thread.Sleep(5000);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);

            var protocolWithWrongServerKey = new Protocol(contextWithWrongServerKey);
            var ex = await Record.ExceptionAsync(async () =>
            {
                await protocolWithWrongServerKey.EnrollAccountAsync(this.myPassword);
            });

            Assert.IsType<ProofOfSuccessNotValidException>(ex);

            var ex2 = await Record.ExceptionAsync(async () =>
            {
                await protocolWithWrongServerKey.VerifyPasswordAsync(this.myPassword, recBytes);
            });

            Assert.IsType<ProofOfSuccessNotValidException>(ex2);
        }

        [Fact] // HTC-5
        public async Task ProtocolWithUpdateToken_Should_VerifyUpdatedRecord()
        {
            // you can verify updated record if context has updateToken with equal version
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);

            var contextWithUpdateToken = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);
            contextWithUpdateToken.UpdatePheClients(this.updateTokenV3);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);

            Assert.Equal<uint>(2, DatabaseRecord.Parser.ParseFrom(recBytes).Version);

            var recordUpdater = new RecordUpdater(this.updateTokenV3);
            var updatedRecBytes = recordUpdater.Update(recBytes);

            Assert.Equal<uint>(3, DatabaseRecord.Parser.ParseFrom(updatedRecBytes).Version);
            var protocolWithUpdateToken = new Protocol(contextWithUpdateToken);

            var recBytesKey = await protocol.VerifyPasswordAsync(this.myPassword, recBytes);
            var keyFromVerify = await protocolWithUpdateToken.VerifyPasswordAsync(this.myPassword, updatedRecBytes);
            Assert.Equal(key, recBytesKey);
            Assert.Equal(key, keyFromVerify);
        }

        [Fact] // HTC-6
        public async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasTheSameVersionAsUpdater()
        {
            // you will get exception if record version == updater version
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);
            context.UpdatePheClients(this.updateTokenV3);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);
            Assert.Equal<uint>(3, DatabaseRecord.Parser.ParseFrom(recBytes).Version);

            var recordUpdater = new RecordUpdater(this.updateTokenV3);

            var ex = Record.Exception(() =>
            {
                recordUpdater.Update(recBytes);
            });

            Assert.IsType<WrongVersionException>(ex);
        }

        [Fact] // HTC-7
        public async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasWrongVersion()
        {
            // you will get exception if record version != (updater version - 1)
            var context = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);
            context.UpdatePheClients(this.updateTokenV3);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(this.myPassword);
            var databaseRec = DatabaseRecord.Parser.ParseFrom(recBytes);
            databaseRec.Version = 1;

            var recordUpdater = new RecordUpdater(this.updateTokenV3);
            var ex = Record.Exception(() =>
            {
                recordUpdater.Update(databaseRec.ToByteArray());
            });
            Assert.IsType<WrongVersionException>(ex);

            var ex2 = await Record.ExceptionAsync(async () =>
            {
                await protocol.VerifyPasswordAsync(this.myPassword, databaseRec.ToByteArray());
            });

            Assert.IsType<WrongVersionException>(ex2);
        }

        [Fact] // HTC-11
        public async Task Enroll_Should_RaiseArgumentExceptionIfEmptyPassword()
        {
            var contextWithUpdateToken = this.InitContext(this.appToken, this.servicePublicKey2, this.clientSecretKey2);
            contextWithUpdateToken.UpdatePheClients(this.updateTokenV3);
            var protocol = new Protocol(contextWithUpdateToken);

            var ex = await Record.ExceptionAsync(async () =>
            {
                await protocol.EnrollAccountAsync(string.Empty);
            });

            // raise exception
            Assert.IsType<ArgumentException>(ex);
        }

        private ProtocolContext InitContext(string applicationToken, string servicePubKey, string clientPrivKey)
        {
            var serializer = new HttpBodySerializer();
            var serviceUrl = ServiceUrl.ProvideByToken(applicationToken).Replace("api", this.serviceSubdomain);
            var client = new PheHttpClient(serializer, applicationToken, serviceUrl);
            var context = new ProtocolContext(applicationToken, client, servicePubKey, clientPrivKey);

            return context;
        }
    }
}
