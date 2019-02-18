namespace Passw0rd.Tests
{
    using System;
    using System.Threading.Tasks;
    using Google.Protobuf;
    using Microsoft.Extensions.Configuration;
    using Passw0rd;
    using Passw0rd.Client;
    using Passw0rd.Client.Connection;
    using Passw0rd.Utils;
    using Xunit;

    public class ProtocolTests
    {
        private string myPassword = "passw9rd";
        private ServiceTestData passw0rdData;
        private ServiceTestData virgilData;

        public ProtocolTests()
        {
            this.passw0rdData = new ServiceTestData("passw0rd");
            this.virgilData = new ServiceTestData("virgilsecurity");
        }

        [Fact] // HTC-1
        public async Task EncrollAccount_Should_GenerateNewRecord()
        {
            await this.EnrollAccount_Should_GenerateNewRecordForService(this.passw0rdData);
            await this.EnrollAccount_Should_GenerateNewRecordForService(this.virgilData);
        }

        [Fact] // HTC-2
        public async Task EncrollAccountWithUpdateToken_Should_GenerateNewRecordWithTokenVersion()
        {
            await this.EncrollAccountWithUpdateToken_Should_GenerateNewRecordWithTokenVersionForService(this.passw0rdData);
            await this.EncrollAccountWithUpdateToken_Should_GenerateNewRecordWithTokenVersionForService(this.virgilData);
        }

        [Fact] // Current logic contradicts HTC-3
        public async Task VerifyPasswordWithWrongPassword_Should_ReturnResultWithEmptyKey()
        {
            await this.VerifyPasswordWithWrongPassword_Should_ReturnResultWithEmptyKeyForService(this.passw0rdData);
            await this.VerifyPasswordWithWrongPassword_Should_ReturnResultWithEmptyKeyForService(this.virgilData);
        }

        [Fact] // HTC-4
        public async Task ProtocolWithWrongServiceKey_Should_RaiseProofOfSuccessNotValidException()
        {
            // you will get ProofOfSuccessNotValidException if try to enroll with wrong servicePublicKey
            await this.ProtocolWithWrongServiceKey_Should_RaiseProofOfSuccessNotValidExceptionForService(this.passw0rdData);
            await this.ProtocolWithWrongServiceKey_Should_RaiseProofOfSuccessNotValidExceptionForService(this.virgilData);
        }

        [Fact] // HTC-5
        public async Task ProtocolWithUpdateToken_Should_VerifyUpdatedRecord()
        {
            await this.ProtocolWithUpdateToken_Should_VerifyUpdatedRecordForService(this.passw0rdData);
            await this.ProtocolWithUpdateToken_Should_VerifyUpdatedRecordForService(this.virgilData);
        }

        [Fact] // HTC-6
        public async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasTheSameVersionAsUpdater()
        {
            await this.Updater_Should_RaiseWrongVersionExceptionIfRecordHasTheSameVersionAsUpdaterForService(this.passw0rdData);
            await this.Updater_Should_RaiseWrongVersionExceptionIfRecordHasTheSameVersionAsUpdaterForService(this.virgilData);
        }

        [Fact] // HTC-7
        public async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasWrongVersion()
        {
            await this.Updater_Should_RaiseWrongVersionExceptionIfRecordHasWrongVersionForService(this.passw0rdData);
            await this.Updater_Should_RaiseWrongVersionExceptionIfRecordHasWrongVersionForService(this.virgilData);
        }

        [Fact] // HTC-11
        public async Task Enroll_Should_RaiseArgumentExceptionIfEmptyPassword()
        {
            await this.Enroll_Should_RaiseArgumentExceptionIfEmptyPasswordForService(this.passw0rdData);
            await this.Enroll_Should_RaiseArgumentExceptionIfEmptyPasswordForService(this.virgilData);
        }

        private async Task Enroll_Should_RaiseArgumentExceptionIfEmptyPasswordForService(ServiceTestData serviceTestData)
        {
            var contextWithUpdateToken = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);
            contextWithUpdateToken.UpdatePheClients(serviceTestData.UpdateTokenV3);
            var protocol = new Protocol(contextWithUpdateToken);

            var ex = await Record.ExceptionAsync(async () =>
            {
                await protocol.EnrollAccountAsync(string.Empty);
            });

            // raise exception
            Assert.IsType<ArgumentException>(ex);
        }

        private ProtocolContext InitContext(string applicationToken, string servicePubKey, string clientPrivKey, string serviceSubdomain)
        {
            var serializer = new HttpBodySerializer();
            var serviceUrl = ServiceUrl.ProvideByToken(applicationToken).Replace("api", serviceSubdomain);
            var client = new PheHttpClient(serializer, applicationToken, serviceUrl);
            var context = new ProtocolContext(applicationToken, client, servicePubKey, clientPrivKey);

            return context;
        }

        private async Task EnrollAccount_Should_GenerateNewRecordForService(ServiceTestData serviceTestData)
        {
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);

            var protocol = new Protocol(context);
            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);
            var rec = DatabaseRecord.Parser.ParseFrom(enrollResult.Record);
            Assert.Equal<uint>(2, rec.Version);
            Assert.NotNull(rec.Record);
            Assert.NotNull(enrollResult.Key);
            Assert.Equal(32, enrollResult.Key.Length);

            System.Threading.Thread.Sleep(4000);

            var result = await protocol.VerifyPasswordAsync(this.myPassword, enrollResult.Record);
            Assert.True(result.IsSuccess);
            Assert.Equal(enrollResult.Key, result.Key);
        }

        private async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasWrongVersionForService(ServiceTestData serviceTestData)
        {
            // you will get exception if record version != (updater version - 1)
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);
            context.UpdatePheClients(serviceTestData.UpdateTokenV3);

            var protocol = new Protocol(context);
            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);
            var databaseRec = DatabaseRecord.Parser.ParseFrom(enrollResult.Record);
            databaseRec.Version = 1;

            var recordUpdater = new RecordUpdater(serviceTestData.UpdateTokenV3);
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

        private async Task EncrollAccountWithUpdateToken_Should_GenerateNewRecordWithTokenVersionForService(ServiceTestData serviceTestData)
        {
            // if token has version =  (keys' version + 1), then database record will have token version
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);
            context.UpdatePheClients(serviceTestData.UpdateTokenV3);

            var protocol = new Protocol(context);

            System.Threading.Thread.Sleep(5000);

            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);
            var rec = DatabaseRecord.Parser.ParseFrom(enrollResult.Record);
            Assert.Equal<uint>(3, rec.Version);
            Assert.NotNull(rec.Record);
            Assert.NotNull(enrollResult.Key);
            Assert.Equal(32, enrollResult.Key.Length);

            var result = await protocol.VerifyPasswordAsync(this.myPassword, enrollResult.Record);
            Assert.True(result.IsSuccess);
            Assert.Equal(enrollResult.Key, result.Key);
        }

        private async Task VerifyPasswordWithWrongPassword_Should_ReturnResultWithEmptyKeyForService(ServiceTestData serviceTestData)
        {
            // you can't verify database record if provide wrong password
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);

            var protocol = new Protocol(context);
            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);

            var result = await protocol.VerifyPasswordAsync("wrong password", enrollResult.Record);
            Assert.False(result.IsSuccess);
            Assert.Null(result.Key);
        }

        private async Task ProtocolWithWrongServiceKey_Should_RaiseProofOfSuccessNotValidExceptionForService(ServiceTestData serviceTestData)
        {
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);

            var contextWithWrongServerKey = this.InitContext(
                serviceTestData.AppToken,
                "PK.2.BK6oQNcAEyMc0fmc7coHbaQHqwoYPTiIM6A4393wEE9vRbCeUjKZSHzluHI80bGhJ61/eg1SUZNtgmMie4U80gI=",
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);

            System.Threading.Thread.Sleep(5000);

            var protocol = new Protocol(context);
            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);

            var protocolWithWrongServerKey = new Protocol(contextWithWrongServerKey);
            var ex = await Record.ExceptionAsync(async () =>
            {
                await protocolWithWrongServerKey.EnrollAccountAsync(this.myPassword);
            });

            Assert.IsType<ProofOfSuccessNotValidException>(ex);

            var ex2 = await Record.ExceptionAsync(async () =>
            {
                await protocolWithWrongServerKey.VerifyPasswordAsync(this.myPassword, enrollResult.Record);
            });

            Assert.IsType<ProofOfSuccessNotValidException>(ex2);
        }

        private async Task ProtocolWithUpdateToken_Should_VerifyUpdatedRecordForService(ServiceTestData serviceTestData)
        {
            // you can verify updated record if context has updateToken with equal version
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);

            var contextWithUpdateToken = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);
            contextWithUpdateToken.UpdatePheClients(serviceTestData.UpdateTokenV3);

            var protocol = new Protocol(context);
            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);

            Assert.Equal<uint>(2, DatabaseRecord.Parser.ParseFrom(enrollResult.Record).Version);

            var recordUpdater = new RecordUpdater(serviceTestData.UpdateTokenV3);
            var updatedRecBytes = recordUpdater.Update(enrollResult.Record);

            Assert.Equal<uint>(3, DatabaseRecord.Parser.ParseFrom(updatedRecBytes).Version);
            var protocolWithUpdateToken = new Protocol(contextWithUpdateToken);

            var result = await protocol.VerifyPasswordAsync(this.myPassword, enrollResult.Record);
            var result2 = await protocolWithUpdateToken.VerifyPasswordAsync(this.myPassword, updatedRecBytes);
            Assert.Equal(enrollResult.Key, result.Key);
            Assert.Equal(enrollResult.Key, result2.Key);
        }

        private async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasTheSameVersionAsUpdaterForService(ServiceTestData serviceTestData)
        {
            // you will get exception if record version == updater version
            var context = this.InitContext(
                serviceTestData.AppToken,
                serviceTestData.ServicePublicKey2,
                serviceTestData.ClientSecretKey2,
                serviceTestData.ServiceSubdomain);
            context.UpdatePheClients(serviceTestData.UpdateTokenV3);

            var protocol = new Protocol(context);
            var enrollResult = await protocol.EnrollAccountAsync(this.myPassword);
            Assert.Equal<uint>(3, DatabaseRecord.Parser.ParseFrom(enrollResult.Record).Version);

            var recordUpdater = new RecordUpdater(serviceTestData.UpdateTokenV3);

            var ex = Record.Exception(() =>
            {
                recordUpdater.Update(enrollResult.Record);
            });

            Assert.IsType<WrongVersionException>(ex);
        }
    }
}
