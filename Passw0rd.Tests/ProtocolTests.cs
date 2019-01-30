namespace Passw0rd.Tests
{
    using System;
    using System.Configuration;
    using System.Linq;
    using System.Threading.Tasks;
    using Google.Protobuf;
    using Microsoft.Extensions.Configuration;
    using Moq;
    using NSubstitute;
    using Passw0rd.Phe;
    using Passw0rd.Utils;
    using Passw0Rd;
    using Phe;
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

        public ProtocolTests(){
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
        [Fact] //HTC-1
        public async Task EncrollAccount_Should_GenerateNewRecord()
        {
           // var a = configuration["AppToken"];
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress);
            
            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);
            var rec = DatabaseRecord.Parser.ParseFrom(recBytes);
            Assert.Equal<uint>(2, rec.Version);
            Assert.NotNull(rec.Record);
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);

            System.Threading.Thread.Sleep(4000);

            var accountKey = await protocol.VerifyPasswordAsync(myPassword, recBytes);
            Assert.Equal(key, accountKey);
        }

        [Fact] //HTC-2
        public async Task EncrollAccountWithUpdateToken_Should_GenerateNewRecordWithTokenVersion()
        {
            // if token has version =  (keys' version + 1), then database record will have token version
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress,
                updateToken: updateTokenV3);
            
           // var pwd = Bytes.ToString(myPassword, StringEncoding.UTF8);
            var protocol = new Protocol(context);
           
            System.Threading.Thread.Sleep(5000);

            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);
            var rec = DatabaseRecord.Parser.ParseFrom(recBytes);
            Assert.Equal<uint>(3, rec.Version);
            Assert.NotNull(rec.Record);
            Assert.NotNull(key);
            Assert.Equal(32, key.Length);

            var accountKey = await protocol.VerifyPasswordAsync(myPassword, recBytes);
            Assert.Equal(key, accountKey);
        }

        [Fact] //HTC-3
        public async Task VerifyPasswordWithWrongPassword_Should_RaiseWrongPasswordException()
        {
            // you can't verify database record if provide wrong password
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress);
            // var pwd = Bytes.ToString(myPassword, StringEncoding.UTF8);
            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);
            var ex = await Record.ExceptionAsync( async() => { 
                 await protocol.VerifyPasswordAsync("wrong password", recBytes); });

            Assert.IsType<WrongPasswordException>(ex); 
        }

        
        [Fact] //HTC-4
        public async Task ProtocolWithWrongServiceKey_Should_RaiseProofOfSuccessNotValidException()
        {
            // you will get ProofOfSuccessNotValidException if try to enroll with wrong servicePublicKey
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress);
             var contextWithWrongServerKey = ProtocolContext.Create(
               appToken: appToken,
                servicePublicKey: "PK.2.BK6oQNcAEyMc0fmc7coHbaQHqwoYPTiIM6A4393wEE9vRbCeUjKZSHzluHI80bGhJ61/eg1SUZNtgmMie4U80gI=",
               clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress);

            System.Threading.Thread.Sleep(5000);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);

            var protocolWithWrongServerKey = new Protocol(contextWithWrongServerKey);
            var ex = await Record.ExceptionAsync( async() => { 
                await protocolWithWrongServerKey.EnrollAccountAsync(myPassword); });

            Assert.IsType<ProofOfSuccessNotValidException>(ex); 

            var ex2 = await Record.ExceptionAsync( async() => { 
                await protocolWithWrongServerKey.VerifyPasswordAsync(myPassword, recBytes); });

            Assert.IsType<ProofOfSuccessNotValidException>(ex2); 
        }


        [Fact] //HTC-5
        public async Task ProtocolWithUpdateToken_Should_VerifyUpdatedRecord()
        {
            // you can verify updated record if context has updateToken with equal version
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress);
            
            var contextWithUpdateToken = ProtocolContext.Create(
              appToken: appToken,
              servicePublicKey: servicePublicKey2,
              clientSecretKey: clientSecretKey2,
              apiUrl: serviceAddress,
              updateToken: updateTokenV3);

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);

            Assert.Equal<uint>(2, DatabaseRecord.Parser.ParseFrom(recBytes).Version);

            var recordUpdater = new RecordUpdater(updateTokenV3);
            var updatedRecBytes = recordUpdater.Update(recBytes);

            Assert.Equal<uint>(3, DatabaseRecord.Parser.ParseFrom(updatedRecBytes).Version); 
            var protocolWithUpdateToken = new Protocol(contextWithUpdateToken);

            var recBytesKey = await protocol.VerifyPasswordAsync(myPassword, recBytes);
            var keyFromVerify = await protocolWithUpdateToken.VerifyPasswordAsync(myPassword, updatedRecBytes);
            Assert.Equal(key, recBytesKey);
            Assert.Equal(key, keyFromVerify);
        }


        [Fact] //HTC-6
        public async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasTheSameVersionAsUpdater()
        {
            // you will get exception if record version == updater version
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
               updateToken: updateTokenV3,
                apiUrl: serviceAddress);


            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);
            Assert.Equal<uint>(3, DatabaseRecord.Parser.ParseFrom(recBytes).Version); 

            var recordUpdater = new RecordUpdater(updateTokenV3);

            var ex = Record.Exception( () => { 
                recordUpdater.Update(recBytes); });

            Assert.IsType<WrongVersionException>(ex); 
        }

        [Fact] //HTC-7
        public async Task Updater_Should_RaiseWrongVersionExceptionIfRecordHasWrongVersion()
        {
            // you will get exception if record version != (updater version - 1) 
            var context = ProtocolContext.Create(
               appToken: appToken,
               servicePublicKey: servicePublicKey2,
               clientSecretKey: clientSecretKey2,
               updateToken: updateTokenV3,
                apiUrl: serviceAddress);
            

            var protocol = new Protocol(context);
            var (recBytes, key) = await protocol.EnrollAccountAsync(myPassword);
            var databaseRec = DatabaseRecord.Parser.ParseFrom(recBytes);
            databaseRec.Version = 1;


            var recordUpdater = new RecordUpdater(updateTokenV3);
            var ex = Record.Exception( () => {
                recordUpdater.Update(databaseRec.ToByteArray()); });
            Assert.IsType<WrongVersionException>(ex); 

            var ex2 = await Record.ExceptionAsync( async() => { 
                await protocol.VerifyPasswordAsync(myPassword, databaseRec.ToByteArray()); });

            Assert.IsType<WrongVersionException>(ex2); 
        }


        [Fact] //HTC-11
        public async Task Enroll_Should_RaiseArgumentExceptionIfEmptyPassword()
        {
            var contextWithUpdateToken = ProtocolContext.Create(
              appToken: appToken,
              servicePublicKey: servicePublicKey2,
              clientSecretKey: clientSecretKey2,
                apiUrl: serviceAddress,
                updateToken: updateTokenV3);

            var protocol = new Protocol(contextWithUpdateToken);

            var ex = await Record.ExceptionAsync( async() => { 
                await protocol.EnrollAccountAsync(""); });

            Assert.IsType<ArgumentException>(ex); 
            //raise exception
        }
    }
}
