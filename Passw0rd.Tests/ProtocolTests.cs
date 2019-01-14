namespace Passw0rd.Tests
{
    using System.Threading.Tasks;
    using Xunit;

    public class ProtocolTests
    {
        [Fact]
        public async Task Should_EnrollNewRecord_When_PasswordSpecified()
        {
            var context = ProtocolContext.Create(
                appToken: "e60e6d91b0e3480b816f306337e96aaa",
                accessToken: "-rTsFFkAOGf6am4bEF_aAdoHt2kOGy78",
                serverPublicKey: "PK.1.BJ2+TUK/WVTfuYjgKj0KOVH4nKUqdBihqhH/EN1fyggwATu4gzGMC0P35jBDZnSTEFdm2zmC4qndyI5MKBvFjX8=",
                clientSecretKey: "SK.1.W7FVp+LhG/ton7P+wKu0ndIPECY5+mTzX7iWaW9+sXA="
            );

            var protocol = new Protocol(context);

            var record = await protocol.EnrollAsync("passw0rd");

            await Task.Delay(2000);
            
            var verifyResult = await protocol.VerifyAsync(record, "passw0rd");

            var context1 = ProtocolContext.Create(
                appToken: "e60e6d91b0e3480b816f306337e96aaa",
                accessToken: "-rTsFFkAOGf6am4bEF_aAdoHt2kOGy78",
                serverPublicKey: "PK.1.BJ2+TUK/WVTfuYjgKj0KOVH4nKUqdBihqhH/EN1fyggwATu4gzGMC0P35jBDZnSTEFdm2zmC4qndyI5MKBvFjX8=",
                clientSecretKey: "SK.1.W7FVp+LhG/ton7P+wKu0ndIPECY5+mTzX7iWaW9+sXA=",
                updateToken: new[] {
                    "UT.2.MEQEIGw7O3Hm/9rSUBrShEFKiQQk8yi39TnGS7dpUP9/8aQiBCBhp5NxCylYeCpJq/hjK2SuTiA9Pl8zD8BZUDau6B72Ag=="
                }
            );

            var protocol1 = new Protocol(context1);

            var record1 = protocol1.Update(record);

            await Task.Delay(2000);

            var verifyResult1 = await protocol1.VerifyAsync(record1, "passw0rd");

            Assert.True(verifyResult.IsSuccess);
        }
    }
}
