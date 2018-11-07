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
                appId: "58533793ee4f41bf9fcbf178dbac9b3a",
                accessToken: "-KM2dB9-butQv1Op6l0L5TEFy2fL-zty",
                serverPublicKey: "BFFiWkunWRuVMvJVybtCOZEReUui5V3NmwY21doyxoFlurSYEo1fwSW22mQ8ZPq9pUWVm1rvYhF294wstqu//a4=",
                clientSecretKey: "YEwMBsXkJ5E5Mb9VKD+pu+gRXOySZXWaRXvkFebRYOc="
            );

            var protocol = new Protocol(context);
            var record = await protocol.EnrollAsync("passw0rd");
        }
    }
}
