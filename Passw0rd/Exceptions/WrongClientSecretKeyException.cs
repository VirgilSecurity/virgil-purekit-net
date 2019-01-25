using System;
namespace Passw0rd
{
    public class WrongClientSecretKeyException: Passw0rdProtocolException
    {
        public WrongClientSecretKeyException(string message) : base(message)
        {
        }
    }
}
