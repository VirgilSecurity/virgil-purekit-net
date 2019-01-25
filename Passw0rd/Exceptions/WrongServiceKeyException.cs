using System;
namespace Passw0rd
{
    public class WrongServiceKeyException : Passw0rdProtocolException
    {
        public WrongServiceKeyException(string message) : base(message)
        {
        }
    }
}
