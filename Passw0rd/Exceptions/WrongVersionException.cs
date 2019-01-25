using System;
namespace Passw0rd
{
    public class WrongVersionException : Passw0rdProtocolException
    {
        public WrongVersionException(string message) : base(message)
        {
        }
    }
}