using System;
namespace Passw0rd
{
    public class WrongPasswordException : Passw0rdProtocolException
    {
        public WrongPasswordException(string message) : base(message)
        {
        }
    }
}