using System;
namespace Passw0rd
{
    internal static class Validation
    {
        public static void NotNull(object obj, string message = null)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(message, nameof(obj));
            }
        }


        public static void NotNullOrWhiteSpace(string obj, string message = null)
        {
            if (String.IsNullOrWhiteSpace(obj))
            {
                throw new ArgumentException(message, nameof(obj));
            }
        }

        public static void NotNullOrEmptyByteArray(byte[] obj, string message = null)
        {
            if (obj == null || obj.Length == 0)
            {
                throw new ArgumentException(message, nameof(obj));
            }
        }

    }
}


