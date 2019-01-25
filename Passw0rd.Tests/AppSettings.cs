using System;
using System.Configuration;

namespace Passw0rd.Tests
{
    public class AppSettings
    {
        static AppSettings()
        {
        }
        public static string AppToken = ConfigurationManager.AppSettings["AppToken"];
        public static string ServicePublicKey = ConfigurationManager.AppSettings["ServicePublicKey"];
        public static string ClientSecretKey = ConfigurationManager.AppSettings["ClientSecretKey"];
        public static string ClientSecretKey2 = ConfigurationManager.AppSettings["ClientSecretKey2"];
        public static string ServicePublicKey2 = ConfigurationManager.AppSettings["ServicePublicKey2"];
        public static string UpdateTokenV2 = ConfigurationManager.AppSettings["UpdateTokenV2"];
        public static string UpdateTokenV3 = ConfigurationManager.AppSettings["UpdateTokenV3"];

    }
}
