using System;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TpmEkManaged
{
    class Program
    {
        static void Main(string[] args)
        {
            X509Certificate2 cert = new X509Certificate2(args[0]);
            SHA256 sha = new SHA256CryptoServiceProvider();
            byte[] result = sha.ComputeHash(cert.GetPublicKey());
            SoapHexBinary shb = new SoapHexBinary(result);
            Console.WriteLine(shb.ToString());
        }
    }
}
