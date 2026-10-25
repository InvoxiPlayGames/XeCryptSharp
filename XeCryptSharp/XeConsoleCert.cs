using System;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace XeCryptSharp
{
    [Flags]
    public enum ConsoleType : uint
    {
        Devkit = 0x1,
        Retail = 0x2,
        Testkit = 0x40000000,
        Recovered = 0x80000000
    }
    public class XeConsoleCert
    {
        public XeConsoleID ConsoleID { get; private set; }
        public string PartNumber { get; private set; }
        public ushort Privileges { get; private set; }
        public ConsoleType ConsoleType { get; private set; }
        public DateTime MfrDate { get; private set; }
        public RSAParameters PublicKey { get; private set; }

        public XeConsoleCert(byte[] certData)
        {
            if (certData.Length != 0x1A8)
                throw new Exception("Invalid data length for console certificate");
            ushort length = Utils.ToUInt16BE(certData, 0);
            if (length != 0x1A8)
                throw new Exception("Invalid provided length for console certificate");
            ConsoleID = new XeConsoleID(certData.Skip(0x2).Take(0x5));
            PartNumber = Encoding.ASCII.GetString(certData, 0x7, 11);
            Privileges = Utils.ToUInt16BE(certData, 0x16);
            ConsoleType = (ConsoleType)Utils.ToUInt32BE(certData, 0x18);
            string mfrDateString = Encoding.ASCII.GetString(certData, 0x1C, 0x8);
            MfrDate = DateTime.ParseExact(mfrDateString, "MM-dd-yy", CultureInfo.InvariantCulture, DateTimeStyles.None);
            // convert the public key to RSA parameters
            PublicKey = new RSAParameters
            {
                Exponent = certData.Skip(0x24).Take(0x4).ToArray(), // BE is fine here
                Modulus = Utils.SwapBy8(certData.Skip(0x28).Take(0x80))
            };
            // 0x100 @ 0xA8 is the signature against Microsoft key
            // TODO: implement checking against this key
        }
    }
}
