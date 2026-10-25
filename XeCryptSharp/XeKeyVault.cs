using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Cryptography;
using System.Text;

namespace XeCryptSharp
{
    public class XeKeyVault
    {
        public string SerialNumber { get; private set; }
        public XeConsoleCert ConsoleCert { get; private set; }

        public XeConsoleID ConsoleID
        {
            get
            {
                return ConsoleCert.ConsoleID;
            }
        }

        public DateTime MfrDate
        {
            get
            {
                return ConsoleCert.MfrDate;
            }
        }

        private Dictionary<XeKey, byte[]> _keyVault = new Dictionary<XeKey, byte[]>();
        public byte[] GetKey(XeKey type)
        {
            if (!_keyVault.ContainsKey(type))
                throw new Exception($"Key vault does not have {type}");
            return _keyVault[type];
        }

        private void ReadKeyFromStream(Stream s, XeKey type, int length)
        {
            byte[] newKey = new byte[length];
            if (s.Read(newKey, 0, length) != length)
                throw new Exception($"Failed to read key {type} from keyvault stream (0x{s.Position})");
            _keyVault[type] = newKey;
        }

        private void LoadKVFromStream(Stream s, bool hashed = false)
        {
            if (hashed)
                s.Position += 0x10; // skip over the hash
            // TODO: verify hash from CPU key if we are given one
            // TODO: clean this the fuck up
            s.Position += 0x8; // TODO: what's this again
            ReadKeyFromStream(s, XeKey.ManufacturingMode, 0x1);
            ReadKeyFromStream(s, XeKey.AlternateKeyVault, 0x1);
            ReadKeyFromStream(s, XeKey.RestrictedPrivilegesFlags, 0x1);
            ReadKeyFromStream(s, XeKey.ReservedByte3, 0x1);
            ReadKeyFromStream(s, XeKey.ODDFeatures, 0x2);
            ReadKeyFromStream(s, XeKey.ODDAuthType, 0x2);
            ReadKeyFromStream(s, XeKey.RestrictedHVExtLoader, 0x4);
            ReadKeyFromStream(s, XeKey.PolicyFlashSize, 0x4);
            ReadKeyFromStream(s, XeKey.PolicyBuiltInMUSize, 0x4);
            ReadKeyFromStream(s, XeKey.ReservedDword4, 0x4);
            ReadKeyFromStream(s, XeKey.RestrictedPrivileges, 0x8);
            ReadKeyFromStream(s, XeKey.ReservedQword2, 0x8);
            ReadKeyFromStream(s, XeKey.ReservedQword3, 0x8);
            ReadKeyFromStream(s, XeKey.ReservedQword4, 0x8);
            ReadKeyFromStream(s, XeKey.ReservedKey1, 0x10);
            ReadKeyFromStream(s, XeKey.ReservedKey2, 0x10);
            ReadKeyFromStream(s, XeKey.ReservedKey3, 0x10);
            ReadKeyFromStream(s, XeKey.ReservedKey4, 0x10);
            ReadKeyFromStream(s, XeKey.ReservedRandomKey1, 0x10);
            ReadKeyFromStream(s, XeKey.ReservedRandomKey2, 0x10);
            ReadKeyFromStream(s, XeKey.ConsoleSerialNumber, 0xC);
            ReadKeyFromStream(s, XeKey.BoardSerialNumber, 0xC);
            ReadKeyFromStream(s, XeKey.GameRegion, 0x2);
            s.Position += 0x6; // padding
            ReadKeyFromStream(s, XeKey.ConsoleObfuscationKey, 0x10);
            ReadKeyFromStream(s, XeKey.KeyObfuscationKey, 0x10);
            ReadKeyFromStream(s, XeKey.RoamableObfuscationKey, 0x10);
            ReadKeyFromStream(s, XeKey.DVDKey, 0x10);
            ReadKeyFromStream(s, XeKey.PrimaryActivationKey, 0x18);
            ReadKeyFromStream(s, XeKey.SecondaryActivationKey, 0x10);
            ReadKeyFromStream(s, XeKey.GlobalDeviceKey1, 0x10);
            ReadKeyFromStream(s, XeKey.GlobalDeviceKey2, 0x10);
            ReadKeyFromStream(s, XeKey.WirelessControllerMSKey1, 0x10);
            ReadKeyFromStream(s, XeKey.WirelessControllerMSKey2, 0x10);
            ReadKeyFromStream(s, XeKey.WiredWebcamMSKey1, 0x10);
            ReadKeyFromStream(s, XeKey.WiredWebcamMSKey2, 0x10);
            ReadKeyFromStream(s, XeKey.WiredControllerMSKey1, 0x10);
            ReadKeyFromStream(s, XeKey.WiredControllerMSKey2, 0x10);
            ReadKeyFromStream(s, XeKey.MemoryUnitMSKey1, 0x10);
            ReadKeyFromStream(s, XeKey.MemoryUnitMSKey2, 0x10);
            ReadKeyFromStream(s, XeKey.OtherDeviceMSKey1, 0x10);
            ReadKeyFromStream(s, XeKey.OtherDeviceMSKey2, 0x10);
            ReadKeyFromStream(s, XeKey.WirelessController3PKey1, 0x10);
            ReadKeyFromStream(s, XeKey.WirelessController3PKey2, 0x10);
            ReadKeyFromStream(s, XeKey.WiredWebcam3PKey1, 0x10);
            ReadKeyFromStream(s, XeKey.WiredWebcam3PKey2, 0x10);
            ReadKeyFromStream(s, XeKey.WiredController3PKey1, 0x10);
            ReadKeyFromStream(s, XeKey.WiredController3PKey2, 0x10);
            ReadKeyFromStream(s, XeKey.MemoryUnit3PKey1, 0x10);
            ReadKeyFromStream(s, XeKey.MemoryUnit3PKey2, 0x10);
            ReadKeyFromStream(s, XeKey.OtherDevice3PKey1, 0x10);
            ReadKeyFromStream(s, XeKey.OtherDevice3PKey2, 0x10);
            ReadKeyFromStream(s, XeKey.ConsolePrivateKey, 0x1D0);
            ReadKeyFromStream(s, XeKey.XeikaPrivateKey, 0x390);
            ReadKeyFromStream(s, XeKey.CardeaPrivateKey, 0x1D0);
            ReadKeyFromStream(s, XeKey.ConsoleCertificate, 0x1A8);
            ReadKeyFromStream(s, XeKey.XeikaCertificate, 0x1288);
            s.Position += 0x100; // XEKEY_SPECIAL_KEY_VAULT_SIGNATURE
            ReadKeyFromStream(s, XeKey.CardeaCertificate, 0x2108);

            // parse some of the stuff
            ConsoleCert = new XeConsoleCert(_keyVault[XeKey.ConsoleCertificate]);
            SerialNumber = Encoding.ASCII.GetString(_keyVault[XeKey.ConsoleSerialNumber]);
        }

        public XeKeyVault(Stream stream, bool hashed = false)
        {
            LoadKVFromStream(stream, hashed);
        }

        public XeKeyVault(byte[] kvData)
        {
            if (kvData.Length != 0x3FF0 && kvData.Length != 0x4000)
                throw new Exception("Invalid key vault length");

            bool hashed = kvData.Length == 0x4000;
            using (MemoryStream ms = new MemoryStream(kvData))
                LoadKVFromStream(ms, hashed);
        }

        public RSAParameters GetConsoleRSAKey()
        {
            return Utils.XeCryptToRSA(_keyVault[XeKey.ConsolePrivateKey], true);
        }
    }
}
