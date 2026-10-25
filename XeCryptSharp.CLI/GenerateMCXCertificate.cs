// not part of the main XeCryptSharp library because it's to do with a non-XeCrypt part of the system
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace XeCryptSharp.CLI;

class XeMCXCertificate
{
    // Generates a Windows Media Center Extender certificate + private key from a given console KV and MAC
    // Useful if trying to make a client to connect to the server
    public static X509Certificate2 MediaCenterCertFromKV(XeKeyVault kv, byte[] consoleMAC)
    {
        // create a serial number + UUID from the console MAC
        byte[] serial = [ 0, 0, 0, 0, 0, 0, 0, 0x01 ];
        string uuid = $"uuid:20000000-0000-0000-0200-{BitConverter.ToString(consoleMAC).Replace("-", "")}"; // UUID for the remoted experience service
        Buffer.BlockCopy(consoleMAC, 0, serial, 0, 0x6);
        // import the console's private key 
        RSA rsa = RSA.Create();
        rsa.ImportParameters(kv.GetConsoleRSAKey());

        // build our certificate request
        CertificateRequest req = new(new X500DistinguishedName("CN=Microsoft XBOX 360"), rsa, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        // add the UUID as the SAN
        SubjectAlternativeNameBuilder sanBuilder = new();
        sanBuilder.AddUri(new Uri(uuid));
        req.CertificateExtensions.Add(sanBuilder.Build());
        // add the key usage extensions
        X509KeyUsageFlags flags = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.DataEncipherment;
        req.CertificateExtensions.Add(new X509KeyUsageExtension(flags, false));
        OidCollection usageOid = new()
        {
            new Oid("1.3.6.1.5.5.7.3.2"), // Client Authentication
            new Oid("1.3.6.1.4.1.311.10.5.12") // Windows Media Center Extender?
        };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usageOid, false));
        // Windows Media Center Extender Xbox360 Console Certificate?
        req.CertificateExtensions.Add(new X509Extension(new Oid("1.3.6.1.4.1.311.55.1.1"), kv.GetKey(XeKey.ConsoleCertificate), false));

        // set the validity period to what the MCX XEX does
        // expired but this has no effect on usability, this is just to create a 1:1 matching certificate
        DateTimeOffset notBefore = DateTimeOffset.ParseExact("051116184441Z", "yyMMddHHmmssZ", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);
        DateTimeOffset notAfter = DateTimeOffset.ParseExact("251116150003Z", "yyMMddHHmmssZ", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal);

        // create a signature generator so we can make a self-signed cert with a custom serial
        // modern .NET gets really sad when we try using SHA1, so custom class to work around it
        X509SignatureGeneratorSHA1 signer = new(rsa);
        X509Certificate2 cert = req.Create(req.SubjectName, signer, notBefore, notAfter, serial);
        return cert.CopyWithPrivateKey(rsa);
    }
}

// Helper class because the base X509SignatureGenerator turns its nose up at SHA-1
class X509SignatureGeneratorSHA1 : X509SignatureGenerator
{
    private readonly X509SignatureGenerator _base;

    internal X509SignatureGeneratorSHA1(RSA rsa)
    {
        _base = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
    }

    protected override PublicKey BuildPublicKey()
    {
        return _base.PublicKey;
    }

    public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
    {
        return _base.SignData(data, HashAlgorithmName.SHA1);
    }

    public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
    {
        // sha1WithRSA (1.3.14.3.2.29)
        return [ 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1d, 0x05, 0x00 ];
    }
}
