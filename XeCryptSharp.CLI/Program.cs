using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using XeCryptSharp;
using XeCryptSharp.CLI;

static XeKeyVault LoadKVFromFile(string file)
{
    FileStream fs = File.OpenRead("KV.bin");
    if (fs.Length != 0x3FF0 && fs.Length != 0x4000)
        throw new Exception("Invalid key vault length");
    XeKeyVault kv = new(fs, fs.Length == 0x4000);
    return kv;
}

static void KVInfo(string file)
{
    XeKeyVault kv = LoadKVFromFile(file);
    Console.WriteLine($"Serial Number: {kv.SerialNumber}");
    Console.WriteLine($"Console ID: {kv.ConsoleID}");
    Console.WriteLine($"Console Type: {kv.ConsoleCert.ConsoleType}");
    Console.WriteLine($"Part Number: {kv.ConsoleCert.PartNumber}");
    Console.WriteLine($"Manufacture Date: {kv.ConsoleCert.MfrDate}");
}

static void MCXCert(string file, string mac, string outDir)
{
    Directory.CreateDirectory(outDir);
    byte[] macbytes = Convert.FromHexString(mac.Replace(":", "").Replace("-", "")); // try to "normalise" mac before converting
    XeKeyVault kv = LoadKVFromFile(file);
    var cert = XeMCXCertificate.MediaCenterCertFromKV(kv, macbytes);
    string outPub = Path.Join(outDir, $"{kv.ConsoleID}_mcx.pem");
    string outPrv = Path.Join(outDir, $"{kv.ConsoleID}_prv.pem");
    File.WriteAllText(outPub, cert.ExportCertificatePem());
    File.WriteAllText(outPrv, cert.GetRSAPrivateKey()!.ExportRSAPrivateKeyPem());
    Console.WriteLine("Generated Windows Media Center Extender certificates!");
    Console.WriteLine($"Certificate saved to '{outPub}'");
    Console.WriteLine($"Private key saved to '{outPrv}'");
    Console.WriteLine("/!\\ Don't send the private key to anyone!");
}

if (args.Length < 1)
{
    Console.WriteLine("available commands:");
    Console.WriteLine("  kvinfo [path/to/KV]");
    Console.WriteLine("    - displays info about a given keyvault");
    Console.WriteLine("  mcxcert [path/to/KV] [console MAC address] [output directory]");
    Console.WriteLine("    - generates Windows Media Center Extender certificates for a KV");
    return;
}

if (args[0].ToLowerInvariant() == "kvinfo")
    KVInfo(args[1]);
if (args[0].ToLowerInvariant() == "mcxcert")
    MCXCert(args[1], args[2], args[3]);
