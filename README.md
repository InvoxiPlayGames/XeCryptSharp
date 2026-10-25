# XeCryptSharp

.NET Standard 2.0 (.NET Framework 4.6.2+, .NET 5.0+) library for dealing with
Xbox 360 cryptography.

## Implementation Checklist

* [x] Parsing key vaults
* [ ] Verifying key vaults (retail)
* [ ] Generating key vaults (devkit)
* [x] Parsing console certificates
* [x] Parsing RSA public keys
* [x] Parsing RSA private keys
* [ ] Loading static keys
* [ ] License & NuGET
* [ ] Some more stuff

## Examples

See [XeCryptSharp.CLI](./XeCryptSharp.CLI/) for more example code.

### Signing data with a console private key

```cs
// Load the file as a stream
FileStream fs = File.OpenStream("kv.bin");
// Read in the key vault data
XeKeyVault kv = new(fs);
// Create a .NET RSA handle
RSA rsa = RSA.Create();
// Load the private key from the key vault
rsa.ImportParameters(kv.GetConsoleRSAKey());
// Sign the data with the RSA private key
byte[] signature = rsa.SignData();
Array.Reverse(signature); // Makes it valid for XeCrypt
```

## CLI

```
available commands:
  kvinfo [path/to/KV]
    - displays info about a given keyvault
  mcxcert [path/to/KV] [console MAC address] [output directory]
    - generates Windows Media Center Extender certificates for a KV
```

## Shoutouts

* [emoose/ExCrypt](https://github.com/emoose/ExCrypt)
* [cOzInABox/XeCrypt](https://github.com/cOzInABox/XeCrypt)
* [GoobyCorp/Xbox-360-Crypto](https://github.com/GoobyCorp/Xbox-360-Crypto)
