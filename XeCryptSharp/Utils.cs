using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace XeCryptSharp
{
    public class Utils
    {
        // Based off
        //  https://github.com/emoose/xbox-reversing/blob/5f85b9e/stfschk/XeCrypt.cs#L18-L26
        internal static byte[] SwapBy8(IEnumerable<byte> input)
        {
            // TODO: can we make this more efficient?
            byte[] buffer = input.ToArray();
            Array.Reverse(buffer);
            for (int x = 0; x < buffer.Length; x += 8)
                Array.Reverse(buffer, x, 8);
            return buffer;
        }

        internal static ushort ToUInt16BE(byte[] buffer, int offset)
        {
            unchecked
            {
                return (ushort)(buffer[offset + 1] | (buffer[offset + 0] << 8));
            }
        }

        internal static short ToInt16BE(byte[] buffer, int offset)
        {
            return (short)ToUInt16BE(buffer, offset);
        }

        internal static uint ToUInt32BE(byte[] buffer, int offset)
        {
            unchecked
            {
                return (uint)(buffer[offset + 3] | (buffer[offset + 2] << 8) | (buffer[offset + 1] << 16) | (buffer[offset + 0] << 24));
            }
        }

        internal static int ToInt32BE(byte[] buffer, int offset)
        {
            return (int)ToUInt32BE(buffer, offset);
        }

        internal static BigInteger BEToBigInteger(byte[] data)
        {
            // .NET Standard 2.0 was just before BigInteger started supporting isBigEndian/isUnsigned
            // so we have to:
            // - reverse the array to make it little endian
            // - add 1 null byte at the start to force it to be unsigned
            byte[] reversed = new byte[data.Length + 1];
            Buffer.BlockCopy(data, 0, reversed, 1, data.Length);
            Array.Reverse(reversed);
            return new BigInteger(reversed);
        }

        // Adapted from https://gist.github.com/AArnott/c105f9a1c8ebf546a027
        internal static void CalculateD(ref RSAParameters parameters)
        {
            var p = BEToBigInteger(parameters.P);
            var q = BEToBigInteger(parameters.Q);
            var e = BEToBigInteger(parameters.Exponent);

            var pMinus1 = p - 1;
            var qMinus1 = q - 1;
            var phiOfN = pMinus1 * qMinus1;

            var d = ModInverse(e, phiOfN);

            // TODO: the output byte array may not be seen as unsigned later
            // unsure what CryptoAPI RSA and OpenSSL RSA backends have to think about this
            parameters.D = d.ToByteArray();
            Array.Reverse(parameters.D);
        }

        // From https://gist.github.com/AArnott/c105f9a1c8ebf546a027
        /// <summary>
        /// Calculates the modular multiplicative inverse of <paramref name="a"/> modulo <paramref name="n"/>
        /// using the extended Euclidean algorithm.
        /// </summary>
        /// <remarks>
        /// This implementation comes from the pseudocode defining the inverse(a, n) function at
        /// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
        /// </remarks>
        internal static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger t = 0, nt = 1, r = n, nr = a;

            if (n < 0)
            {
                n = -n;
            }

            if (a < 0)
            {
                a = n - (-a % n);
            }

            while (nr != 0)
            {
                var quot = r / nr;

                var tmp = nt; nt = t - quot * nt; t = tmp;
                tmp = nr; nr = r - quot * nr; r = tmp;
            }

            if (r > 1) throw new ArgumentException(nameof(a) + " is not convertible.");
            if (t < 0) t = t + n;
            return t;
        }

        // Creates a set of .NET RSAParameters for an input XeCrypt public or private key block
        public static RSAParameters XeCryptToRSA(byte[] key, bool privateKey = false)
        {
            int numQw = ToInt32BE(key, 0);
            int keySz = numQw * 0x8;
            int keyHalf = keySz / 2;
            RSAParameters rsa = new RSAParameters
            {
                Exponent = key.Skip(0x4).Take(0x4).ToArray(), // BE is fine here
                Modulus = Utils.SwapBy8(key.Skip(0x10).Take(keySz)),
            };
            if (privateKey)
            {
                int offset = 0x10 + keySz;
                rsa.P = Utils.SwapBy8(key.Skip(offset).Take(keyHalf));
                offset += keyHalf;
                rsa.Q = Utils.SwapBy8(key.Skip(offset).Take(keyHalf));
                offset += keyHalf;
                rsa.DP = Utils.SwapBy8(key.Skip(offset).Take(keyHalf));
                offset += keyHalf;
                rsa.DQ = Utils.SwapBy8(key.Skip(offset).Take(keyHalf));
                offset += keyHalf;
                rsa.InverseQ = Utils.SwapBy8(key.Skip(offset).Take(keyHalf));
                offset += keyHalf;
                // XeCrypt key blobs don't include D but CryptoAPI and OpenSSL expect a valid D
                // No, BouncyCastle *also* does... so we can't use that.
                CalculateD(ref rsa);
            }
            return rsa;
        }
    }
}