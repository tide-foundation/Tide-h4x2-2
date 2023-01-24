using H4x2_TinySDK.Ed25519;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace H4x2_TinySDK.Tools
{
    public class AES
    {
        public static string Encrypt(string plaintext, string key) => Encrypt(Encoding.ASCII.GetBytes(plaintext), Convert.FromBase64String(key));
        public static string Encrypt(string plaintext, BigInteger key) => Encrypt(Encoding.ASCII.GetBytes(plaintext), key.ToByteArray(true, false));
        public static string Encrypt(string plaintext, byte[] key) => Encrypt(Encoding.ASCII.GetBytes(plaintext), key);
        public static string Encrypt(byte[] plainbytes, byte[] key_p) // check this works with JS
        {
            var paddedKey = Utils.PadRight(key_p, 32);
            using (var aes = new AesGcm(paddedKey))
            {
                var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(nonce);

                var tag = new byte[AesGcm.TagByteSizes.MaxSize];

                var ciphertext = new byte[plainbytes.Length];

                aes.Encrypt(nonce, plainbytes, ciphertext, tag);

                var encryptedData = Convert.ToBase64String(nonce.Concat(ciphertext).Concat(tag).ToArray());

                return encryptedData;
            }
        }
        public static string Decrypt(string encryptedtext, BigInteger key) => Decrypt(encryptedtext, key.ToByteArray(true, false));
        public static string Decrypt(string encryptedtext, byte[] key_p)
        {
            var paddedKey = Utils.PadRight(key_p, 32);
            using (var aes = new AesGcm(paddedKey))
            {
                var fullbytes = Convert.FromBase64String(encryptedtext);
                var plaintextBytes = new byte[fullbytes.Length - 28];  // Nonce is 12B + Tag whcih is 16B

                var nonce = fullbytes.Take(12).ToArray();
                var tag = fullbytes.Skip(nonce.Length + plaintextBytes.Length).ToArray();
                var cipher = fullbytes.Skip(12).Take(plaintextBytes.Length).ToArray();

                aes.Decrypt(nonce, cipher, tag, plaintextBytes);

                return Encoding.UTF8.GetString(plaintextBytes);
            }
        }
    }
}
