using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;


namespace H4x2_TinySDK.Tools
{
    public class AesKey 
    {
        private const int _countSize = 1;
        public byte[] Key { get; protected set; }
        public byte[] MacKey { get; protected set; }

        public AesKey(byte[] key, byte[] macKey) 
        {
            Key = key;
            MacKey = macKey;
        }


        public static AesKey Seed(byte[] data) => Derive(data, new byte[15]);

        private static AesKey Derive(byte[] secret, byte[] iv)
        {
            var sec = HMAC(new byte[] { 1 }.Concat(iv).ToArray(), secret);
            var mac = HMAC(new byte[] { 2 }.Concat(iv).ToArray(), secret);
            return new AesKey(sec.Take(16).ToArray(), mac);
        }

        private static byte[] HMAC(byte[] data, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }
    }
}
