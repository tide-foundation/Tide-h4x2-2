
using System.Numerics;
using System.Security.Cryptography;
using H4x2_TinySDK.Tools;
using H4x2_TinySDK.Ed25519;
using System.Text;

namespace H4x2_TinySDK.Ed25519
{
    class PrivateKey
    {
        internal byte[] Digest { get; } // TODO: Protect this in memory
        public BigInteger Priv { get; }
        public PrivateKey(string base64Bytes)
        {
            Digest = HashAndPrune(Convert.FromBase64String(base64Bytes));
            Priv = new BigInteger(Digest.Take(32).ToArray(), true, false);
        }
        public byte[] HashAndPrune(byte[] data)
        {
            // As per the RFC:
            // 1. Hash the secret data with SHA512
            byte[] h = SHA512.HashData(data);

            // 2. a. Clear the lower 3 bits of the first byte
            h[0] = (byte)(h[0] & 248);
            // 2. b. Highest bit of last octect is set
            h[31] = (byte)(h[31] & 127);
            // 2. c. Second highest bit on last octect is set
            h[31] = (byte)(h[31] | 64);


            return h;
        }
        public PublicKey Public()
        {
            return new PublicKey(Curve.G * Priv);
        }
        public string Sign(string message)
        {
            var A = Public().Pub.ToByteArray();

            var message_bytes = Encoding.ASCII.GetBytes(message);

            var prefix = Digest.Skip(32);

            var r_bytes = SHA512.HashData(prefix.Concat(message_bytes).ToArray());
            var r = Utils.Mod(new BigInteger(r_bytes, true, false), Curve.N);
            var R = (Curve.G * r);

            var k_bytes = SHA512.HashData(R.ToByteArray().Concat(A).Concat(message_bytes).ToArray());
            var k = Utils.Mod(new BigInteger(k_bytes, true, false), Curve.N);

            var S = Utils.Mod(r + (k * Priv), Curve.N);

            var encoding = R.ToByteArray().Concat(Utils.PadRight(S.ToByteArray(true, false), 32)); // R is not compressed in signature
            return Convert.ToBase64String(encoding.ToArray());
        }
        public static string Generate() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    }
    class PublicKey
    {
        public Point Pub { get; }
        public PublicKey(Point pub)
        {
            Pub = pub;
        }
        public Point GetPoint() => Pub;
        public bool Verify()
        {
            throw new NotImplementedException();
        }
        public string ToBase64()
        {
            return Pub.ToBase64();
        }
        public string ToUID()
        {
            var hashed = SHA256.HashData(Pub.ToByteArray()).Take(8).ToArray();
            return Convert.ToHexString(hashed);
        }
    }
}
