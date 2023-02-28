// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

using H4x2_TinySDK.Ed25519;
using System.Numerics;
using H4x2_TinySDK.Tools;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Cryptography;

namespace H4x2_TinySDK.Math
{
    public class EdDSA
    {
        public static (Point R, BigInteger s) Sign(string message, Key key) => Sign(Encoding.ASCII.GetBytes(message), key);
        public static (Point R, BigInteger s) Sign(byte[] message, BigInteger priv) => Sign(message, new Key(priv));
        /// <summary>
        /// EdDSA signing with point Ed25519
        /// </summary>
        /// <param name="message"></param>
        /// <param name="key"></param>
        /// <returns>A Point R and BigInteger s.</returns>
        public static (Point R, BigInteger s) Sign(byte[] message, Key key)
        {
            BigInteger r = Utils.RandomBigInt();
            Point R = Curve.G * r;

            byte[] encodedR = R.ToByteArray();
            byte[] encodedPubKey = key.Y.ToByteArray();
            byte[] toHash = encodedR.Concat(encodedPubKey).Concat(message).ToArray();
            // h = hash(R + pubKey + msg) mod n
            var h = HashMessage(toHash) % Curve.N;
            // s = (r + h * privKey) mod n
            BigInteger s = (r + (key.Priv * h) ) % Curve.N;

            return (R, s);
        }

        public static bool Verify(string message, string signature, Point pub) => Verify(Encoding.ASCII.GetBytes(message), Convert.FromBase64String(signature), pub);
        /// <summary>
        /// EdDSA verification with point Ed25519
        /// </summary>
        /// <param name="message"></param>
        /// <param name="R"></param>
        /// <param name="s"></param>
        /// <param name="key"></param>
        /// <returns>A Boolean : True if the verification is successful , else => false.</returns>
        public static bool Verify(byte[] message, byte[] signature, Point pub)
        {
            if (signature == null || signature.Length != 64)
                return false;

            Point R = Point.FromBytes(signature.Take(32).ToArray());
            BigInteger s = new BigInteger(signature.Skip(32).ToArray());

            byte[] encodedR = R.ToByteArray();
            byte[] encodedPubKey = pub.ToByteArray();
            byte[] toHash = encodedR.Concat(encodedPubKey).Concat(message).ToArray();
            // h = hash(R + pubKey + msg) mod q
            var h = HashMessage(toHash) % Curve.N;

            return (Curve.G * s).isEqual(R + (pub * h));
        }

        /// <summary>
        /// Hashing with SHA512
        /// </summary>
        /// <param name="message"></param>
        /// <returns>A BigInteger.</returns>
        public static BigInteger HashMessage(byte[] message)
        {
            return new BigInteger(SHA512.HashData(message).ToArray(), true, false);
        }
    }
}
