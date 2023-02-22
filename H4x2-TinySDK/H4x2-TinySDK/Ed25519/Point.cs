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

using System.Numerics;
using System.Text;
using H4x2_TinySDK.Tools;

namespace H4x2_TinySDK.Ed25519
{
    /// <summary>
    /// Represents a point on the Ed25519 Curve.
    /// </summary>
    public class Point
    {
        private BigInteger X { get; }
        private BigInteger Y { get; }
        private BigInteger Z { get; }
        private BigInteger T { get; }

        /// <summary>
        /// Create a point from extended coordinates. Consider passing only x and y for simpler use.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <param name="z"></param>
        /// <param name="t"></param>
        public Point(BigInteger x, BigInteger y, BigInteger z, BigInteger t)
        {
            X = x;
            Y = y;
            Z = z;
            T = t;
        }
        /// <summary>
        /// Create a point from normal coordinates.
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        public Point(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
            Z = 1;
            T = Mod(x * y);
        }
        /// <summary>
        /// Creates a point from bytes.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="compact"></param>
        /// <returns></returns>
        public static Point FromBytes(IReadOnlyList<byte> data)
        {
            var x = new BigInteger(data.Take(32).ToArray(), true, false);
            var y = new BigInteger(data.Skip(32).ToArray(), true, false);
            var point = new Point(x, y);
            return point;
        }
        public static Point FromBase64(string data) => Point.FromBytes(Convert.FromBase64String(data));
        /// <summary>
        /// Performs ( X * modular_inverse(Z) ) % M to get the actual x coordinate.
        /// </summary>
        /// <returns>The actual x coordinate of this point.</returns>
        public BigInteger GetX() => Mod(X * BigInteger.ModPow(Z, Curve.M - 2, Curve.M));
        /// <summary>
        /// Performs ( Y * modular_inverse(Z) ) % M to get the actual y coordinate.
        /// </summary>
        /// <returns>The actual y coordinate of this point.</returns>
        public BigInteger GetY() => Mod(Y * BigInteger.ModPow(Z, Curve.M - 2, Curve.M));
        /// <summary>
        /// Determines if two points are equal to each other.
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool isEqual(Point other)
        {
            BigInteger X1Z2 = Mod(this.X * other.Z);
            BigInteger X2Z1 = Mod(other.X * this.Z);
            BigInteger Y1Z2 = Mod(this.Y * other.Z);
            BigInteger Y2Z1 = Mod(other.Y * this.Z);
            return (X1Z2 == X2Z1) && (Y1Z2 == Y2Z1);
        }
        /// <summary>
        /// Determines whether this point is a valid point on the Ed25519 Curve.
        /// </summary>
        /// <returns>A boolean whether the point it is or isn't on the curve.</returns>
        public bool IsValid()
        {
            BigInteger y = GetY();
            BigInteger x = GetX();
            BigInteger y2 = Mod(y * y);
            BigInteger x2 = Mod(x * x);
            return Mod(y2 * Mod(1 + Curve.Not_Minus_D * x2)) == Mod(1 + x2);
        }
        /// <summary>
        /// Determines if this point is safe for point multiplication.
        /// </summary>
        /// <returns></returns>
        public bool IsSafePoint()
        {
            BigInteger x = this.GetX();
            BigInteger y = this.GetY();

            if (this.IsInfinity())
                return false;
            /*This check will be always pass since we use %M*/
            if (x < 0 || y < 0 || x >= Curve.M || y >= Curve.M)
                return false;
            if (!this.IsValid())
                return false;
            if (!(this * Curve.N).IsInfinity())
                return false;
            return true;
        }
        /// <summary>
        /// Determines if this point is the infinity point.
        /// </summary>
        /// <returns></returns>
        public bool IsInfinity()
        {
            return this.isEqual(Curve.Infinity);
        }
        /// <summary>
        /// </summary>
        /// <returns>The point coordinates as unsigned, little endian byte arrays. 
        public byte[] ToByteArray()
        {
            return this.GetX().ToByteArray(true, false).PadRight(32)
                    .Concat(this.GetY().ToByteArray(true, false).PadRight(32)).ToArray();
        }
        /// <summary>
        /// </summary>
        /// <returns>The point as a base64 encoded string</returns>
        public string ToBase64()
        {
            return Convert.ToBase64String(this.ToByteArray());
        }
        /// <summary>
        /// Compresses the point into a 32 byte array.
        /// </summary>
        /// <returns></returns>
        public byte[] Compress()
        {
            var x_lsb = this.GetX() & 1;
            // Encode the y-coordinate as a little-endian string of 32 octets.
            byte[] yByteArray = this.GetY().ToByteArray(true, false).PadRight(32);
            int new_msb = 0;
            if (x_lsb == 1)
            {
                new_msb = yByteArray[31] | 128;
            }
            if (x_lsb == 0)
            {
                new_msb = yByteArray[31] & 127;
            }
            // Copy the least significant bit of the x - coordinate to the most significant bit of the final octet.
            yByteArray[31] = (byte)new_msb;
            return yByteArray;
        }
        /// <summary>
        /// Multiplies a point by a scalar using double and add algorithm on the Ed25519 Curve.
        /// Does not perform safety checks on scalar or the point, yet.
        /// </summary>
        /// <param name="point"></param>
        /// <param name="num"></param>
        /// <returns>A new point on the Ed25519 Curve.</returns>
        public static Point operator *(Point point, BigInteger num)
        {
            Point newPoint = new Point(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero);
            while (num > BigInteger.Zero)
            {
                if ((num & BigInteger.One).Equals(BigInteger.One)) newPoint = newPoint + point;
                point = Double(point);
                num = num >> 1;
            }
            return newPoint;
        }
        /// <summary>
        /// Add a point by itself ("double") on the Ed25519 Curve.
        /// </summary>
        /// <param name="point"></param>
        /// <returns>A new point on the Ed25519 Curve.</returns>
        public static Point Double(in Point point)
        {
            // Algorithm taken from https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html.

            BigInteger A = Mod(point.X * point.X);
            BigInteger B = Mod(point.Y * point.Y);
            BigInteger C = Mod(Curve.Two * Mod(point.Z * point.Z));
            BigInteger D = Mod(Curve.A * A);
            BigInteger x1y1 = point.X + point.Y;
            BigInteger E = Mod(Mod(x1y1 * x1y1) - A - B);
            BigInteger G = D + B;
            BigInteger F = G - C;
            BigInteger H = D - B;
            BigInteger X3 = Mod(E * F);
            BigInteger Y3 = Mod(G * H);
            BigInteger T3 = Mod(E * H);
            BigInteger Z3 = Mod(F * G);
            return new Point(X3, Y3, Z3, T3);
        }
        /// <summary>
        /// Adds two points on the Ed25519 Curve. Currently, does not check if point is on curve or prime order group.
        /// </summary>
        /// <param name="point1"></param>
        /// <param name="point2"></param>
        /// <returns>A new point on the Ed25519 Curve.</returns>
        public static Point operator +(in Point point1, in Point point2)
        {
            // TODO: check to see if point is on curve and on the prime order subgroup
            // Algorithm taken from https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html.

            BigInteger A = Mod((point1.Y - point1.X) * (point2.Y + point2.X));
            BigInteger B = Mod((point1.Y + point1.X) * (point2.Y - point2.X));
            BigInteger F = Mod(B - A);
            if (F.Equals(BigInteger.Zero)) return Double(point1);
            BigInteger C = Mod(point1.Z * Curve.Two * point2.T);
            BigInteger D = Mod(point1.T * Curve.Two * point2.Z);
            BigInteger E = D + C;
            BigInteger G = B + A;
            BigInteger H = D - C;
            BigInteger X3 = Mod(E * F);
            BigInteger Y3 = Mod(G * H);
            BigInteger T3 = Mod(E * H);
            BigInteger Z3 = Mod(F * G);
            return new Point(X3, Y3, Z3, T3);
        }
        private static BigInteger Mod(BigInteger a)
        {
            BigInteger res = a % Curve.M;
            return res >= BigInteger.Zero ? res : Curve.M + res;
        }
    }
}