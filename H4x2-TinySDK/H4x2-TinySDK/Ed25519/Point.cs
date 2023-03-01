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
            return Decompress(data.ToArray());
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
            if (this.IsInfinity())
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
            return this.Compress();
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
        private byte[] Compress()
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
        private static Point Decompress(IReadOnlyList<byte> point_bytes)
        {
            // 1.  First, interpret the string as an integer in little-endian
            // representation. Bit 255 of this number is the least significant
            // bit of the x-coordinate and denote this value x_0.  The
            // y-coordinate is recovered simply by clearing this bit.  If the
            // resulting value is >= p, decoding fails.
            byte[] normed = point_bytes.ToArray();
            normed[31] = (byte)(point_bytes[31] & ~128);
            BigInteger y = new BigInteger(normed, true, false);

            if ( y >= Curve.M) throw new Exception("Decompress:Expected 0 < hex < P");

            // 2.  To recover the x-coordinate, the curve equation implies
            // x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
            // non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
            BigInteger y2 = Mod(y * y);
            BigInteger u = Mod(y2 - BigInteger.One);
            BigInteger v = Mod(Curve.D * y2 + BigInteger.One);
            (bool isValid, BigInteger x) = uvRatio(u, v);
            if (!isValid) throw new Exception("Decompress: invalid y coordinate");

            // 4.  Finally, use the x_0 bit to select the right square root.  If
            // x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
            // 2, set x <-- p - x.  Return the decoded point (x,y).
            bool isXOdd = (x & 1) == 1;
            bool isLastByteOdd = (point_bytes[31] & 0x80) != 0;
            if (isLastByteOdd != isXOdd) {
                x = Mod(-x);
            }
            return new Point(x, y);
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
        private static BigInteger Pow2(BigInteger a, BigInteger power)
        {
            while(power-- > BigInteger.Zero){
                a = Mod(a * a);
            }
            return a;
        }
        private static BigInteger Pow_2_252_3(BigInteger a)
        {
            BigInteger _1n = BigInteger.One;
            BigInteger _2n = new BigInteger(2);
            BigInteger _5n = new BigInteger(5);
            BigInteger _10n = new BigInteger(10);
            BigInteger _20n = new BigInteger(20);
            BigInteger _40n = new BigInteger(40);
            BigInteger _80n = new BigInteger(80);
            BigInteger x2 = (a * a) % Curve.M;
            BigInteger b2 = (x2 * a) % Curve.M;
            BigInteger b4 = (Pow2(b2, _2n) * b2) % Curve.M; // x^15, 1111
            BigInteger b5 = (Pow2(b4, _1n) * a) % Curve.M; // x^31
            BigInteger b10 = (Pow2(b5, _5n) * b5) % Curve.M;
            BigInteger b20 = (Pow2(b10, _10n) * b10) % Curve.M;
            BigInteger b40 = (Pow2(b20, _20n) * b20) % Curve.M;
            BigInteger b80 = (Pow2(b40, _40n) * b40) % Curve.M;
            BigInteger b160 = (Pow2(b80, _80n) * b80) % Curve.M;
            BigInteger b240 = (Pow2(b160, _80n) * b80) % Curve.M;
            BigInteger b250 = (Pow2(b240, _10n) * b10) % Curve.M;
            BigInteger pow_p_5_8 = (Pow2(b250, _2n) * a) % Curve.M;
            return pow_p_5_8;
        }
        private static (bool, BigInteger) uvRatio(BigInteger u, BigInteger v)
        {
            BigInteger v3 = Mod(v * v * v);                  // v³
            BigInteger v7 = Mod(v3 * v3 * v);                // v⁷
            BigInteger pow = Pow_2_252_3(u * v7);
            BigInteger x = Mod(u * v3 * pow);                  // (uv³)(uv⁷)^(p-5)/8
            BigInteger vx2 = Mod(v * x * x);                 // vx²
            BigInteger root1 = x;                            // First root candidate
            BigInteger root2 = Mod(x * Curve.SQRT_M1);             // Second root candidate
            bool useRoot1 = vx2 == u;                 // If vx² = u (mod p), x is a square root
            bool useRoot2 = vx2 == Mod(-u);           // If vx² = -u, set x <-- x * 2^((p-1)/4)
            bool noRoot = vx2 == Mod(-u * Curve.SQRT_M1);   // There is no valid root, vx² = -u√(-1)
            if (useRoot1) x = root1;
            if (useRoot2 || noRoot) x = root2;          // We return root2 anyway, for const-time
            if (edIsNegative(x)) x = Mod(-x);
            return (useRoot1 || useRoot2, x);
        }
        private static bool edIsNegative(BigInteger num)
        {
            return (Mod(num) & 1) == 1;
        }
    }
}