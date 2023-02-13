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
using H4x2_TinySDK.Tools;

namespace H4x2_TinySDK.Math
{
    public class EccSecretSharing
    {
        public static List<ECPoint> Share(BigInteger secret, IEnumerable<BigInteger> xs, int threshold, BigInteger p)
        {
            var coeffs = Randoms(threshold - 1, p);
            coeffs.Insert(0, secret);

            return xs.Select(x => new ECPoint(x, EvalPoly(coeffs, x, p))).ToList();
        }
        public static BigInteger EvalPoly(IReadOnlyList<BigInteger> coeffs, BigInteger x, BigInteger p)
        {
            var y = coeffs[coeffs.Count - 1];
            for (var i = coeffs.Count - 2; i >= 0; i--)
                y = (y * x % p) + coeffs[i] % p;

            return y;
        }
        public static BigInteger EvalLi(BigInteger xi, IEnumerable<BigInteger> xs, BigInteger p)
        {
            return xs.Where(xj => xj != xi)
                .Select(xj => (xj - xi).PrimeInv(p) * xj % p)
                .Aggregate(BigInteger.One, (num, li) => li * num % p).Mod(p);
        }
        public static List<BigInteger> Randoms(int count, BigInteger p)
        {
            var list = new List<BigInteger>();
            while (list.Count < count)
            {
                var number = Utils.RandomBigInt();
                if (!list.Contains(number))
                    list.Add(number);
            }
            return list;
        }
    }

    public class ECPoint : PointBase<BigInteger> 
    {
        public ECPoint(BigInteger x, BigInteger y) : base(x, y) { }
    }

     public abstract class PointBase<T> : IEquatable<PointBase<T>> where T : IEquatable<T>
    {
        public T X { get; protected set; }
        public T Y { get; protected set; }
        
        public PointBase(T x, T y)
        {
            if (x == null || y == null)
                throw new ArgumentNullException();

            X = x;
            Y = y;
        }

        public static bool operator ==(PointBase<T> p1, PointBase<T> p2) => !ReferenceEquals(p1, null) && p1.Equals(p2);

        public static bool operator !=(PointBase<T> p1, PointBase<T> p2) => ReferenceEquals(p1, null) || !(p1.Equals(p2));

        public bool Equals(PointBase<T> p) => !ReferenceEquals(p, null) && X.Equals(p.X) && Y.Equals(p.Y);
        
        public override bool Equals(object obj) => typeof(PointBase<T>) == obj.GetType() && Equals(obj as PointBase<T>);

        public override int GetHashCode() => X.GetHashCode() ^ Y.GetHashCode();
    }

}
