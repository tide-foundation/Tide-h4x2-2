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

namespace H4x2_TinySDK.Ed25519
{
    public class Curve
    {
        private readonly static BigInteger m = BigInteger.Parse("57896044618658097711785492504343953926634992332820282019728792003956564819949");
        private readonly static BigInteger n = BigInteger.Parse("7237005577332262213973186563042994240857116359379907606001950938285454250989");
        private readonly static BigInteger d = BigInteger.Parse("37095705934669439343138083508754565189542113879843219016388785533085940283555");
        private readonly static BigInteger not_minus_d = BigInteger.Parse("20800338683988658368647408995589388737092878452977063003340006470870624536394");
        private readonly static BigInteger sQRT_M1 = BigInteger.Parse("19681161376707505956807079304988542015446066515923890162744021073123829784752");
        private readonly static BigInteger two = BigInteger.Parse("2");
        private readonly static BigInteger minusOne = BigInteger.MinusOne;
        public static ref readonly BigInteger M => ref m;
        public static ref readonly BigInteger N => ref n;
        public static ref readonly BigInteger D => ref d;
        public static ref readonly BigInteger Not_Minus_D => ref not_minus_d;
        public static ref readonly BigInteger SQRT_M1 => ref sQRT_M1;
        public static ref readonly BigInteger MinusOne => ref minusOne;
        public static ref readonly BigInteger A => ref minusOne;
        public static ref readonly BigInteger Two => ref two;

        private readonly static BigInteger gx = BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202");
        private readonly static BigInteger gy = BigInteger.Parse("46316835694926478169428394003475163141307993866256225615783033603165251855960");
        private readonly static BigInteger gt = BigInteger.Parse("46827403850823179245072216630277197565144205554125654976674165829533817101731");
        private readonly static Point g = new Point(gx, gy, BigInteger.One, gt);
        public static ref readonly Point G => ref g;

        public static readonly Point Infinity = new Point(BigInteger.Zero, BigInteger.One, BigInteger.One, BigInteger.Zero); //infinity also known as identity for ed25519

    }
}
