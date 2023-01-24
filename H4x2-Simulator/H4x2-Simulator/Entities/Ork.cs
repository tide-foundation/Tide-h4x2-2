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
using System.Security.Cryptography;
using System.Text;
using H4x2_TinySDK.Tools;
using H4x2_TinySDK.Ed25519;

namespace H4x2_Simulator.Entities;

public class Ork
{
	public string OrkId { get; set; }
	public string OrkPub { get; set; }
	public string OrkUrl { get; set; }
	public string SignedOrkUrl { get; set; }
	public BigInteger GetOrkId()
	{
		if(OrkId is null) throw new Exception("Ork Class: OrkId is null");
		return BigInteger.Parse(OrkId);
	}
	public void SetOrkId(BigInteger orkId) => OrkId = orkId.ToString();
	public Point GetOrkPub()
	{
		if(OrkPub is null) throw new Exception("Ork Class: OrkPub is null");
		return Point.FromBase64(OrkPub);
	}
	public void SetOrkPub(Point orkPub) => OrkPub = orkPub.ToBase64();
	public static BigInteger GenerateID(string data) =>  Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(data)), false, true), Curve.N);
}

