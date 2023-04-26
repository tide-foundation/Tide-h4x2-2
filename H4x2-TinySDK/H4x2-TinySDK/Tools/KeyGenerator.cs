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

using System.Text;
using System.Numerics;
using System.Text.Json;
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Math;
using System.Security.Cryptography;

namespace H4x2_TinySDK.Tools
{ 
    public class KeyGenerator
    {
        private BigInteger MSecOrki { get; } // this ork's private scalar
        internal byte[] MSecOrki_Key => MSecOrki.ToByteArray(true, false);
        private Point MgOrki { get; } // this ork's public point
        internal Key mgOrki_Key => new Key(0, MgOrki);
        public int Threshold { get; }
        public int MaxAmount { get; }
        private readonly Caching _cachingManager;


        public KeyGenerator(BigInteger mSecOrki, Point mgOrki, int threshold, int maxAmount)
        {
            MSecOrki = mSecOrki;
            MgOrki = mgOrki;
            Threshold = threshold;
            MaxAmount = maxAmount;
            _cachingManager = new Caching();
        }

        public string GenShard(string keyID, Point[] mgORKj, int numKeys)
        {
            _cachingManager.Remove("KeyGen:" + keyID); // start clean
            if (!mgORKj.Any(pub => pub.isEqual(mgOrki_Key.Y)))
            {
                throw new Exception("GenShard: This ORKs public key was not provided in the list of publics");
            }
            if (mgORKj.Count() != MaxAmount)
            {
                throw new Exception("GenShard: User attempting to create account with different amount of ORKs than config");
            }
            if (mgORKj.Count() < 2)
            {
                throw new Exception("GenShard: Number of ork keys provided must be greater than 1");
            }
            if (numKeys < 1 || numKeys > 5)
            {
                throw new Exception("GenShard: Number of keys requested must be at minimum 1, maximum 4");
            }


            // Generate DiffieHellman Keys based on this ork's priv and other Ork's Pubs
            byte[][] ECDHij = mgORKj.Select(pub => createKey(pub)).ToArray();
            // Ids(Xs) of all orks
            var mgOrkj_Xs = mgORKj.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N));
            var my_X = Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(this.mgOrki_Key.Y.ToBase64())), false, true), Curve.N);
            BigInteger li = SecretSharing.EvalLi(my_X, mgOrkj_Xs, Curve.N);

            long timestampi = DateTime.UtcNow.Ticks;

            BigInteger[] k = new BigInteger[numKeys];
            Point[] gKn = new Point[numKeys];
            Point[] gRn = new Point[numKeys];
            BigInteger[] Sn = new BigInteger[numKeys];
            PolyPoint[][] Yij = new PolyPoint[numKeys][];
            BigInteger r;
            BigInteger h;

            for (int i = 0; i < numKeys; i++)
            {
                // Generate random k shard
                k[i] = Utils.RandomBigInt();

                // Calculate public shard
                gKn[i] = Curve.G * k[i];

                // Calculate Zero Knowledge Proof for gK[n]i
                r = Utils.RandomBigInt();
                gRn[i] = Curve.G * r;
                h = new BigInteger(SHA512.HashData(gRn[i].ToByteArray().Concat(gKn[i].ToByteArray()).ToArray()), true, false) % Curve.N;
                Sn[i] = (r + (h * k[i])) % Curve.N;

                // For each ORK, secret share value ki
                Yij[i] = (SecretSharing.Share(k[i], mgOrkj_Xs, Threshold, Curve.N)).ToArray();
            }
            // Encrypt shard Yj with each ORK key
            string[] YCiphers = ECDHij.Select((key, i) => encryptShares(key, Yij, i, timestampi, keyID, gKn, gRn, Sn)).ToArray();

            // Generate partial EdDSA R2
            BigInteger ri = Utils.RandomBigInt();
            Point gRi = Curve.G * ri;

            // Store latest state
            string cacheState = JsonSerializer.Serialize(new CacheState_GenShard
            {
                MgORKj = mgORKj.Select(p => p.ToByteArray64()).ToArray(), // remember IDs are string representations of Xs
                ECDHij = ECDHij,
                K = k.Select(i => i.ToByteArray(true, true)).ToArray(),
                Li = li.ToByteArray(true, true),
                Stage = 2,
                GKn = gKn.Select(gK => gK.ToByteArray64()).ToArray(),
                Ri = ri.ToByteArray(true, false)
            }) ;

            GenShardResponse response = new GenShardResponse
            {
                YijCiphers = YCiphers,
                GRi = gRi.ToByteArray(),
                Timestampi = timestampi.ToString()
            };

            _cachingManager.AddOrGetCache("KeyGen:" + keyID, cacheState).GetAwaiter().GetResult(); // add state to memory

            return JsonSerializer.Serialize(response);
        }

        /// <summary>
        /// Make sure orkShares provided are sorted in same order as mgORKj. For example, orkshare[0].From = ork2 AND mgORKj[0] = ork2's public.
        /// This function cannot correlate orkId to public key unless it's in the same order
        /// </summary>
        public string SendShard(string keyID, string[] yijCiphers, Point[] gMultiplier, Point R2)
        {
            string state_s = _cachingManager.AddOrGetCache("KeyGen:" + keyID, string.Empty).GetAwaiter().GetResult(); //Retrive the state cached from GenShard function
            _cachingManager.Remove("KeyGen:" + keyID); // remove in case something fails

            if(String.IsNullOrEmpty(state_s)) throw new Exception("SendShard: KeyID in state does not exist");

            // Reastablish state
            CacheState_GenShard state = JsonSerializer.Deserialize<CacheState_GenShard>(state_s);
            if(state.Stage != 2) throw new Exception("SendShard: Requests in wrong order");

            // Decrypts only the shares that were sent to itself
            IEnumerable<ShareData> decryptedShares = yijCiphers.Select((share, i) => decryptShares(share, state.ECDHij[i]));
            if (!decryptedShares.All(share => share.KeyID.Equals(keyID))) // check that no one is attempting to recreate someone else's key for their own account
            {
                throw new Exception("SendShard: KeyID of this share does not equal KeyID supplied");
            }

            // Verify the time difference is not material (30min)
            long timestamp = Median(decryptedShares.Select(share => long.Parse(share.Timestampi)).ToArray()); // get median of timestamps
            if (!decryptedShares.All(share => VerifyDelay(long.Parse(share.Timestampi), timestamp)))
            {
                throw new Exception("SendShard: One or more of the shares has expired");
            }

            if (yijCiphers.Length != MaxAmount) throw new Exception("SendShard: Did not recieve correct amount of ciphers");

            int numKeys = decryptedShares.All(s => s.Shares.Length == decryptedShares.First().Shares.Length) 
                ? decryptedShares.First().Shares.Length 
                : throw new Exception("SendShard: Different amount of shares provided");

            BigInteger[] Y = new BigInteger[numKeys];
            BigInteger[] k = state.K.Select(i => new BigInteger(i, true, true)).ToArray();
            Point[] gMultiplied = new Point[numKeys];
            byte[] gR_S;
            Point Y_Pub;

            Point[] gKn = new Point[numKeys];
            for (int i = 0; i < numKeys; i++) gKn[i] = Curve.Infinity; // populate list with infinity
            

            for (int i = 0; i < numKeys; i++)
            {
                // Aggregate all shares to form final Y coordinate
                Y[i] = decryptedShares.Aggregate(BigInteger.Zero, (sum, point) => (sum + new BigInteger(point.Shares[i], true, true)) % Curve.N);

                // Multiply the required multipliers
                if(i < gMultiplier.Length){
                    if(gMultiplier[i] is null) gMultiplied[i] = null;
                    else if(gMultiplier[i].IsSafePoint()) gMultiplied[i] = gMultiplier[i] * k[i];
                    else throw new Exception("SendShard: Not all points supplied are safe");
                }

                // Validating the Zero Knowledge Proof
                if (!decryptedShares.All(share =>
                {
                    gR_S = share.RPubs[i].Concat(share.Si[i].PadRight(32)).ToArray(); // concact R and S TODO: Maybe do this before?
                    Y_Pub = Point.FromBytes(share.SharePubs[i]);
                    gKn[i] = gKn[i] + Y_Pub;
                    return EdDSA.Verify(Array.Empty<byte>(), gR_S, Y_Pub);
                })) throw new Exception("SendShard: Not all public signatures pass verification");      
            }
            // This is done only on first key
            Point R = state.MgORKj.Select(p => Point.From64Bytes(p))
                                  .Aggregate(Curve.Infinity, (sum, next) => sum + next) + R2;

            // Prepare the signature message
            byte[] MData_To_Hash = gKn[0].ToByteArray().Concat(Encoding.ASCII.GetBytes(timestamp.ToString())).Concat(Encoding.ASCII.GetBytes(keyID)).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = SHA256.HashData(MData_To_Hash);
            byte[] HData_To_Hash = R.ToByteArray().Concat(gKn[0].ToByteArray()).Concat(M).ToArray();
            BigInteger H = Utils.Mod(new BigInteger(SHA512.HashData(HData_To_Hash), true, false), Curve.N);

            BigInteger ri = new BigInteger(state.Ri, true, false); // restablish little r

            // Generate the partial signature with ORK's lagrange
            BigInteger li = new BigInteger(state.Li, true, true);
            BigInteger si = Utils.Mod(this.MSecOrki + ri + (H * Y[0] * li), Curve.N);


            string stateData = AES.Encrypt(JsonSerializer.Serialize(new EncCommitState
            {
                KeyID = keyID,
                Timestamp = timestamp,
                gKn = gKn.Select(gK => gK.ToByteArray64()).ToArray(),
                Yn = Y.Select(y => y.ToByteArray(true, true)).ToArray(),
                mgORKj = state.MgORKj,
                R2 = R2.ToByteArray64()
            }), MSecOrki);

            var response = JsonSerializer.Serialize(new SendShardResponse
            {
                
                GMultiplied = gMultiplied.Select(point => point is null ? null : point.ToByteArray()).ToArray(),
                Si = si.ToByteArray(true, false),
                GK1 = gKn[0].ToByteArray(),
                EncCommitStatei = stateData
            });

            return response;
        }

        public CommitResponse Commit(string keyID, BigInteger S, string encCommitStatei)
        {
            // Reastablish state
            EncCommitState state = JsonSerializer.Deserialize<EncCommitState>(AES.Decrypt(encCommitStatei, MSecOrki_Key)); // decrypt encrypted state in response

            if (!state.KeyID.Equals(keyID))
            {
                throw new Exception("Commit: KeyID of instanciated object does not equal that of previous state");
            }
            if (!VerifyDelay(state.Timestamp, DateTime.UtcNow.Ticks))
            {
                throw new Exception("Commit: State has expired");
            }

            Point gK = Point.From64Bytes(state.gKn[0]);
            byte[] MData_To_Hash = gK.ToByteArray().Concat(Encoding.ASCII.GetBytes(state.Timestamp.ToString()).Concat(Encoding.ASCII.GetBytes(keyID))).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = SHA256.HashData(MData_To_Hash);

            Point[] mgORKj = state.mgORKj.Select(mgORK => Point.From64Bytes(mgORK)).ToArray();
            Point R2 = Point.From64Bytes(state.R2);
            Point R = mgORKj.Aggregate(Curve.Infinity, (sum, next) => next + sum) + R2;

            byte[] HData_To_Hash = R.ToByteArray().Concat(gK.ToByteArray()).Concat(M).ToArray();
            BigInteger H = Utils.Mod(new BigInteger(SHA512.HashData(HData_To_Hash), true, false), Curve.N);

            // Verify the Signature 
            bool valid = (Curve.G * S).isEqual(R + (gK * H));

            if (!valid)
            {
                throw new Exception("Commit: Validation failed");
            }

            return new CommitResponse
            {
                KeyID = state.KeyID,
                Timestampi = state.Timestamp,
                mIDORK = mgORKj.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N).ToString()).ToArray(),
                gKn = state.gKn.Select(p => Point.From64Bytes(p).ToBase64()).ToArray(),
                Yn = state.Yn.Select(y => new BigInteger(y, true, true).ToString()).ToArray(),
                R2 = R2.ToBase64(),
                S = S.ToString()
            };
        }

        private byte[] createKey(Point point)
        {
            if (MgOrki.isEqual(point))
                return MSecOrki_Key;
            else
                return (point * MSecOrki).ToByteArray();
        }

        private bool VerifyDelay(long timestamp, long timestampi)
        {
            return (System.Math.Abs(timestamp - timestampi) < 18000000000); // Checks different between timestamps is less than 30 min
        }
        private long Median(long[] data)  // TODO: implement this somewhere better
        {
            Array.Sort(data);
            if (data.Length % 2 == 0)
                return (data[data.Length / 2 - 1] + data[data.Length / 2]) / 2;
            else
                return data[data.Length / 2];
        }
        private ShareData decryptShares(string encryptedShare, byte[] DHKey)
        {
            return JsonSerializer.Deserialize<ShareData>(AES.Decrypt(encryptedShare, DHKey)); // decrypt encrypted share and create DataToEncrypt object
        }

        private string encryptShares(byte[] key, PolyPoint[][] shares, int index, long timestampi, string keyID, Point[] gKn, Point[] gRn, BigInteger[] Sn)
        {
            var data_to_encrypt = new ShareData
            {
                KeyID = keyID,
                Timestampi = timestampi.ToString(),
                Shares = shares.Select(pointShares => pointShares[index].Y.ToByteArray(true, true)).ToArray(),
                SharePubs = gKn.Select(sharePub => sharePub.ToByteArray()).ToArray(),
                RPubs = gRn.Select(gR => gR.ToByteArray()).ToArray(),
                Si = Sn.Select(s => s.ToByteArray(true, false)).ToArray()
            };
            return AES.Encrypt(JsonSerializer.Serialize(data_to_encrypt), key);
        }


        internal class CacheState_GenShard
        {
            public byte[][] MgORKj { get; set; } // list of ORK Pubs
            public byte[][] ECDHij { get; set; } // list of ECDH Keys
            public int Stage { get; set; } 
            public byte[][] K { get; set; }
            public byte[] Li { get; set; }
            public byte[][] GKn { get; set; } // list of partial pubs
            public byte[] Ri { get; set; } // little r for entry signing
        }
       

        internal class GenShardResponse
        {
            public string Timestampi { get; set; }
            public string[] YijCiphers { get; set; }
            public byte[] GRi { get; set; }
        }
        internal class SendShardResponse
        {
            public byte[][] GMultiplied { get; set; }
            public byte[] Si { get; set; }
            public byte[] GK1 { get; set; }
            public string EncCommitStatei { get; set; }
        }

        internal class ShareData
        {
            public string KeyID { get; set; } 
            public string Timestampi { get; set; }
            public byte[][] Shares { get; set; } // Y[n]j
            public byte[][] SharePubs { get; set; } // gK[n]i
            public byte[][] RPubs { get; set; } // gR[n]i
            public byte[][] Si { get; set; } // S[n]i
        }

        internal class EncCommitState
        {
            public string KeyID { get; set; }
            public long Timestamp { get; set; }
            public byte[][] gKn { get; set; }
            public byte[][] Yn { get; set; }
            public byte[][] mgORKj { get; set; }
            public byte[] R2 { get; set; }
        }


        public class CommitResponse
        {
            public string KeyID { get; set; }
            public long Timestampi { get; set; }
            public string[] mIDORK { get; set; }
            public string S { get; set; }
            public string R2 { get; set; }
            public string[] gKn { get; set; }
            public string[] Yn { get; set; }
        }

    }
}

