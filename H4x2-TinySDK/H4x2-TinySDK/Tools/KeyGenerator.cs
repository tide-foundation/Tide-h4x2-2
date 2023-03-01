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
        internal byte[] MSecOrki_Key => MSecOrki.ToByteArray(true, true);
        private Point MgOrki { get; } // this ork's public point
        internal Key mgOrki_Key => new Key(0, MgOrki);
        private string My_Username { get; } // this ork's username
        public int Threshold { get; } // change me
        private readonly Caching _cachingManager;


        public KeyGenerator(BigInteger mSecOrki, Point mgOrki, string my_Username, int threshold)
        {
            MSecOrki = mSecOrki;
            MgOrki = mgOrki;
            My_Username = my_Username;
            Threshold = threshold;
            _cachingManager = new Caching();
        }

        public string GenShard(string keyID, Point[] mgORKj, int numKeys, Point[] gMultiplier)
        {
            _cachingManager.Remove(keyID); // start clean

            if (mgORKj.Count() < 2)
            {
                throw new Exception("GenShard: Number of ork keys provided must be greater than 1");
            }
            if (numKeys < 1)
            {
                throw new Exception("GenShard: Number of keys requested must be at minimum 1");
            }

            // Generate random key multiplier
            BigInteger EphKeyi = Utils.RandomBigInt();

            // Generate DiffieHellman Keys based on this ork's priv and other Ork's Pubs
            byte[][] ECDHij = mgORKj.Select(pub => createKey(pub, EphKeyi)).ToArray();
            // Ids(Xs) of all orks
            var mgOrkj_Xs = mgORKj.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N));
            var my_X = Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(this.mgOrki_Key.Y.ToBase64())), false, true), Curve.N);
            BigInteger li = SecretSharing.EvalLi(my_X, mgOrkj_Xs, Curve.N);

            long timestampi = DateTime.UtcNow.Ticks;

            BigInteger[] k = new BigInteger[numKeys];
            Point[] gK = new Point[numKeys];
            PolyPoint[][] Yij = new PolyPoint[numKeys][];

            for (int i = 0; i < numKeys; i++)
            {
                // Generate random k shard
                k[i] = Utils.RandomBigInt();

                // Calculate public shard
                gK[i] = Curve.G * k[i];

                // For each ORK, secret share value ki
                Yij[i] = (SecretSharing.Share(k[i], mgOrkj_Xs, Threshold, Curve.N)).ToArray();
            }
            // Encrypt shard Yj with each ORK key
            string[] YCiphers = ECDHij.Select((key, i) => encryptShares(key, Yij, i, timestampi, keyID)).ToArray();

            // Encrypted partial public with ephemeral key
            string[] gKnCiphers = gK.Select(point => AES.Encrypt(point.ToBase64(), EphKeyi)).ToArray(); // encrypt base64 encoded point with string representation of ephKey

            // Encrypt latest state
            string cacheState = JsonSerializer.Serialize(new CacheState_GenShard
            {
                MgORKj = mgORKj.Select(p => p.ToByteArray64()).ToArray(), // remember IDs are string representations of Xs
                ECDHij = ECDHij,
                EphKey = EphKeyi.ToByteArray(true, true),
                K = k.Select(i => i.ToByteArray(true, true)).ToArray(),
                Li = li.ToByteArray(true, true),
                Stage = 1
            });

            GenShardResponse response = new GenShardResponse
            {
                GKCiphers = gKnCiphers,
                YijCiphers = YCiphers,
                Timestampi = timestampi.ToString()
            };

            _cachingManager.AddOrGetCache(keyID, cacheState).GetAwaiter().GetResult(); // add state to memory

            return JsonSerializer.Serialize(response);
        }

        /// <summary>
        /// Make sure orkShares provided are sorted in same order as mgORKj. For example, orkshare[0].From = ork2 AND mgORKj[0] = ork2's public.
        /// This function cannot correlate orkId to public key unless it's in the same order
        /// </summary>
        public string SendShard(string keyID, string[][] gKnCiphers, string[] yijCiphers, Point[] gMultiplier)
        {
            string state_s = _cachingManager.AddOrGetCache(keyID, string.Empty).GetAwaiter().GetResult(); //Retrive the state cached from GenShard function
            _cachingManager.Remove(keyID); // remove in case something fails

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

            int numKeys = decryptedShares.All(s => s.Shares.Length == decryptedShares.First().Shares.Length) 
                ? decryptedShares.First().Shares.Length 
                : throw new Exception("SendShard: Different amount of shares provided");

            BigInteger[] Y = new BigInteger[numKeys];
            BigInteger[] k = state.K.Select(i => new BigInteger(i, true, true)).ToArray();
            Point[] gKntesti = new Point[numKeys];
            Point[] gMultiplied = new Point[numKeys];
            for (int i = 0; i < numKeys; i++)
            {
                // Aggregate all shares to form final Y coordinate
                Y[i] = decryptedShares.Aggregate(BigInteger.Zero, (sum, point) => (sum + new BigInteger(point.Shares[i], true, true)) % Curve.N);

                // Generate sharded public key for final verification
                gKntesti[i] = Curve.G * Y[i];

                // Multiply the required multipliers
                if(i < gMultiplier.Length){
                    if(gMultiplier[i] is null) gMultiplied[i] = null;
                    else if(gMultiplier[i].IsSafePoint()) gMultiplied[i] = gMultiplier[i] * k[i];
                    else throw new Exception("SendShard: Not all points supplied are safe");
                }
            }

            // Generate partial EdDSA R2
            BigInteger ri = Utils.RandomBigInt();
            Point gRi = Curve.G * ri;

            string cacheData = JsonSerializer.Serialize(new CacheState_SendShard
            {
                MgORKj = state.MgORKj,
                ECDHij = state.ECDHij,
                Yn = Y.Select(point => point.ToByteArray(true, true)).ToArray(),
                Timestamp = timestamp,
                Ri = ri.ToByteArray(true, true),
                GKnCiphers = gKnCiphers,
                Li = state.Li,
                Stage = 3
            });

            var response = JsonSerializer.Serialize(new SendShardResponse
            {
                EphKeyi = new BigInteger(state.EphKey, true, true).ToString(),
                GKntesti = gKntesti.Select(point => point.ToByteArray()).ToArray(),
                GMultiplied = gMultiplied.Select(point => point.ToByteArray()).ToArray(),
                GRi = gRi.ToByteArray()
            });

            _cachingManager.AddOrGetCache(keyID, cacheData).GetAwaiter().GetResult(); // add latest cache

            return response;
        }

        public string SetKey(string keyID, Point[] gKntest, Point R2, string[] EphKeyj)
        {
            string state_s = _cachingManager.AddOrGetCache(keyID, string.Empty).GetAwaiter().GetResult(); //Retrive the state cached from GenShard function
            _cachingManager.Remove(keyID); // remove in case something fails
            if(String.IsNullOrEmpty(state_s)) throw new Exception("SetKey: KeyID in state does not exist");

            // Reastablish state
            CacheState_SendShard state = JsonSerializer.Deserialize<CacheState_SendShard>(state_s);
            if(state.Stage != 3) throw new Exception("SetKey: Requests in wrong order");

            // Decrypt the partial publics with EphKey
            int numKeys = state.Yn.Length;
            BigInteger[] ephKeys = EphKeyj.Select(k => BigInteger.Parse(k)).ToArray();
            Point[] gKn = new Point[numKeys];
            for(int i = 0; i < numKeys; i++)
            {
                // TODO: !!!!! Keep one of these shards in cache
                gKn[i] = state.GKnCiphers.Select((cipher, j) => Point.FromBase64(AES.Decrypt(cipher[i], ephKeys[j]))) // decrypt all points for key[i]
                                         .Aggregate(Curve.Infinity, (sum, next) => sum + next);                       // sum all points we just decrypted
                // Verifying both publics
                if(!gKn[i].isEqual(gKntest[i])) throw new Exception("SetKey: GKTest failed");
            }

            // This is done only on first key
            Point R = state.MgORKj.Select(p => Point.From64Bytes(p))
                                  .Aggregate(Curve.Infinity, (sum, next) => sum + next) + R2;
    
            // Prepare the signature message
            byte[] MData_To_Hash = gKn[0].ToByteArray().Concat(Encoding.ASCII.GetBytes(state.Timestamp.ToString())).Concat(Encoding.ASCII.GetBytes(keyID)).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = SHA256.HashData(MData_To_Hash);
            byte[] HData_To_Hash = R.ToByteArray().Concat(gKn[0].ToByteArray()).Concat(M).ToArray();
            BigInteger H = Utils.Mod(new BigInteger(SHA512.HashData(HData_To_Hash), true, false), Curve.N);

            BigInteger ri = new BigInteger(state.Ri, true, true); // restablish little r

            // Generate the partial signature with ORK's lagrange
            BigInteger li = new BigInteger(state.Li, true, true);
            BigInteger Y = new BigInteger(state.Yn[0], true, true);
            BigInteger si = this.MSecOrki + ri + (H * Y * li);

            // Encrypt latest state
            string encrypted_state = AES.Encrypt(JsonSerializer.Serialize(new EncCommitState
            {
                KeyID = keyID,
                Timestampi = state.Timestamp,
                gKn = gKn.Select(point => point.ToByteArray64()).ToArray(),
                Yn = state.Yn,
                mgORKj = state.MgORKj,
                R2 = R2.ToByteArray64()
            }), MSecOrki);

            return JsonSerializer.Serialize(new PreCommitResponse
            {
                Si = si.ToString(),
                EncCommitState_Encrypted = encrypted_state
            });
        }

        public CommitResponse Commit(string keyID, BigInteger S, string encCommitStatei)
        {
            // Reastablish state
            EncCommitState state = JsonSerializer.Deserialize<EncCommitState>(AES.Decrypt(encCommitStatei, MSecOrki_Key)); // decrypt encrypted state in response

            if (!state.KeyID.Equals(keyID))
            {
                throw new Exception("Commit: KeyID of instanciated object does not equal that of previous state");
            }
            if (!VerifyDelay(state.Timestampi, DateTime.UtcNow.Ticks))
            {
                throw new Exception("Commit: State has expired");
            }

            Point gK = Point.From64Bytes(state.gKn[0]);
            byte[] MData_To_Hash = gK.ToByteArray().Concat(Encoding.ASCII.GetBytes(state.Timestampi.ToString()).Concat(Encoding.ASCII.GetBytes(keyID))).ToArray(); // M = hash( gK[1] | timestamp | keyID )
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
                Timestampi = state.Timestampi,
                mIDORK = mgORKj.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N).ToString()).ToArray(),
                gKn = state.gKn.Select(gK => Point.From64Bytes(gK)).ToArray(),
                Yn = state.Yn.Select(y => new BigInteger(y, true, true)).ToArray(),
                R2 = R2,
                S = S
            };
        }
        public CommitPrismResponse CommitPrism(string keyID, Point gPRISMtest, string EncSetKeyStatei)
        {

            StateData state = JsonSerializer.Deserialize<StateData>(AES.Decrypt(EncSetKeyStatei, MSecOrki_Key)); // decrypt encrypted state in response

            if (!state.KeyID.Equals(keyID))
            {
                throw new Exception("CommitPrism: KeyID of instanciated object does not equal that of previous state");
            }

            Point gPRISM = Point.FromBytes(state.gKn[0]);
            // Verifying 
            if (!gPRISMtest.isEqual(gPRISM))
            {
                throw new Exception("CommitPrism: gPRISMtest failed");
            }
            return new CommitPrismResponse
            {
                Prismi = new BigInteger(state.Yn[0], true, true),
                gPrism = gPRISM
            };
        }

        private byte[] createKey(Point point, BigInteger ephKeyi)
        {
            if (MgOrki.isEqual(point))
                return MSecOrki_Key;
            else
                return (new BigInteger(SHA256.HashData((point * MSecOrki).ToByteArray()), true, false) * ephKeyi).ToByteArray(true, false); // ECDH = hash(mSecORKi * mgORKj) * EphKeyi
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

        private string encryptShares(byte[] key, PolyPoint[][] shares, int index, long timestampi, string keyID)
        {
            var data_to_encrypt = new ShareData
            {
                KeyID = keyID,
                Timestampi = timestampi.ToString(),
                Shares = shares.Select(pointShares => pointShares[index].Y.ToByteArray(true, true)).ToArray(),
            };
            return AES.Encrypt(JsonSerializer.Serialize(data_to_encrypt), key);
        }

        internal class CacheState_GenShard
        {
            public byte[][] MgORKj { get; set; } // list of ORK Pubs
            public byte[][] ECDHij { get; set; } // list of ECDH Keys
            public byte[] EphKey { get; set; }
            public int Stage { get; set; } 
            public byte[][] K { get; set; }
            public byte[] Li { get; set; }
        }
        internal class CacheState_SendShard
        {
            public byte[][] MgORKj { get; set; } // list of ORK Pubs
            public byte[][] ECDHij { get; set; } // list of ECDH Keys
            public byte[][] Yn { get; set; }
            public long Timestamp { get; set; }
            public byte[] Ri { get; set; }
            public string[][] GKnCiphers { get; set; } // stuff encrypted with eph key
            public byte[] Li { get; set; }
            public int Stage { get; set; } 
        }

        internal class GenShardResponse
        {
            public string[] GKCiphers { get; set; }
            public string[] YijCiphers { get; set; }
            public string Timestampi { get; set; }
            public byte[] GRi { get; set; }
        }
        internal class SendShardResponse
        {
            public string EphKeyi { get; set; }
            public byte[][] GKntesti { get; set; }
            public byte[][] GMultiplied { get; set; }
            public byte[] GRi { get; set; }
        }

        internal class ShareData
        {
            public string KeyID { get; set; } 
            public string Timestampi { get; set; }
            public byte[][] Shares { get; set; }
        }

        internal class StateData
        {
            public string KeyID { get; set; }
            public string Timestampi { get; set; }
            public byte[][] gKn { get; set; }
            public byte[][] Yn { get; set; }
            public byte[][] gKntesti { get; set; }
            public string ri { get; set; }
            public byte[][] mgORKj { get; set; }
        }
        internal class SetKeyResponse
        {
            public byte[][] gKntesti { get; set; } //ed25519Points
            public byte[] gRi { get; set; } //ed25519Point
            public string gKsigni { get; set; } // signed gKtesti by this ork
            public string state_id { get; set; }
        }
        internal class EncCommitState
        {
            public string KeyID { get; set; }
            public long Timestampi { get; set; }
            public byte[][] gKn { get; set; }
            public byte[][] Yn { get; set; }
            public byte[][] mgORKj { get; set; }
            public byte[] R2 { get; set; }
        }

        internal class PreCommitResponse
        {
            public string Si { get; set; }
            public string EncCommitState_Encrypted { get; set; }
        }

        public class CommitResponse
        {
            public string KeyID { get; set; }
            public long Timestampi { get; set; }
            public string[] mIDORK { get; set; }
            public BigInteger S { get; set; }
            public Point R2 { get; set; }
            public Point[] gKn { get; set; }
            public BigInteger[] Yn { get; set; }
        }

        public class CommitPrismResponse
        {
            public BigInteger Prismi { get; set; }
            public Point gPrism { get; set; }
        }

    }
}

