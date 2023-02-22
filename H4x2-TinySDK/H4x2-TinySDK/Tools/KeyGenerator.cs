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

        public string GenShard(string keyID, Point[] mgOrkij, int numKeys, Point[] gMultiplier, string[] orkNames)
        {
            if (gMultiplier is not null) // if multiplier list is null, do not throw ex
            {
                if(!gMultiplier.All(multipler => 
                    { 
                        if(multipler is not null) if(!multipler.IsSafePoint()) return false; // point is (not safe) AND (not null), throw ex
                        return true; // point is (not null AND safe) OR (null)
                    })) 
                { 
                    throw new Exception("GenShard: Not all points supplied are safe");
                }
            }
            if (mgOrkij.Count() != orkNames.Count())
            {
                throw new Exception("GenShard: Length of keys supplied is not equal to length of supplied ork usernames");
            }
            if (mgOrkij.Count() < 2)
            {
                throw new Exception("GenShard: Number of ork keys provided must be greater than 1");
            }
            if (numKeys < 1)
            {
                throw new Exception("GenShard: Number of keys requested must be at minimum 1");
            }

            // Generate DiffieHellman Keys based on this ork's priv and other Ork's Pubs
            byte[][] ECDHij = mgOrkij.Select(key => createKey(key)).ToArray();

            // Here we generate the X values of the polynomial through creating GUID from other orks publics, then generating a bigInt (the X) from those GUIDs
            // This was based on how the JS creates the X values from publics in ClientBase.js and IdGenerator.js
            var mgOrkj_Xs = mgOrkij.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N)); /// CHANGE THIS OH LORD

            long timestampi = DateTime.UtcNow.Ticks;

            BigInteger[] k = new BigInteger[numKeys];
            Point[] gK = new Point[numKeys];
            PolyPoint[][] Yij = new PolyPoint[numKeys][];
            Point[] gMultiplied = new Point[gMultiplier == null ? 0 : gMultiplier.Length];

            for (int i = 0; i < numKeys; i++)
            {
                // Generate random k shard
                k[i] = Utils.RandomBigInt();

                // Calculate public shard
                gK[i] = Curve.G * k[i];

                // For each ORK, secret share value ki
                Yij[i] = (EccSecretSharing.Share(k[i], mgOrkj_Xs, Threshold, Curve.N)).ToArray();

                // Multiply the required multipliers
                if(i < gMultiplier.Length){
                    if(gMultiplier[i] is null) gMultiplied[i] = null;
                    else gMultiplied[i] = gMultiplier[i] * k[i];
                }
            }
            // Encrypt shares and partial public with each ork key
            ShareEncrypted[] YCiphers = orkNames.Select((username, i) => encryptShares(ECDHij, Yij, gK, i, timestampi, username, keyID)).ToArray();

            GenShardResponse response = new GenShardResponse
            {
                GK = gK[0].ToByteArray(),
                EncryptedOrkShares = YCiphers,
                GMultiplied = gMultiplier == null ? null : gMultiplied.Select(multiplier => multiplier is null ? null : multiplier.ToByteArray()).ToArray(),
                Timestampi = timestampi.ToString()
            };

            return JsonSerializer.Serialize(response);
        }

        /// <summary>
        /// Make sure orkShares provided are sorted in same order as mgOrkij. For example, orkshare[0].From = ork2 AND mgOrkij[0] = ork2's public.
        /// This function cannot correlate orkId to public key unless it's in the same order
        /// </summary>
        public (string, string) SetKey(string keyID, string[] orkShares, Point[] mgOrkij)
        {
            IEnumerable<ShareEncrypted> encryptedShares = orkShares.Select(share => JsonSerializer.Deserialize<ShareEncrypted>(share)); // deserialize all ork shares back into objects
            if (!encryptedShares.All(share => share.To.Equals(My_Username)))
            {
                throw new Exception("SetKey: One or more of the shares were sent to the incorrect ork");
            }

            // Decrypts only the shares that were sent to itself and the partial publics
            byte[][] ECDHij = mgOrkij.Select(key => createKey(key)).ToArray();
            IEnumerable<DataToEncrypt> decryptedShares = encryptedShares.Select((share, i) => decryptShares(share, ECDHij[i]));
            if (!decryptedShares.All(share => share.KeyID.Equals(keyID))) // check that no one is attempting to recreate someone else's key for their own account
            {
                throw new Exception("SetKey: KeyID of this share does not equal KeyID supplied");
            }

            // Verify the time difference is not material (30min)
            long timestamp = Median(decryptedShares.Select(share => long.Parse(share.Timestampi)).ToArray()); // get median of timestamps
            if (!decryptedShares.All(share => VerifyDelay(long.Parse(share.Timestampi), timestamp)))
            {
                throw new Exception("SetKey: One or more of the shares has expired");
            }

            int numKeys = decryptedShares.First().PartialPubs.Count();
            Point[] gK = new Point[numKeys];
            BigInteger[] Y = new BigInteger[numKeys];
            Point[] gKTest = new Point[numKeys];
            for (int i = 0; i < numKeys; i++) // will iterate by the number of keys to build
            {
                // Add own all previously encrypted gKs together to mitigate malicious user
                gK[i] = decryptedShares.Aggregate(Curve.Infinity, (total, next) => total + Point.FromBytes(next.PartialPubs[i]));

                // Aggregate all shares to form final Y coordinate
                Y[i] = decryptedShares.Aggregate(BigInteger.Zero, (sum, point) => (sum + new BigInteger(point.Shares[i], true, true)) % Curve.N);

                // Generate sharded public key for final verification
                gKTest[i] = Curve.G * Y[i];
            }

            // Encrypt latest state with this ork's private key
            string encrypted_data = AES.Encrypt(JsonSerializer.Serialize(new StateData
            {
                KeyID = decryptedShares.First().KeyID,
                Timestampi = timestamp.ToString(),
                gKn = gK.Select(point => point.ToByteArray()).ToArray(),
                Yn = Y.Select(num => num.ToByteArray(true, true)).ToArray()   ///// add R Key here
            }), MSecOrki_Key);

            // Generate EdDSA R from all the ORKs publics
            byte[] MData_To_Hash = gK[0].ToByteArray().Concat(BitConverter.GetBytes(timestamp).Concat(Encoding.ASCII.GetBytes(keyID))).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = Utils.HashSHA512(MData_To_Hash);

            var ri = Utils.RandomBigInt();
            var RKey = Utils.RandomBigInt();
            _cachingManager.AddOrGetCache(RKey.ToString(), ri.ToString()).GetAwaiter().GetResult(); //add the r to caching with RKey

            Point gRi = Curve.G * ri;

            var response = new SetKeyResponse
            {
                gKTesti = gKTest.Select(point => point.ToByteArray()).ToArray(),
                gRi = gRi.ToByteArray(),
                EncSetKeyStatei = encrypted_data
            };
            return (JsonSerializer.Serialize(response), AES.Encrypt(RKey.ToString(), MSecOrki_Key));
        }

        public PreCommitResponse PreCommit(string keyID, Point[] gKntest, Point[] mgOrkij, Point R2, string EncSetKeyStatei, string randomKey)
        {
            var key = AES.Decrypt(randomKey, MSecOrki_Key);
            string r = _cachingManager.AddOrGetCache(key, string.Empty).GetAwaiter().GetResult(); //Retrive the r cached while setkey function.
            if (r == null || r == "")
            {
                throw new Exception("PreCommit: Random not found in cache");
            }
            _cachingManager.Remove(randomKey); //remove the r from cache

            // Reastablish state
            StateData state = JsonSerializer.Deserialize<StateData>(AES.Decrypt(EncSetKeyStatei, MSecOrki_Key)); // decrypt encrypted state in response

            if (!state.KeyID.Equals(keyID))
            {
                throw new Exception("PreCommit: KeyID of instanciated object does not equal that of previous state");
            }
            if (!VerifyDelay(long.Parse(state.Timestampi), DateTime.UtcNow.Ticks))
            {
                throw new Exception("PreCommit: State has expired");
            }
            Point[] gKn = state.gKn.Select(bytes => Point.FromBytes(bytes)).ToArray();
            byte[] MData_To_Hash = gKn[0].Compress().Concat(Encoding.ASCII.GetBytes(state.Timestampi)).Concat(Encoding.ASCII.GetBytes(keyID)).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = Utils.Hash(MData_To_Hash);

            BigInteger ri = BigInteger.Parse(r);

            // Verifying both publics
            if (!gKntest.Select((gKtest, i) => gKtest.isEqual(gKn[i])).All(verify => verify == true))
            { // check all elements of gKtest[n] == gK[n]
                throw new Exception("PreCommit: gKtest failed");
            }

            // This is done only on the first key
            Point R = mgOrkij.Aggregate(Curve.Infinity, (sum, next) => next + sum) + R2;

            // Prepare the signature message
            byte[] HData_To_Hash = R.Compress().Concat(gKn[0].Compress()).Concat(M).ToArray();
            BigInteger H = new BigInteger(Utils.HashSHA512(HData_To_Hash), true, false).Mod(Curve.N);


            // Calculate the lagrange coefficient for this ORK
            var mgOrkj_Xs = mgOrkij.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N));
            var my_X = Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(this.mgOrki_Key.Y.ToBase64())), false, true), Curve.N);
            BigInteger li = EccSecretSharing.EvalLi(my_X, mgOrkj_Xs, Curve.N);
            // Generate the partial signature
            BigInteger Y = new BigInteger(state.Yn[0], true, true);
            BigInteger Si = this.MSecOrki + ri + (H * Y * li);
            // BigInteger Si = this.MSecOrki + BigInteger.Parse(r) + (H * Y * li);


            return new PreCommitResponse
            {
                Timestampi = state.Timestampi,
                gKn = state.gKn.Select(gK => Point.FromBytes(gK)).ToArray(),
                Yn = state.Yn.Select(Y => new BigInteger(Y, true, true)).ToArray(),
                S = Si
            };
        }

        public CommitResponse Commit(string keyID, BigInteger S, Point[] mgOrkij, Point R2, string EncSetKeyStatei)
        {
            // Reastablish state
            // SetKeyResponse decryptedResponse = JsonSerializer.Deserialize<SetKeyResponse>(EncSetKeyStatei);  // deserialize reponse
            StateData state = JsonSerializer.Deserialize<StateData>(AES.Decrypt(EncSetKeyStatei, MSecOrki_Key)); // decrypt encrypted state in response

            if (!state.KeyID.Equals(keyID))
            {
                throw new Exception("Commit: KeyID of instanciated object does not equal that of previous state");
            }
            if (!VerifyDelay(long.Parse(state.Timestampi), DateTime.UtcNow.Ticks))
            {
                throw new Exception("Commit: State has expired");
            }

            Point gK = Point.FromBytes(state.gKn[0]);
            byte[] MData_To_Hash = gK.ToByteArray().Concat(Encoding.ASCII.GetBytes(state.Timestampi).Concat(Encoding.ASCII.GetBytes(keyID))).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = Utils.Hash(MData_To_Hash);

            Point R = mgOrkij.Aggregate(Curve.Infinity, (sum, next) => next + sum) + R2;

            byte[] HData_To_Hash = R.ToByteArray().Concat(gK.ToByteArray()).Concat(M).ToArray();
            BigInteger H = new BigInteger(Utils.HashSHA512(HData_To_Hash), true, false).Mod(Curve.N);

            // Verify the Signature 
            bool valid = (Curve.G * S).isEqual(R + (gK * H));

            if (!valid)
            {
                throw new Exception("Commit: Validation failed");
            }

            return new CommitResponse
            {
                Timestampi = long.Parse(state.Timestampi),
                gKn = state.gKn.Select(gK => Point.FromBytes(gK)).ToArray(),
                Yn = state.Yn.Select(Y => new BigInteger(Y, true, true)).ToArray()
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

        private byte[] createKey(Point point)
        {
            if (MgOrki.isEqual(point))
                return MSecOrki_Key;
            else
                return (point * MSecOrki).Compress();
        }

        private bool VerifyDelay(long timestamp, long timestampi)
        {
            return (System.Math.Abs(timestamp - timestampi) < 18000000000); // Checks different between timestamps is less than 30 min
        }
        private long Median(long[] data)  // TODO: implement this somewhere better in Cryptide
        {
            Array.Sort(data);
            if (data.Length % 2 == 0)
                return (data[data.Length / 2 - 1] + data[data.Length / 2]) / 2;
            else
                return data[data.Length / 2];
        }
        private DataToEncrypt decryptShares(ShareEncrypted encryptedShare, byte[] DHKey)
        {
            return JsonSerializer.Deserialize<DataToEncrypt>(AES.Decrypt(encryptedShare.EncryptedData, DHKey)); // decrypt encrypted share and create DataToEncrypt object
        }

        private ShareEncrypted encryptShares(byte[][] DHKeys, PolyPoint[][] shares, Point[] gK, int index, long timestampi, string to_username, string keyID)
        {
            var data_to_encrypt = new DataToEncrypt
            {
                KeyID = keyID,
                Timestampi = timestampi.ToString(),
                Shares = shares.Select(pointShares => pointShares[index].Y.ToByteArray(true, true)).ToArray(),
                PartialPubs = gK.Select(partialPub => partialPub.ToByteArray()).ToArray()
            };
            var orkShare = new ShareEncrypted
            {
                To = to_username,
                From = My_Username,
                EncryptedData = AES.Encrypt(JsonSerializer.Serialize(data_to_encrypt), DHKeys[index]) //check this  SHA256.HashData((prismPub * orkKey.Priv).ToByteArray());
            };
            return orkShare;
        }

        internal class GenShardResponse
        {
            public byte[] GK { get; set; } // represents G * k[i]  ToByteArray()
            public ShareEncrypted[] EncryptedOrkShares { get; set; }
            public byte[][] GMultiplied { get; set; }
            public string Timestampi { get; set; }
        }

        internal class ShareEncrypted
        {
            public string To { get; set; } /// Ork Username the share will go to
            public string From { get; set; } /// Ork Username the share is sent from
            public string EncryptedData { get; set; } // this is the DataToEncrypt object encrypted
        }

        internal class DataToEncrypt
        {
            public string KeyID { get; set; } // Guid of key to string()
            public string Timestampi { get; set; }
            public byte[][] Shares { get; set; }
            public byte[][] PartialPubs { get; set; }
        }
        internal class StateData
        {
            public string KeyID { get; set; } // Guid of key to string()
            public string Timestampi { get; set; }
            public byte[][] gKn { get; set; }
            public byte[][] Yn { get; set; }
        }
        internal class SetKeyResponse
        {
            public byte[][] gKTesti { get; set; } //ed25519Points
            public byte[] gRi { get; set; } //ed25519Point
            public string EncSetKeyStatei { get; set; } // encrypted StateData
        }
        public class PreCommitResponse
        {
            public string Timestampi { get; set; }
            public Point[] gKn { get; set; }
            public BigInteger[] Yn { get; set; }
            public BigInteger S { get; set; }
        }

        public class CommitResponse
        {
            public long Timestampi { get; set; }
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

