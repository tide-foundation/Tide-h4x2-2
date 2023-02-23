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

        public string GenShard(string keyID, Point[] mgORKj, int numKeys, Point[] gMultiplier, string[] orkNames)
        {
            if (mgORKj.Count() != orkNames.Count())
            {
                throw new Exception("GenShard: Length of keys supplied is not equal to length of supplied ork usernames");
            }
            if (mgORKj.Count() < 2)
            {
                throw new Exception("GenShard: Number of ork keys provided must be greater than 1");
            }
            if (numKeys < 1)
            {
                throw new Exception("GenShard: Number of keys requested must be at minimum 1");
            }

            // Generate DiffieHellman Keys based on this ork's priv and other Ork's Pubs
            byte[][] ECDHij = mgORKj.Select(key => createKey(key)).ToArray();

            // Here we generate the X values of the polynomial through creating GUID from other orks publics, then generating a bigInt (the X) from those GUIDs
            // This was based on how the JS creates the X values from publics in ClientBase.js and IdGenerator.js
            var mgOrkj_Xs = mgORKj.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N)); /// CHANGE THIS OH LORD

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
                    else if(gMultiplier[i].IsSafePoint()) gMultiplied[i] = gMultiplier[i] * k[i];
                    else throw new Exception("GenShard: Not all points supplied are safe");
                }
            }
            // Encrypt shares and partial public with each ork key
            ShareEncrypted[] YCiphers = orkNames.Select((username, i) => encryptShares(ECDHij, Yij, gK, i, timestampi, username, keyID)).ToArray();

            // Encrypt latest state
            string encSetKeyState = AES.Encrypt(JsonSerializer.Serialize(new SetKeyState
            {
                keyID = keyID,
                mgORKj = mgORKj.Select(p => p.ToByteArray()).ToArray(), // remember IDs are string representations of Xs
                ECDHij = ECDHij
            }), MSecOrki);

            GenShardResponse response = new GenShardResponse
            {
                GK = gK[0].ToByteArray(),
                EncryptedOrkShares = YCiphers,
                GMultiplied = gMultiplier == null ? null : gMultiplied.Select(multiplier => multiplier is null ? null : multiplier.ToByteArray()).ToArray(),
                Timestampi = timestampi.ToString(),
                EncSetKeyState = encSetKeyState
            };

            return JsonSerializer.Serialize(response);
        }

        /// <summary>
        /// Make sure orkShares provided are sorted in same order as mgORKj. For example, orkshare[0].From = ork2 AND mgORKj[0] = ork2's public.
        /// This function cannot correlate orkId to public key unless it's in the same order
        /// </summary>
        public string SetKey(string keyID, string[] orkShares, string EncSetKeyState)
        {
            // Reastablish state
            SetKeyState state = JsonSerializer.Deserialize<SetKeyState>(AES.Decrypt(EncSetKeyState, MSecOrki));

            if(!keyID.Equals(state.keyID))
            {
                throw new Exception("SetKey: KeyID in state does not match what was provided");
            }



            IEnumerable<ShareEncrypted> encryptedShares = orkShares.Select(share => JsonSerializer.Deserialize<ShareEncrypted>(share)); // deserialize all ork shares back into objects
            if (!encryptedShares.All(share => share.To.Equals(My_Username)))
            {
                throw new Exception("SetKey: One or more of the shares were sent to the incorrect ork");
            }

            // Decrypts only the shares that were sent to itself and the partial publics
            IEnumerable<DataToEncrypt> decryptedShares = encryptedShares.Select((share, i) => decryptShares(share, state.ECDHij[i]));
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
            Point[] gKntesti = new Point[numKeys];
            for (int i = 0; i < numKeys; i++) // will iterate by the number of keys to build
            {
                // Add own all previously encrypted gKs together to mitigate malicious user
                gK[i] = decryptedShares.Aggregate(Curve.Infinity, (total, next) => total + Point.FromBytes(next.PartialPubs[i]));

                // Aggregate all shares to form final Y coordinate
                Y[i] = decryptedShares.Aggregate(BigInteger.Zero, (sum, point) => (sum + new BigInteger(point.Shares[i], true, true)) % Curve.N);

                // Generate sharded public key for final verification
                gKntesti[i] = Curve.G * Y[i];
            }

            // Sign sharded public key for vinal validation
            byte[] to_sign = SHA256.HashData(gKntesti.Select(p => p.Compress()).Aggregate((sum, next) => (byte[])sum.Concat(next)));
            string gKsigni =  new Key(MSecOrki).Sign(to_sign);

            // Generate random r
            BigInteger ri = Utils.RandomBigInt();

            // Create state to store in cache
            string state_id = Guid.NewGuid().ToString(); // identifier to grab r from cache in PreCommit
            string state_data = JsonSerializer.Serialize(new StateData
            {
                KeyID = decryptedShares.First().KeyID,
                Timestampi = timestamp.ToString(),
                gKn = gK.Select(point => point.ToByteArray()).ToArray(),
                Yn = Y.Select(num => num.ToByteArray(true, true)).ToArray(),
                gKntesti = gKntesti.Select(point => point.ToByteArray()).ToArray(),
                ri = ri.ToString(),
                mgORKj = state.mgORKj
            });

            // Add state data to cache
            _cachingManager.AddOrGetCache(state_id, state_data).GetAwaiter().GetResult(); // add the r to caching with RKey
            
            Point gRi = Curve.G * ri;

            var response = new SetKeyResponse
            {
                gKntesti = gKntesti.Select(point => point.ToByteArray()).ToArray(),
                gRi = gRi.ToByteArray(),
                gKsigni = gKsigni,
                state_id = state_id
            };
            return JsonSerializer.Serialize(response);
        }

        public string PreCommit(string keyID, Point[][] gKntesti, string[] gKsigni, Point R2, string state_id)
        {
            // Reastablish state
            string state_s = _cachingManager.AddOrGetCache(state_id, string.Empty).GetAwaiter().GetResult(); //Retrive the state cached from SetKey function.
            StateData state = JsonSerializer.Deserialize<StateData>(state_s); // decrypt encrypted state in response

            // Validate authenticity of all public shards
            byte[][] to_verify = gKntesti.Select(gKtest => SHA512.HashData(gKtest.Select(p => p.Compress()).Aggregate((sum, next) => (byte[])sum.Concat(next)))).ToArray(); // oh my god this is a long line
            Point[] mgORKj = state.mgORKj.Select(p => Point.FromBytes(p)).ToArray();
            var verify_index = 0;
            foreach(Point pub in mgORKj){
                if(!EdDSA.Verify(to_verify[verify_index], gKsigni[verify_index], pub)) throw new Exception("PreCommit: gKntesti verification failed");
                verify_index +=1;
            }

            if (!state.KeyID.Equals(keyID))
            {
                throw new Exception("PreCommit: KeyID of instanciated object does not equal that of previous state");
            }
            if (!VerifyDelay(long.Parse(state.Timestampi), DateTime.UtcNow.Ticks))
            {
                throw new Exception("PreCommit: State has expired");
            }

            _cachingManager.Remove(state_s); //remove the r from cache

            // Calculate the lagrange coefficient for this ORK
            var mgOrkj_Xs = mgORKj.Select(pub => Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(pub.ToBase64())), false, true), Curve.N));
            var my_X = Utils.Mod(new BigInteger(SHA256.HashData(Encoding.ASCII.GetBytes(this.mgOrki_Key.Y.ToBase64())), false, true), Curve.N);
            BigInteger li = EccSecretSharing.EvalLi(my_X, mgOrkj_Xs, Curve.N);

            // Interpolate the key public
            if(!gKntesti.All(p => p.Count() == gKntesti[0].Count())) throw new Exception("PreCommit: Not all gKntests provided the same amount of points");
            Point[] gKntest = gKntesti[0].Select((_, i) => gKntesti.Aggregate(Curve.Infinity, (sum, next) => sum + next[i])).ToArray(); // using first element as length counter

            // Verifying both publics
            Point[] gKn = state.gKn.Select(bytes => Point.FromBytes(bytes)).ToArray();
            if (!gKntest.Select((gKtest, i) => gKtest.isEqual(gKn[i])).All(verify => verify == true))
            { // check all elements of gKtest[n] == gK[n]
                throw new Exception("PreCommit: gKtest failed");
            }

            // This is only done on the first key: n=0
            Point R = mgORKj.Aggregate(Curve.Infinity, (sum, next) => next + sum) + R2;

            // Prepare the signature message
            byte[] MData_To_Hash = gKn[0].Compress().Concat(Encoding.ASCII.GetBytes(state.Timestampi)).Concat(Encoding.ASCII.GetBytes(keyID)).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = SHA256.HashData(MData_To_Hash);
            byte[] HData_To_Hash = R.Compress().Concat(gKn[0].Compress()).Concat(M).ToArray();
            BigInteger H = Utils.Mod(new BigInteger(SHA512.HashData(HData_To_Hash), true, false), Curve.N);

            BigInteger ri = BigInteger.Parse(state.ri);

            // Generate the partial signature
            BigInteger Y = new BigInteger(state.Yn[0], true, true);
            BigInteger Si = this.MSecOrki + ri + (H * Y * li);

            string encrypted_state = AES.Encrypt(JsonSerializer.Serialize(new EncCommitState
            {
                Timestampi = state.Timestampi,
                gKn = state.gKn,
                Yn = state.Yn.Select(Y => new BigInteger(Y, true, true)).ToArray(),
                mgORKj = state.mgORKj
            }), MSecOrki);

            return JsonSerializer.Serialize(new PreCommitResponse
            {
                S = Si,
                EncCommitState_Encrypted = encrypted_state
            });
        }

        public CommitResponse Commit(string keyID, BigInteger S, Point[] mgORKj, Point R2, string EncSetKeyStatei)
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
            byte[] MData_To_Hash = gK.Compress().Concat(Encoding.ASCII.GetBytes(state.Timestampi).Concat(Encoding.ASCII.GetBytes(keyID))).ToArray(); // M = hash( gK[1] | timestamp | keyID )
            byte[] M = SHA256.HashData(MData_To_Hash);

            Point R = mgORKj.Aggregate(Curve.Infinity, (sum, next) => next + sum) + R2;

            byte[] HData_To_Hash = R.Compress().Concat(gK.Compress()).Concat(M).ToArray();
            BigInteger H = new BigInteger(SHA512.HashData(HData_To_Hash), true, false).Mod(Curve.N);

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

        internal class SetKeyState
        {
            public string keyID { get; set; }
            public byte[][] mgORKj { get; set; } // list of ORK Pubs
            public byte[][] ECDHij { get; set; } // list of ECDH Keys 
        }

        internal class GenShardResponse
        {
            public byte[] GK { get; set; } // represents G * k[i]  ToByteArray()
            public ShareEncrypted[] EncryptedOrkShares { get; set; }
            public byte[][] GMultiplied { get; set; }
            public string Timestampi { get; set; }
            public string EncSetKeyState { get; set; }
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
            public string keyID { get; set; }
            public string Timestampi { get; set; }
            public byte[][] gKn { get; set; }
            public BigInteger[] Yn { get; set; }
            public byte[][] mgORKj { get; set; }
        }

        internal class PreCommitResponse
        {
            public BigInteger S { get; set; }
            public string EncCommitState_Encrypted { get; set; }
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

