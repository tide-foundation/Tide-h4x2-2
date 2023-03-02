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


using Microsoft.AspNetCore.Mvc;
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Tools;
using System.Numerics;
using H4x2_Node.Services;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;

namespace H4x2_Node.Controllers
{
    public class ApplyController : Controller
    {
        private Settings _settings { get; }
        private IUserService _userService;
        private readonly KeyGenerator _keyGenerator;
        public ApplyController(Settings settings, IUserService userService)
        {
            _settings = settings;
            _userService = userService;
            _keyGenerator = new KeyGenerator(_settings.Key.Priv, _settings.Key.Y, _settings.OrkName, _settings.Threshold);
        }

        [HttpPost]
        public ActionResult Prism([FromQuery] string uid, Point point)
        {
            if (uid == null) throw new ArgumentNullException("uid cannot be null");
            try
            {
                if (point == null) throw new Exception("Apply Controller: Point supplied is not valid and/or safe");
                var user = _userService.GetById(uid); // get user
                var userPrism = BigInteger.Parse(user.Prismi); // get user prism
                var response = Flows.Apply.Prism(point, userPrism);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public ActionResult AuthData([FromQuery] string uid, [FromForm] string authData)
        {
            if (uid == null) throw new ArgumentNullException("uid cannot be null");
            try
            {
                var user = _userService.GetById(uid);
                var userCVK = BigInteger.Parse(user.CVK);
                var response = Flows.Apply.AuthData(authData, user.PrismAuthi, userCVK);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Ok("--FAILED--:" + ex.Message);
            }

        }



        [HttpPost]
        public ActionResult Convert([FromQuery] string uid, Point gBlurPass)
        {
            if (!gBlurPass.IsSafePoint())
                return Ok("--FAILED--: Invalid parameters !");

            var user = _userService.GetById(uid);
            if (user is null)
                return Ok("--FAILED--: User not found !");

            var gBlurPassPrismi = gBlurPass * BigInteger.Parse(user.Prismi);

            var Token = new TranToken();
            var purpose = "auth";
            var data_to_sign = Encoding.UTF8.GetBytes(uid.ToString() + purpose); // also includes timestamp inside TranToken object
            Token.Sign(_settings.SecretKey, data_to_sign);

            var response = new
            {
                GBlurPassPrism = gBlurPassPrismi.ToByteArray(),
                EncReply = AES.Encrypt(Token.ToByteArray(), System.Convert.FromBase64String(user.PrismAuthi))
            };

            return Ok(JsonSerializer.Serialize(response));
        }


        [HttpGet]
        public ActionResult Authenticate([FromQuery] string uid, [FromQuery] string certTimei, [FromQuery] string token)
        {
            var tran = TranToken.Parse(System.Convert.FromBase64String(token));
            var bytesCertTimei = System.Convert.FromBase64String(certTimei);
            var CertTimei = TranToken.Parse(bytesCertTimei);

            var user = _userService.GetById(uid);

            var buffer = new byte[System.Convert.FromBase64String(uid).Length + bytesCertTimei.Length];
            System.Convert.FromBase64String(uid).CopyTo(buffer, 0);
            bytesCertTimei.CopyTo(buffer, System.Convert.FromBase64String(uid).Length);

            if (user == null)
                return Ok("--FAILED--: User not found !");
            if (tran == null || !tran.Check(System.Convert.FromBase64String(user.PrismAuthi), buffer))
                return Ok("--FAILED--: Invalid token !");
            if (!CertTimei.OnTime)
                return Ok("--FAILED--: Expired !");
            var purpose = "auth";
            var data_to_sign = Encoding.UTF8.GetBytes(uid.ToString() + purpose);

            // Verify hmac(timestami ||userId || purpose , mSecOrki)== certTimei
            if (!CertTimei.Check(_settings.SecretKey, data_to_sign))
                return Ok("--FAILED--: " + Unauthorized());

            return Ok();
        }

        [HttpPost]
        public ActionResult PreSignCvk([FromQuery] string uid, [FromQuery] long timestamp2, [FromQuery] string challenge, Point gSessKeyPub)
        {
            var M_bytes = Encoding.ASCII.GetBytes(challenge).ToArray();

            var CVKRi = Utils.RandomBigInt();
            var gCVKRi = Curve.G * CVKRi;

            var ECDH_seed = SHA256.HashData((gSessKeyPub * _settings.Key.Priv).ToByteArray());

            return Ok(AES.Encrypt(gCVKRi.ToByteArray(), ECDH_seed));
        }


        [HttpPost]
        public ActionResult SignCvk([FromQuery] string uid, [FromQuery] long timestamp2, [FromQuery] string challenge, Point gCVKR, Point gSessKeyPub)
        {
            var user = _userService.GetById(uid);
            if (user == null)
                return Ok("--FAILED--: User not found !");

            //Verify timestamp2 in recent (10 min)
            var Time = DateTime.FromBinary(timestamp2);
            const long _window = TimeSpan.TicksPerHour; //Check later

            if (!(Time >= DateTime.UtcNow.AddTicks(-_window) && Time <= DateTime.UtcNow.AddTicks(_window)))
                return Ok("--FAILED--: Expired !");

            if (!gSessKeyPub.IsSafePoint())
                return Ok("--FAILED--: Invalid Parameter !");

            /// Standard EdDSA signature to sign challenge with CVKi from here on

            var M = Encoding.ASCII.GetBytes(challenge).ToArray(); // perform JWT checking here first

            /// From RFC 8032 5.1.6.2:
            /// Compute SHA-512(dom2(F, C) || prefix || PH(M)), where M is the
            /// message to be signed.  Interpret the 64-octet digest as a little-
            /// endian integer r.
            ///
            /// prefix : CVKRi   r : CVKRi
            var CVKRi_ToHash = BigInteger.Parse(user.CVK).ToByteArray(true, false).Concat(M).ToArray();
            var CVKRi = new BigInteger(SHA512.HashData(CVKRi_ToHash), true, false).Mod(Curve.N);

            /// From RFC 8032 5.1.6.4:
            /// Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
            /// 64-octet digest as a little-endian integer k.
            ///
            /// R : gCVKR     A : gCVK     PH(M) : challenge    k : CVKH
            var CVKH_ToHash = gCVKR.Compress().Concat(Point.FromBase64(user.GCVK).Compress()).Concat(M).ToArray();
            var CVKH = new BigInteger(SHA512.HashData(CVKH_ToHash), true, false).Mod(Curve.N);

            /// From RFC 8032 5.1.6.5:
            /// Compute S = (r + k * s) mod L.  For efficiency, again reduce k
            /// modulo L first.
            ///
            /// r: CVKRi    k : CVKH    s : CVKi
            var CVKSi = (CVKRi + (CVKH * BigInteger.Parse(user.CVK))).Mod(Curve.N);

            var ECDH_seed = SHA256.HashData((gSessKeyPub * _settings.Key.Priv).ToByteArray());

            // No need to return R : gCVKR as we already have it
            //return Ok(AES.Encrypt(CVKSi.ToByteArray(true, false), ECDH_seed));

            var response = new
            {
                UserCVK = user.GCVK,
                EncCVKSi = AES.Encrypt(CVKSi.ToByteArray(true, false), ECDH_seed)
            };

            return Ok(JsonSerializer.Serialize(response));
        }


        [HttpPut]
        public ActionResult CommitPrism([FromQuery] string uid, [FromQuery] string certTimei, [FromQuery] string token, Point gPRISMtest, Point gPRISMAuth, string state)
        {
            var tran = TranToken.Parse(System.Convert.FromBase64String(token));
            var bytesCertTimei = System.Convert.FromBase64String(certTimei);
            var CertTimei = TranToken.Parse(bytesCertTimei);

            var user = _userService.GetById(uid);
            if (user == null)
                return Ok("--FAILED--: User not found !");

            var buffer = new byte[System.Convert.FromBase64String(uid).Length + bytesCertTimei.Length];
            System.Convert.FromBase64String(uid).CopyTo(buffer, 0);
            bytesCertTimei.CopyTo(buffer, System.Convert.FromBase64String(uid).Length);

            if (tran == null || !tran.Check(System.Convert.FromBase64String(user.PrismAuthi), buffer))
                return Ok("--FAILED--: Invalid token !");
            if (!CertTimei.OnTime)
                return Ok("--FAILED--: Expired !");

            var purpose = "auth";
            var data_to_sign = Encoding.UTF8.GetBytes(uid.ToString() + purpose);

            // Verify hmac(timestami ||userId || purpose , mSecOrki)== certTimei
            if (!CertTimei.Check(_settings.SecretKey, data_to_sign))
                return Ok("--FAILED--: " + Unauthorized());
            try
            {
                StateData decrypted_state = JsonSerializer.Deserialize<StateData>(AES.Decrypt(state, _settings.Key.Priv.ToByteArray(true, true))); // decrypt encrypted state in response

                if (!decrypted_state.KeyID.Equals(uid))
                {
                    return Ok("--FAILED--: CommitPrism: KeyID of instanciated object does not equal that of previous state");
                }

                Point gPRISM = Point.FromBytes(decrypted_state.gKn[0]);
                // Verifying 
                if (!gPRISMtest.isEqual(gPRISM))
                {
                    return Ok("--FAILED--: CommitPrism: gPRISMtest failed");
                }

                byte[] PRISMAuth_hash = SHA256.HashData((gPRISMAuth * _settings.Key.Priv).ToByteArray());
                var PRISMAuthi = System.Convert.ToBase64String(PRISMAuth_hash);

                user.Prismi = new BigInteger(decrypted_state.Yn[0], true, true).ToString();
                user.PrismAuthi = PRISMAuthi;

                _userService.Update(user);
            }
            catch (Exception e)
            {
                return Ok("--FAILED--:" + e.Message);
            }

            return Ok();
        }
    }

    internal class StateData
    {
        public string KeyID { get; set; } // Guid of key to string()
        public string Timestampi { get; set; }
        public byte[][] gKn { get; set; }
        public byte[][] Yn { get; set; }
    }

}
