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
                var userCVK = BigInteger.One; // get user CVK  
                var response = Flows.Apply.AuthData(authData, user.PrismAuthi, userCVK);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Ok("--FAILED--:" + ex.Message);
            }

        }



        [HttpPost]
        public ActionResult Apply([FromQuery] string uid, Point gBlurUser, Point gBlurPass)
        {
            if (!gBlurPass.IsSafePoint() || !gBlurUser.IsSafePoint())
                return Ok("--FAILED--: Invalid parameters !");

            var user = _userService.GetById(uid);
            if (user == null)
                return Ok("--FAILED--: User not found !");

            var gBlurPassPrismi = gBlurPass * BigInteger.Parse(user.Prismi);
            var gBlurUserCMKi = gBlurUser * BigInteger.Parse(user.Cmki);

            var Token = new TranToken();
            var purpose = "auth";
            var data_to_sign = Encoding.UTF8.GetBytes(uid.ToString() + purpose); // also includes timestamp inside TranToken object
            //Token.Sign(_settings.SecretKey, data_to_sign);
            var responseToEncrypt = new ApplyResponseToEncrypt
            {
                GBlurUserCMKi = gBlurUserCMKi.ToByteArray(),
                GCMK2 = (Curve.G * BigInteger.Parse(user.Cmk2i)).ToByteArray(),
                GCMK = (Curve.G * BigInteger.Parse(user.Cmki)).ToByteArray(),
                CertTimei = Token.ToByteArray()
            };

            var response = new
            {
                GBlurPassPrism = gBlurPassPrismi.ToByteArray(),
                EncReply = AES.Encrypt(responseToEncrypt.ToJSON(), user.PrismAuthi)
            };

            return Ok(JsonSerializer.Serialize(response));
        }


        [HttpPost]
        public ActionResult Authenticate([FromQuery] string uid, [FromQuery] string certTimei, [FromQuery] string token, [FromQuery] string req)
        {
            var tran = TranToken.Parse(Convert.FromBase64String(token));
            var bytesCertTimei = Convert.FromBase64String(certTimei);
            var CertTimei = TranToken.Parse(bytesCertTimei);

            var user = _userService.GetById(uid);

            var buffer = new byte[Convert.FromBase64String(uid).Length + bytesCertTimei.Length];
            Convert.FromBase64String(uid).CopyTo(buffer, 0);
            bytesCertTimei.CopyTo(buffer, Convert.FromBase64String(uid).Length);

            if (user == null)
                return Ok("--FAILED--: User not found !");
            if (tran == null || !tran.Check(Convert.FromBase64String(user.PrismAuthi), buffer))
                return Ok("--FAILED--: Invalid token !");
            if (!CertTimei.OnTime)
                return Ok("--FAILED--: Expired !");

            var purpose = "auth";
            var data_to_sign = Encoding.UTF8.GetBytes(uid.ToString() + purpose);

            // Verify hmac(timestami ||userId || purpose , mSecOrki)== certTimei
            // if (!CertTimei.Check(_settings.SecretKey, data_to_sign))
            // { // CertTime != Encoding.ASCII.GetBytes(certTimei) 
            //     //_logger.LoginUnsuccessful(ControllerContext.ActionDescriptor.ControllerName, tran.Id, uid, $"Authenticate: Invalid certime  for {uid}");
            //     return Unauthorized();
            // }

            string jsonStr = AES.Decrypt(req, Convert.FromBase64String(user.PrismAuthi));

            var AuthReq = JsonSerializer.Deserialize<AuthRequest>(jsonStr);

            var BlurHCmkMul = BigInteger.Parse(AuthReq.BlurHCmkMul);

            if (BlurHCmkMul == BigInteger.Zero)
                return Ok("--FAILED--:  Invalid request !");

            var BlindH = (BlurHCmkMul * new BigInteger(Utils.Hash(Encoding.ASCII.GetBytes("CMK authentication")), true, false).Mod(Curve.N)).Mod(Curve.N); // TODO: Create proper bigInt from hash function
            var ToHash = Encoding.ASCII.GetBytes(user.Cmk2i.ToString()).Concat(Encoding.ASCII.GetBytes(BlurHCmkMul.ToString())).ToArray();
            var BlindR = new BigInteger(Utils.Hash(ToHash), true, false).Mod(Curve.N);

            var response = new
            {
                si = Convert.ToBase64String((BlindR + BlindH * BigInteger.Parse(user.Cmki)).Mod(Curve.N).ToByteArray()),
                gRi = Convert.ToBase64String((Curve.G * BlindR).ToByteArray())
            };

            return Ok(AES.Encrypt(JsonSerializer.Serialize(response), user.PrismAuthi));
        }


        [HttpPut]
        public ActionResult CommitPrism([FromQuery] string uid, [FromQuery] string certTimei, [FromQuery] string token, Point gPRISMtest, Point gPRISMAuth, string data)
        {
            var tran = TranToken.Parse(Convert.FromBase64String(token));
            var bytesCertTimei = Convert.FromBase64String(certTimei);
            var CertTimei = TranToken.Parse(bytesCertTimei);

            var user = _userService.GetById(uid);
            if (user == null)
                return Ok("--FAILED--: User not found !");

            var buffer = new byte[Convert.FromBase64String(uid).Length + bytesCertTimei.Length];
            Convert.FromBase64String(uid).CopyTo(buffer, 0);
            bytesCertTimei.CopyTo(buffer, Convert.FromBase64String(uid).Length);

            if (tran == null || !tran.Check(Convert.FromBase64String(user.PrismAuthi), buffer))
                return Ok("--FAILED--: Invalid token !");
            if (!CertTimei.OnTime)
                return Ok("--FAILED--: Expired !");

            var purpose = "auth";
            var data_to_sign = Encoding.UTF8.GetBytes(uid.ToString() + purpose);

            // Verify hmac(timestami ||userId || purpose , mSecOrki)== certTimei
            // if (!CertTimei.Check(_settings.SecretKey, data_to_sign))
            // { // CertTime != Encoding.ASCII.GetBytes(certTimei) 
            //   // _logger.LoginUnsuccessful(ControllerContext.ActionDescriptor.ControllerName, tran.Id, uid, $"CommitPrism: Invalid certime  for {uid}");
            //     return Unauthorized();
            // }

            KeyGenerator.CommitPrismResponse commitPrismResponse;
            try
            {
                commitPrismResponse = _keyGenerator.CommitPrism(uid.ToString(), gPRISMtest, data);
            }
            catch (Exception e)
            {
                return Ok("--FAILED--:" + e.Message);
            }

            byte[] PRISMAuth_hash = Utils.Hash((gPRISMAuth * _settings.Key.Priv).ToByteArray());
            var PRISMAuthi = Convert.ToBase64String(PRISMAuth_hash);

            user.Prismi = commitPrismResponse.Prismi.ToString();
            user.PrismAuthi = PRISMAuthi;

            _userService.Update(user);

            return Ok();
        }
    }

    public class ApplyResponseToEncrypt
    {
        public byte[] GBlurUserCMKi { get; set; }
        public byte[] GCMK2 { get; set; }
        public byte[] GCMK { get; set; }
        public byte[] CertTimei { get; set; } // 32 byte size

        //not currently being used, sits here just in case
        public byte[] ToByteArray()
        {
            var buffer = new byte[224];
            GBlurUserCMKi.CopyTo(buffer, 0);
            GCMK2.CopyTo(buffer, 64);
            GCMK.CopyTo(buffer, 128);
            CertTimei.CopyTo(buffer, 192);
            return buffer;
        }

        // doing this because the size of ed25519 points will change in future
        public string ToJSON() => JsonSerializer.Serialize(this);


    }

    public class AuthRequest
    {
        public string UserId { get; set; }
        public string CertTime { get; set; }
        public string BlurHCmkMul { get; set; }
    }
}
