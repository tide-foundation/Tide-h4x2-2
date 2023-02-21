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

using H4x2_Node.Services;
using H4x2_TinySDK.Ed25519;
using Microsoft.AspNetCore.Mvc;
using H4x2_TinySDK.Tools;
using System.Text.Json;
using H4x2_Node.Entities;
using System.Security.Cryptography;
using System.Numerics;

namespace H4x2_Node.Controllers
{
    public class CreateController : Controller
    {
        private Settings _settings { get; }
        private IUserService _userService;
        protected readonly IConfiguration _config;
        private readonly KeyGenerator _keyGenerator;
        public CreateController(Settings settings, IUserService userService, IConfiguration config)
        {
            _settings = settings;
            _userService = userService;
            _config = config;
            _keyGenerator = new KeyGenerator(_settings.Key.Priv, _settings.Key.Y, _settings.OrkName, _settings.Threshold);

        }

        [HttpPost]
        public async Task<ActionResult> Prism([FromQuery] string uid, Point point)
        {
            try
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                string simulatorURL = _config.GetValue<string>("Endpoints:Simulator:Api");
                if (await _userService.UserExists(uid, simulatorURL)) throw new InvalidOperationException("User already exists !");

                var response = Flows.Create.Prism(uid, point, _settings.Key.Priv);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Ok("--FAILED--:" + ex.Message);
            }

        }

        [HttpPost]
        public ActionResult Account([FromQuery] string uid, string encryptedState, Point prismPub)
        {
            if (uid == null) throw new ArgumentNullException("uid cannot be null");
            try
            {
                var (user, response) = Flows.Create.Account(uid, encryptedState, prismPub, _settings.Key);
                _userService.Create(user);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public ActionResult GenShard([FromQuery] string uid, [FromQuery] string numKeys, [FromQuery] ICollection<string> orkIds, ICollection<string> orkPubs, ICollection<string> multipliers)
        {
            var orkPublics = orkPubs.Select(pub => Point.FromBytes(Convert.FromBase64String(pub)));
            var mulArray = multipliers.ToArray();
            var Multipliers = new Point[mulArray.Count()];
            for (int i = 0; i < mulArray.Count(); i++)
                Multipliers[i] = Point.FromBytes(Convert.FromBase64String(mulArray[i]));
            return Ok(_keyGenerator.GenShard(uid, orkPublics.ToArray(), Int32.Parse(numKeys), Multipliers, orkIds.ToArray()));
        }

        [HttpPost]
        public ActionResult SetKey([FromQuery] string uid, ICollection<string> orkPubs, ICollection<string> yijCipher)
        {
            var orkPublics = orkPubs.Select(pub => Point.FromBytes(Convert.FromBase64String(pub)));
            string setResponse, randomKey;
            try
            {
                (setResponse, randomKey) = _keyGenerator.SetKey(uid, yijCipher.ToArray(), orkPublics.ToArray());
            }
            catch (Exception e)
            {
                return Ok("--FAILED--:" + e.Message);
            }
            var response = new
            {
                Response = setResponse,
                RandomKey = randomKey
            };

            return Ok(JsonSerializer.Serialize(response));
        }

        [HttpPost]
        public ActionResult PreCommit([FromQuery] string uid, [FromQuery] string emaili, Point R2, Point gCMKtest, Point gPRISMtest, Point gCMK2test, Point gPRISMAuth, ICollection<string> orkPubs, string encSetKey, string randomKey)
        {
            var orkPublics = orkPubs.Select(pub => Point.FromBytes(Convert.FromBase64String(pub)));
            KeyGenerator.PreCommitResponse preCommitResponse;
            var gKtest = new Point[] { gCMKtest, gPRISMtest, gCMK2test };
            try
            {
                preCommitResponse = _keyGenerator.PreCommit(uid, gKtest, orkPublics.ToArray(), R2, encSetKey, randomKey);

                byte[] prismAuthi = SHA256.HashData((gPRISMAuth * _settings.Key.Priv).ToByteArray());

                var user = new User
                {
                    UID = uid,
                    GCmk = preCommitResponse.gKn[0].ToBase64(),
                    Cmki = preCommitResponse.Yn[0].ToString(),
                    Prismi = preCommitResponse.Yn[1].ToString(),
                    PrismAuthi = Convert.ToBase64String(prismAuthi),
                    Cmk2i = preCommitResponse.Yn[2].ToString(),
                    GCmk2 = preCommitResponse.gKn[2].ToBase64(),
                    Email = emaili,
                    CommitStatus = "P"

                };
                _userService.Create(user);

                return Ok(preCommitResponse.S.ToString());
            }
            catch (Exception e)
            {
                return Ok("--FAILED--:" + e.Message);
            }
        }

        [HttpPost]
        public ActionResult Commit([FromQuery] string uid, [FromQuery] string S, Point R2, ICollection<string> orkPubs, string encryptedState)
        {
            BigInteger S_int = BigInteger.Parse(S);
            var orkPublics = orkPubs.Select(pub => Point.FromBytes(Convert.FromBase64String(pub)));
            KeyGenerator.CommitResponse commitResponse;
            try
            {
                commitResponse = _keyGenerator.Commit(uid, S_int, orkPublics.ToArray(), R2, encryptedState);

                var user = _userService.GetById(uid);
                if (user == null)
                    return Ok("--FAILED--:User not found !");

                user.CommitStatus = "C";
                _userService.Update(user);
                return Ok();
            }
            catch (Exception e)
            {
                return Ok("--FAILED--:" + e.Message);
            }
        }
    }
}
