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
        public async Task<IActionResult> GenShard([FromQuery] string uid, int numKeys, IEnumerable<string> mIdORKij)
        {
            
            try
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                string simulatorURL = _config.GetValue<string>("Endpoints:Simulator:Api");
                if (await _userService.UserExists(uid, simulatorURL)) throw new InvalidOperationException("User already exists");

                // get ork publics from ids
                Point[] mgORKj = await SimulatorClient.GetORKPubs(simulatorURL, mIdORKij);

                var response = _keyGenerator.GenShard(uid, mgORKj, numKeys);
                return Ok(response);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public IActionResult SendShard([FromQuery] string uid, string[] yijCipher, string[][] gKnCipher, IEnumerable<string> gMultipliers)
        {
            try
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                Point[] gMultiplier = Utils.GetPointList(gMultipliers);
                var response = _keyGenerator.SendShard(uid, gKnCipher, yijCipher, gMultiplier);
                return Ok(response);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public IActionResult SetKey([FromQuery] string uid, string[] gKntest_p, string[] gKsigni, Point R2, string[] ephKeyj)
        {
            try 
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                Point[] gKntesti = Utils.GetPointList(gKntest_p).ToArray();

                var response = _keyGenerator.SetKey(uid, gKntesti, R2, ephKeyj);
                return Ok(response);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public IActionResult Commit([FromQuery] string uid, string S, string EncCommitStatei, Point gPrismAuth)
        {
            try{
                if (uid == null) throw new ArgumentNullException("uid cannot be null");
                string prismAuthi = Convert.ToBase64String(SHA256.HashData((gPrismAuth * _settings.Key.Priv).ToByteArray()));

                KeyGenerator.CommitResponse response = _keyGenerator.Commit(uid, BigInteger.Parse(S), EncCommitStatei);
                User newUser = new User 
                {
                    UID = uid,
                    Prismi = response.Yn[1].ToString(),
                    PrismAuthi = prismAuthi,
                    CVK = response.Yn[0].ToString(),
                    GCVK = response.gKn[0].ToBase64()
                };
                _userService.Create(newUser);
                var encryptedCVK = AES.Encrypt(newUser.CVK, prismAuthi);
                // Submit entry to simulator
                return Ok(encryptedCVK);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }
    }
}
