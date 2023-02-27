﻿// 
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
        public async Task<IActionResult> GenShard2([FromQuery] string uid, int numKeys, IEnumerable<string> mIdORKij, IEnumerable<string> gMultiplier_p)
        {
            
            try
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                string simulatorURL = _config.GetValue<string>("Endpoints:Simulator:Api");
                if (await _userService.UserExists(uid, simulatorURL)) throw new InvalidOperationException("User already exists");

                // get ork publics from ids
                Point[] mgORKj = await SimulatorClient.GetORKPubs(simulatorURL, mIdORKij);

                Point[] gMultiplier = Utils.GetPointList(gMultiplier_p);

                var response = _keyGenerator.GenShard(uid, mgORKj, numKeys, gMultiplier);
                return Ok(response);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public IActionResult SetKey2([FromQuery] string uid, string[] yijCipher, string encSetKeyStatei)
        {
            try
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                var response = _keyGenerator.SetKey(uid, yijCipher, encSetKeyStatei);
                return Ok(response);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public IActionResult PreCommit2([FromQuery] string uid, string[][] gKntesti_p, string[] gKsigni, Point R2, string state_id)
        {
            try 
            {
                if (uid == null) throw new ArgumentNullException("uid cannot be null");

                Point[][] gKntesti = gKntesti_p.Select(gKntest => Utils.GetPointList(gKntest)).ToArray();

                var response = _keyGenerator.PreCommit(uid, gKntesti, gKsigni, R2, state_id);
                return Ok(response);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }

        [HttpPost]
        public IActionResult Commit2([FromQuery] string uid, string S, string EncCommitStatei, Point gPrismAuth)
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
                return Ok(encryptedCVK);
            }catch(Exception ex){
                return Ok("--FAILED--:" + ex.Message);
            }
        }
    }
}
