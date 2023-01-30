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

namespace H4x2_Node.Controllers
{
    public class CreateController : Controller
    {
        private Settings _settings { get; }
        private IUserService _userService;
        protected readonly IConfiguration _config;
        public CreateController(Settings settings, IUserService userService, IConfiguration config)
        {
            _settings = settings;
            _userService = userService;
            _config = config;
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
            catch(Exception ex)
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
            catch
            {
                return Ok("--FAILED--:");
            }
        }

    }
}
