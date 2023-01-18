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


using Microsoft.AspNetCore.Mvc;
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Math;
using System.Numerics;
using H4x2_Node.Services;
using H4x2_TinySDK.Tools;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using H4x2_Node.Entities;

namespace H4x2_Node.Controllers
{
    public class ApplyController : Controller
    {
        private Settings _settings { get; }
        private IUserService _userService;
        public ApplyController(Settings settings, IUserService userService)
        {
            _settings = settings;
            _userService = userService;
        }

        [HttpPost("Create/Prism/{uid}")]
        public ActionResult CreatePrism([FromRoute] string uid, [FromBody] Point point){
            // call to simulater checking uid does not exist
            var response = Flows.Prism.CreatePrism(uid, point, _settings.Key.Priv);
            return Ok(response);
        }

        [HttpPost("Create/Account")]
        public ActionResult CreateAccount([FromForm] string encryptedState, [FromForm] Point prismPub) // check from form works here
        {
            try
            {
                var (user, response) = Flows.Prism.CreateAccount(encryptedState, prismPub, _settings.Key);
                _userService.Create(user);
                return Ok(response);
            }
            catch(InvalidOperationException ie)
            {
                return StatusCode(409, ie.Message);
            }
            catch
            {
                return BadRequest();
            }
        }

        [HttpPost("Apply/Prism/{uid}")]
        public ActionResult Prismm([FromRoute] string uid, [FromBody] Point point) => Apply(uid, point, _settings.Key.Priv);

        private ActionResult Apply(string uid, Point toApply, BigInteger key)
        {
            try
            {
                if (toApply == null) throw new Exception("Apply Controller: Point supplied is not valid and/or safe");
                
                var user = _userService.GetById(uid); 

                Point appliedPoint = PRISM.Apply(toApply, key);
                return Ok(appliedPoint.ToBase64());
            }
            catch (Exception ex)
            {
                return BadRequest(new {message = ex.Message});
            }
        }
    }

    public class State
    {
        public string Prism { get; set; }
        public string UID { get; set; }
    }
}
