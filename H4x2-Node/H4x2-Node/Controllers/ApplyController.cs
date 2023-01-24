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
using H4x2_TinySDK.Math;
using System.Numerics;
using H4x2_Node.Services;

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

        [HttpPost]
        public ActionResult Prism(string uid, Point point)
        {
            try
            {
                if (point == null) throw new Exception("Apply Controller: Point supplied is not valid and/or safe");
                var user = _userService.GetById(uid); // get user
                var userPrism = BigInteger.Parse(user.Prismi); // get user prism
                var response = Flows.Apply.Prism(point, userPrism);
                return Ok(response);
            }
            catch (Exception ex) // TODO: Make exceptions more concise
            {
                return BadRequest();
            }
        }

        [HttpPost]
        public ActionResult AuthData(string uid, [FromForm] string authData)
        {
            try
            {
                var user = _userService.GetById(uid);
                var userCVK = BigInteger.Parse(user.CVKi); // get user CVK
                var response = Flows.Apply.AuthData(authData, user.PrismAuthi, userCVK);
                return Ok(response);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
            
        }
    }
}
