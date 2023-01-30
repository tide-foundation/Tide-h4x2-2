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

namespace H4x2_Vendor.Controllers;

using Microsoft.AspNetCore.Mvc;
using H4x2_Vendor.Services;
using H4x2_Vendor.Entities;

[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;
    protected readonly IConfiguration _config;
    public UsersController(IUserService userService, IConfiguration config)
    {
        _userService = userService;
        _config = config;
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var users = _userService.GetAll();
        return Ok(users);
    }

    [HttpGet("{id}")]
    public IActionResult GetById(string id)
    {
        var user = _userService.GetById(id);
        return Ok(user);
    }

    [HttpGet("code/{id}")]
    public IActionResult GetCode(string id)
    {
        var user = _userService.GetById(id);
        return Ok(user.Secret);
    }

    [HttpPost]
    public async Task<IActionResult> Create(User user)
    {  
        try
        {
            // check user exists in simulator first
            string simulatorURL = _config.GetValue<string>("Endpoints:Simulator:Api");
            if (!await _userService.UserExists(user.UID, simulatorURL)) throw new InvalidOperationException("User does not exist in simulator");

            _userService.Create(user);
            return Ok(new { message = "Entry created" });
        
        }catch(Exception ex)
        {
            return BadRequest(ex.Message);
        }  
    }   
}