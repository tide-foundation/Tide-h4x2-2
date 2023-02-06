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

namespace H4x2_Simulator.Controllers;

using Microsoft.AspNetCore.Mvc;
using H4x2_Simulator.Services;
using H4x2_Simulator.Entities;
using H4x2_Simulator.Models;

[ApiController]
[Route("[controller]")]
public class UsersController : ControllerBase
{
    private IUserService _userService;

    public UsersController(IUserService userService)
    {
        _userService = userService;
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

    [HttpPost]
    public IActionResult Create(UserCreatRequest userCreatReq)
    {
        try {
            _userService.CreatRequest(userCreatReq);
            return Ok(new { message = "User created" });
        }
        catch(Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }  

    [HttpGet("exists/{id}")]
    public IActionResult Exists(string id)
    {
        return Ok(_userService.Exists(id));
    }
}