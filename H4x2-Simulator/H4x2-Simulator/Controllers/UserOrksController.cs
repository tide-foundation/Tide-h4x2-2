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

[ApiController]
[Route("[controller]")]
public class UserOrksController : ControllerBase
{
    private IUserOrkService _userOrkService;

    public UserOrksController(IUserOrkService userOrkService)
    {
        _userOrkService = userOrkService;
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var userOrk = _userOrkService.GetAll();
        return Ok(userOrk);
    }

    [HttpGet("/userOrks/userId/{id}")]
    public IActionResult GetUserOrks(string id)
    {
        try{
            var response = _userOrkService.GetUserOrks(id);
            return Ok(response);
        }
        catch(Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost]
    public IActionResult Create(UserOrk userOrk)
    {
        try {
            _userOrkService.Create(userOrk);
            return Ok(new { message = "UserOrks entry created" });
        }
        catch(Exception ex)
        {
            return BadRequest(ex.InnerException.Message); //check again
        }
    }  

}