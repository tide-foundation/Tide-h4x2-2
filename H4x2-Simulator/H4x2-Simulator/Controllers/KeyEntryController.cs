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

[Route("[controller]")]
[ApiController]
public class KeyEntryController : ControllerBase
{
    private IKeyEntryService _keyEntryService;

    public KeyEntryController(IKeyEntryService keyEntryService)
    {
        _keyEntryService = keyEntryService;
    }

    [HttpGet]
    public IActionResult Index()
    {
        var users = _keyEntryService.GetAll();
        return Ok(users);
    }

    [HttpGet("orks/{id}")]
    public IActionResult Orks(string id)
    {
        var orks = _keyEntryService.GetKeyOrks(id);
        return Ok(orks);
    }

    [HttpGet("{id}")]
    public IActionResult GetById(string id)
    {
        var user = _keyEntryService.GetKeyEntry(id);
        return Ok(user);
    }

    [HttpPost("add")]
    public IActionResult Add(Entry entry)
    {
        try {
            _keyEntryService.Validate(entry);
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
        return Ok(_keyEntryService.Exists(id));
    }
}