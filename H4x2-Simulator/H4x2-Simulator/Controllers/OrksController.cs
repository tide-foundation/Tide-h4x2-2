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


using H4x2_Simulator.Services;
using H4x2_Simulator.Entities;
using Microsoft.AspNetCore.Mvc;

namespace H4x2_Simulator.Controllers;

[ApiController]
[Route("[controller]")]
public class OrksController : ControllerBase
{

    private IOrkService _orkService;

    public OrksController(IOrkService orkService)
    {
        _orkService = orkService;
    }

    [HttpGet]
    public IActionResult GetAll()
    {
        var orks = _orkService.GetAll();
        return Ok(orks);
    }

    [HttpGet("{id}")]
    public IActionResult GetById(string id)
    {
        var ork = _orkService.GetById(id);
        return Ok(ork);
    }

    [HttpGet("publics")]
    public async Task<IActionResult> GetPublics([FromQuery] IEnumerable<string> ids)
    {
        var orkPubs = _orkService.GetPubsByIds(ids);
        return Ok(orkPubs); // returns dumb list of ork pubs - should we throw error if an id isn't found?
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromForm] string orkName, [FromForm] string orkUrl, [FromForm] string signedOrkUrl)
    {
        try
        {
            Ork ork = await _orkService.ValidateOrk(orkName, orkUrl, signedOrkUrl);
            _orkService.Create(ork);
            return Ok(new { message = "Ork created" });
        }
        catch(Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
    [HttpPut("update")]
    public IActionResult Update([FromForm] string newOrkName, [FromForm] string newOrkUrl, [FromForm] string signedOrkUrl, [FromForm] string orkPub)
    {
        try
        {
            _orkService.Update(newOrkName, newOrkUrl, signedOrkUrl, orkPub);
            return Ok(new { message = "Ork updated" });
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }


    [HttpPut("update")]
    public IActionResult Update([FromForm] string newOrkName, [FromForm] string newOrkUrl, [FromForm] string signedOrkUrl, [FromForm] string orkPub)
    {
        try
        {
            _orkService.Update(newOrkName, newOrkUrl, signedOrkUrl, orkPub);
            return Ok(new { message = "Ork updated" });
        }
        catch(Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpGet("orkUrl/")]
    public IActionResult GetByOrkUrl([FromForm] string url){
        var ork = _orkService.GetOrkByUrl(url);
        return Ok(ork);
    }

    [HttpGet("active/")]
    public IActionResult GetActiveOrks()
    {
        var orks =  _orkService.GetActiveOrks();
        return Ok(orks);
    }

    [HttpGet("exists")]
    public IActionResult CheckOrkExists([FromQuery] string pub)
    {
        return Ok(_orkService.CheckOrkExists(pub));
    }

}

