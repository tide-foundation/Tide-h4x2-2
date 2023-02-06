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

namespace H4x2_Simulator.Services;


using H4x2_Simulator.Entities;
using H4x2_Simulator.Helpers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

public interface IUserOrkService
{
    IEnumerable<UserOrk> GetAll();
    string GetUserOrks(string userId);
    void Create(UserOrk userOrk);
}

public class UserOrkService : IUserOrkService
{
    private DataContext _context;
    private IOrkService _orkService;
    public UserOrkService(DataContext context, IOrkService orkService)
    {
        _context = context;
        _orkService = orkService;
    }

    public IEnumerable<UserOrk> GetAll()
    {
        return _context.UserOrks;
    }

    public string GetUserOrks(string userId)
    {
        var userOrksList = _context.UserOrks.Where(o => o.UserId == userId).ToList();
        List<string> orkPubs = new List<string>();
        List<string> orkUrls = new List<string>();
        foreach(UserOrk userOrk in userOrksList){
            var ork = _orkService.GetById(userOrk.OrkId);
            if(ork == null) throw new Exception("User not found !");
            orkPubs.Add(ork.OrkPub);
            orkUrls.Add(ork.OrkUrl);
        }
        var response = new
        {
            orkUrls = orkUrls.ToArray(),
            orkPubs = orkPubs.ToArray()
        };
        return JsonSerializer.Serialize(response);
    }

    public void Create(UserOrk userOrk)
    {
        //validate for existence
        if (_context.UserOrks.Any(x => x.Id == userOrk.Id))
            throw new Exception("Entry with the Id '" + userOrk.Id + "' already exists");

        // save userOrk
        _context.UserOrks.Add(userOrk);
        _context.SaveChanges();
    }

}