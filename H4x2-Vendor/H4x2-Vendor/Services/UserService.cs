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

namespace H4x2_Vendor.Services;

using H4x2_Vendor.Entities;
using H4x2_Vendor.Helpers;

public interface IUserService
{
    IEnumerable<User> GetAll();
    User GetById(string id);
    void Create(User user);
    Task GetEntryAsync(string url);
    Task<bool> UserExists(string uid, string simulatorURL);
}

public class UserService : IUserService
{
    private DataContext _context;
    static readonly HttpClient _client = new HttpClient();

    public UserService(DataContext context)
    {
        _context = context;

    }
    public IEnumerable<User> GetAll()
    {
        return _context.UserSecrets;
    }

    public User GetById(string id)
    {
        return getUserRecord(id);
    }
    public void Create(User user)
    {
        // validate
        if (_context.UserSecrets.Any(x => x.UID == user.UID))
            throw new Exception("Entry with the UId '" + user.UID + "' already exists");
        // save user secret
        _context.UserSecrets.Add(user);
        _context.SaveChanges();   
    }

    public async Task GetEntryAsync(string url)
    {
        string entry = await _client.GetStringAsync(url);
        if(String.IsNullOrEmpty(entry))
            throw new Exception("Entry does not exist.");     
    }

    public async Task<bool> UserExists(string uid, string simulatorURL)
    {
        string exists = await _client.GetStringAsync(simulatorURL + "/users/exists/" + uid);
        if (exists.Equals("true")) return true;
        else if (exists.Equals("false")) return false;
        else throw new Exception("User exists: Simulator is performing an unexpected operation");
    }

    private User getUserRecord(string id)
    {
        var user = _context.UserSecrets.Find(id);
        if (user == null) throw new KeyNotFoundException("Entry not found");
        return user;
    }

   
}