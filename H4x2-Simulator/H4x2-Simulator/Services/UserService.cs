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
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Math;
using System.Text.Json;
using H4x2_Simulator.Models;

public interface IUserService
{
    IEnumerable<User> GetAll();
    User GetById(string id);
    void CreatRequest(UserCreatRequest userRequest);
    void Create(User user);
    //void ValidateUser(User user);
    bool Exists(string id);
}

public class UserService : IUserService
{
    private DataContext _context;
    private IOrkService _orkService;
    private IUserOrkService _userOrkService;
    public UserService(DataContext context, IOrkService orkService, IUserOrkService userOrkService)
    {
        _context = context;
        _orkService = orkService;
        _userOrkService = userOrkService;
    }

    public IEnumerable<User> GetAll()
    {
        return _context.Users;
    }

    public User GetById(string id)
    {
        return getUser(id);
    }

    public void CreatRequest(UserCreatRequest userReq)
    {
        try{
            var transaction = _context.Database.BeginTransaction();

            if (userReq.UserId.Length > 64) throw new Exception("Validate user: UserId length is too long");
            
            if(userReq.OrkIds.Length != 3 )
                throw new Exception("Number of Orks should be 3 !");
            
            User newUser = new User();
            newUser.UserId = userReq.UserId;
            Create(newUser);

            foreach(string orkId in userReq.OrkIds){
                UserOrk newUserOrk = new UserOrk();
                newUserOrk.UserId = userReq.UserId;
                newUserOrk.OrkId = orkId;
                _userOrkService.Create(newUserOrk);
            }
            transaction.Commit(); // Commit transaction if all commands succeed, transaction will auto-rollback when disposed if either commands fails.
        }catch(Exception ex){
            if (ex.InnerException != null)
                throw new Exception(ex.InnerException.Message);
            throw new Exception(ex.Message);
        }
    }

    public void Create(User user)
    {
        // validate for user existence
        if (_context.Users.Any(x => x.UserId == user.UserId))
            throw new Exception("User with the Id '" + user.UserId + "' already exists");

        // save user
        _context.Users.Add(user);
        _context.SaveChanges();
    }

    // public void ValidateUser(User user)
    // {   
    //     if (user.UserId.Length > 64) throw new Exception("Validate user: UserId length is too long");

    //     List<string> orkPubList = new List<string>();
    //     if(user.OrkUrls.Length <= 0 || user.OrkUrls.Length != user.SignedEntries.Length)
    //         throw new Exception("Ork Urls are not passed or not matching with signed entries!");
    //     // Query ORK public
    //     foreach(string orkUrl in user.OrkUrls)
    //         orkPubList.Add(_orkService.GetOrkByUrl(orkUrl).OrkPub);
        
    //     String[] orksPubs = orkPubList.ToArray();
    //     // Verify signature
    //     for(int i = 0 ; i < orksPubs.Length ; i++){
    //         var edPoint = Point.FromBase64(orksPubs[i]);
    //         if(!EdDSA.Verify(user.UserId, user.SignedEntries[i], edPoint))
    //             throw new Exception("Invalid signed entry for ork url '" + user.OrkUrls[i] + "' !");
    //     }
    // }

    private User getUser(string id)
    {
        var user = _context.Users.Find(id);
        return user;
    }

    public bool Exists(string id)
    {
        if (this.getUser(id) == null) return false;
        return true;
    }
}