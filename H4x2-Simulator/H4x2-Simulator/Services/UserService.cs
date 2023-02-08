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
using H4x2_Simulator.Models;

public interface IUserService
{
    IEnumerable<User> GetAll();
    User GetById(string id);
    void CreatRequest(UserCreatRequest userRequest);
    void Create(User user);
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
                throw new Exception("Ork are not passed or the number of orks not equal to 3 !");
            
            Create(new User(userReq.UserId));

            foreach(string orkId in userReq.OrkIds)
                _userOrkService.Create( new UserOrk(userReq.UserId, orkId));
            
            transaction.Commit(); // Commit transaction if all commands succeed, transaction will auto-rollback if either commands fails.
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

    private User getUser(string id)
    {
        var user = _context.Users.Find(id);
        return user;
    }

    public bool Exists(string id)
    {
        if (this.getUser(id) is null) return false;
        return true;
    }
}