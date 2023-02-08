﻿// 
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

using System.Numerics;
using H4x2_Simulator.Entities;
using H4x2_Simulator.Helpers;
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Math;
using System.Net;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;

namespace H4x2_Simulator.Services;

public interface IOrkService
{
    IEnumerable<Ork> GetAll();
    Ork GetById(string id);
    void Create(Ork ork);
    Task<Ork> ValidateOrk(string orkName, string OrkUrl, string SignedOrkUrl);
    Ork GetOrkByUrl(string url);
    bool CheckOrkExists(string pub);
    List<Ork> GetActiveOrks();
    void Update(string newOrkName, string newOrkUrl, string SignedOrkUrl, string orkPub);
}

public class OrkService : IOrkService
{
    private DataContext _context;
    static readonly HttpClient _client = new HttpClient()
    {
        Timeout = TimeSpan.FromMilliseconds(5000),
    };
   
    public OrkService(DataContext context)
	{
        _context = context;
    }

    public IEnumerable<Ork> GetAll()
    {
        return _context.Orks;
    }

    public Ork GetById(string id)
    {
        return getOrk(id);
    } 

    public async Task<Ork> ValidateOrk(string orkName, string orkUrl, string signedOrkUrl)
    {
       
        // Query ORK public
        string orkPub = await _client.GetStringAsync(orkUrl + "/public");

        // Check orkName + orkPub length
        if (orkName.Length > 20) throw new Exception("Validate ork: Ork name is too long");
        if (orkPub.Length > 88) throw new Exception("Validate ork: Ork public is too long");

        // Verify signature
        var edPoint = Point.FromBase64(orkPub);
        if(!EdDSA.Verify(orkUrl, signedOrkUrl, edPoint))
            throw new Exception("Invalid signed ork !");

        //  Generate ID
        BigInteger orkId = Ork.GenerateID(orkPub);

        return new Ork{
            OrkId = orkId.ToString(),
            OrkName = orkName,
            OrkPub = orkPub,
            OrkUrl = orkUrl,
            SignedOrkUrl = signedOrkUrl
        };      
    }
    public void Create(Ork ork)
    {
        // validate for ork existence
        if (_context.Orks.Any(x => (x.OrkId == ork.OrkId) || (x.OrkName == ork.OrkName)))
            throw new Exception("Ork with the id or name already exists");
        
        // save ork
        _context.Orks.Add(ork);
        _context.SaveChanges();
    }

    public void Update(string newOrkName, string newOrkUrl, string signedOrkUrl, string orkPubKey)
    {
        try{
            var transaction = _context.Database.BeginTransaction();
            Ork ork = _context.Orks.Where(ork => ork.OrkPub == orkPubKey).FirstOrDefault();
            if (ork == null) throw new KeyNotFoundException("Ork not found");

            Point orkPub = Point.FromBase64(ork.OrkPub);
            if (!EdDSA.Verify(newOrkUrl, signedOrkUrl, orkPub)) throw new Exception("Invalid signature");

            // Now we have to update all the users orks that had this url as their ork url before
            // TODO: Use foreign keys on User entity so we don't have to do this. (very messy + time consuming)
            int index;
      
            foreach (User user in _context.Users.ToArray())
            {
                index = Array.IndexOf(user.OrkUrls, ork.OrkUrl);
                if (index != -1)
                {
                    user.OrkUrls[index] = newOrkUrl;
                    _context.Users.Update(user);
                }
            }

            ork.OrkUrl = newOrkUrl;
            ork.OrkName = newOrkName;
            _context.Orks.Update(ork);
            _context.SaveChanges();
            transaction.Commit(); // Commit transaction if all commands succeed, transaction will auto-rollback if either commands fails.
        }catch(Exception ex){
            throw new Exception(ex.Message);
        }
    }

    private Ork getOrk(string id)
    {
        var ork = _context.Orks.Find(id);
        if (ork == null) throw new KeyNotFoundException("Ork not found");
        return ork;
    }

    
    public Ork GetOrkByUrl(string orkUrl){
        var ork = _context.Orks.Where(o => o.OrkUrl == orkUrl).FirstOrDefault();
        return ork;
    }

    public List<Ork> GetActiveOrks()
    {
        var orksList = GetAll().ToList();
        var activeOrksList = new ConcurrentBag<Ork>();
        Parallel.ForEach(orksList , ork =>
        {
            if(IsActive(ork.OrkUrl).Result)
                activeOrksList.Add(ork);   
        });

        return activeOrksList.ToList();
    }

    public bool CheckOrkExists(string pub)
    { 
        return _context.Orks.Any(ork => ork.OrkPub.Equals(pub));
    }

    private async Task<bool> IsActive (string url)
    {
        try{ 
            HttpResponseMessage response = await _client.GetAsync(url +"/public");
            if(response.IsSuccessStatusCode)
                return true;       
            return false;
        }catch(Exception ex){
            return false;
        } 
    }




}

