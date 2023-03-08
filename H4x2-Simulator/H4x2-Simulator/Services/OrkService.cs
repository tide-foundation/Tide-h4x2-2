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

using System.Numerics;
using H4x2_Simulator.Entities;
using H4x2_Simulator.Helpers;
using H4x2_TinySDK.Ed25519;
using H4x2_TinySDK.Math;
using System.Net;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Concurrent;


namespace H4x2_Simulator.Services;

public interface IOrkService
{
    IEnumerable<Ork> GetAll();
    Ork GetById(string id);
    void Create(Ork ork);
    Task<Ork> ValidateOrk(string orkName, string OrkUrl, string SignedOrkUrl);
    Ork GetOrkByUrl(string url);
    List<Ork> GetActiveOrks();
    IEnumerable<Ork> GetActiveOrksThreshold();
    IEnumerable<string> GetPubsByIds(IEnumerable<string> ids);
    IEnumerable<Ork> GetByIds(IEnumerable<string> ids);

}

public class OrkService : IOrkService
{
    private DataContext _context;
    static readonly HttpClient _client = new HttpClient()
    {
        Timeout = TimeSpan.FromMilliseconds(3000),
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

    public IEnumerable<string> GetPubsByIds(IEnumerable<string> ids)
    {
        return _context.Orks.Where(ork => ids.Contains(ork.OrkId))
            .Select(ork => ork.OrkPub);
    }
    public IEnumerable<Ork> GetByIds(IEnumerable<string> ids)
    {
        return _context.Orks.Where(ork => ids.Contains(ork.OrkId));
    }

    public async Task<Ork> ValidateOrk(string orkName, string orkUrl, string signedOrkUrl)
    {
       
        // Query ORK public
        string orkPub_s = await _client.GetStringAsync(orkUrl + "/public");

        // Check orkName + orkPub length
        if (orkName.Length > 20) throw new Exception("Validate ork: Ork name is too long");
        if (orkPub_s.Length > 88) throw new Exception("Validate ork: Ork public is too long");

        // Verify signature
        var orkPub = Point.FromBase64(orkPub_s);
        if(!EdDSA.Verify(orkUrl, signedOrkUrl, orkPub))
            throw new Exception("Invalid signed ork !");

        //  Generate ID
        BigInteger orkId = Ork.GenerateID(orkPub_s);

        return new Ork
        {
            OrkId = orkId.ToString(),
            OrkName = orkName,
            OrkUrl = orkUrl,
            OrkPub = orkPub_s,
            SignedOrkUrl = signedOrkUrl
        };
    }
    public void Create(Ork ork)
    {
        // validate for ork existence
        if (_context.Orks.Any(x => x.OrkId == ork.OrkId))
            throw new Exception("Ork with the Id '" + ork.OrkId + "' already exists");
        
        // save ork
        _context.Orks.Add(ork);
        _context.SaveChanges();
    }

    private Ork getOrk(string id)
    {
        var ork = _context.Orks.Find(id);
        if (ork is null) throw new KeyNotFoundException("Ork not found");
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

    public IEnumerable<Ork> GetActiveOrksThreshold(){
        Random rand = new Random();  
        int RecordsToFetch = 3; //change the number
        int FinalRecordsCount = 1; //change the number
        int TotalRecords = _context.Orks.Count() ;
        if(TotalRecords < RecordsToFetch)
            throw new Exception("There is no enough number of orks in DB !");
        int skipper = rand.Next(0, TotalRecords - RecordsToFetch + 1);  
        
        var orksList = _context.Orks.Skip(skipper).Take(RecordsToFetch).ToList(); 

        var activeOrksList = new  ConcurrentDictionary<int, Ork> ();
        int count = 0;
    
        Parallel.ForEach(orksList , (ork, state) => 
        {    
            if(IsActive(ork.OrkUrl).Result){
                Interlocked.Increment(ref count);
                if(count <= FinalRecordsCount)
                    activeOrksList.TryAdd(count,ork);
                else 
                    state.Stop();
            }         
        });
        return activeOrksList.ToArray().Select(p => p.Value);; 
    }

}

