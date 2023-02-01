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


namespace H4x2_Simulator.Services;

public interface IOrkService
{
    IEnumerable<Ork> GetAll();
    Ork GetById(string id);
    void Create(Ork ork);
    Task<Ork> ValidateOrk(string orkName, string OrkUrl, string SignedOrkUrl);
    Ork GetOrkByUrl(string url);
    List<Ork> GetActiveOrks();
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
        if (_context.Orks.Any(x => x.OrkId == ork.OrkId))
            throw new Exception("Ork with the Id '" + ork.OrkId + "' already exists");
        
        // save ork
        _context.Orks.Add(ork);
        _context.SaveChanges();
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
        var orks = GetAll();
        List<Ork> orksList = orks.ToList();
        List<Ork> activeOrksList = new List<Ork>();
        Parallel.ForEach(orksList , ork =>
        {
            if(IsActive(ork.OrkUrl).Result)
                activeOrksList.Add(ork);   
        });

        return activeOrksList;
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

