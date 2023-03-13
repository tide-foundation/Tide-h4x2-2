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
using H4x2_Simulator.Models;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Text;
using System.Security.Cryptography;
using H4x2_TinySDK.Tools;
using System.Numerics;
using System.Text.Json;

public interface IKeyEntryService
{
    IEnumerable<KeyEntry> GetAll();
    KeyEntry GetKeyEntry(string id);
    void Create(KeyEntry KeyEntry);
    bool Exists(string id);
    void Validate(Entry entry);
    public string GetKeyOrks(string userId);
}

public class KeyEntryService : IKeyEntryService
{
    private DataContext _context;
    private IOrkService _orkService;
    public KeyEntryService(DataContext context, IOrkService orkService)
    {
        _context = context;
        _orkService = orkService;
    }

    public IEnumerable<KeyEntry> GetAll()
    {
        return _context.KeyEntries;
    }

    public void Validate(Entry entry)
    {
        KeyEntry? exising_entry = GetKeyEntry(entry.UserId);
        if (exising_entry != null) if(exising_entry.Timestamp > entry.Timestamp) return;

        if (entry.UserId.Length > 64) throw new Exception("Validate KeyEntry: KeyEntryId length is too long");

        if (entry.OrkIds.Length < 2) throw new Exception("Validate KeyEntry: KeyEntry requires multiple orks to be hosted");

        // Verify signature
        BigInteger S = BigInteger.Parse(entry.S);
        Point gCVK = Point.FromBase64(entry.GCVK);
        Point[] orkPubs = entry.OrkIds.Select(id => Point.FromBase64(_orkService.GetById(id).OrkPub)).ToArray();
        Point R2 = Point.FromBase64(entry.R2);
        Point R = orkPubs.Aggregate((sum, next) => sum + next) + R2;
        byte[] MData_To_Hash = gCVK.ToByteArray().Concat(Encoding.ASCII.GetBytes(entry.Timestamp.ToString())).Concat(Encoding.ASCII.GetBytes(entry.UserId)).ToArray(); // M = hash( gK[1] | timestamp | keyID )
        byte[] M = SHA256.HashData(MData_To_Hash);
        byte[] HData_To_Hash = R.ToByteArray().Concat(gCVK.ToByteArray()).Concat(M).ToArray();
        BigInteger H = Utils.Mod(new BigInteger(SHA512.HashData(HData_To_Hash), true, false), Curve.N);

        bool valid = (Curve.G * S).isEqual(R + (gCVK * H));
 
        if (!valid) throw new Exception("Validate KeyEntry: Signature invalid");

        List<Ork> orks = _orkService.GetByIds(entry.OrkIds).ToList();

        KeyEntry keyEntry = new KeyEntry
        {
            Id = entry.UserId,
            Orks = orks,
            Entry_S = entry.S,
            Entry_R2 = entry.R2,
            Timestamp = entry.Timestamp,
            Public = entry.GCVK
        };

        using (var transaction = _context.Database.BeginTransaction())
        {
            exising_entry = GetKeyEntry(entry.UserId); // check again (async functions)
            if (exising_entry != null)
            {
                if (exising_entry.Timestamp >= entry.Timestamp) return;
                else Update(keyEntry);
            }
            else if (exising_entry is null) Create(keyEntry);
            transaction.Commit();
        }
    }

    public void Create(KeyEntry KeyEntry)
    {
        // save KeyEntry
        _context.KeyEntries.Add(KeyEntry);
        _context.SaveChanges();
    }

    public void Update(KeyEntry KeyEntry)
    {
        _context.KeyEntries.Update(KeyEntry);
        _context.SaveChanges();
    }

    public KeyEntry GetKeyEntry(string id)
    {
        var keyEntry = _context.KeyEntries.Find(id);
        return keyEntry;
    }

    public bool Exists(string id)
    {
        if (this.GetKeyEntry(id) is null) return false;
        return true;
    }
    public string GetKeyOrks(string userId)
    {
        var orks = _context.KeyEntries
            .Where(entry => entry.Id.Equals(userId))
            .SelectMany(c => c.Orks);

        if (orks.Count() == 0)
            throw new Exception("User not found");

        var response = new
        {
            orkIds = orks.Select(ork => ork.OrkId).ToList().ToArray(),
            orkUrls = orks.Select(ork => ork.OrkUrl).ToList().ToArray(),
            orkPubs = orks.Select(ork => ork.OrkPub).ToList().ToArray()
        };
        return JsonSerializer.Serialize(response);
    }

}