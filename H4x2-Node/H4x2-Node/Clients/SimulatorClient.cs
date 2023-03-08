using H4x2_TinySDK.Ed25519;
using System;
using System.ComponentModel;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

public class SimulatorClient
{
    static readonly HttpClient _client = new HttpClient();
    private readonly string simURL;
    public SimulatorClient(string URL)
    {
        simURL = URL;
    }
    public async Task<bool> UserExists(string id)
    {
        string exists = await _client.GetStringAsync(simURL + "/keyentry/exists/" + id);
        if (exists.Equals("true")) return true;
        else if (exists.Equals("false")) return false;
        else throw new Exception("User exists: Simulator is performing an unexpected operation");
    }
    public async Task<Point[]> GetORKPubs(IEnumerable<string> ORKIds)
    {
        var ids = ORKIds.Select(id => "ids=" + id);
        var uri = simURL + "/orks/publics?" + String.Join("&", ids);
        var response = await _client.GetStringAsync(uri);
        var pubs = JsonSerializer.Deserialize<string[]>(response); // dumb list of ork pubs based on order of ids given - maybe change in future?
        return pubs.Select(p => Point.FromBase64(p)).ToArray();
    }

    public async Task SubmitEntry(string keyId, string keyPublic, string[] orkIds, string s, string r2, long timestamp)
    {
        Entry entry = new Entry
        {
            UserId = keyId,
            OrkIds = orkIds,
            GCVK = keyPublic,
            S = s,
            R2 = r2,
            Timestamp = timestamp
        };
        var uri = simURL + "/keyentry/add";
        var content = new StringContent(JsonSerializer.Serialize(entry), Encoding.UTF8, "application/json");

        var result = _client.PostAsync(uri, content).Result.EnsureSuccessStatusCode();
    }
    private class Entry
    {
        public string UserId { get; set; }
        public string[] OrkIds { get; set; }
        public string GCVK { get; set; }
        public string S { get; set; }
        public string R2 { get; set; }
        public long Timestamp { get; set; }
    }
}