using H4x2_TinySDK.Ed25519;
using System.Text.Json;

public class SimulatorClient
{
    static readonly HttpClient _client = new HttpClient();
    public static async Task<Point[]> GetORKPubs(string simulatorURL, IEnumerable<string> ORKIds)
    {
        var ids = ORKIds.Select(id => "ids=" + id);
        var uri = simulatorURL + "/orks/publics?" + String.Join("&", ids);
        var response = await _client.GetStringAsync(uri);
        var pubs = JsonSerializer.Deserialize<string[]>(response); // dumb list of ork pubs based on order of ids given - maybe change in future?
        return pubs.Select(p => Point.FromBase64(p)).ToArray();
    }
}