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