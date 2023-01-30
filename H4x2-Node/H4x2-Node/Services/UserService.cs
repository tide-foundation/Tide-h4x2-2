namespace H4x2_Node.Services;

using H4x2_Node.Entities;
using H4x2_Node.Helpers;
using System.Data.SqlTypes;

public interface IUserService
{
    IEnumerable<User> GetAll();
    User GetById(string id);
    void Create(User user);
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
        return _context.Users;
    }

    public User GetById(string id)
    {
        return getUser(id);
    }
    public async Task<bool> UserExists(string uid, string simulatorURL)
    {
        string exists = await _client.GetStringAsync(simulatorURL + "/users/exists/" + uid);
        if (exists.Equals("true")) return true;
        else if (exists.Equals("false")) return false;
        else throw new Exception("User exists: Simulator is performing an unexpected operation");
    }
    public void Create(User user)
    {
        // validate
        if (_context.Users.Any(x => x.UID == user.UID))
            throw new InvalidOperationException("User with the Id '" + user.UID + "' already exists in local DB");
        // save user
        _context.Users.Add(user);
        _context.SaveChanges();
    }
    private User getUser(string id)
    {
        var user = _context.Users.Find(id);
        if (user == null) throw new KeyNotFoundException("User not found !");
        return user;
    }


}