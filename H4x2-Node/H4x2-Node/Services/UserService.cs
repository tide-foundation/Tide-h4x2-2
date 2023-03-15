namespace H4x2_Node.Services;

using H4x2_Node.Entities;
using H4x2_Node.Helpers;
using System.Data.SqlTypes;

public interface IUserService
{
    IEnumerable<User> GetAll();
    User GetById(string id);
    void Create(User user);
    void Update(User user);
}

public class UserService : IUserService
{
    private DataContext _context;

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
    public void Create(User user)
    {
        // validate
        if (_context.Users.Any(x => x.UID == user.UID))
            throw new InvalidOperationException("User already exists !");
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
    public void Update(User user){
        _context.Users.Update(user);
        _context.SaveChanges();
    }

}