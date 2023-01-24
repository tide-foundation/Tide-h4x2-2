namespace H4x2_Node.Helpers;

using Microsoft.EntityFrameworkCore;
using H4x2_Node.Entities;
public class DataContext : DbContext
{
    protected readonly IConfiguration Configuration;

    public DataContext(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite(Configuration.GetConnectionString("LocalDbConnectionString"));
    }

    public DbSet<User> Users { get; set; }

}