namespace H4x2_Vendor.Helpers;

using Microsoft.EntityFrameworkCore;
using H4x2_Vendor.Entities;

public class DataContext : DbContext
{
    protected readonly IConfiguration Configuration;

    public DataContext(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder options)
    {
        options.UseSqlite(Configuration.GetConnectionString("WebApiDatabase"));
    }

    public DbSet<User> UserSecrets { get; set; }
}