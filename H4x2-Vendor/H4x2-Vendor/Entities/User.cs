namespace H4x2_Vendor.Entities;

using System.ComponentModel.DataAnnotations;
public class User
{
    [Key]
    public string UID { get; set; }
    public string Secret { get; set; }
    

}