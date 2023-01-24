namespace H4x2_Node.Entities;

using System.ComponentModel.DataAnnotations;
public class User
{
    [Key]
    public string UID {get; set;}
    public string Prismi { get; set; }
    public string CVKi { get; set; }
    public string PrismAuthi { get; set; }

}