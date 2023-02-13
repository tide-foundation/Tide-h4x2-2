namespace H4x2_Node.Entities;

using System.ComponentModel.DataAnnotations;
public class User
{
    [Key]
    public string UID {get; set;}
    public string Prismi { get; set; }
    public string CVKi { get; set; }
    public string PrismAuthi { get; set; }
    public string GCmk {get; set;}
    public string Cmki { get; set; }
    public string Cmk2i { get; set; }
    public string GCmk2 {get; set;}
    public string Email { get; set; }
    public string CommitStatus {get; set;}

}