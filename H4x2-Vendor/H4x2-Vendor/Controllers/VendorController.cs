namespace H4x2_Vendor.Controllers;

using Microsoft.AspNetCore.Mvc;
using H4x2_Vendor.Services;
using H4x2_Vendor.Entities;

[ApiController]
[Route("[controller]")]
public class VendorController : Controller
{
    public IActionResult Index()
    {
        return View();
    }
}