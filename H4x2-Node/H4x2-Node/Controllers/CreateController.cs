using H4x2_Node.Services;
using H4x2_TinySDK.Ed25519;
using Microsoft.AspNetCore.Mvc;

namespace H4x2_Node.Controllers
{
    public class CreateController : Controller
    {
        private Settings _settings { get; }
        private IUserService _userService;
        public CreateController(Settings settings, IUserService userService)
        {
            _settings = settings;
            _userService = userService;
        }

        [HttpPost]
        public ActionResult Prism(string uid, Point point)
        {
            // call to simulater checking uid does not exist

            var response = Flows.Create.Prism(uid, point, _settings.Key.Priv);
            return Ok(response);
        }

        [HttpPost]
        public ActionResult Account(string uid, string encryptedState, Point prismPub)
        {
            try
            {
                var (user, response) = Flows.Create.Account(uid, encryptedState, prismPub, _settings.Key);
                _userService.Create(user);
                return Ok(response);
            }
            catch (InvalidDataException ie) // if user exists
            {
                return StatusCode(409, ie.Message);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }

    }
}
