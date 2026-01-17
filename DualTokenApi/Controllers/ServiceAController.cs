using DualTokenApi.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DualTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [DualSchemeAuthorize(Roles = "Manager")]
    public class ServiceAController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("You have accessed Service A with Token A.");
        }
    }
}
