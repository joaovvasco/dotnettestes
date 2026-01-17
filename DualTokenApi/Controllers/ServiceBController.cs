using DualTokenApi.Attributes;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DualTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [DualSchemeAuthorize(Roles = "Employee")]
    public class ServiceBController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("You have accessed Service B with Token B.");
        }
    }
}
