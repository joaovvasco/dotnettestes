using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DualTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("token-a")]
        public IActionResult GetTokenA()
        {
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:KeyA"]);
            return Ok(new { token = GenerateToken(key) });
        }

        [HttpGet("token-b")]
        public IActionResult GetTokenB()
        {
            var key = Encoding.ASCII.GetBytes(_configuration["JwtConfig:KeyB"]);
            return Ok(new { token = GenerateToken(key) });
        }

        private string GenerateToken(byte[] key)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("id", "user_id") }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
