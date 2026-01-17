using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DualTokenApi.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace DualTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ISigningKeyService _signingKeyService;

        public AuthController(ISigningKeyService signingKeyService)
        {
            _signingKeyService = signingKeyService;
        }

        [HttpGet("token-a")]
        public IActionResult GetTokenA()
        {
            var key = _signingKeyService.GetCurrentKey("SchemeA");
            return Ok(new { token = GenerateToken(key, "Manager") });
        }

        [HttpGet("token-b")]
        public IActionResult GetTokenB()
        {
            var key = _signingKeyService.GetCurrentKey("SchemeB");
            return Ok(new { token = GenerateToken(key, "Employee") });
        }

        private string GenerateToken(SecurityKey key, string role)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("id", "user_id"),
                    new Claim(ClaimTypes.Role, role)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
