using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DualTokenApi.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DualTokenApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ISigningKeyService _signingKeyService;
        private readonly IConfiguration _configuration;

        public AuthController(ISigningKeyService signingKeyService, IConfiguration configuration)
        {
            _signingKeyService = signingKeyService;
            _configuration = configuration;
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
            double expirationMinutes = _configuration.GetValue<double>("JwtConfig:ExpirationMinutes", 60);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("id", "user_id"),
                    new Claim(ClaimTypes.Role, role)
                }),
                Expires = DateTime.UtcNow.AddMinutes(expirationMinutes),
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
