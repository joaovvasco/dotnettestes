using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using DualTokenApi.Models;
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

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            var configUser = _configuration["AuthConfig:User:Username"];
            var configPass = _configuration["AuthConfig:User:Password"];

            if (model.Username == configUser && model.Password == configPass)
            {
                var key = _signingKeyService.GetCurrentKey("SchemeA");
                return Ok(new { token = GenerateToken(key, "Manager", model.Username) });
            }

            return Unauthorized("Invalid credentials");
        }

        [HttpPost("service-token")]
        public IActionResult GetServiceToken([FromBody] ServiceKeyModel model)
        {
            var configKey = _configuration["AuthConfig:ServiceApiKey"];

            if (model.ApiKey == configKey)
            {
                var key = _signingKeyService.GetCurrentKey("SchemeB");
                return Ok(new { token = GenerateToken(key, "Employee", "ServiceBot") });
            }

            return Unauthorized("Invalid API Key");
        }

        private string GenerateToken(SecurityKey key, string role, string subjectName)
        {
            double expirationMinutes = _configuration.GetValue<double>("JwtConfig:ExpirationMinutes", 60);

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, subjectName),
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
