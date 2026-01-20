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
                var keys = _signingKeyService.GetKeys("SchemeA");
                LogKeys(keys);
                return Ok(new { token = GenerateToken(keys.Primary, "Manager", model.Username) });
            }

            return Unauthorized("Invalid credentials");
        }

        [HttpPost("service-token")]
        public IActionResult GetServiceToken([FromBody] ServiceKeyModel model)
        {
            var configKey = _configuration["AuthConfig:ServiceApiKey"];

            if (model.ApiKey == configKey)
            {
                var keys = _signingKeyService.GetKeys("SchemeB");
                LogKeys(keys);
                return Ok(new { token = GenerateToken(keys.Primary, "Employee", "ServiceBot") });
            }

            return Unauthorized("Invalid API Key");
        }

        private void LogKeys((SecurityKey Primary, SecurityKey Secondary) keys)
        {
            Console.WriteLine($"PrimarySigningKey: {GetKeyString(keys.Primary)}");
            Console.WriteLine($"SecondarySigningKey: {GetKeyString(keys.Secondary)}");
        }

        private string GetKeyString(SecurityKey key)
        {
            if (key is SymmetricSecurityKey symKey)
            {
                return Convert.ToBase64String(symKey.Key);
            }
            return key?.ToString() ?? "None";
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
