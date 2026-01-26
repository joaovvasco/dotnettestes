using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using DualTokenApi.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace DualTokenApi.Tests
{
    public class SigningKeyRotationTests
    {
        [Fact]
        public void TestKeyRotation()
        {
            // Arrange
            double expirationMinutes = -0.96; // 0.04 * 60 = 2.4 seconds

            var myConfig = new Dictionary<string, string>
            {
                {"JwtConfig:ExpirationMinutes", expirationMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture)},
                {"JwtConfig:KeyA", "ThisIsASecretKeyForSchemeAThatIsLongEnough"},
                {"JwtConfig:KeyB", "ThisIsASecretKeyForSchemeBThatIsLongEnough"}
            };

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(myConfig)
                .Build();

            var service = new SigningKeyService(configuration);
            string scheme = "SchemeA";

            // Act 1: Get Initial Keys
            var keys1 = service.GetKeys(scheme);
            Assert.NotNull(keys1.Primary);
            Assert.Null(keys1.Secondary); // Initially no secondary

            var primary1 = keys1.Primary;

            // Wait for rotation interval (approx 2.4s)
            // Let's wait 3 seconds to be safe
            Thread.Sleep(3000);

            // Act 2: Get Keys after rotation
            var keys2 = service.GetKeys(scheme);

            // Assert
            Assert.NotNull(keys2.Primary);
            Assert.NotNull(keys2.Secondary);

            // The new primary should be different from the old primary
            Assert.NotEqual(primary1, keys2.Primary);

            // The old primary should now be the secondary
            Assert.Equal(primary1, keys2.Secondary);

            // Verify Key properties
             if (primary1 is SymmetricSecurityKey sym1 && keys2.Secondary is SymmetricSecurityKey sym2)
             {
                 Assert.Equal(sym1.Key, sym2.Key);
             }
        }

        [Fact]
        public void TestTokenValidationAfterRotation()
        {
             // Arrange
            double expirationMinutes = -0.96; // 0.04 * 60 = 2.4 seconds

            var myConfig = new Dictionary<string, string>
            {
                {"JwtConfig:ExpirationMinutes", expirationMinutes.ToString(System.Globalization.CultureInfo.InvariantCulture)},
                {"JwtConfig:KeyA", "ThisIsASecretKeyForSchemeAThatIsLongEnough"},
                {"JwtConfig:KeyB", "ThisIsASecretKeyForSchemeBThatIsLongEnough"}
            };

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(myConfig)
                .Build();

            var service = new SigningKeyService(configuration);
            string scheme = "SchemeA";

            // 1. Generate Token with Initial Primary Key
            var keys1 = service.GetKeys(scheme);
            var initialPrimary = keys1.Primary;

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "TestUser"),
                    new Claim(ClaimTypes.Role, "Manager")
                }),
                // Make sure expiration of token itself is long enough to survive our sleep
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(initialPrimary, SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // 2. Wait for rotation interval
            // Rotation interval is ~2.4s. Wait 3s.
            Thread.Sleep(3000);

            // 3. Get Validation Keys (triggers rotation)
            var validationKeys = service.GetValidationKeys(scheme);

            // 4. Validate Token
            // The validationKeys should now contain the New Primary and the Old Primary (now Secondary).
            // Since our token was signed with the Old Primary, it should validate successfully.

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = validationKeys,
                ValidateIssuer = false,
                ValidateAudience = false,
                // Ensure lifetime validation doesn't fail due to tight timings, though 5 min expiry is safe
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            SecurityToken validatedToken;
            try
            {
                var principal = tokenHandler.ValidateToken(tokenString, validationParameters, out validatedToken);

                // Assert
                Assert.NotNull(principal);
                Assert.Equal("TestUser", principal.Identity.Name);
            }
            catch (Exception ex)
            {
                // Verify if it failed because key was not found or other reason
                Assert.True(false, $"Token validation failed: {ex.Message}");
            }

            // Further verification: Check that rotation actually happened
            var keysAfter = service.GetKeys(scheme);
            Assert.NotEqual(initialPrimary, keysAfter.Primary);
            Assert.Equal(initialPrimary, keysAfter.Secondary);
        }
    }
}
