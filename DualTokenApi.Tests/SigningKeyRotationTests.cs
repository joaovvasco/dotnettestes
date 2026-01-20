using System;
using System.Collections.Generic;
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
            // We want rotation interval to be very small.
            // Logic: _rotationInterval = TimeSpan.FromMinutes(expirationMinutes + 1);
            // We want interval ~ 1-2 seconds.
            // 2 seconds = 2/60 minutes approx 0.0333
            // expirationMinutes + 1 = 0.0333 => expirationMinutes = -0.9667

            // Let's target 2 seconds.
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

            // Verify Key properties (just in case they are different objects with same content)
             if (primary1 is SymmetricSecurityKey sym1 && keys2.Secondary is SymmetricSecurityKey sym2)
             {
                 Assert.Equal(sym1.Key, sym2.Key);
             }
        }
    }
}
