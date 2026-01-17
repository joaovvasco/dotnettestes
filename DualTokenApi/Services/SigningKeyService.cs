using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DualTokenApi.Services
{
    public class SigningKeyService : ISigningKeyService
    {
        private class KeyInfo
        {
            public SecurityKey Key { get; set; }
            public DateTime CreatedAt { get; set; }
        }

        private class SchemeKeySet
        {
            public KeyInfo Primary { get; set; }
            public KeyInfo Secondary { get; set; }
        }

        private readonly ConcurrentDictionary<string, SchemeKeySet> _keys;
        private readonly ConcurrentDictionary<string, object> _locks;
        private readonly TimeSpan _rotationInterval;

        public SigningKeyService(IConfiguration configuration)
        {
            _keys = new ConcurrentDictionary<string, SchemeKeySet>();
            _locks = new ConcurrentDictionary<string, object>();

            // Load expiration time from config, default to 60 minutes
            double expirationMinutes = configuration.GetValue<double>("JwtConfig:ExpirationMinutes", 60);

            // Rotation interval is Expiration + 1 minute
            _rotationInterval = TimeSpan.FromMinutes(expirationMinutes + 1);

            // Initialize with keys from configuration
            var keyA = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtConfig:KeyA"]));
            var keyB = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtConfig:KeyB"]));

            _keys.TryAdd("SchemeA", new SchemeKeySet
            {
                Primary = new KeyInfo { Key = keyA, CreatedAt = DateTime.UtcNow }
            });
            _keys.TryAdd("SchemeB", new SchemeKeySet
            {
                Primary = new KeyInfo { Key = keyB, CreatedAt = DateTime.UtcNow }
            });
        }

        public SecurityKey GetCurrentKey(string scheme)
        {
            var lockObj = _locks.GetOrAdd(scheme, new object());

            lock (lockObj)
            {
                if (!_keys.TryGetValue(scheme, out var keySet))
                {
                    throw new ArgumentException($"No keys found for scheme: {scheme}");
                }

                // Check if it's time to rotate
                if (DateTime.UtcNow - keySet.Primary.CreatedAt > _rotationInterval)
                {
                    // Rotate: Primary becomes Secondary, New Key becomes Primary
                    keySet.Secondary = keySet.Primary;
                    keySet.Primary = new KeyInfo
                    {
                        Key = GenerateNewKey(),
                        CreatedAt = DateTime.UtcNow
                    };
                }

                return keySet.Primary.Key;
            }
        }

        public IEnumerable<SecurityKey> GetValidationKeys(string scheme)
        {
            var lockObj = _locks.GetOrAdd(scheme, new object());

            lock (lockObj)
            {
                if (_keys.TryGetValue(scheme, out var keySet))
                {
                    var list = new List<SecurityKey> { keySet.Primary.Key };
                    if (keySet.Secondary != null)
                    {
                        list.Add(keySet.Secondary.Key);
                    }
                    return list;
                }
            }
            return Enumerable.Empty<SecurityKey>();
        }

        private SecurityKey GenerateNewKey()
        {
            var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32]; // 256 bits
            rng.GetBytes(bytes);
            return new SymmetricSecurityKey(bytes);
        }
    }
}
