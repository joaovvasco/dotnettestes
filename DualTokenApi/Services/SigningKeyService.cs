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

        private readonly ConcurrentDictionary<string, List<KeyInfo>> _keys;
        private readonly ConcurrentDictionary<string, object> _locks;
        private readonly TimeSpan _rotationInterval;

        public SigningKeyService(IConfiguration configuration)
        {
            _keys = new ConcurrentDictionary<string, List<KeyInfo>>();
            _locks = new ConcurrentDictionary<string, object>();

            // Load rotation interval from config, default to 24 hours
            double minutes = configuration.GetValue<double>("JwtConfig:RotationIntervalMinutes", 1440);
            _rotationInterval = TimeSpan.FromMinutes(minutes);

            // Initialize with keys from configuration
            var keyA = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtConfig:KeyA"]));
            var keyB = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtConfig:KeyB"]));

            _keys.TryAdd("SchemeA", new List<KeyInfo>
            {
                new KeyInfo { Key = keyA, CreatedAt = DateTime.UtcNow }
            });
            _keys.TryAdd("SchemeB", new List<KeyInfo>
            {
                new KeyInfo { Key = keyB, CreatedAt = DateTime.UtcNow }
            });
        }

        public SecurityKey GetCurrentKey(string scheme)
        {
            var lockObj = _locks.GetOrAdd(scheme, new object());

            lock (lockObj)
            {
                if (!_keys.TryGetValue(scheme, out var keyList) || !keyList.Any())
                {
                    throw new ArgumentException($"No keys found for scheme: {scheme}");
                }

                var currentKeyInfo = keyList.Last();

                // Check if it's time to rotate
                if (DateTime.UtcNow - currentKeyInfo.CreatedAt > _rotationInterval)
                {
                    // Rotate
                    var newKey = GenerateNewKey();
                    var newKeyInfo = new KeyInfo
                    {
                        Key = newKey,
                        CreatedAt = DateTime.UtcNow
                    };
                    keyList.Add(newKeyInfo);
                    return newKey;
                }

                return currentKeyInfo.Key;
            }
        }

        public IEnumerable<SecurityKey> GetValidationKeys(string scheme)
        {
            var lockObj = _locks.GetOrAdd(scheme, new object());

            lock (lockObj)
            {
                if (_keys.TryGetValue(scheme, out var keyList))
                {
                    // Return a copy of the list to avoid thread issues after leaving the lock
                    return keyList.Select(k => k.Key).ToList();
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
