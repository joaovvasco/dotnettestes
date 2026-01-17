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
        private readonly ConcurrentDictionary<string, List<SecurityKey>> _keys;

        public SigningKeyService(IConfiguration configuration)
        {
            _keys = new ConcurrentDictionary<string, List<SecurityKey>>();

            // Initialize with keys from configuration
            var keyA = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtConfig:KeyA"]));
            var keyB = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(configuration["JwtConfig:KeyB"]));

            _keys.TryAdd("SchemeA", new List<SecurityKey> { keyA });
            _keys.TryAdd("SchemeB", new List<SecurityKey> { keyB });
        }

        public SecurityKey GetCurrentKey(string scheme)
        {
            if (_keys.TryGetValue(scheme, out var keys) && keys.Any())
            {
                // Return the last added key (most recent)
                return keys.Last();
            }
            throw new ArgumentException($"No keys found for scheme: {scheme}");
        }

        public IEnumerable<SecurityKey> GetValidationKeys(string scheme)
        {
            if (_keys.TryGetValue(scheme, out var keys))
            {
                return keys;
            }
            return Enumerable.Empty<SecurityKey>();
        }

        public void Rotate(string scheme)
        {
            // Generate a new 256-bit key
            var rng = RandomNumberGenerator.Create();
            var bytes = new byte[32];
            rng.GetBytes(bytes);
            var newKey = new SymmetricSecurityKey(bytes);

            _keys.AddOrUpdate(scheme,
                new List<SecurityKey> { newKey },
                (k, list) =>
                {
                    list.Add(newKey);
                    return list;
                });
        }
    }
}
