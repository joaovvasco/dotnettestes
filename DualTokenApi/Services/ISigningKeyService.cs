using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;

namespace DualTokenApi.Services
{
    public interface ISigningKeyService
    {
        SecurityKey GetCurrentKey(string scheme);
        IEnumerable<SecurityKey> GetValidationKeys(string scheme);
    }
}
