using Microsoft.AspNetCore.Authorization;

namespace DualTokenApi.Attributes
{
    public class DualSchemeAuthorizeAttribute : AuthorizeAttribute
    {
        public DualSchemeAuthorizeAttribute()
        {
            AuthenticationSchemes = "SchemeA,SchemeB";
        }
    }
}
