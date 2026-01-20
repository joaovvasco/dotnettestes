using System;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace DualTokenApi.Attributes
{
    public class DualSchemeAuthorizeAttribute : AuthorizeAttribute, IAuthorizationFilter
    {
        public DualSchemeAuthorizeAttribute()
        {
            AuthenticationSchemes = "SchemeA,SchemeB";
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;

            if (!user.Identity.IsAuthenticated)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            // Determine the scheme used
            var identity = user.Identity as ClaimsIdentity;
            var scheme = identity?.AuthenticationType;

            // Manual Role Check
            var requiredRoles = Roles?.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(r => r.Trim()).ToArray() ?? Array.Empty<string>();
            bool hasRole = requiredRoles.Length == 0 || requiredRoles.Any(role => user.IsInRole(role));

            if (!hasRole)
            {
                context.Result = new ForbidResult();
                return;
            }

            if (scheme == "SchemeA")
            {
                // Login Token: Verify User and Role
                // We already checked Role above. Now check User.
                // "Verificar User" implies checking specific user claims exists
                var hasUserName = user.HasClaim(c => c.Type == ClaimTypes.Name && !string.IsNullOrEmpty(c.Value));

                if (!hasUserName)
                {
                    context.Result = new ForbidResult();
                    return;
                }
            }
            else if (scheme == "SchemeB")
            {
                // Service Token: Verify only Role
                // We already checked Role above.
                // Ensure it IS a service token if we want to be strict, but the logic says "if Service Token, check Role".
                // Since we rely on AuthenticationType, we are good.
            }
            else
            {
                // Unknown scheme, reject? Or allow if authenticated?
                // Given AuthenticationSchemes="SchemeA,SchemeB", it should be one of them.
                // But if it's neither (e.g. testing?), we might fail.
                // Let's assume strictness.
                context.Result = new UnauthorizedResult();
                return;
            }
        }
    }
}
