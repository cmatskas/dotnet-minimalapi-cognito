using System.Net;
using System.Security.Claims;

public static class AuthHelper
{
    public static void UserHasAnyAcceptedScopes(HttpContext context, string[] acceptedScopes)
        {
            if (acceptedScopes == null)
            {
                throw new ArgumentNullException(nameof(acceptedScopes));
            }

            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            IEnumerable<Claim> userClaims;
            ClaimsPrincipal user;

            // Need to lock due to https://docs.microsoft.com/en-us/aspnet/core/performance/performance-best-practices?#do-not-access-httpcontext-from-multiple-threads
            lock (context)
            {
                user = context.User;
                userClaims = user.Claims;
            }

            if (user == null || userClaims == null || !userClaims.Any())
            {
                lock (context)
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                }

                throw new UnauthorizedAccessException("IDW10204: The user is unauthenticated. The HttpContext does not contain any claims.");
            }
            else
            {

                var scopeClaim = user.FindFirst("scope");

                if (scopeClaim == null || !scopeClaim.Value.Split(' ').Intersect(acceptedScopes).Any())
                {
                    string message = $"Auth error: The 'scope' claim does not contain scopes '{string.Join(",", acceptedScopes)}' or was not found.";

                    lock (context)
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                        context.Response.WriteAsync(message);
                        context.Response.CompleteAsync();
                    }

                    throw new UnauthorizedAccessException(message);
                }
            }
        }
    }