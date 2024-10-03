using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Build.Security.AspNetCore.Middleware.Dto;
using Build.Security.AspNetCore.Middleware.Request;
using Microsoft.AspNetCore.Http;

namespace API;

public class SaRequestEnricher : IRequestEnricher
{
    public Task EnrichRequestAsync(OpaQueryRequest request, HttpContext httpContext)
    {
        // Assuming the access token is stored in an authorization header
        var authHeader = httpContext.Request.Headers["Authorization"].ToString();

        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
        {
            var token = authHeader.Substring("Bearer ".Length).Trim();

            // Add the access token to the enriched request input
            request.Input.Enriched["access_token"] = token;
            //-------------------
            // Decode the JWT token
            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtHandler.ReadJwtToken(token);

            // Optionally, you can add claims to the enriched request
            foreach (var claim in jwtToken.Claims)
            {
                request.Input.Enriched[claim.Type] = claim.Value;
            }
            //---------------------------
        }
        else
        {
            // Set access_token to null if not available
            request.Input.Enriched["access_token"] = null;
        }

        return Task.CompletedTask; // No need for async modifier
    }
}