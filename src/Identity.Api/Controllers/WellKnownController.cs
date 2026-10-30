using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Identity.Infrastructure.Security;

namespace Identity.Api.Controllers;

/// <summary>
/// Lets other services validate access tokens on their own, with only the public keys:
/// <c>AddJwtBearer(o =&gt; { o.Authority = "https://identity.example.com"; o.Audience = "identity"; })</c>
/// (for that, Jwt:Issuer must be this public base URL).
/// </summary>
[ApiController]
[Route(".well-known")]
public sealed class WellKnownController(SigningKeyProvider keys, IOptions<JwtOptions> jwt) : ControllerBase
{
    [HttpGet("jwks.json")]
    [ResponseCache(Duration = 300, Location = ResponseCacheLocation.Any)]
    public IActionResult Jwks() =>
        Ok(new { keys = keys.PublicJwks.Select(k => new { k.Kty, k.Use, k.Alg, k.Kid, k.N, k.E }) });

    [HttpGet("openid-configuration")]
    [ResponseCache(Duration = 300, Location = ResponseCacheLocation.Any)]
    public IActionResult Configuration()
    {
        var baseUrl = $"{Request.Scheme}://{Request.Host}{Request.PathBase}";
        return Ok(new Dictionary<string, object>
        {
            ["issuer"] = jwt.Value.Issuer,
            ["jwks_uri"] = $"{baseUrl}/.well-known/jwks.json",
            ["id_token_signing_alg_values_supported"] = new[] { SecurityAlgorithms.RsaSha256 },
        });
    }
}
