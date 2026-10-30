using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Identity.Api.Extensions;
using Identity.Application.Services;

namespace Identity.Api.Controllers;

public sealed record IntrospectRequest([Required, MaxLength(4096)] string Token);

/// <summary>
/// RFC 7662-style token introspection for confidential clients (their backends):
/// <c>Authorization: Basic base64(clientId:secret)</c> and <c>{ "token": "&lt;access token&gt;" }</c>.
/// Answers whether the token is valid AND its session is still alive right now (logout, lock, revocation...).
/// </summary>
[ApiController]
[AllowAnonymous]
[Route("auth/introspect")]
[EnableRateLimiting(RateLimitingExtensions.Default)]
public sealed class IntrospectionController(IntrospectionService introspection) : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<IntrospectionResponse>> Introspect(IntrospectRequest req, CancellationToken ct)
    {
        if (!TryReadBasicCredentials(out var clientId, out var secret))
        {
            Response.Headers.WWWAuthenticate = "Basic realm=\"identity\"";
            return Unauthorized();
        }
        return await introspection.IntrospectAsync(clientId, secret, req.Token, ct);
    }

    private bool TryReadBasicCredentials(out string clientId, out string secret)
    {
        clientId = secret = "";
        if (!AuthenticationHeaderValue.TryParse(Request.Headers.Authorization, out var header)
            || !"Basic".Equals(header.Scheme, StringComparison.OrdinalIgnoreCase) || header.Parameter is null)
            return false;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter));
            var colon = decoded.IndexOf(':');
            if (colon <= 0) return false;
            clientId = Uri.UnescapeDataString(decoded[..colon]);
            secret = Uri.UnescapeDataString(decoded[(colon + 1)..]);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
