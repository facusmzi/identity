using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;
using Identity.Application.Dtos;

namespace Identity.Api.Extensions;

/// <summary>
/// Browser sessions without tokens in JavaScript. With <c>useCookies: true</c> the access and refresh tokens are
/// set as <c>__Host-</c> cookies (HttpOnly, Secure, SameSite=Strict, Path=/, no Domain), so an XSS cannot read
/// them and no subdomain can set or overwrite them.
/// <para>
/// CSRF uses the double-submit pattern: a third <c>__Host-</c> cookie, readable by the page, holds a random token
/// that the page must echo in the <c>X-CSRF-Token</c> header on every state-changing request authenticated by
/// cookie. Another site can neither read that cookie nor make the browser send the header. Unlike ASP.NET
/// antiforgery tokens it is not tied to the user's identity, so it keeps working for /auth/refresh after the
/// access token expired.
/// </para>
/// </summary>
public static class SessionCookies
{
    public const string Access = "__Host-identity-access";
    public const string Refresh = "__Host-identity-refresh";
    public const string Csrf = "__Host-identity-csrf";
    public const string CsrfHeader = "X-CSRF-Token";

    public static void Write(HttpResponse response, AuthTokensResponse tokens)
    {
        response.Cookies.Append(Access, tokens.AccessToken, Options(httpOnly: true, tokens.AccessExpiresAt));
        response.Cookies.Append(Refresh, tokens.RefreshToken, Options(httpOnly: true, tokens.RefreshExpiresAt));
        // A new CSRF token per login/refresh; the page reads it from document.cookie.
        response.Cookies.Append(Csrf, Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)),
            Options(httpOnly: false, tokens.RefreshExpiresAt));
    }

    public static void Clear(HttpResponse response)
    {
        foreach (var name in new[] { Access, Refresh, Csrf })
            response.Cookies.Delete(name, Options(httpOnly: name != Csrf, expires: null));
    }

    /// <summary>The body the client gets back: same shape, but the secrets stay in the cookies.</summary>
    public static AuthTokensResponse WithoutSecrets(AuthTokensResponse tokens) => tokens with { AccessToken = "", RefreshToken = "" };

    public static bool UsesCookies(HttpRequest request) =>
        !request.Headers.ContainsKey("Authorization")
        && (request.Cookies.ContainsKey(Access) || request.Cookies.ContainsKey(Refresh));

    private static CookieOptions Options(bool httpOnly, DateTime? expires) => new()
    {
        HttpOnly = httpOnly,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };
}

/// <summary>
/// Requires the double-submit CSRF token on state-changing requests that would be authenticated by the session
/// cookies (no Authorization header present). Bearer clients are unaffected: browsers never add that header on
/// their own, so a forged cross-site request cannot carry it.
/// </summary>
public sealed class CsrfFilter : IAsyncAuthorizationFilter
{
    private static readonly HashSet<string> SafeMethods = ["GET", "HEAD", "OPTIONS", "TRACE"];

    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var request = context.HttpContext.Request;
        if (SafeMethods.Contains(request.Method) || !SessionCookies.UsesCookies(request)) return Task.CompletedTask;

        var cookie = request.Cookies[SessionCookies.Csrf];
        var header = request.Headers[SessionCookies.CsrfHeader].ToString();
        var valid = !string.IsNullOrEmpty(cookie) && !string.IsNullOrEmpty(header)
                    && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(cookie), Encoding.UTF8.GetBytes(header));
        if (valid) return Task.CompletedTask;

        context.Result = new ObjectResult(new ProblemDetails
        {
            Status = StatusCodes.Status403Forbidden,
            Title = $"Missing or invalid {SessionCookies.CsrfHeader} header",
            Extensions = { ["code"] = "CSRF_INVALID" },
        })
        { StatusCode = StatusCodes.Status403Forbidden };
        return Task.CompletedTask;
    }
}
