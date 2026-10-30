using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Identity.Api.Extensions;
using Identity.Application.Dtos;
using Identity.Application.Security;

namespace Identity.Tests;

/// <summary>Browser-style sessions: tokens in __Host- cookies, CSRF double-submit on state-changing requests.</summary>
public sealed class CookieSessionTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private const string Password = "Passw0rd!";

    private static string NewEmail() => $"cookie-{Guid.NewGuid():N}@test.local";

    /// <summary>Like a browser: HTTPS (so Secure cookies are kept) and a cookie jar.</summary>
    private HttpClient Browser() =>
        factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new Uri("https://localhost"), HandleCookies = true });

    private static IReadOnlyList<string> SetCookies(HttpResponseMessage res) =>
        res.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToList() : [];

    private static string CookieValue(HttpResponseMessage res, string name) =>
        SetCookies(res).Single(c => c.StartsWith(name + "=")).Split(';')[0][(name.Length + 1)..];

    private async Task<(HttpClient Browser, string Csrf, HttpResponseMessage Login)> CookieLoginAsync(string? email = null)
    {
        email ??= NewEmail();
        await factory.CreateVerifiedUserAsync(email, Password);
        var browser = Browser();
        var login = await browser.PostAsJsonAsync("/auth/login", new { email, password = Password, useCookies = true });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        return (browser, CookieValue(login, SessionCookies.Csrf), login);
    }

    private static HttpRequestMessage Post(string path, string? csrf, object? body = null)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, path) { Content = body is null ? null : JsonContent.Create(body) };
        if (csrf is not null) req.Headers.Add(SessionCookies.CsrfHeader, csrf);
        return req;
    }

    [Fact]
    public async Task Cookie_login_keeps_the_tokens_out_of_javascripts_reach()
    {
        var (browser, _, login) = await CookieLoginAsync();

        var body = (await login.Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.Null(body.AccessToken);
        Assert.Null(body.RefreshToken);
        Assert.NotNull(body.AccessExpiresAt);

        var cookies = SetCookies(login);
        foreach (var name in new[] { SessionCookies.Access, SessionCookies.Refresh })
        {
            var cookie = cookies.Single(c => c.StartsWith(name + "=")).ToLowerInvariant();
            Assert.Contains("httponly", cookie);
            Assert.Contains("secure", cookie);
            Assert.Contains("samesite=strict", cookie);
            Assert.Contains("path=/", cookie);
            Assert.DoesNotContain("domain=", cookie);
        }
        Assert.DoesNotContain("httponly", cookies.Single(c => c.StartsWith(SessionCookies.Csrf + "=")).ToLowerInvariant());

        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task State_changing_requests_need_the_csrf_header()
    {
        var (browser, csrf, _) = await CookieLoginAsync();

        var none = await browser.SendAsync(Post("/auth/logout", null));
        Assert.Equal(HttpStatusCode.Forbidden, none.StatusCode);
        Assert.Contains("CSRF_INVALID", await none.Content.ReadAsStringAsync());

        var wrong = await browser.SendAsync(Post("/auth/logout", csrf + "x"));
        Assert.Equal(HttpStatusCode.Forbidden, wrong.StatusCode);

        // A forged request failed, so the session is still alive...
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);

        // ...and the real page, which can read the CSRF cookie, logs out.
        var ok = await browser.SendAsync(Post("/auth/logout", csrf));
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Contains(SetCookies(ok), c => c.StartsWith(SessionCookies.Access + "=;"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Refresh_uses_the_cookie_and_rotates_the_csrf_token()
    {
        var (browser, csrf, _) = await CookieLoginAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(Post("/auth/refresh", null))).StatusCode);

        var refreshed = await browser.SendAsync(Post("/auth/refresh", csrf));
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        var body = (await refreshed.Content.ReadFromJsonAsync<AuthTokensResponse>())!;
        Assert.Equal("", body.RefreshToken);
        var newCsrf = CookieValue(refreshed, SessionCookies.Csrf);
        Assert.NotEqual(csrf, newCsrf);

        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(Post("/auth/logout", csrf))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(Post("/auth/logout", newCsrf))).StatusCode);
    }

    [Fact]
    public async Task A_dead_cookie_session_clears_the_cookies()
    {
        var email = NewEmail();
        var (browser, csrf, _) = await CookieLoginAsync(email);
        var other = factory.CreateClient();
        await IdentityFactory.LoginAsync(other, email, Password);
        await other.PostAsync("/auth/logout-all", null);

        var res = await browser.SendAsync(Post("/auth/refresh", csrf));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Contains(SetCookies(res), c => c.StartsWith(SessionCookies.Refresh + "=;"));
    }

    [Fact]
    public async Task Bearer_requests_are_unaffected_even_with_cookies_present()
    {
        var email = NewEmail();
        var (browser, _, _) = await CookieLoginAsync(email);
        var bearer = await IdentityFactory.LoginAsync(factory.CreateClient(), email, Password);

        // Cookies in the jar, but an explicit Authorization header: no CSRF needed (browsers never add it).
        var req = Post("/auth/logout", null);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await browser.SendAsync(req)).StatusCode);
    }

    [Fact]
    public async Task Mfa_login_can_finish_in_cookie_mode()
    {
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email, Password);
        var setup = await (await client.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        await client.PostAsJsonAsync("/auth/mfa/enable", new { code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow)) });

        var browser = Browser();
        var first = await (await browser.PostAsJsonAsync("/auth/login", new { email, password = Password, useCookies = true }))
            .Content.ReadFromJsonAsync<LoginResponse>();
        Assert.True(first!.MfaRequired);

        var code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow) + 1);
        var second = await browser.PostAsJsonAsync("/auth/login/mfa", new { mfaToken = first.MfaToken, code, useCookies = true });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal("", (await second.Content.ReadFromJsonAsync<AuthTokensResponse>())!.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Cors_allows_credentials_and_the_csrf_header_for_configured_origins_only()
    {
        using var withCors = factory.WithWebHostBuilder(b => b.UseSetting("Cors:AllowedOrigins:0", "https://app.example.com"));
        var preflight = new HttpRequestMessage(HttpMethod.Options, "/auth/logout");
        preflight.Headers.Add("Origin", "https://app.example.com");
        preflight.Headers.Add("Access-Control-Request-Method", "POST");
        preflight.Headers.Add("Access-Control-Request-Headers", SessionCookies.CsrfHeader);

        var res = await withCors.CreateClient().SendAsync(preflight);
        Assert.Equal("true", res.Headers.GetValues("Access-Control-Allow-Credentials").Single());
        Assert.Contains(SessionCookies.CsrfHeader, res.Headers.GetValues("Access-Control-Allow-Headers").Single(), StringComparison.OrdinalIgnoreCase);
    }
}
