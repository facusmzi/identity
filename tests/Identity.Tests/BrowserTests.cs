using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Playwright;

namespace Identity.Tests;

/// <summary>
/// The cookie mode checked by a real Chromium, which is what actually enforces HttpOnly, Secure, SameSite and CORS
/// (the in-process test client does not). The API runs on Kestrel; the "frontend" page is served from another
/// origin, and a "hostile" page from a third origin that is not in Cors:AllowedOrigins.
/// Skipped locally when Chromium is not installed (run bin/.../playwright.ps1 install chromium); required in CI.
/// </summary>
public sealed class BrowserFixture : IAsyncLifetime
{
    public string Api { get; private set; } = "";
    public string Frontend { get; private set; } = "";
    public string Hostile { get; private set; } = "";
    public KestrelIdentityFactory? Factory { get; private set; }
    public IBrowser? Browser { get; private set; }
    public string? SkipReason { get; private set; }

    private IPlaywright? _playwright;
    private readonly List<WebApplication> _pages = [];

    public async Task InitializeAsync()
    {
        try
        {
            _playwright = await Playwright.CreateAsync();
            Browser = await _playwright.Chromium.LaunchAsync(new() { Headless = true });
        }
        catch (Exception ex) when (Environment.GetEnvironmentVariable("CI") is null)
        {
            SkipReason = $"Chromium not available ({ex.GetType().Name}); run playwright.ps1 install chromium";
            return;
        }

        var (apiPort, frontendPort, hostilePort) = (FreePort(), FreePort(), FreePort());
        Api = $"http://localhost:{apiPort}";
        Frontend = $"http://localhost:{frontendPort}";
        Hostile = $"http://localhost:{hostilePort}";

        Factory = new KestrelIdentityFactory(Frontend);
        Factory.UseKestrel(apiPort);
        Factory.StartServer();

        foreach (var port in new[] { frontendPort, hostilePort })
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.UseUrls($"http://localhost:{port}");
            var page = builder.Build();
            page.MapGet("/", () => Results.Content("<!doctype html><title>page</title>", "text/html"));
            await page.StartAsync();
            _pages.Add(page);
        }
    }

    public async Task DisposeAsync()
    {
        foreach (var page in _pages) await page.DisposeAsync();
        if (Browser is not null) await Browser.DisposeAsync();
        _playwright?.Dispose();
        Factory?.Dispose();
    }

    public void Require() => Skip.If(SkipReason is not null, SkipReason);

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

public sealed class KestrelIdentityFactory(string frontendOrigin) : IdentityFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Cors:AllowedOrigins:0", frontendOrigin);
    }
}

public sealed class BrowserTests(BrowserFixture fixture) : IClassFixture<BrowserFixture>
{
    private const string Password = "Passw0rd!";

    // Runs inside the page: exactly what a frontend would do with fetch.
    private const string CookieFlow = """
        async ({ api, email, password }) => {
          const out = {};
          const json = { 'Content-Type': 'application/json' };
          const login = await fetch(api + '/auth/login', { method: 'POST', credentials: 'include', headers: json,
            body: JSON.stringify({ email, password, useCookies: true }) });
          out.login = login.status;
          out.csrf = login.headers.get('X-CSRF-Token');
          out.accessTokenInBody = (await login.json()).accessToken;
          out.documentCookie = document.cookie;

          out.me = (await fetch(api + '/auth/me', { credentials: 'include' })).status;
          out.logoutWithoutCsrf = (await fetch(api + '/auth/logout', { method: 'POST', credentials: 'include' })).status;
          out.csrfAfterReload = (await (await fetch(api + '/auth/csrf', { credentials: 'include' })).json()).csrfToken;

          const refresh = await fetch(api + '/auth/refresh', { method: 'POST', credentials: 'include',
            headers: { 'X-CSRF-Token': out.csrf } });
          out.refresh = refresh.status;
          out.rotatedCsrf = refresh.headers.get('X-CSRF-Token');

          out.logout = (await fetch(api + '/auth/logout', { method: 'POST', credentials: 'include',
            headers: { 'X-CSRF-Token': out.rotatedCsrf } })).status;
          out.meAfterLogout = (await fetch(api + '/auth/me', { credentials: 'include' })).status;
          return out;
        }
        """;

    [SkippableFact]
    public async Task A_real_browser_keeps_tokens_hidden_and_enforces_csrf()
    {
        fixture.Require();
        var email = $"browser-{Guid.NewGuid():N}@test.local";
        await fixture.Factory!.CreateVerifiedUserAsync(email, Password);

        await using var context = await fixture.Browser!.NewContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.Frontend);

        var result = await page.EvaluateAsync<JsonElement>(CookieFlow, new { api = fixture.Api, email, password = Password });
        string S(string name) => result.GetProperty(name).ToString();

        Assert.Equal("200", S("login"));
        Assert.False(string.IsNullOrEmpty(S("csrf")), "the page must be able to read the CSRF token from the header");
        Assert.Equal(JsonValueKind.Null, result.GetProperty("accessTokenInBody").ValueKind);
        Assert.DoesNotContain("identity-access", S("documentCookie"));
        Assert.DoesNotContain("identity-refresh", S("documentCookie"));

        Assert.Equal("200", S("me"));
        Assert.Equal("403", S("logoutWithoutCsrf"));
        Assert.Equal(S("csrf"), S("csrfAfterReload"));
        Assert.Equal("200", S("refresh"));
        Assert.NotEqual(S("csrf"), S("rotatedCsrf"));
        Assert.Equal("200", S("logout"));
        Assert.Equal("401", S("meAfterLogout"));
    }

    [SkippableFact]
    public async Task The_browser_stores_the_session_cookies_with_the_strict_attributes()
    {
        fixture.Require();
        var email = $"browser-{Guid.NewGuid():N}@test.local";
        await fixture.Factory!.CreateVerifiedUserAsync(email, Password);

        await using var context = await fixture.Browser!.NewContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.Frontend);
        await page.EvaluateAsync("""
            async ({ api, email, password }) => { await fetch(api + '/auth/login', { method: 'POST', credentials: 'include',
              headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, useCookies: true }) }); }
            """, new { api = fixture.Api, email, password = Password });

        var cookies = await context.CookiesAsync([fixture.Api]);
        foreach (var name in new[] { "__Host-identity-access", "__Host-identity-refresh" })
        {
            var cookie = Assert.Single(cookies, c => c.Name == name);
            Assert.True(cookie.HttpOnly);
            Assert.True(cookie.Secure);
            Assert.Equal(SameSiteAttribute.Strict, cookie.SameSite);
            Assert.Equal("/", cookie.Path);
        }
        Assert.False(Assert.Single(cookies, c => c.Name == "__Host-identity-csrf").HttpOnly);
    }

    [SkippableFact]
    public async Task A_page_from_an_origin_not_in_cors_cannot_read_anything()
    {
        fixture.Require();
        var email = $"browser-{Guid.NewGuid():N}@test.local";
        await fixture.Factory!.CreateVerifiedUserAsync(email, Password);

        await using var context = await fixture.Browser!.NewContextAsync();
        var frontend = await context.NewPageAsync();
        await frontend.GotoAsync(fixture.Frontend);
        await frontend.EvaluateAsync("""
            async ({ api, email, password }) => { await fetch(api + '/auth/login', { method: 'POST', credentials: 'include',
              headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, useCookies: true }) }); }
            """, new { api = fixture.Api, email, password = Password });

        // Same browser, same cookies, but a page the API does not trust.
        var hostile = await context.NewPageAsync();
        await hostile.GotoAsync(fixture.Hostile);
        var outcome = await hostile.EvaluateAsync<string>("""
            async (api) => {
              try { const r = await fetch(api + '/auth/csrf', { credentials: 'include' }); return 'read:' + (await r.text()); }
              catch (e) { return 'blocked'; }
            }
            """, fixture.Api);

        Assert.Equal("blocked", outcome);
    }
}
