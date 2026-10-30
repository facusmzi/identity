using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using Identity.Application.Dtos;
using Identity.Application.Security;

namespace Identity.Tests;

/// <summary>With Redis unreachable, the service keeps working (degraded), it does not answer 500.</summary>
public sealed class RedisOutageTests(RedisDownFactory factory) : IClassFixture<RedisDownFactory>
{
    private static string NewEmail() => $"down-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Register_login_refresh_and_logout_work_without_redis()
    {
        var email = NewEmail();
        var (client, tokens) = await factory.CreateVerifiedUserAsync(email);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        var refreshed = await RefreshReuseTests.Refresh(client, tokens.RefreshToken);
        await RefreshReuseTests.Refresh(client, refreshed.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Mfa_login_works_without_redis()
    {
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);
        var setup = await (await client.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        await client.PostAsJsonAsync("/auth/mfa/enable", new { code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow)) });

        var first = await (await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" }))
            .Content.ReadFromJsonAsync<LoginResponse>();
        var second = await factory.CreateClient().PostAsJsonAsync("/auth/login/mfa",
            new { mfaToken = first!.MfaToken, code = Totp.Compute(secret, Totp.TimeStep(DateTimeOffset.UtcNow) + 1) });
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    [Fact]
    public async Task The_account_lockout_fails_open_and_nothing_waits_for_timeouts()
    {
        var email = NewEmail();
        await factory.CreateVerifiedUserAsync(email);
        var client = factory.CreateClient();

        var sw = Stopwatch.StartNew();
        for (var i = 0; i < 12; i++)
            Assert.Equal(HttpStatusCode.Unauthorized,
                (await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" })).StatusCode);
        sw.Stop();

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" })).StatusCode);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"12 logins took {sw.Elapsed}");
    }

    [Fact]
    public async Task Readiness_reports_the_outage()
    {
        var res = await factory.CreateClient().GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, res.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await factory.CreateClient().GetAsync("/health/live")).StatusCode);
    }
}
