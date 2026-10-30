using System.Net;
using System.Net.Http.Json;
using Identity.Application.Dtos;
using Identity.Application.Security;

namespace Identity.Tests;

/// <summary>Long jumps in time: each test gets its own factory, since the jump would break later JWT checks.</summary>
public sealed class SessionLifetimeTests
{
    private static string NewEmail() => $"life-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Refreshing_keeps_a_session_alive_but_never_past_the_absolute_limit()
    {
        using var factory = new TimeTravelFactory();
        var (client, tokens) = await factory.CreateVerifiedUserAsync(NewEmail());
        var refreshToken = tokens.RefreshToken;

        // Refresh every 25 days (inside the 30-day sliding window): fine until day 90.
        for (var day = 25; day <= 75; day += 25)
        {
            factory.Clock.Advance(TimeSpan.FromDays(25));
            var next = await RefreshReuseTests.Refresh(client, refreshToken);
            Assert.True(next.RefreshExpiresAt <= tokens.RefreshExpiresAt.AddDays(60).AddMinutes(1),
                "the sliding expiry must be capped by the absolute one");
            refreshToken = next.RefreshToken;
        }

        factory.Clock.Advance(TimeSpan.FromDays(16)); // day 91
        var expired = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
    }

    [Fact]
    public async Task An_idle_session_expires_after_the_sliding_window()
    {
        using var factory = new TimeTravelFactory();
        var (client, tokens) = await factory.CreateVerifiedUserAsync(NewEmail());

        factory.Clock.Advance(TimeSpan.FromDays(31));
        var res = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task An_mfa_login_challenge_expires_after_five_minutes()
    {
        using var factory = new TimeTravelFactory();
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);
        var setup = await (await client.PostAsync("/auth/mfa/setup", null)).Content.ReadFromJsonAsync<MfaSetupResponse>();
        var secret = Base32.Decode(setup!.Secret);
        await client.PostAsJsonAsync("/auth/mfa/enable", new { code = Totp.Compute(secret, Totp.TimeStep(factory.Clock.GetUtcNow())) });

        var login = await (await factory.CreateClient().PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" }))
            .Content.ReadFromJsonAsync<LoginResponse>();
        factory.Clock.Advance(TimeSpan.FromMinutes(6));

        var code = Totp.Compute(secret, Totp.TimeStep(factory.Clock.GetUtcNow()));
        var late = await factory.CreateClient().PostAsJsonAsync("/auth/login/mfa", new { mfaToken = login!.MfaToken, code });
        Assert.Equal(HttpStatusCode.Unauthorized, late.StatusCode);
    }
}
