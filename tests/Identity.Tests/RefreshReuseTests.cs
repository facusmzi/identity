using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Identity.Application.Dtos;

namespace Identity.Tests;

/// <summary>Uses the fake clock to step outside the 5 s grace window instead of sleeping.</summary>
public sealed class RefreshReuseTests(TimeTravelFactory factory) : IClassFixture<TimeTravelFactory>
{
    private static readonly TimeSpan PastGrace = TimeSpan.FromSeconds(6);

    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Replaying_a_rotated_token_after_the_grace_window_revokes_the_session()
    {
        var (client, t0) = await factory.CreateVerifiedUserAsync(NewEmail());
        var t1 = await Refresh(client, t0.RefreshToken);

        // Warm the session cache with the latest access token: the revocation must still apply at once.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", t1.AccessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);

        factory.Clock.Advance(PastGrace);

        var replay = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = t0.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Contains("REFRESH_TOKEN_REUSED", await replay.Content.ReadAsStringAsync());

        // The legitimate (latest) tokens die too: we cannot tell who the thief is.
        var latest = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = t1.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, latest.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Within_the_grace_window_a_replay_gets_the_same_new_pair()
    {
        var (client, t0) = await factory.CreateVerifiedUserAsync(NewEmail());
        var t1 = await Refresh(client, t0.RefreshToken);

        factory.Clock.Advance(TimeSpan.FromSeconds(2));
        var replay = await Refresh(client, t0.RefreshToken);

        Assert.Equal(t1.RefreshToken, replay.RefreshToken);
    }

    [Fact]
    public async Task Older_generations_are_detected_too()
    {
        var (client, t0) = await factory.CreateVerifiedUserAsync(NewEmail());
        var t1 = await Refresh(client, t0.RefreshToken);
        await Refresh(client, t1.RefreshToken);

        factory.Clock.Advance(PastGrace);

        var replay = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = t0.RefreshToken });
        Assert.Contains("REFRESH_TOKEN_REUSED", await replay.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Garbage_refresh_token_is_rejected_without_side_effects()
    {
        var (client, tokens) = await factory.CreateVerifiedUserAsync(NewEmail());

        var res = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken = "not-a-token" });
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

        await Refresh(client, tokens.RefreshToken);
    }

    internal static async Task<AuthTokensResponse> Refresh(HttpClient client, string refreshToken)
    {
        var res = await client.PostAsJsonAsync("/auth/refresh", new { refreshToken });
        res.EnsureSuccessStatusCode();
        return (await res.Content.ReadFromJsonAsync<AuthTokensResponse>())!;
    }
}
