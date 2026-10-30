using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Dtos;

namespace Identity.Tests.Postgres;

/// <summary>Behaviour that SQLite cannot prove: real concurrency, Npgsql translation, migrations, Redis.</summary>
[Collection(PostgresCollection.Name)]
[Trait("Category", "Postgres")]
public sealed class PostgresTests(PostgresFixture fixture)
{
    private static string NewEmail() => $"pg-{Guid.NewGuid():N}@test.local";

    [SkippableFact]
    public async Task Migrations_apply_and_partial_unique_index_allows_reusing_a_deleted_email()
    {
        var factory = fixture.Require();
        var email = NewEmail();
        var (client, _) = await factory.CreateVerifiedUserAsync(email);

        var delete = new HttpRequestMessage(HttpMethod.Delete, "/auth/me") { Content = JsonContent.Create(new { password = "Passw0rd!" }) };
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(delete)).StatusCode);

        Assert.Equal(HttpStatusCode.Accepted,
            (await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" })).StatusCode);
        Assert.Equal(2, await factory.WithDbAsync(db => db.Users.IgnoreQueryFilters().CountAsync(u => u.Email == email)));
        Assert.Empty(await factory.WithDbAsync(db => db.Database.GetPendingMigrationsAsync()));
    }

    [SkippableFact]
    public async Task Concurrent_registrations_of_one_email_create_exactly_one_account()
    {
        var factory = fixture.Require();
        var email = NewEmail();

        var responses = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ =>
            factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" })));

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.Accepted, r.StatusCode));
        Assert.Equal(1, await factory.WithDbAsync(db => db.Users.CountAsync(u => u.Email == email)));
    }

    [SkippableFact]
    public async Task Concurrent_refreshes_with_the_same_token_share_one_rotation()
    {
        var factory = fixture.Require();
        var (_, tokens) = await factory.CreateVerifiedUserAsync(NewEmail());

        var responses = await Task.WhenAll(Enumerable.Range(0, 10).Select(_ =>
            factory.CreateClient().PostAsJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken })));

        Assert.All(responses, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        var pairs = await Task.WhenAll(responses.Select(r => r.Content.ReadFromJsonAsync<AuthTokensResponse>()));
        Assert.Single(pairs.Select(p => p!.RefreshToken).Distinct());

        // Not mistaken for token theft: the session is still alive.
        var next = await factory.CreateClient().PostAsJsonAsync("/auth/refresh", new { refreshToken = pairs[0]!.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, next.StatusCode);
    }

    [SkippableFact]
    public async Task Redis_login_throttle_locks_the_account()
    {
        var factory = fixture.Require();
        var email = NewEmail();
        await factory.CreateVerifiedUserAsync(email);
        var client = factory.CreateClient();

        for (var i = 0; i < 10; i++)
            await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" });

        var locked = await client.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" });
        Assert.Equal(HttpStatusCode.TooManyRequests, locked.StatusCode);
    }

    [SkippableFact]
    public async Task Concurrent_dispatchers_deliver_each_email_exactly_once()
    {
        var factory = fixture.Require();
        var emails = Enumerable.Range(0, 15).Select(_ => NewEmail()).ToList();
        foreach (var email in emails)
            await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email, password = "Passw0rd!" });

        await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => factory.DispatchEmailsAsync()));

        Assert.All(emails, e => Assert.Equal(1, factory.Emails.CodesSentTo(e)));
    }

    [SkippableFact]
    public async Task Readiness_checks_postgres_and_redis()
    {
        var factory = fixture.Require();
        var res = await factory.CreateClient().GetAsync("/health/ready");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("Healthy", await res.Content.ReadAsStringAsync());
    }
}
