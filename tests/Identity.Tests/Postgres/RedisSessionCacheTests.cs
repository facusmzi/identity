using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Identity.Application.Abstractions.Security;
using Identity.Application.Dtos;
using Identity.Application.Services;

namespace Identity.Tests.Postgres;

[Collection(PostgresCollection.Name)]
[Trait("Category", "Postgres")]
public sealed class RedisSessionCacheTests(PostgresFixture fixture)
{
    private static string NewEmail() => $"pg-{Guid.NewGuid():N}@test.local";

    /// <summary>
    /// The race the generation number exists for: a request reads the session from the database, a revocation
    /// commits and invalidates, and only then does the request write its (now stale) entry. It must not be served.
    /// </summary>
    [SkippableFact]
    public async Task An_entry_written_after_an_invalidation_with_the_old_generation_is_never_served()
    {
        var factory = fixture.Require();
        await using var scope = factory.Services.CreateAsyncScope();
        var cache = scope.ServiceProvider.GetRequiredService<ISessionCache>();
        var principal = new SessionPrincipal(Guid.NewGuid(), Guid.NewGuid(), true, ["User"], [], DateTime.UtcNow.AddDays(1));

        var (_, generationSeenByRequest) = await cache.GetAsync(principal.SessionId, principal.UserId); // request starts
        await cache.InvalidateUserAsync(principal.UserId);                                            // revocation commits
        await cache.SetAsync(principal, generationSeenByRequest, TimeSpan.FromSeconds(30));          // late, stale write

        var (cached, _) = await cache.GetAsync(principal.SessionId, principal.UserId);
        Assert.Null(cached);
    }

    [SkippableFact]
    public async Task Real_redis_cache_serves_hits_and_honours_logout()
    {
        var factory = fixture.Require();
        var (client, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        var userId = (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id; // warm

        // Revoked in the database only: still served from Redis, proving the cache is in use.
        await factory.WithDbAsync(db => db.Sessions.Where(s => s.UserId == userId)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, DateTime.UtcNow)));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/logout", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }
}
