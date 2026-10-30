using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis;
using Identity.Application.Dtos;
using Identity.Application.Services;
using Identity.Infrastructure.Caching;

namespace Identity.Tests;

public sealed class SessionCacheTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"user-{Guid.NewGuid():N}@test.local";

    [Fact]
    public async Task Validated_sessions_are_served_from_cache()
    {
        var (client, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode); // warm

        // Revoke behind the services' back: the cache does not know, so the request is still served from it.
        var userId = (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        await factory.WithDbAsync(db => db.Sessions.Where(s => s.UserId == userId)
            .ExecuteUpdateAsync(u => u.SetProperty(s => s.RevokedAt, DateTime.UtcNow)));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
    }

    /// <summary>With the cache warm, each path that ends sessions must take effect on the very next request.</summary>
    [Theory]
    [InlineData("logout")]
    [InlineData("logout-all")]
    [InlineData("change-password")]
    [InlineData("reset-password")]
    [InlineData("delete-account")]
    [InlineData("revoke-session")]
    [InlineData("admin-delete")]
    public async Task Every_revocation_path_bypasses_a_warm_cache(string path)
    {
        var email = NewEmail();
        var (victim, tokens) = await factory.CreateVerifiedUserAsync(email);
        var actor = factory.CreateClient(); // anonymous, for the reset flow
        var victimId = (await victim.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id; // warms the cache
        var victimSession = (await victim.GetFromJsonAsync<List<SessionResponse>>("/sessions"))!.Single(s => s.Current).Id;

        // A second session of the victim acts, so the warm one is the one that must die.
        var second = factory.CreateClient();
        await TestHostFactory.LoginAsync(second, email, "Passw0rd!");

        switch (path)
        {
            case "logout":
                await victim.PostAsync("/auth/logout", null);
                break;
            case "logout-all":
                await second.PostAsync("/auth/logout-all", null);
                break;
            case "change-password":
                await second.PostAsJsonAsync("/auth/change-password", new { oldPassword = "Passw0rd!", newPassword = "Changed123x" });
                break;
            case "reset-password":
                await actor.PostAsJsonAsync("/auth/forgot-password", new { email });
                var token = (await factory.LastResetTokenAsync(email))!;
                await actor.PostAsJsonAsync("/auth/reset-password", new { email, token, newPassword = "Reset123x" });
                break;
            case "delete-account":
                await second.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "/auth/me") { Content = JsonContent.Create(new { password = "Passw0rd!" }) });
                break;
            case "revoke-session":
                await second.DeleteAsync($"/sessions/{victimSession}");
                break;
            case "admin-delete":
                var admin = factory.CreateClient();
                await TestHostFactory.LoginAsync(admin, TestHostFactory.AdminEmail, TestHostFactory.AdminPassword);
                await admin.DeleteAsync($"/admin/users/{victimId}");
                break;
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await victim.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Role_changes_reach_a_warm_cache_immediately()
    {
        var (user, _) = await factory.CreateVerifiedUserAsync(NewEmail());
        var userId = (await user.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync("/admin/roles")).StatusCode); // cached without Admin

        var admin = factory.CreateClient();
        await TestHostFactory.LoginAsync(admin, TestHostFactory.AdminEmail, TestHostFactory.AdminPassword);
        await admin.PostAsJsonAsync($"/admin/users/{userId}/roles", new { role = "Admin" });

        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/admin/roles")).StatusCode);
    }

    [Fact]
    public async Task Redis_outage_degrades_to_database_without_waiting()
    {
        var options = ConfigurationOptions.Parse("127.0.0.1:1"); // nothing listens there
        options.AbortOnConnectFail = false;
        options.ConnectTimeout = 200;
        using var redis = await ConnectionMultiplexer.ConnectAsync(options);
        var cache = new RedisSessionCache(redis, NullLogger<RedisSessionCache>.Instance);
        var principal = new SessionPrincipal(Guid.NewGuid(), Guid.NewGuid(), true, ["User"], [], DateTime.UtcNow.AddDays(1));

        var sw = Stopwatch.StartNew();
        var (cached, generation) = await cache.GetAsync(principal.SessionId, principal.UserId);
        await cache.SetAsync(principal, generation, TimeSpan.FromSeconds(30));
        await cache.InvalidateUserAsync(principal.UserId);
        sw.Stop();

        Assert.Null(cached);
        Assert.True(sw.ElapsedMilliseconds < 2000, $"took {sw.ElapsedMilliseconds} ms");
    }
}
