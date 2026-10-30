using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Identity.Application.Dtos;
using Identity.Domain.Authorization;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Security;

namespace Identity.Tests;

/// <summary>Admin lock/unlock, admin view of sessions, rehash, security headers, fallback policy and seed-admin.</summary>
public sealed class AccountControlTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private const string Password = "Passw0rd!";

    private static string NewEmail() => $"ctl-{Guid.NewGuid():N}@test.local";

    private async Task<HttpClient> AdminAsync()
    {
        var client = factory.CreateClient();
        await IdentityFactory.LoginAsync(client, IdentityFactory.AdminEmail, IdentityFactory.AdminPassword);
        return client;
    }

    private async Task<(HttpClient Client, AuthTokensResponse Tokens, Guid Id, string Email)> UserAsync()
    {
        var email = NewEmail();
        var (client, tokens) = await factory.CreateVerifiedUserAsync(email, Password);
        var id = (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        return (client, tokens, id, email);
    }

    [Fact]
    public async Task A_locked_account_stops_working_at_once_and_unlock_restores_it()
    {
        var admin = await AdminAsync();
        var (user, tokens, id, email) = await UserAsync();

        var locked = await admin.PostAsync($"/admin/users/{id}/lock", null);
        Assert.Equal(HttpStatusCode.OK, locked.StatusCode);
        Assert.NotNull((await locked.Content.ReadFromJsonAsync<AdminUserResponse>())!.LockedAt);

        var anon = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken })).StatusCode);

        // Only someone with the right password learns the account is disabled.
        var right = await anon.PostAsJsonAsync("/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, right.StatusCode);
        Assert.Contains("ACCOUNT_DISABLED", await right.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" })).StatusCode);

        // A password reset cannot be used to get around the lock.
        await anon.PostAsJsonAsync("/auth/forgot-password", new { email });
        Assert.Null(await factory.LastResetTokenAsync(email));

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync($"/admin/users/{id}/unlock", null)).StatusCode);
        await IdentityFactory.LoginAsync(anon, email, Password);
    }

    [Fact]
    public async Task Locking_respects_the_admin_rules()
    {
        var admin = await AdminAsync();
        var adminId = (await admin.GetFromJsonAsync<UserResponse>("/auth/me"))!.Id;
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/admin/users/{adminId}/lock", null)).StatusCode);

        // Someone who can manage users but lacks the target's permissions cannot lock them.
        var role = $"Mgr{Guid.NewGuid():N}"[..16];
        await admin.PostAsJsonAsync("/admin/roles", new { name = role, permissions = new[] { Permissions.UsersManage } });
        var (manager, _, managerId, _) = await UserAsync();
        await admin.PostAsJsonAsync($"/admin/users/{managerId}/roles", new { role });

        var lockAdmin = await manager.PostAsync($"/admin/users/{adminId}/lock", null);
        Assert.Equal(HttpStatusCode.Forbidden, lockAdmin.StatusCode);
        Assert.Contains("PRIVILEGE_ESCALATION", await lockAdmin.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Admins_can_see_and_revoke_any_users_sessions_with_reasons()
    {
        var admin = await AdminAsync();
        var (user, _, id, email) = await UserAsync();
        var second = factory.CreateClient();
        await IdentityFactory.LoginAsync(second, email, Password);
        await second.PostAsync("/auth/logout", null);

        var list = await admin.GetFromJsonAsync<List<AdminSessionResponse>>($"/admin/users/{id}/sessions");
        Assert.Equal(2, list!.Count);
        Assert.Single(list, s => s.RevokedReason == "Logout" && !s.Active);
        var active = Assert.Single(list, s => s.Active);
        Assert.True(active.AbsoluteExpiresAt > active.ExpiresAt.AddDays(-1));

        Assert.Equal(HttpStatusCode.OK, (await admin.DeleteAsync($"/admin/users/{id}/sessions/{active.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.GetAsync("/auth/me")).StatusCode);

        var after = await admin.GetFromJsonAsync<List<AdminSessionResponse>>($"/admin/users/{id}/sessions");
        Assert.Equal("AdminRevoked", after!.Single(s => s.Id == active.Id).RevokedReason);
    }

    [Fact]
    public async Task Weak_password_hashes_are_upgraded_on_login()
    {
        var (_, _, id, email) = await UserAsync();
        var weak = new Argon2PasswordHasher(Options.Create(new PasswordHashingOptions { MemoryKb = 512, Iterations = 1, Parallelism = 1 }));
        var weakHash = await weak.HashAsync(Password);
        await factory.WithDbAsync(db => db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordHash, weakHash)));

        await IdentityFactory.LoginAsync(factory.CreateClient(), email, Password);

        var stored = await factory.WithDbAsync(db => db.Users.Where(u => u.Id == id).Select(u => u.PasswordHash).SingleAsync());
        Assert.Contains("m=1024,t=1,p=1", stored); // the test configuration's parameters
        await IdentityFactory.LoginAsync(factory.CreateClient(), email, Password); // and it still verifies
    }

    [Fact]
    public async Task Responses_carry_security_headers_and_are_not_cached_except_the_jwks()
    {
        var client = factory.CreateClient();
        var health = await client.GetAsync("/health/live");
        Assert.Equal("nosniff", health.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", health.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("default-src 'none'", health.Headers.GetValues("Content-Security-Policy").Single());
        Assert.True(health.Headers.CacheControl!.NoStore);

        var jwks = await client.GetAsync("/.well-known/jwks.json");
        Assert.False(jwks.Headers.CacheControl!.NoStore);
        Assert.Equal(TimeSpan.FromSeconds(300), jwks.Headers.CacheControl.MaxAge);
    }

    [Fact]
    public async Task Unknown_routes_are_401_for_anonymous_callers_and_404_for_signed_in_ones()
    {
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient().GetAsync("/no-such-route")).StatusCode);
        var (user, _, _, _) = await UserAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync("/no-such-route")).StatusCode);
    }

    [Fact]
    public async Task Seed_admin_creates_an_admin_or_promotes_an_existing_user()
    {
        var newAdmin = NewEmail();
        Assert.Contains("created", await DbInitializer.SeedAdminAsync(factory.Services, newAdmin, "Strong-Admin-2026"));
        var client = factory.CreateClient();
        await IdentityFactory.LoginAsync(client, newAdmin, "Strong-Admin-2026");
        Assert.Contains("Admin", (await client.GetFromJsonAsync<UserResponse>("/auth/me"))!.Roles);

        var (user, _, _, email) = await UserAsync();
        Assert.Contains("now has the Admin role", await DbInitializer.SeedAdminAsync(factory.Services, email, "Ignored-Pass-2026"));
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/admin/users")).StatusCode);
    }
}
