using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Identity.Application.Options;
using Identity.Application.Abstractions.Messaging;
using Identity.Application.Abstractions.Security;
using Identity.Application.Dtos;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Persistence.Interceptors;

namespace Identity.Tests;

/// <summary>Runs the real API with SQLite in-memory instead of Postgres and in-memory fakes for Redis/SMTP.</summary>
public class IdentityFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "Admin12345";

    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public CapturingEmailSender Emails { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        _connection.Open();

        builder.UseEnvironment("Testing");
        builder.UseSetting("Jwt:Secret", "test-secret-test-secret-test-secret-123");
        builder.UseSetting("PasswordHashing:MemoryKb", "1024");
        builder.UseSetting("PasswordHashing:Iterations", "1");
        builder.UseSetting("PasswordHashing:Parallelism", "1");
        builder.UseSetting("RateLimiting:StrictPermitLimit", "10000");
        builder.UseSetting("RateLimiting:PermitLimit", "10000");
        builder.UseSetting("Auth:VerificationResendCooldownSeconds", "0");
        builder.UseSetting("Seed:AdminEmail", AdminEmail);
        builder.UseSetting("Seed:AdminPassword", AdminPassword);

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<AppDbContext>>();
            services.AddDbContext<AppDbContext>((sp, options) => options
                .UseSqlite(_connection)
                .UseSnakeCaseNamingConvention()
                .AddInterceptors(sp.GetRequiredService<AuditAndSoftDeleteInterceptor>()));

            services.RemoveAll<IRefreshGraceStore>();
            services.AddSingleton<IRefreshGraceStore, InMemoryRefreshGraceStore>();

            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Emails);

            services.RemoveAll<ILoginThrottle>();
            services.AddSingleton<ILoginThrottle, InMemoryLoginThrottle>();
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _connection.Dispose();
    }

    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> action)
    {
        await using var scope = Services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    /// <summary>Registers, verifies and logs in a fresh user.</summary>
    public async Task<(HttpClient Client, AuthTokensResponse Tokens)> CreateVerifiedUserAsync(string email, string password = "Passw0rd!")
    {
        var client = CreateClient();
        (await client.PostAsJsonAsync("/auth/register", new { email, password })).EnsureSuccessStatusCode();
        (await client.PostAsJsonAsync("/auth/verify-email", new { email, code = Emails.LastCodeFor(email), password })).EnsureSuccessStatusCode();
        var tokens = await LoginAsync(client, email, password);
        return (client, tokens);
    }

    public static async Task<AuthTokensResponse> LoginAsync(HttpClient client, string email, string password)
    {
        var res = await client.PostAsJsonAsync("/auth/login", new { email, password });
        res.EnsureSuccessStatusCode();
        var tokens = (await res.Content.ReadFromJsonAsync<AuthTokensResponse>())!;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        return tokens;
    }
}

public sealed class CapturingEmailSender : IEmailSender
{
    private readonly ConcurrentDictionary<string, string> _codes = new();
    private readonly ConcurrentDictionary<string, int> _codeCounts = new();
    private readonly ConcurrentDictionary<string, string> _resetTokens = new();

    public Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default)
    {
        _codes[to] = code;
        _codeCounts.AddOrUpdate(to, 1, (_, n) => n + 1);
        return Task.CompletedTask;
    }

    public int CodesSentTo(string email) => _codeCounts.GetValueOrDefault(email.ToLowerInvariant());

    public Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default)
    {
        _resetTokens[to] = token;
        return Task.CompletedTask;
    }

    public string LastCodeFor(string email) => _codes[email.ToLowerInvariant()];

    public string? LastResetTokenFor(string email) => _resetTokens.GetValueOrDefault(email.ToLowerInvariant());
}

/// <summary>Same semantics as RedisLoginThrottle, in memory.</summary>
public sealed class InMemoryLoginThrottle(IOptions<AuthOptions> options) : ILoginThrottle
{
    private readonly AuthOptions _opt = options.Value;
    private readonly ConcurrentDictionary<string, int> _failures = new();
    private readonly ConcurrentDictionary<string, DateTime> _locks = new();

    public Task<TimeSpan?> GetLockoutAsync(string email, CancellationToken ct = default) =>
        Task.FromResult<TimeSpan?>(_locks.TryGetValue(email, out var until) && until > DateTime.UtcNow ? until - DateTime.UtcNow : null);

    public Task RegisterFailureAsync(string email, CancellationToken ct = default)
    {
        if (_failures.AddOrUpdate(email, 1, (_, n) => n + 1) >= _opt.LoginMaxFailures)
        {
            _locks[email] = DateTime.UtcNow.AddMinutes(_opt.LoginLockoutMinutes);
            _failures.TryRemove(email, out _);
        }
        return Task.CompletedTask;
    }

    public Task ResetAsync(string email, CancellationToken ct = default)
    {
        _failures.TryRemove(email, out _);
        _locks.TryRemove(email, out _);
        return Task.CompletedTask;
    }
}

/// <summary>Same refresh flow but with a 1 second grace window, so tests can step outside it.</summary>
public sealed class ShortGraceFactory : IdentityFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("Auth:RefreshGraceSeconds", "1");
    }
}

public sealed class InMemoryRefreshGraceStore : IRefreshGraceStore
{
    private readonly ConcurrentDictionary<string, (AuthTokensResponse Tokens, DateTime ExpiresAt)> _items = new();

    public Task<AuthTokensResponse?> GetAsync(string oldRefreshTokenHash, CancellationToken ct = default) =>
        Task.FromResult(_items.TryGetValue(oldRefreshTokenHash, out var item) && item.ExpiresAt > DateTime.UtcNow
            ? item.Tokens
            : null);

    public Task SetAsync(string oldRefreshTokenHash, AuthTokensResponse tokens, TimeSpan ttl, CancellationToken ct = default)
    {
        _items[oldRefreshTokenHash] = (tokens, DateTime.UtcNow + ttl);
        return Task.CompletedTask;
    }
}
