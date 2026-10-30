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
using Microsoft.Extensions.Time.Testing;
using Identity.Application.Options;
using Identity.Application.Abstractions.Security;
using Identity.Application.Dtos;
using Identity.Application.Services;
using Identity.Infrastructure.Caching;
using Identity.Infrastructure.Messaging;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Persistence.Interceptors;

namespace Identity.Tests;

/// <summary>
/// The real API in the "Testing" environment (ephemeral signing key, cheap Argon2, no rate limits). Emails go
/// through the real outbox; background workers are off and tests deliver pending emails on demand, so nothing
/// runs concurrently with the request under test.
/// </summary>
public abstract class TestHostFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "Admin12345";
    public const string StoreClientId = "store";
    public const string StoreAudience = "store-api";
    public const string StoreSecret = "store-secret-0123456789-abcdefghij-xyz";
    public const string StoreWebhookUrl = "https://store.test/identity-events";
    public const string StoreWebhookSecret = "store-webhook-secret-0123456789-abcdef";

    public CapturingEmailTransport Emails { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("PasswordHashing:MemoryKb", "1024");
        builder.UseSetting("PasswordHashing:Iterations", "1");
        builder.UseSetting("PasswordHashing:Parallelism", "1");
        builder.UseSetting("RateLimiting:StrictPermitLimit", "10000");
        builder.UseSetting("RateLimiting:PermitLimit", "10000");
        builder.UseSetting("RateLimiting:Distributed", "false"); // the Postgres suite turns it on with real Redis
        builder.UseSetting("Auth:VerificationResendCooldownSeconds", "0");
        builder.UseSetting("Outbox:Enabled", "false");
        builder.UseSetting("Retention:Enabled", "false");
        // Two client apps: a store (confidential, can introspect) and a public mobile app.
        builder.UseSetting("Clients:0:Id", StoreClientId);
        builder.UseSetting("Clients:0:Audience", StoreAudience);
        builder.UseSetting("Clients:0:Secret", StoreSecret);
        builder.UseSetting("Clients:0:WebhookUrl", StoreWebhookUrl);
        builder.UseSetting("Clients:0:WebhookSecret", StoreWebhookSecret);
        builder.UseSetting("Clients:1:Id", "mobile");
        builder.UseSetting("Clients:1:Audience", "mobile-api");
        builder.UseSetting("Seed:AdminEmail", AdminEmail);
        builder.UseSetting("Seed:AdminPassword", AdminPassword);

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<IEmailTransport>();
            services.AddSingleton<IEmailTransport>(Emails);

            // Never call the real HIBP from tests.
            services.RemoveAll<IPasswordBreachChecker>();
            services.AddSingleton<IPasswordBreachChecker>(Breaches);

            // Webhook calls go to a fake receiver instead of the network.
            services.AddHttpClient(WebhookProcessor.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Webhooks);
        });
    }

    public FakeBreachChecker Breaches { get; } = new();
    public WebhookReceiver Webhooks { get; } = new();

    public async Task<int> DispatchWebhooksAsync()
    {
        await using var scope = Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<WebhookProcessor>().DispatchPendingAsync();
    }

    public async Task<int> DispatchEmailsAsync()
    {
        await using var scope = Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<OutboxProcessor>().DispatchPendingAsync();
    }

    public async Task<string> LastCodeAsync(string email)
    {
        await DispatchEmailsAsync();
        return Emails.LastCodeFor(email);
    }

    public async Task<string?> LastResetTokenAsync(string email)
    {
        await DispatchEmailsAsync();
        return Emails.LastResetTokenFor(email);
    }

    public async Task<int> CodesSentToAsync(string email)
    {
        await DispatchEmailsAsync();
        return Emails.CodesSentTo(email);
    }

    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> action)
    {
        await using var scope = Services.CreateAsyncScope();
        return await action(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }

    public async Task WithScopeAsync(Func<IServiceProvider, Task> action)
    {
        await using var scope = Services.CreateAsyncScope();
        await action(scope.ServiceProvider);
    }

    /// <summary>Registers, verifies and logs in a fresh user.</summary>
    public async Task<(HttpClient Client, AuthTokensResponse Tokens)> CreateVerifiedUserAsync(string email, string password = "Passw0rd!")
    {
        var client = CreateClient();
        (await client.PostAsJsonAsync("/auth/register", new { email, password })).EnsureSuccessStatusCode();
        (await client.PostAsJsonAsync("/auth/verify-email", new { email, code = await LastCodeAsync(email), password })).EnsureSuccessStatusCode();
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

/// <summary>SQLite in-memory instead of Postgres and in-memory fakes for Redis. Fast; used by most tests.</summary>
public class IdentityFactory : TestHostFactory
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // WithWebHostBuilder re-runs this for derived factories sharing the connection.
        if (_connection.State != System.Data.ConnectionState.Open) _connection.Open();
        base.ConfigureWebHost(builder);

        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<AppDbContext>>();
            services.AddDbContext<AppDbContext>((sp, options) => options
                .UseSqlite(_connection)
                .UseSnakeCaseNamingConvention()
                .AddInterceptors(sp.GetRequiredService<AuditAndSoftDeleteInterceptor>()));

            services.RemoveAll<IRefreshGraceStore>();
            services.AddSingleton<IRefreshGraceStore>(sp => new InMemoryRefreshGraceStore(sp.GetRequiredService<TimeProvider>()));

            services.RemoveAll<ILoginThrottle>();
            services.AddSingleton<ILoginThrottle, InMemoryLoginThrottle>();

            services.RemoveAll<ISessionCache>();
            services.AddSingleton<ISessionCache>(sp => new InMemorySessionCache(sp.GetRequiredService<TimeProvider>()));
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        _connection.Dispose();
    }
}

/// <summary>Real Redis implementations pointed at a port where nothing listens: a genuine Redis outage.</summary>
public sealed class RedisDownFactory : IdentityFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("ConnectionStrings:Redis", "127.0.0.1:1,connectTimeout=200");
        builder.UseSetting("RateLimiting:Distributed", "true");
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<ILoginThrottle>();
            services.AddSingleton<ILoginThrottle, RedisLoginThrottle>();
            services.RemoveAll<IRefreshGraceStore>();
            services.AddSingleton<IRefreshGraceStore, RedisRefreshGraceStore>();
            services.RemoveAll<ISessionCache>();
            services.AddSingleton<ISessionCache, RedisSessionCache>();
        });
    }
}

/// <summary>
/// Same app with a controllable clock: tests move time forward instead of sleeping. The clock starts at the real
/// time and auto-advances 1 ms per read so timestamps stay distinct and ordered. JWT validation still uses the real
/// clock, so only jump far ahead in a factory used for nothing else afterwards.
/// </summary>
public sealed class TimeTravelFactory : IdentityFactory
{
    public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow) { AutoAdvanceAmount = TimeSpan.FromMilliseconds(1) };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
        });
    }
}

public sealed class CapturingEmailTransport : IEmailTransport
{
    private readonly ConcurrentDictionary<string, string> _codes = new();
    private readonly ConcurrentDictionary<string, int> _codeCounts = new();
    private readonly ConcurrentDictionary<string, string> _resetTokens = new();

    /// <summary>When set, sending throws (to exercise the outbox retry path).</summary>
    public Exception? FailWith { get; set; }

    public Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default)
    {
        if (FailWith is not null) throw FailWith;
        _codes[to] = code;
        _codeCounts.AddOrUpdate(to, 1, (_, n) => n + 1);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default)
    {
        if (FailWith is not null) throw FailWith;
        _resetTokens[to] = token;
        return Task.CompletedTask;
    }

    private readonly ConcurrentQueue<(string To, string Subject)> _notices = new();

    public Task SendSecurityNoticeAsync(string to, string subject, string message, CancellationToken ct = default)
    {
        if (FailWith is not null) throw FailWith;
        _notices.Enqueue((to, subject));
        return Task.CompletedTask;
    }

    public IReadOnlyList<string> NoticesFor(string email) =>
        _notices.Where(n => n.To == email.ToLowerInvariant()).Select(n => n.Subject).ToList();

    public string LastCodeFor(string email) => _codes[email.ToLowerInvariant()];

    public string? LastResetTokenFor(string email) => _resetTokens.GetValueOrDefault(email.ToLowerInvariant());

    public int CodesSentTo(string email) => _codeCounts.GetValueOrDefault(email.ToLowerInvariant());
}

/// <summary>Same semantics as RedisLoginThrottle, in memory.</summary>
public sealed class InMemoryLoginThrottle(IOptions<AuthOptions> options) : ILoginThrottle
{
    private readonly AuthOptions _opt = options.Value;
    private readonly ConcurrentDictionary<string, int> _failures = new();
    private readonly ConcurrentDictionary<string, DateTime> _locks = new();

    public Task<TimeSpan?> GetLockoutAsync(string email, CancellationToken ct = default) =>
        Task.FromResult<TimeSpan?>(_locks.TryGetValue(email, out var until) && until > DateTime.UtcNow ? until - DateTime.UtcNow : null);

    public Task<bool> RegisterFailureAsync(string email, CancellationToken ct = default)
    {
        if (_failures.AddOrUpdate(email, 1, (_, n) => n + 1) < _opt.LoginMaxFailures) return Task.FromResult(false);

        _locks[email] = DateTime.UtcNow.AddMinutes(_opt.LoginLockoutMinutes);
        _failures.TryRemove(email, out _);
        return Task.FromResult(true);
    }

    public Task ResetAsync(string email, CancellationToken ct = default)
    {
        _failures.TryRemove(email, out _);
        _locks.TryRemove(email, out _);
        return Task.CompletedTask;
    }
}

/// <summary>Breached = the passwords in <see cref="Breached"/>; <see cref="Unavailable"/> simulates HIBP being down.</summary>
public sealed class FakeBreachChecker : IPasswordBreachChecker
{
    public HashSet<string> Breached { get; } = ["Password123", "Qwerty12345"];
    public bool Unavailable { get; set; }

    public Task<BreachCheckStatus> CheckAsync(string password, CancellationToken ct = default) =>
        Task.FromResult(Unavailable ? BreachCheckStatus.Unavailable
            : Breached.Contains(password) ? BreachCheckStatus.Breached : BreachCheckStatus.NotBreached);
}

/// <summary>Same generation semantics as RedisSessionCache, in memory.</summary>
public sealed class InMemorySessionCache(TimeProvider clock) : ISessionCache
{
    private readonly ConcurrentDictionary<Guid, (SessionPrincipal Principal, long Generation, DateTime ExpiresAt)> _entries = new();
    private readonly ConcurrentDictionary<Guid, long> _generations = new();

    public Task<(SessionPrincipal? Principal, long Generation)> GetAsync(Guid sessionId, Guid userId, CancellationToken ct = default)
    {
        var generation = _generations.GetValueOrDefault(userId);
        var hit = _entries.TryGetValue(sessionId, out var e) && e.Generation == generation && e.ExpiresAt > clock.GetUtcNow().UtcDateTime;
        return Task.FromResult<(SessionPrincipal?, long)>((hit ? e.Principal : null, generation));
    }

    public Task SetAsync(SessionPrincipal principal, long generation, TimeSpan ttl, CancellationToken ct = default)
    {
        _entries[principal.SessionId] = (principal, generation, clock.GetUtcNow().UtcDateTime + ttl);
        return Task.CompletedTask;
    }

    public Task InvalidateUserAsync(Guid userId, CancellationToken ct = default)
    {
        _generations.AddOrUpdate(userId, 1, (_, g) => g + 1);
        return Task.CompletedTask;
    }
}

public sealed class InMemoryRefreshGraceStore(TimeProvider clock) : IRefreshGraceStore
{
    private readonly ConcurrentDictionary<string, (AuthTokensResponse Tokens, DateTime ExpiresAt)> _items = new();

    public Task<AuthTokensResponse?> GetAsync(string oldRefreshTokenHash, CancellationToken ct = default) =>
        Task.FromResult(_items.TryGetValue(oldRefreshTokenHash, out var item) && item.ExpiresAt > clock.GetUtcNow().UtcDateTime
            ? item.Tokens
            : null);

    public Task SetAsync(string oldRefreshTokenHash, AuthTokensResponse tokens, TimeSpan ttl, CancellationToken ct = default)
    {
        _items[oldRefreshTokenHash] = (tokens, clock.GetUtcNow().UtcDateTime + ttl);
        return Task.CompletedTask;
    }
}

/// <summary>Records webhook POSTs; <see cref="FailNext"/> makes the next ones answer 500.</summary>
public sealed class WebhookReceiver : HttpMessageHandler
{
    public ConcurrentQueue<(string Url, string Body, Dictionary<string, string> Headers)> Received { get; } = new();
    public int FailNext { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        if (FailNext > 0)
        {
            FailNext--;
            return new HttpResponseMessage(System.Net.HttpStatusCode.InternalServerError);
        }
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value));
        Received.Enqueue((request.RequestUri!.ToString(), await request.Content!.ReadAsStringAsync(ct), headers));
        return new HttpResponseMessage(System.Net.HttpStatusCode.NoContent);
    }
}
