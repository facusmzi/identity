using Microsoft.AspNetCore.Hosting;
using Testcontainers.PostgreSql;
using Testcontainers.Redis;

namespace Identity.Tests.Postgres;

/// <summary>
/// Real PostgreSQL and Redis in containers (Testcontainers talks to Docker or to Podman's Docker-compatible
/// API). Without a container runtime the tests are skipped locally, but they fail in CI.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _postgres;
    private RedisContainer? _redis;

    public PostgresIdentityFactory? Factory { get; private set; }
    public string? SkipReason { get; private set; }
    public string PostgresConnection { get; private set; } = "";
    public string RedisConnection { get; private set; } = "";

    public async Task InitializeAsync()
    {
        try
        {
            _postgres = new PostgreSqlBuilder("docker.io/library/postgres:17-alpine").Build();
            _redis = new RedisBuilder("docker.io/library/redis:7-alpine").Build();
            await Task.WhenAll(_postgres.StartAsync(), _redis.StartAsync());
            Factory = new PostgresIdentityFactory(_postgres.GetConnectionString(), _redis.GetConnectionString());
            PostgresConnection = _postgres.GetConnectionString();
            RedisConnection = _redis.GetConnectionString();
        }
        catch (Exception ex) when (Environment.GetEnvironmentVariable("CI") is null)
        {
            SkipReason = $"No container runtime available ({ex.GetType().Name}: {ex.Message})";
        }
    }

    public async Task DisposeAsync()
    {
        Factory?.Dispose();
        if (_postgres is not null) await _postgres.DisposeAsync();
        if (_redis is not null) await _redis.DisposeAsync();
    }

    public PostgresIdentityFactory Require()
    {
        Skip.If(SkipReason is not null, SkipReason);
        return Factory!;
    }
}

/// <summary>The API with its real infrastructure: Npgsql, migrations, Redis grace store and login throttle.</summary>
public sealed class PostgresIdentityFactory(string postgres, string redis, Action<IWebHostBuilder>? extra = null) : TestHostFactory
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseSetting("ConnectionStrings:Postgres", postgres);
        builder.UseSetting("ConnectionStrings:Redis", redis);
        builder.UseSetting("Database:MigrateOnStartup", "true");
        builder.UseSetting("RateLimiting:Distributed", "true");
        extra?.Invoke(builder); // last, so it overrides the defaults above
    }
}

[CollectionDefinition(Name)]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>
{
    public const string Name = "postgres";
}
