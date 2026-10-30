using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Persistence;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Persistence.Repositories;

namespace Identity.Infrastructure.Maintenance;

public sealed class RetentionOptions
{
    public const string Section = "Retention";

    /// <summary>Run the periodic cleanup (disabled in tests, which call it on demand).</summary>
    public bool Enabled { get; set; } = true;
    public int IntervalMinutes { get; set; } = 60;

    /// <summary>Expired / revoked sessions are physically deleted this long after they ended.</summary>
    public int EndedSessionDays { get; set; } = 30;

    /// <summary>Delivered or abandoned outbox emails.</summary>
    public int OutboxDays { get; set; } = 7;

    public int AuditDays { get; set; } = 365;
}

/// <summary>Hard-deletes data whose retention period is over. Idempotent, so several instances may run it.</summary>
public sealed class RetentionCleanup(
    ISessionRepository sessions, AuditLogRepository audit, AppDbContext db,
    TimeProvider clock, IOptions<RetentionOptions> options, ILogger<RetentionCleanup> logger)
{
    private readonly RetentionOptions _opt = options.Value;

    public async Task RunAsync(CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;

        var purgedSessions = await sessions.PurgeEndedAsync(now.AddDays(-_opt.EndedSessionDays), ct);

        var outboxBefore = now.AddDays(-_opt.OutboxDays);
        var purgedOutbox = await PurgeOutboxAsync(outboxBefore, ct);

        var purgedAudit = await audit.PurgeOlderThanAsync(now.AddDays(-_opt.AuditDays), ct);

        if (purgedSessions + purgedOutbox + purgedAudit > 0)
            logger.LogInformation("Retention cleanup removed {Sessions} sessions, {Outbox} outbox emails, {Audit} audit entries",
                purgedSessions, purgedOutbox, purgedAudit);
    }

    // Retention purge (sanctioned hard delete).
    private Task<int> PurgeOutboxAsync(DateTime before, CancellationToken ct) =>
        db.OutboxEmails.Where(m => m.SentAt < before || m.FailedAt < before).ExecuteDeleteAsync(ct);
}

public sealed class RetentionCleanupService(
    IServiceScopeFactory scopes, IOptions<RetentionOptions> options, ILogger<RetentionCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;

        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(Math.Max(1, options.Value.IntervalMinutes)));
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<RetentionCleanup>().RunAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Retention cleanup failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
