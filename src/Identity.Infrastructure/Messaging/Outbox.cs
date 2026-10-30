using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Messaging;
using Identity.Infrastructure.Persistence;

namespace Identity.Infrastructure.Messaging;

/// <summary>Delivers an email right now (SMTP, or the log in development). Only the outbox processor calls it.</summary>
public interface IEmailTransport
{
    Task SendVerificationCodeAsync(string to, string code, CancellationToken ct = default);
    Task SendPasswordResetAsync(string to, string token, string? link, CancellationToken ct = default);
    Task SendSecurityNoticeAsync(string to, string subject, string message, CancellationToken ct = default);
}

public sealed class OutboxOptions
{
    public const string Section = "Outbox";

    /// <summary>Run the background dispatcher (disabled in tests, which dispatch on demand).</summary>
    public bool Enabled { get; set; } = true;
    public int PollSeconds { get; set; } = 2;
    public int BatchSize { get; set; } = 20;
    public int MaxAttempts { get; set; } = 8;
    public int LockSeconds { get; set; } = 60;
}

/// <summary>
/// A pending email. The payload holds the code / reset token in clear text only until it is delivered
/// (or gives up): it is wiped right after, so the table never keeps usable secrets.
/// </summary>
public sealed class OutboxEmail
{
    public const string VerificationCode = "verification-code";
    public const string PasswordReset = "password-reset";
    public const string SecurityNotice = "security-notice";

    public Guid Id { get; set; } = Guid.CreateVersion7();
    public required string Kind { get; set; }
    public required string To { get; set; }
    public string? Payload { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime NextAttemptAt { get; set; }
    public DateTime? LockedUntil { get; set; }
    public int Attempts { get; set; }
    public DateTime? SentAt { get; set; }
    public DateTime? FailedAt { get; set; }
    public string? LastError { get; set; }
}

internal sealed record VerificationPayload(string Code);
internal sealed record PasswordResetPayload(string Token, string? Link);
internal sealed record SecurityNoticePayload(string Subject, string Message);

/// <summary>Stages emails in the DbContext; they are inserted by the caller's SaveChanges.</summary>
public sealed class EfEmailOutbox(AppDbContext db, TimeProvider clock) : IEmailOutbox
{
    public void EnqueueVerificationCode(string to, string code) =>
        Add(OutboxEmail.VerificationCode, to, new VerificationPayload(code));

    public void EnqueuePasswordReset(string to, string token, string? link) =>
        Add(OutboxEmail.PasswordReset, to, new PasswordResetPayload(token, link));

    public void EnqueueSecurityNotice(string to, string subject, string message) =>
        Add(OutboxEmail.SecurityNotice, to, new SecurityNoticePayload(subject, message));

    private void Add(string kind, string to, object payload)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        db.OutboxEmails.Add(new OutboxEmail
        {
            Kind = kind,
            To = to,
            Payload = JsonSerializer.Serialize(payload),
            CreatedAt = now,
            NextAttemptAt = now,
        });
    }
}

/// <summary>
/// Claims due messages one by one with a conditional UPDATE (safe with several API instances), sends them and
/// records the outcome. Failures are retried with exponential backoff up to <see cref="OutboxOptions.MaxAttempts"/>.
/// </summary>
public sealed class OutboxProcessor(
    AppDbContext db, IEmailTransport transport, TimeProvider clock, IOptions<OutboxOptions> options, ILogger<OutboxProcessor> logger)
{
    private readonly OutboxOptions _opt = options.Value;

    public async Task<int> DispatchPendingAsync(CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var due = await db.OutboxEmails.AsNoTracking()
            .Where(m => m.SentAt == null && m.FailedAt == null && m.NextAttemptAt <= now
                        && (m.LockedUntil == null || m.LockedUntil < now))
            .OrderBy(m => m.CreatedAt)
            .Select(m => m.Id)
            .Take(_opt.BatchSize)
            .ToListAsync(ct);

        var sent = 0;
        foreach (var id in due)
        {
            var lockUntil = now.AddSeconds(_opt.LockSeconds);
            var claimed = await db.OutboxEmails
                .Where(m => m.Id == id && m.SentAt == null && m.FailedAt == null && (m.LockedUntil == null || m.LockedUntil < now))
                .ExecuteUpdateAsync(u => u.SetProperty(m => m.LockedUntil, lockUntil), ct);
            if (claimed == 0) continue; // another instance took it

            var message = await db.OutboxEmails.AsNoTracking().FirstAsync(m => m.Id == id, ct);
            if (await TrySendAsync(message, ct)) sent++;
        }
        return sent;
    }

    private async Task<bool> TrySendAsync(OutboxEmail message, CancellationToken ct)
    {
        try
        {
            await SendAsync(message, ct);
            var sentAt = clock.GetUtcNow().UtcDateTime;
            await db.OutboxEmails.Where(m => m.Id == message.Id).ExecuteUpdateAsync(u => u
                .SetProperty(m => m.SentAt, sentAt)
                .SetProperty(m => m.Payload, (string?)null)
                .SetProperty(m => m.LockedUntil, (DateTime?)null)
                .SetProperty(m => m.LastError, (string?)null), ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var attempts = message.Attempts + 1;
            var now = clock.GetUtcNow().UtcDateTime;
            var giveUp = attempts >= _opt.MaxAttempts;
            var retryAt = now.AddSeconds(Math.Min(3600, 10 * Math.Pow(2, attempts - 1)));
            var error = ex.Message.Length > 1000 ? ex.Message[..1000] : ex.Message;

            await db.OutboxEmails.Where(m => m.Id == message.Id).ExecuteUpdateAsync(u => u
                .SetProperty(m => m.Attempts, attempts)
                .SetProperty(m => m.NextAttemptAt, retryAt)
                .SetProperty(m => m.LockedUntil, (DateTime?)null)
                .SetProperty(m => m.LastError, error)
                .SetProperty(m => m.FailedAt, giveUp ? (DateTime?)now : null)
                .SetProperty(m => m.Payload, giveUp ? null : message.Payload), ct);

            if (giveUp) logger.LogError(ex, "Giving up on email {MessageId} ({Kind}) after {Attempts} attempts", message.Id, message.Kind, attempts);
            else logger.LogWarning(ex, "Email {MessageId} ({Kind}) failed, retry {Attempts} at {RetryAt}", message.Id, message.Kind, attempts, retryAt);
            return false;
        }
    }

    private Task SendAsync(OutboxEmail message, CancellationToken ct)
    {
        var payload = message.Payload ?? throw new InvalidOperationException("Outbox message has no payload");
        return message.Kind switch
        {
            OutboxEmail.VerificationCode =>
                transport.SendVerificationCodeAsync(message.To, JsonSerializer.Deserialize<VerificationPayload>(payload)!.Code, ct),
            OutboxEmail.PasswordReset => SendResetAsync(message.To, JsonSerializer.Deserialize<PasswordResetPayload>(payload)!, ct),
            OutboxEmail.SecurityNotice => SendNoticeAsync(message.To, JsonSerializer.Deserialize<SecurityNoticePayload>(payload)!, ct),
            _ => throw new InvalidOperationException($"Unknown outbox kind '{message.Kind}'"),
        };
    }

    private Task SendResetAsync(string to, PasswordResetPayload p, CancellationToken ct) =>
        transport.SendPasswordResetAsync(to, p.Token, p.Link, ct);

    private Task SendNoticeAsync(string to, SecurityNoticePayload p, CancellationToken ct) =>
        transport.SendSecurityNoticeAsync(to, p.Subject, p.Message, ct);
}

public sealed class OutboxDispatcher(
    IServiceScopeFactory scopes, IOptions<OutboxOptions> options, ILogger<OutboxDispatcher> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(Math.Max(1, options.Value.PollSeconds)));
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<OutboxProcessor>().DispatchPendingAsync(stoppingToken);
                await scope.ServiceProvider.GetRequiredService<OutboxBacklog>()
                    .RefreshAsync(scope.ServiceProvider.GetRequiredService<AppDbContext>(), stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Outbox dispatch failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
