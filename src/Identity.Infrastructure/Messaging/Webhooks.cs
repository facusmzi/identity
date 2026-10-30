using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Messaging;
using Identity.Application.Services;
using Identity.Infrastructure.Persistence;

namespace Identity.Infrastructure.Messaging;

/// <summary>One delivery of one event to one client. The payload only carries ids, never personal data.</summary>
public sealed class OutboxWebhook
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public required string ClientId { get; set; }
    public required string EventType { get; set; }
    public required string Payload { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime NextAttemptAt { get; set; }
    public DateTime? LockedUntil { get; set; }
    public int Attempts { get; set; }
    public DateTime? SentAt { get; set; }
    public DateTime? FailedAt { get; set; }
    public string? LastError { get; set; }
}

/// <summary>Stages one row per client with a WebhookUrl; inserted by the caller's SaveChanges.</summary>
public sealed class EfAccountEvents(AppDbContext db, ClientRegistry clients, TimeProvider clock) : IAccountEvents
{
    public void Publish(string type, Guid userId)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        foreach (var client in clients.All.Where(c => !string.IsNullOrEmpty(c.WebhookUrl)))
        {
            var id = Guid.CreateVersion7();
            db.OutboxWebhooks.Add(new OutboxWebhook
            {
                Id = id,
                ClientId = client.Id,
                EventType = type,
                Payload = JsonSerializer.Serialize(new { id, type, occurredAt = now, data = new { userId } }),
                CreatedAt = now,
                NextAttemptAt = now,
            });
        }
    }
}

/// <summary>
/// POSTs due events, signed so the receiver can trust them:
/// <c>Identity-Signature: t=&lt;unix seconds&gt;,v1=&lt;hex HMAC-SHA256(WebhookSecret, "&lt;t&gt;.&lt;body&gt;")&gt;</c>.
/// Any non-2xx answer is retried with exponential backoff (same budget as emails); rows are claimed with a
/// conditional UPDATE so several instances never deliver the same event twice concurrently.
/// </summary>
public sealed class WebhookProcessor(
    AppDbContext db, IHttpClientFactory httpFactory, ClientRegistry clients, TimeProvider clock,
    IOptions<OutboxOptions> options, ILogger<WebhookProcessor> logger)
{
    public const string HttpClientName = "webhooks";
    private readonly OutboxOptions _opt = options.Value;

    public async Task<int> DispatchPendingAsync(CancellationToken ct = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var due = await db.OutboxWebhooks.AsNoTracking()
            .Where(w => w.SentAt == null && w.FailedAt == null && w.NextAttemptAt <= now && (w.LockedUntil == null || w.LockedUntil < now))
            .OrderBy(w => w.CreatedAt).Select(w => w.Id).Take(_opt.BatchSize).ToListAsync(ct);

        var sent = 0;
        foreach (var id in due)
        {
            var lockUntil = now.AddSeconds(_opt.LockSeconds);
            var claimed = await db.OutboxWebhooks
                .Where(w => w.Id == id && w.SentAt == null && w.FailedAt == null && (w.LockedUntil == null || w.LockedUntil < now))
                .ExecuteUpdateAsync(u => u.SetProperty(w => w.LockedUntil, lockUntil), ct);
            if (claimed == 0) continue;

            var webhook = await db.OutboxWebhooks.AsNoTracking().FirstAsync(w => w.Id == id, ct);
            if (await TrySendAsync(webhook, ct)) sent++;
        }
        return sent;
    }

    public static string Sign(string secret, long timestamp, string body) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes($"{timestamp}.{body}")));

    private async Task<bool> TrySendAsync(OutboxWebhook webhook, CancellationToken ct)
    {
        try
        {
            var client = clients.Find(webhook.ClientId);
            if (client is not { WebhookUrl: { Length: > 0 } url, WebhookSecret: { Length: > 0 } secret })
                throw new InvalidOperationException($"Client '{webhook.ClientId}' no longer has a webhook configured");

            var timestamp = clock.GetUtcNow().ToUnixTimeSeconds();
            using var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(webhook.Payload, Encoding.UTF8, "application/json"),
            };
            request.Headers.Add("Identity-Event-Id", webhook.Id.ToString());
            request.Headers.Add("Identity-Event-Type", webhook.EventType);
            request.Headers.Add("Identity-Signature", $"t={timestamp},v1={Sign(secret, timestamp, webhook.Payload)}");

            using var response = await httpFactory.CreateClient(HttpClientName).SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
                throw new HttpRequestException($"Webhook answered {(int)response.StatusCode}");

            var sentAt = clock.GetUtcNow().UtcDateTime;
            await db.OutboxWebhooks.Where(w => w.Id == webhook.Id).ExecuteUpdateAsync(u => u
                .SetProperty(w => w.SentAt, sentAt)
                .SetProperty(w => w.LockedUntil, (DateTime?)null)
                .SetProperty(w => w.LastError, (string?)null), ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            var attempts = webhook.Attempts + 1;
            var now = clock.GetUtcNow().UtcDateTime;
            var giveUp = attempts >= _opt.MaxAttempts;
            var retryAt = now.AddSeconds(Math.Min(3600, 10 * Math.Pow(2, attempts - 1)));
            var error = ex.Message.Length > 1000 ? ex.Message[..1000] : ex.Message;

            await db.OutboxWebhooks.Where(w => w.Id == webhook.Id).ExecuteUpdateAsync(u => u
                .SetProperty(w => w.Attempts, attempts)
                .SetProperty(w => w.NextAttemptAt, retryAt)
                .SetProperty(w => w.LockedUntil, (DateTime?)null)
                .SetProperty(w => w.LastError, error)
                .SetProperty(w => w.FailedAt, giveUp ? (DateTime?)now : null), ct);

            if (giveUp) logger.LogError(ex, "Giving up on webhook {EventId} ({Type}) to {Client}", webhook.Id, webhook.EventType, webhook.ClientId);
            else logger.LogWarning(ex, "Webhook {EventId} to {Client} failed, retry {Attempts} at {RetryAt}", webhook.Id, webhook.ClientId, attempts, retryAt);
            return false;
        }
    }
}

public sealed class WebhookDispatcher(
    IServiceScopeFactory scopes, IOptions<OutboxOptions> options, ILogger<WebhookDispatcher> logger) : BackgroundService
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
                await scope.ServiceProvider.GetRequiredService<WebhookProcessor>().DispatchPendingAsync(stoppingToken);
                await scope.ServiceProvider.GetRequiredService<OutboxBacklog>()
                    .RefreshAsync(scope.ServiceProvider.GetRequiredService<AppDbContext>(), stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Webhook dispatch failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
