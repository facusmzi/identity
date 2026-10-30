using System.Diagnostics.Metrics;
using Microsoft.EntityFrameworkCore;
using Identity.Application.Services;
using Identity.Infrastructure.Persistence;

namespace Identity.Infrastructure.Messaging;

/// <summary>
/// <c>identity.outbox.pending{kind=email|webhook}</c>: messages waiting for delivery. A number that keeps growing
/// means SMTP or a client's webhook endpoint is down. Refreshed by the dispatchers after each pass (the gauge
/// callback itself never touches the database).
/// </summary>
public sealed class OutboxBacklog
{
    private long _emails;
    private long _webhooks;

    public OutboxBacklog(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(IdentityMetrics.MeterName);
        meter.CreateObservableGauge("identity.outbox.pending", () => new[]
        {
            new Measurement<long>(Interlocked.Read(ref _emails), new KeyValuePair<string, object?>("kind", "email")),
            new Measurement<long>(Interlocked.Read(ref _webhooks), new KeyValuePair<string, object?>("kind", "webhook")),
        }, description: "Emails and webhooks waiting for delivery");
    }

    public async Task RefreshAsync(AppDbContext db, CancellationToken ct)
    {
        Interlocked.Exchange(ref _emails, await db.OutboxEmails.CountAsync(m => m.SentAt == null && m.FailedAt == null, ct));
        Interlocked.Exchange(ref _webhooks, await db.OutboxWebhooks.CountAsync(w => w.SentAt == null && w.FailedAt == null, ct));
    }
}
