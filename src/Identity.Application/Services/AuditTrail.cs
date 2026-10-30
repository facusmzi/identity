using System.Text.Json;
using Identity.Application.Abstractions;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Entities;

namespace Identity.Application.Services;

/// <summary>Stages audit entries; they are saved with the same SaveChanges as the action they describe.</summary>
public sealed class AuditTrail(IAuditLogRepository repository, IRequestContext request, TimeProvider clock)
{
    public void Record(string action, Guid? actorUserId, Guid? targetUserId, object? details = null) =>
        repository.Add(new AuditEntry
        {
            OccurredAt = clock.GetUtcNow().UtcDateTime,
            Action = action,
            ActorUserId = actorUserId,
            TargetUserId = targetUserId,
            IpAddress = request.IpAddress,
            Details = details is null ? null : JsonSerializer.Serialize(details),
        });
}
