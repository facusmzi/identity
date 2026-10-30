using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Common;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Repositories;

public sealed class AuditLogRepository(AppDbContext db) : IAuditLogRepository
{
    public void Add(AuditEntry entry) => db.AuditEntries.Add(entry);

    public async Task<PagedResult<AuditEntry>> ListAsync(Guid? userId, string? action, int page, int pageSize, CancellationToken ct = default)
    {
        var query = db.AuditEntries.AsNoTracking();
        if (userId is { } id) query = query.Where(e => e.TargetUserId == id || e.ActorUserId == id);
        if (!string.IsNullOrWhiteSpace(action)) query = query.Where(e => e.Action == action);

        var total = await query.CountAsync(ct);
        var items = await query
            .OrderByDescending(e => e.OccurredAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);
        return new PagedResult<AuditEntry>(items, page, pageSize, total);
    }

    // Retention purge (sanctioned hard delete).
    public Task<int> PurgeOlderThanAsync(DateTime before, CancellationToken ct = default) =>
        db.AuditEntries.Where(e => e.OccurredAt < before).ExecuteDeleteAsync(ct);
}
