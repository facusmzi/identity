using Identity.Application.Common;
using Identity.Domain.Entities;

namespace Identity.Application.Abstractions.Persistence;

public interface IAuditLogRepository
{
    /// <summary>Tracked; persisted by the next SaveChanges, i.e. atomically with the action it describes.</summary>
    void Add(AuditEntry entry);

    Task<PagedResult<AuditEntry>> ListAsync(Guid? userId, string? action, int page, int pageSize, CancellationToken ct = default);
}
