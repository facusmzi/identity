using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Repositories;

/// <summary>Reads are untracked; every mutation is a single atomic UPDATE (see ISessionRepository).</summary>
public sealed class SessionRepository(AppDbContext db) : ISessionRepository
{
    private DbSet<Session> Set => db.Sessions;

    public async Task AddAsync(Session session, CancellationToken ct = default) => await Set.AddAsync(session, ct);

    public Task<Session?> GetByIdAsync(Guid sessionId, CancellationToken ct = default) =>
        Set.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sessionId, ct);

    public Task<Session?> GetWithUserAsync(Guid sessionId, CancellationToken ct = default) =>
        Set.AsNoTracking().Include(s => s.User).FirstOrDefaultAsync(s => s.Id == sessionId, ct);

    public Task<Session?> GetActiveWithUserAsync(Guid sessionId, DateTime now, CancellationToken ct = default) =>
        Set.AsNoTracking()
            .Include(s => s.User).ThenInclude(u => u.UserRoles).ThenInclude(ur => ur.Role).ThenInclude(r => r.RolePermissions)
            .FirstOrDefaultAsync(s => s.Id == sessionId && s.RevokedAt == null && s.ExpiresAt > now, ct);

    public async Task<IReadOnlyList<Session>> ListActiveForUserAsync(Guid userId, DateTime now, CancellationToken ct = default) =>
        await Set.AsNoTracking()
            .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > now)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(ct);

    public async Task<bool> TryRotateRefreshTokenAsync(
        Guid sessionId, string oldHash, string newHash, DateTime expiresAt,
        string? ipAddress, string? userAgent, DateTime now, CancellationToken ct = default)
    {
        var affected = await Set
            .Where(s => s.Id == sessionId && s.RefreshTokenHash == oldHash && s.RevokedAt == null)
            .ExecuteUpdateAsync(u => u
                .SetProperty(s => s.RefreshTokenHash, newHash)
                .SetProperty(s => s.PreviousRefreshTokenHash, oldHash)
                .SetProperty(s => s.RefreshRotatedAt, now)
                .SetProperty(s => s.ExpiresAt, expiresAt)
                .SetProperty(s => s.IpAddress, ipAddress)
                .SetProperty(s => s.UserAgent, userAgent)
                .SetProperty(s => s.UpdatedAt, now), ct);
        return affected == 1;
    }

    public Task<int> RevokeAsync(Guid sessionId, DateTime now, CancellationToken ct = default) =>
        Set.Where(s => s.Id == sessionId && s.RevokedAt == null)
            .ExecuteUpdateAsync(u => u
                .SetProperty(s => s.RevokedAt, now)
                .SetProperty(s => s.UpdatedAt, now), ct);

    public Task<int> RevokeAllForUserAsync(Guid userId, DateTime now, Guid? exceptSessionId = null, CancellationToken ct = default) =>
        Set.Where(s => s.UserId == userId && s.RevokedAt == null && (exceptSessionId == null || s.Id != exceptSessionId))
            .ExecuteUpdateAsync(u => u
                .SetProperty(s => s.RevokedAt, now)
                .SetProperty(s => s.UpdatedAt, now), ct);

    // Retention purge: the one sanctioned hard delete. Ended sessions carry no value after the retention period.
    public Task<int> PurgeEndedAsync(DateTime before, CancellationToken ct = default) =>
        Set.IgnoreQueryFilters()
            .Where(s => s.ExpiresAt < before || s.RevokedAt < before || s.DeletedAt < before)
            .ExecuteDeleteAsync(ct);
}
