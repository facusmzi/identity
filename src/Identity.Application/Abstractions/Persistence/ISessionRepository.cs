using Identity.Domain.Entities;
using Identity.Domain.Enums;

namespace Identity.Application.Abstractions.Persistence;

/// <summary>
/// Sessions are read without change tracking and only ever mutated through the atomic bulk methods below
/// (never through tracked entities + SaveChanges). Mixing both is how stale in-memory copies overwrite a
/// concurrent revocation, so the repository does not offer the tracked path at all.
/// </summary>
public interface ISessionRepository
{
    Task AddAsync(Session session, CancellationToken ct = default);

    Task<Session?> GetByIdAsync(Guid sessionId, CancellationToken ct = default);

    /// <summary>Session with its user loaded (null if the session or the user is deleted).</summary>
    Task<Session?> GetWithUserAsync(Guid sessionId, CancellationToken ct = default);

    /// <summary>Active (not revoked, not expired) session, with its user and roles loaded.</summary>
    Task<Session?> GetActiveWithUserAsync(Guid sessionId, DateTime now, CancellationToken ct = default);

    Task<IReadOnlyList<Session>> ListActiveForUserAsync(Guid userId, DateTime now, CancellationToken ct = default);

    /// <summary>
    /// Atomically swaps the refresh token hash only if it still equals <paramref name="oldHash"/>,
    /// remembering the old one as the previous hash. Returns false when another request already rotated it.
    /// </summary>
    Task<bool> TryRotateRefreshTokenAsync(
        Guid sessionId, string oldHash, string newHash, DateTime expiresAt,
        string? ipAddress, string? userAgent, DateTime now, CancellationToken ct = default);

    Task<int> RevokeAsync(Guid sessionId, DateTime now, RevocationReason reason, CancellationToken ct = default);

    Task<int> RevokeAllForUserAsync(Guid userId, DateTime now, RevocationReason reason, Guid? exceptSessionId = null, CancellationToken ct = default);

    /// <summary>For admins: every session of the user that has not been purged yet, newest first.</summary>
    Task<IReadOnlyList<Session>> ListForUserAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Physically deletes sessions that expired or were revoked before <paramref name="before"/>.</summary>
    Task<int> PurgeEndedAsync(DateTime before, CancellationToken ct = default);
}
