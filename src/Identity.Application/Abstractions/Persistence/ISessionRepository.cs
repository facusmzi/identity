using Identity.Domain.Entities;

namespace Identity.Application.Abstractions.Persistence;

public interface ISessionRepository : IRepository<Session>
{
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

    Task<int> RevokeAsync(Guid sessionId, DateTime now, CancellationToken ct = default);

    Task<int> RevokeAllForUserAsync(Guid userId, DateTime now, Guid? exceptSessionId = null, CancellationToken ct = default);
}
