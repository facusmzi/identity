using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Application.Options;

namespace Identity.Application.Services;

public sealed class SessionService(
    ISessionRepository sessions, ISessionCache cache, TimeProvider clock, IOptions<AuthOptions> options)
{
    private readonly TimeSpan _cacheTtl = TimeSpan.FromSeconds(Math.Max(0, options.Value.SessionCacheSeconds));

    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    public async Task<IReadOnlyList<SessionResponse>> ListActiveAsync(Guid userId, Guid currentSessionId, CancellationToken ct = default)
    {
        var list = await sessions.ListActiveForUserAsync(userId, Now, ct);
        return list.Select(s => s.ToResponse(currentSessionId)).ToList();
    }

    /// <summary>Revokes one of the caller's sessions. Returns true if it was the current one.</summary>
    public async Task<bool> RevokeAsync(Guid userId, Guid currentSessionId, Guid sessionId, CancellationToken ct = default)
    {
        var session = await sessions.GetByIdAsync(sessionId, ct);
        if (session is null || session.RevokedAt is not null) throw new NotFoundException("Session not found");
        if (session.UserId != userId) throw new ForbiddenException("Forbidden");

        await sessions.RevokeAsync(sessionId, Now, ct);
        await cache.InvalidateUserAsync(userId, ct);
        return session.Id == currentSessionId;
    }

    /// <summary>
    /// Used by the API on every authenticated request: the session must still be alive. Served from the
    /// session cache when possible (see <see cref="ISessionCache"/> for why that cannot return revoked sessions).
    /// </summary>
    public async Task<SessionPrincipal?> ValidateAsync(Guid sessionId, Guid userId, CancellationToken ct = default)
    {
        if (_cacheTtl <= TimeSpan.Zero) return await LoadAsync(sessionId, userId, ct);

        var (cached, generation) = await cache.GetAsync(sessionId, userId, ct);
        if (cached is not null && cached.UserId == userId && cached.ExpiresAt > Now) return cached;

        var principal = await LoadAsync(sessionId, userId, ct);
        if (principal is null) return null;

        var ttl = principal.ExpiresAt - Now;
        await cache.SetAsync(principal, generation, ttl < _cacheTtl ? ttl : _cacheTtl, ct);
        return principal;
    }

    private async Task<SessionPrincipal?> LoadAsync(Guid sessionId, Guid userId, CancellationToken ct)
    {
        var session = await sessions.GetActiveWithUserAsync(sessionId, Now, ct);
        if (session is null || session.UserId != userId) return null;
        return new SessionPrincipal(session.UserId, session.Id, session.User.EmailVerified,
            session.User.RoleNames(), session.User.EffectivePermissions(), session.ExpiresAt);
    }
}

public sealed record SessionPrincipal(
    Guid UserId, Guid SessionId, bool EmailVerified, IReadOnlyList<string> Roles, IReadOnlyList<string> Permissions, DateTime ExpiresAt);
