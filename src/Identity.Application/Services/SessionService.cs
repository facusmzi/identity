using Identity.Application.Abstractions.Persistence;
using Identity.Application.Common;
using Identity.Application.Dtos;

namespace Identity.Application.Services;

public sealed class SessionService(ISessionRepository sessions, TimeProvider clock)
{
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
        return session.Id == currentSessionId;
    }

    /// <summary>Used by the API on every authenticated request: the session must still be alive.</summary>
    public async Task<SessionPrincipal?> ValidateAsync(Guid sessionId, Guid userId, CancellationToken ct = default)
    {
        var session = await sessions.GetActiveWithUserAsync(sessionId, Now, ct);
        if (session is null || session.UserId != userId) return null;
        return new SessionPrincipal(session.UserId, session.Id, session.User.EmailVerified, session.User.RoleNames());
    }
}

public sealed record SessionPrincipal(Guid UserId, Guid SessionId, bool EmailVerified, IReadOnlyList<string> Roles);
