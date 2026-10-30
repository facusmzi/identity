using Identity.Application.Services;

namespace Identity.Application.Abstractions.Security;

/// <summary>
/// Short-lived cache of validated sessions, so authenticated requests do not hit the database every time.
/// <para>
/// Staleness is prevented with a per-user generation number: an entry is only valid if it was written with the
/// user's current generation, and every change that affects the user's sessions or roles bumps it
/// (<see cref="InvalidateUserAsync"/>) AFTER the change is committed. A request that read the database just before
/// a revocation can still write its entry, but tagged with the old generation, so it is never served.
/// </para>
/// Implementations must treat cache failures as misses: the database stays the source of truth.
/// </summary>
public interface ISessionCache
{
    /// <summary>The cached principal (if valid for the current generation) and the generation to tag a new entry with.</summary>
    Task<(SessionPrincipal? Principal, long Generation)> GetAsync(Guid sessionId, Guid userId, CancellationToken ct = default);

    Task SetAsync(SessionPrincipal principal, long generation, TimeSpan ttl, CancellationToken ct = default);

    /// <summary>Makes every cached session of the user stale. Call after committing the change.</summary>
    Task InvalidateUserAsync(Guid userId, CancellationToken ct = default);
}
