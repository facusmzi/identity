using Identity.Domain.Entities;

namespace Identity.Application.Abstractions.Persistence;

/// <summary>
/// MFA state that must hold under concurrency (several requests, several instances): every "use once" rule is a
/// single conditional UPDATE, never a read-then-write.
/// </summary>
public interface IMfaRepository
{
    void AddChallenge(MfaChallenge challenge);

    /// <summary>Not consumed, not expired. Attempt budget is checked by the caller.</summary>
    Task<MfaChallenge?> GetActiveChallengeAsync(string tokenHash, DateTime now, CancellationToken ct = default);

    /// <returns>False if another request consumed it first.</returns>
    Task<bool> TryConsumeChallengeAsync(Guid challengeId, DateTime now, CancellationToken ct = default);

    Task RegisterChallengeFailureAsync(Guid challengeId, CancellationToken ct = default);

    /// <summary>Accepts a TOTP time step only if it is newer than the last one used by this user (anti-replay).</summary>
    Task<bool> TryAdvanceTimeStepAsync(Guid userId, long timeStep, CancellationToken ct = default);

    /// <returns>False if the code does not exist, was already used or was replaced.</returns>
    Task<bool> TryUseRecoveryCodeAsync(Guid userId, string codeHash, DateTime now, CancellationToken ct = default);

    Task<int> CountUnusedRecoveryCodesAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Logically deletes the current codes and stages the new ones (saved with the next SaveChanges).</summary>
    Task ReplaceRecoveryCodesAsync(Guid userId, IEnumerable<string> codeHashes, DateTime now, CancellationToken ct = default);

    Task<int> PurgeChallengesAsync(DateTime before, CancellationToken ct = default);
}
