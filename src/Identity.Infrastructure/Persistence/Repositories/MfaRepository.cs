using Microsoft.EntityFrameworkCore;
using Identity.Application.Abstractions.Persistence;
using Identity.Domain.Entities;

namespace Identity.Infrastructure.Persistence.Repositories;

/// <summary>Every "only once" rule is one conditional UPDATE, safe with concurrent requests and instances.</summary>
public sealed class MfaRepository(AppDbContext db) : IMfaRepository
{
    public void AddChallenge(MfaChallenge challenge) => db.MfaChallenges.Add(challenge);

    public Task<MfaChallenge?> GetActiveChallengeAsync(string tokenHash, DateTime now, CancellationToken ct = default) =>
        db.MfaChallenges.AsNoTracking()
            .FirstOrDefaultAsync(c => c.TokenHash == tokenHash && c.ConsumedAt == null && c.ExpiresAt > now, ct);

    public async Task<bool> TryConsumeChallengeAsync(Guid challengeId, DateTime now, CancellationToken ct = default) =>
        await db.MfaChallenges
            .Where(c => c.Id == challengeId && c.ConsumedAt == null && c.ExpiresAt > now)
            .ExecuteUpdateAsync(u => u.SetProperty(c => c.ConsumedAt, now), ct) == 1;

    public Task RegisterChallengeFailureAsync(Guid challengeId, CancellationToken ct = default) =>
        db.MfaChallenges.Where(c => c.Id == challengeId)
            .ExecuteUpdateAsync(u => u.SetProperty(c => c.FailedAttempts, c => c.FailedAttempts + 1), ct);

    public async Task<bool> TryAdvanceTimeStepAsync(Guid userId, long timeStep, CancellationToken ct = default) =>
        await db.Users
            .Where(u => u.Id == userId && (u.MfaLastUsedTimeStep == null || u.MfaLastUsedTimeStep < timeStep))
            .ExecuteUpdateAsync(u => u.SetProperty(x => x.MfaLastUsedTimeStep, timeStep), ct) == 1;

    public async Task<bool> TryUseRecoveryCodeAsync(Guid userId, string codeHash, DateTime now, CancellationToken ct = default) =>
        await db.MfaRecoveryCodes
            .Where(c => c.UserId == userId && c.CodeHash == codeHash && c.UsedAt == null)
            .ExecuteUpdateAsync(u => u.SetProperty(c => c.UsedAt, now).SetProperty(c => c.UpdatedAt, now), ct) == 1;

    public Task<int> CountUnusedRecoveryCodesAsync(Guid userId, CancellationToken ct = default) =>
        db.MfaRecoveryCodes.CountAsync(c => c.UserId == userId && c.UsedAt == null, ct);

    public async Task ReplaceRecoveryCodesAsync(Guid userId, IEnumerable<string> codeHashes, DateTime now, CancellationToken ct = default)
    {
        // Logical delete of the old set (a soft delete, not ExecuteDelete): the history stays.
        await db.MfaRecoveryCodes.Where(c => c.UserId == userId)
            .ExecuteUpdateAsync(u => u.SetProperty(c => c.DeletedAt, now).SetProperty(c => c.UpdatedAt, now), ct);
        foreach (var hash in codeHashes)
            db.MfaRecoveryCodes.Add(new MfaRecoveryCode { UserId = userId, CodeHash = hash });
    }

    // Retention purge (sanctioned hard delete): challenges are worthless minutes after creation.
    public Task<int> PurgeChallengesAsync(DateTime before, CancellationToken ct = default) =>
        db.MfaChallenges.Where(c => c.ExpiresAt < before).ExecuteDeleteAsync(ct);
}
