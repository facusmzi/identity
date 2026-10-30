using System.Security.Cryptography;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Application.Security;
using Identity.Domain.Entities;

namespace Identity.Application.Services;

/// <summary>Verifies TOTP codes and recovery codes, enforcing "each code works once" atomically in the database.</summary>
public sealed class SecondFactor(IMfaRepository mfa, ISecretProtector protector, ITokenService tokens, TimeProvider clock)
{
    private const string RecoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"; // no 0/o/1/l/i

    public static string SecretAssociatedData(Guid userId) => $"mfa-secret:{userId:N}";

    public byte[] NewSecret() => RandomNumberGenerator.GetBytes(Totp.SecretBytes);

    public string Protect(Guid userId, byte[] secret) => protector.Protect(secret, SecretAssociatedData(userId));

    public byte[]? Unprotect(Guid userId, string? protectedSecret) =>
        protectedSecret is null ? null : protector.Unprotect(protectedSecret, SecretAssociatedData(userId));

    /// <summary>
    /// True if the code is valid for the secret AND its time step was never used by this user. A code intercepted
    /// in transit therefore cannot be replayed, even while it is still inside its 30 s window.
    /// </summary>
    public async Task<bool> VerifyTotpAsync(Guid userId, string? protectedSecret, string? code, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(code) || Unprotect(userId, protectedSecret) is not { } secret) return false;
        return Totp.Verify(secret, code, clock.GetUtcNow()) is { } step
               && await mfa.TryAdvanceTimeStepAsync(userId, step, ct);
    }

    public async Task<bool> UseRecoveryCodeAsync(Guid userId, string? code, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;
        return await mfa.TryUseRecoveryCodeAsync(userId, HashRecoveryCode(code), clock.GetUtcNow().UtcDateTime, ct);
    }

    /// <summary>Generates new codes and stages them (replacing the old ones); returns them in clear, once.</summary>
    public async Task<IReadOnlyList<string>> ReplaceRecoveryCodesAsync(Guid userId, int count, CancellationToken ct = default)
    {
        var codes = Enumerable.Range(0, count).Select(_ => NewRecoveryCode()).ToList();
        await mfa.ReplaceRecoveryCodesAsync(userId, codes.Select(HashRecoveryCode), clock.GetUtcNow().UtcDateTime, ct);
        return codes;
    }

    private string HashRecoveryCode(string code) =>
        tokens.Hash(code.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).Trim().ToLowerInvariant());

    // 10 chars from a 31-symbol alphabet ≈ 49 bits, shown as xxxxx-xxxxx.
    private static string NewRecoveryCode()
    {
        var chars = Enumerable.Range(0, 10).Select(_ => RecoveryAlphabet[RandomNumberGenerator.GetInt32(RecoveryAlphabet.Length)]).ToArray();
        return $"{new string(chars, 0, 5)}-{new string(chars, 5, 5)}";
    }
}
