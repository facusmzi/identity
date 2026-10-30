using Microsoft.Extensions.Options;
using Identity.Domain.Enums;
using Identity.Application.Abstractions.Messaging;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Application.Options;
using Identity.Application.Security;
using Identity.Domain.Entities;

namespace Identity.Application.Services;

/// <summary>
/// Account-side MFA management. Enabling or disabling revokes the user's other sessions (whoever had them did
/// not prove the new state) and sends a notice email. Wrong codes count towards the account lockout, so a stolen
/// session cannot be used to brute-force them.
/// </summary>
public sealed class MfaService(
    IUserRepository users,
    IMfaRepository mfa,
    ISessionRepository sessions,
    ISessionCache sessionCache,
    IUnitOfWork uow,
    IPasswordHasher passwordHasher,
    ILoginThrottle loginThrottle,
    IEmailOutbox outbox,
    SecondFactor secondFactor,
    AuditTrail audit,
    TimeProvider clock,
    IOptions<MfaOptions> options)
{
    private readonly MfaOptions _opt = options.Value;

    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    public async Task<MfaStatusResponse> GetStatusAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await GetUserAsync(userId, ct);
        return new MfaStatusResponse(user.MfaEnabled, user.MfaEnabled ? await mfa.CountUnusedRecoveryCodesAsync(userId, ct) : 0);
    }

    /// <summary>Generates a new secret, kept pending until a valid code proves the app has it.</summary>
    public async Task<MfaSetupResponse> SetupAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await GetUserAsync(userId, ct);
        if (user.MfaEnabled)
            throw new ConflictException("Two-factor authentication is already enabled; disable it first", "MFA_ALREADY_ENABLED");

        var secret = secondFactor.NewSecret();
        user.MfaPendingSecretEncrypted = secondFactor.Protect(userId, secret);
        await uow.SaveChangesAsync(ct);

        var formatted = string.Join(' ', Base32.Encode(secret).Chunk(4).Select(c => new string(c)));
        return new MfaSetupResponse(formatted, Totp.OtpAuthUri(_opt.Issuer, user.Email, secret));
    }

    public async Task<RecoveryCodesResponse> EnableAsync(Guid userId, Guid currentSessionId, MfaCodeRequest req, CancellationToken ct = default)
    {
        var user = await GetUserAsync(userId, ct);
        if (user.MfaEnabled) throw new ConflictException("Two-factor authentication is already enabled", "MFA_ALREADY_ENABLED");
        if (user.MfaPendingSecretEncrypted is null)
            throw new BadRequestException("Call the setup endpoint before enabling two-factor authentication", "MFA_NOT_SET_UP");

        await EnsureNotLockedAsync(user, ct);
        if (!await secondFactor.VerifyTotpAsync(userId, user.MfaPendingSecretEncrypted, req.Code, ct))
            await FailAsync(user, "enable", ct);

        user.MfaSecretEncrypted = user.MfaPendingSecretEncrypted;
        user.MfaPendingSecretEncrypted = null;
        user.MfaEnabled = true;

        IReadOnlyList<string> codes = [];
        await uow.ExecuteInTransactionAsync(async t =>
        {
            codes = await secondFactor.ReplaceRecoveryCodesAsync(userId, _opt.RecoveryCodes, t);
            audit.Record(AuditActions.MfaEnabled, userId, userId);
            outbox.EnqueueSecurityNotice(user.Email, "Two-factor authentication enabled",
                "Two-factor authentication was turned on for your account. If this wasn't you, reset your password now.");
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.MfaChanged, currentSessionId, t);
        }, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
        return new RecoveryCodesResponse(codes);
    }

    /// <summary>Needs the password and a second factor (TOTP or a recovery code, for a lost phone).</summary>
    public async Task DisableAsync(Guid userId, Guid currentSessionId, MfaDisableRequest req, CancellationToken ct = default)
    {
        var user = await GetUserAsync(userId, ct);
        if (!user.MfaEnabled) throw new ConflictException("Two-factor authentication is not enabled", "MFA_NOT_ENABLED");

        await EnsureNotLockedAsync(user, ct);
        if (user.PasswordHash is null || !await passwordHasher.VerifyAsync(req.Password, user.PasswordHash, ct))
        {
            await loginThrottle.RegisterFailureAsync(user.Email, ct);
            throw new BadRequestException("The password is incorrect", "INVALID_PASSWORD");
        }

        var ok = await secondFactor.VerifyTotpAsync(userId, user.MfaSecretEncrypted, req.Code, ct)
                 || await secondFactor.UseRecoveryCodeAsync(userId, req.RecoveryCode, ct);
        if (!ok) await FailAsync(user, "disable", ct);

        user.MfaEnabled = false;
        user.MfaSecretEncrypted = null;
        user.MfaPendingSecretEncrypted = null;

        await uow.ExecuteInTransactionAsync(async t =>
        {
            await mfa.ReplaceRecoveryCodesAsync(userId, [], Now, t);
            audit.Record(AuditActions.MfaDisabled, userId, userId);
            outbox.EnqueueSecurityNotice(user.Email, "Two-factor authentication disabled",
                "Two-factor authentication was turned off for your account. If this wasn't you, reset your password now.");
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.MfaChanged, currentSessionId, t);
        }, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
    }

    public async Task<RecoveryCodesResponse> RegenerateRecoveryCodesAsync(Guid userId, MfaCodeRequest req, CancellationToken ct = default)
    {
        var user = await GetUserAsync(userId, ct);
        if (!user.MfaEnabled) throw new ConflictException("Two-factor authentication is not enabled", "MFA_NOT_ENABLED");

        await EnsureNotLockedAsync(user, ct);
        if (!await secondFactor.VerifyTotpAsync(userId, user.MfaSecretEncrypted, req.Code, ct))
            await FailAsync(user, "regenerate", ct);

        IReadOnlyList<string> codes = [];
        await uow.ExecuteInTransactionAsync(async t =>
        {
            codes = await secondFactor.ReplaceRecoveryCodesAsync(userId, _opt.RecoveryCodes, t);
            audit.Record(AuditActions.MfaRecoveryCodesRegenerated, userId, userId);
            await uow.SaveChangesAsync(t);
        }, ct);
        return new RecoveryCodesResponse(codes);
    }

    private async Task<User> GetUserAsync(Guid userId, CancellationToken ct) =>
        await users.GetByIdAsync(userId, ct) ?? throw new NotFoundException("User not found");

    private async Task EnsureNotLockedAsync(User user, CancellationToken ct)
    {
        if (await loginThrottle.GetLockoutAsync(user.Email, ct) is { } remaining)
            throw new TooManyRequestsException("Too many failed attempts, try again later", "ACCOUNT_LOCKED", remaining);
    }

    private async Task FailAsync(User user, string operation, CancellationToken ct)
    {
        await loginThrottle.RegisterFailureAsync(user.Email, ct);
        audit.Record(AuditActions.MfaFailed, user.Id, user.Id, new { operation });
        await uow.SaveChangesAsync(ct);
        throw new BadRequestException("The verification code is invalid", "MFA_INVALID");
    }
}
