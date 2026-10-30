using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Messaging;
using Identity.Application.Abstractions.Persistence;
using Identity.Application.Abstractions.Security;
using Identity.Application.Common;
using Identity.Application.Dtos;
using Identity.Application.Options;
using Identity.Domain.Entities;
using Identity.Domain.Enums;

namespace Identity.Application.Services;

public sealed class AuthService(
    IUserRepository users,
    ISessionRepository sessions,
    IRoleRepository roles,
    IUnitOfWork uow,
    IPasswordHasher passwordHasher,
    ITokenService tokens,
    IRefreshGraceStore graceStore,
    ILoginThrottle loginThrottle,
    ISessionCache sessionCache,
    IEmailOutbox outbox,
    IAccountEvents events,
    IMfaRepository mfa,
    SecondFactor secondFactor,
    PasswordPolicy passwordPolicy,
    ClientRegistry clients,
    IdentityMetrics metrics,
    AuditTrail audit,
    TimeProvider clock,
    IOptions<AuthOptions> options,
    IOptions<MfaOptions> mfaOptions,
    ILogger<AuthService> logger)
{
    private readonly AuthOptions _opt = options.Value;
    private readonly MfaOptions _mfaOpt = mfaOptions.Value;

    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Behaves the same whether or not the email is taken (same response, same Argon2 cost, emails delivered
    /// in the background), so it cannot be used to find out who has an account.
    /// Re-registering an unverified account replaces its password: together with verify-email requiring the
    /// password, someone who pre-registers another person's email can never end up owning a verified account.
    /// </summary>
    public async Task RegisterAsync(RegisterRequest req, CancellationToken ct = default)
    {
        var email = NormalizeEmail(req.Email);
        // Before the lookup: a rejected (e.g. breached) password gets the same answer for any email.
        await passwordPolicy.EnsureAcceptableAsync(req.Password, email, userId: null, ct);
        var passwordHash = await passwordHasher.HashAsync(req.Password, ct);

        var existing = await users.GetByEmailAsync(email, ct);
        if (existing is not null)
        {
            metrics.Registration("existing");
            // Verified: the owner can log in or reset the password; say nothing (only persist audit entries).
            if (existing.EmailVerified)
            {
                await uow.SaveChangesAsync(ct);
                return;
            }

            if (TryIssueVerificationCode(existing) is not { } newCode) return;
            existing.PasswordHash = passwordHash;
            outbox.EnqueueVerificationCode(existing.Email, newCode);
            await uow.SaveChangesAsync(ct);
            return;
        }

        var defaultRole = await roles.GetByNameAsync(Role.User, ct)
            ?? throw new InvalidOperationException($"Role '{Role.User}' is not seeded");

        var user = new User { Email = email, PasswordHash = passwordHash };
        user.UserRoles.Add(new UserRole { User = user, Role = defaultRole });
        var code = TryIssueVerificationCode(user)!;

        await users.AddAsync(user, ct);
        outbox.EnqueueVerificationCode(user.Email, code);
        try
        {
            await uow.SaveChangesAsync(ct);
            metrics.Registration("created");
        }
        catch (UniqueConstraintViolationException)
        {
            // A concurrent request registered the same email between our read and our insert.
            // Its registration wins; answer like any other "email already registered" case.
            metrics.Registration("existing");
        }
    }

    /// <summary>
    /// Needs the code (proves the email) and the password (proves who registered). Every failure gives the same
    /// answer and Argon2 always runs, so unknown, verified and pending accounts look alike.
    /// </summary>
    public async Task VerifyEmailAsync(VerifyEmailRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        var pending = user is { EmailVerified: false } ? user : null;

        if (pending is not null)
        {
            EnsureVerificationWindow(pending);
            if (pending.EmailVerificationAttempts >= _opt.VerificationMaxAttempts)
                throw new TooManyRequestsException("Too many failed attempts, try again later", "TOO_MANY_ATTEMPTS", VerificationWindowRemaining(pending));
        }

        var passwordOk = pending?.PasswordHash is { } hash
            ? await passwordHasher.VerifyAsync(req.Password, hash, ct)
            : await FailDummyAsync(req.Password, ct);

        var codeOk = pending is { EmailVerificationCodeHash: { } codeHash, EmailVerificationExpiresAt: { } expiresAt }
            && expiresAt >= Now
            && FixedTimeEquals(tokens.Hash(req.Code), codeHash);

        if (pending is null || !passwordOk || !codeOk)
        {
            if (pending is not null)
            {
                pending.EmailVerificationAttempts++;
                await uow.SaveChangesAsync(ct);
            }
            throw new BadRequestException("Invalid email, code or password", "INVALID_VERIFICATION");
        }

        pending.EmailVerified = true;
        ClearVerificationCode(pending);
        audit.Record(AuditActions.EmailVerified, pending.Id, pending.Id);
        await uow.SaveChangesAsync(ct);
    }

    /// <summary>Silently does nothing for unknown or verified emails, during the cooldown or past the hourly cap.</summary>
    public async Task ResendVerificationAsync(ResendVerificationRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        if (user is not { EmailVerified: false }) return;
        if (TryIssueVerificationCode(user) is not { } code) return;

        outbox.EnqueueVerificationCode(user.Email, code);
        await uow.SaveChangesAsync(ct);
    }

    /// <summary>
    /// First (or only) login step. With MFA enabled a correct password does not give tokens: it gives a short-lived,
    /// single-use challenge for POST /auth/login/mfa.
    /// </summary>
    public async Task<LoginResponse> LoginAsync(LoginRequest req, ClientMeta meta, CancellationToken ct = default)
    {
        var client = clients.Resolve(req.ClientId); // unknown client: 400 before touching the account
        var email = NormalizeEmail(req.Email);
        if (await loginThrottle.GetLockoutAsync(email, ct) is { } remaining)
        {
            metrics.Login("locked");
            throw new TooManyRequestsException("Too many failed logins, account temporarily locked", "ACCOUNT_LOCKED", remaining);
        }

        var user = await users.GetByEmailAsync(email, ct);
        var valid = user?.PasswordHash is null
            ? await FailDummyAsync(req.Password, ct)
            : await passwordHasher.VerifyAsync(req.Password, user.PasswordHash, ct);

        if (!valid)
        {
            var locked = await loginThrottle.RegisterFailureAsync(email, ct);
            audit.Record(AuditActions.LoginFailed, null, user?.Id);
            if (locked) audit.Record(AuditActions.AccountLocked, null, user?.Id);
            if (locked) metrics.Lockout();
            metrics.Login("invalid_credentials");
            await uow.SaveChangesAsync(ct);
            throw new UnauthorizedException("Invalid credentials", "INVALID_CREDENTIALS");
        }

        await loginThrottle.ResetAsync(email, ct);

        // Only revealed to someone who knows the password, so it does not help enumerate accounts.
        if (user!.LockedAt is not null)
        {
            metrics.Login("disabled");
            throw new ForbiddenException("This account has been disabled. Contact support.", "ACCOUNT_DISABLED");
        }

        if (!user.EmailVerified)
        {
            metrics.Login("unverified");
            throw new ForbiddenException("Email not verified", "EMAIL_NOT_VERIFIED");
        }

        // Hashes made with weaker parameters are upgraded transparently the next time the password is known.
        if (passwordHasher.NeedsRehash(user.PasswordHash!))
            user.PasswordHash = await passwordHasher.HashAsync(req.Password, ct);

        if (user.MfaEnabled)
        {
            var mfaToken = tokens.GenerateOpaqueToken();
            mfa.AddChallenge(new MfaChallenge
            {
                UserId = user.Id,
                TokenHash = tokens.Hash(mfaToken),
                CreatedAt = Now,
                ExpiresAt = Now.AddMinutes(_mfaOpt.ChallengeMinutes),
                IpAddress = meta.IpAddress,
                UserAgent = Truncate(meta.UserAgent, 512),
                ClientId = client?.Id,
            });
            await uow.SaveChangesAsync(ct);
            metrics.Login("mfa_required");
            return LoginResponse.Mfa(mfaToken);
        }

        audit.Record(AuditActions.LoginSucceeded, user.Id, user.Id);
        metrics.Login("success");
        return LoginResponse.From(await CreateSessionAsync(user, LoginMethod.Email, meta, client?.Id, ct));
    }

    /// <summary>
    /// Second login step. The challenge survives a typo (it is consumed only by a correct code) but has its own
    /// attempt budget, and every failure also counts towards the account lockout shared with the password step.
    /// </summary>
    public async Task<AuthTokensResponse> LoginWithMfaAsync(MfaLoginRequest req, ClientMeta meta, CancellationToken ct = default)
    {
        var challenge = await mfa.GetActiveChallengeAsync(tokens.Hash(req.MfaToken), Now, ct);
        if (challenge is null || challenge.FailedAttempts >= _mfaOpt.ChallengeMaxAttempts) throw MfaInvalid();

        var user = await users.GetByIdAsync(challenge.UserId, ct);
        if (user is not { MfaEnabled: true, EmailVerified: true, LockedAt: null }) throw MfaInvalid();

        if (await loginThrottle.GetLockoutAsync(user.Email, ct) is { } remaining)
            throw new TooManyRequestsException("Too many failed attempts, account temporarily locked", "ACCOUNT_LOCKED", remaining);

        var usedTotp = await secondFactor.VerifyTotpAsync(user.Id, user.MfaSecretEncrypted, req.Code, ct);
        var usedRecovery = !usedTotp && await secondFactor.UseRecoveryCodeAsync(user.Id, req.RecoveryCode, ct);

        if (!usedTotp && !usedRecovery)
        {
            await mfa.RegisterChallengeFailureAsync(challenge.Id, ct);
            var locked = await loginThrottle.RegisterFailureAsync(user.Email, ct);
            audit.Record(AuditActions.MfaFailed, null, user.Id, new { operation = "login" });
            if (locked) audit.Record(AuditActions.AccountLocked, null, user.Id);
            if (locked) metrics.Lockout();
            metrics.Mfa("failure");
            await uow.SaveChangesAsync(ct);
            throw MfaInvalid();
        }

        if (!await mfa.TryConsumeChallengeAsync(challenge.Id, Now, ct)) throw MfaInvalid();
        await loginThrottle.ResetAsync(user.Email, ct);

        audit.Record(AuditActions.LoginSucceeded, user.Id, user.Id, new { mfa = usedTotp ? "totp" : "recovery_code" });
        metrics.Mfa(usedTotp ? "totp" : "recovery_code");
        if (usedRecovery)
        {
            audit.Record(AuditActions.MfaRecoveryCodeUsed, user.Id, user.Id);
            outbox.EnqueueSecurityNotice(user.Email, "A recovery code was used",
                "One of your two-factor recovery codes was just used to sign in. If this wasn't you, reset your password now.");
        }
        return await CreateSessionAsync(user, LoginMethod.EmailMfa, meta, challenge.ClientId, ct);
    }

    public async Task<AuthTokensResponse> RefreshAsync(RefreshRequest req, ClientMeta meta, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(req.RefreshToken)) throw InvalidRefreshToken();
        var presentedHash = tokens.Hash(req.RefreshToken);

        if (await graceStore.GetAsync(presentedHash, ct) is { } cached)
        {
            metrics.Refresh("grace");
            return cached;
        }

        if (!tokens.TryGetSessionId(req.RefreshToken, out var sessionId))
            throw InvalidRefreshToken();

        var session = await sessions.GetWithUserAsync(sessionId, ct);
        if (session is null || !session.IsActive(Now) || session.User.LockedAt is not null)
            throw InvalidRefreshToken();

        if (!FixedTimeEquals(presentedHash, session.RefreshTokenHash))
            return await HandleStaleRefreshTokenAsync(session, presentedHash, ct);

        var refreshToken = tokens.GenerateRefreshToken(session.Id);
        var refreshExpiresAt = Session.SlidingExpiry(Now, TimeSpan.FromDays(_opt.RefreshTokenDays), session.AbsoluteExpiresAt);

        var rotated = await sessions.TryRotateRefreshTokenAsync(
            session.Id, presentedHash, tokens.Hash(refreshToken), refreshExpiresAt,
            meta.IpAddress ?? session.IpAddress, Truncate(meta.UserAgent, 512) ?? session.UserAgent, Now, ct);

        // Lost the race against a concurrent refresh with the same token: return the winner's pair.
        if (!rotated)
            return await WaitForGraceAsync(presentedHash, ct) ?? throw InvalidRefreshToken();

        var (accessToken, accessExpiresAt) = await CreateAccessTokenAsync(session.UserId, session.Id, session.User.Email, session.LoginMethod, session.ClientId, ct);
        var result = new AuthTokensResponse(accessToken, refreshToken, accessExpiresAt, refreshExpiresAt);

        await graceStore.SetAsync(presentedHash, result, TimeSpan.FromSeconds(_opt.RefreshGraceSeconds), ct);
        metrics.Refresh("success");
        return result;
    }

    // Every path that revokes sessions or changes what a cached session holds calls
    // sessionCache.InvalidateUserAsync right after committing (see ISessionCache).

    public async Task LogoutAsync(Guid userId, Guid sessionId, CancellationToken ct = default)
    {
        await sessions.RevokeAsync(sessionId, Now, RevocationReason.Logout, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
    }

    public async Task LogoutAllAsync(Guid userId, CancellationToken ct = default)
    {
        await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.LogoutAll, ct: ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
    }

    public async Task ChangePasswordAsync(Guid userId, Guid currentSessionId, ChangePasswordRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByIdAsync(userId, ct) ?? throw new NotFoundException("User not found");
        if (user.PasswordHash is null) throw new BadRequestException("User has no password set");

        if (!await passwordHasher.VerifyAsync(req.OldPassword, user.PasswordHash, ct))
            throw new UnauthorizedException("Old password is incorrect", "INVALID_PASSWORD");

        await passwordPolicy.EnsureAcceptableAsync(req.NewPassword, user.Email, userId, ct);
        user.PasswordHash = await passwordHasher.HashAsync(req.NewPassword, ct);
        ClearPasswordReset(user);
        audit.Record(AuditActions.PasswordChanged, userId, userId);

        await uow.ExecuteInTransactionAsync(async t =>
        {
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.PasswordChanged, currentSessionId, t);
        }, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
    }

    /// <summary>
    /// Always succeeds from the caller's point of view (unknown emails, deleted accounts and cooldowns
    /// are silently ignored) so the endpoint cannot be used to find out which emails are registered.
    /// </summary>
    public async Task ForgotPasswordAsync(ForgotPasswordRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        if (user is null || user.LockedAt is not null) return; // locked accounts are only unlocked by an admin

        if (user.PasswordResetSentAt is { } sentAt
            && Now - sentAt < TimeSpan.FromSeconds(_opt.PasswordResetCooldownSeconds))
            return;

        var token = tokens.GenerateOpaqueToken();
        user.PasswordResetTokenHash = tokens.Hash(token);
        user.PasswordResetExpiresAt = Now.AddMinutes(_opt.PasswordResetMinutes);
        user.PasswordResetSentAt = Now;
        outbox.EnqueuePasswordReset(user.Email, token, BuildResetLink(user.Email, token));
        await uow.SaveChangesAsync(ct);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        if (user?.PasswordResetTokenHash is null || user.PasswordResetExpiresAt is null || user.PasswordResetExpiresAt < Now
            || user.LockedAt is not null || !FixedTimeEquals(tokens.Hash(req.Token), user.PasswordResetTokenHash))
            throw new BadRequestException("Invalid or expired reset token", "INVALID_RESET_TOKEN");

        await passwordPolicy.EnsureAcceptableAsync(req.NewPassword, user.Email, user.Id, ct);
        user.PasswordHash = await passwordHasher.HashAsync(req.NewPassword, ct);
        ClearPasswordReset(user);
        // Receiving the reset email proves ownership of the address. This also lets the real owner
        // take back an email that someone else registered first but never verified.
        user.EmailVerified = true;
        ClearVerificationCode(user);
        audit.Record(AuditActions.PasswordReset, user.Id, user.Id);

        await uow.ExecuteInTransactionAsync(async t =>
        {
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(user.Id, Now, RevocationReason.PasswordReset, ct: t);
        }, ct);
        await sessionCache.InvalidateUserAsync(user.Id, ct);
        await loginThrottle.ResetAsync(user.Email, ct);
    }

    public async Task<UserResponse> GetMeAsync(Guid userId, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        return user.ToResponse();
    }

    /// <summary>Logical delete of the caller's own account.</summary>
    public async Task DeleteAccountAsync(Guid userId, DeleteAccountRequest req, CancellationToken ct = default)
    {
        var user = await users.GetWithRolesAsync(userId, ct: ct) ?? throw new NotFoundException("User not found");
        if (user.PasswordHash is null || !await passwordHasher.VerifyAsync(req.Password, user.PasswordHash, ct))
            throw new UnauthorizedException("Password is incorrect", "INVALID_PASSWORD");

        if (user.RoleNames().Contains(Role.Admin) && !await users.AnyOtherInRoleAsync(Role.Admin, userId, ct))
            throw new BadRequestException("You are the last admin; promote someone else first", "LAST_ADMIN");

        audit.Record(AuditActions.AccountDeleted, userId, userId);
        events.Publish(AccountEventTypes.UserDeleted, userId);
        await uow.ExecuteInTransactionAsync(async t =>
        {
            await sessions.RevokeAllForUserAsync(userId, Now, RevocationReason.AccountDeleted, ct: t);
            users.Remove(user);
            await uow.SaveChangesAsync(t);
        }, ct);
        await sessionCache.InvalidateUserAsync(userId, ct);
    }

    /// <summary>
    /// The token belongs to the session but is not its current one. Right after a rotation that is a
    /// concurrent refresh (wait for the winner's pair); otherwise an old token is being replayed, which
    /// means it leaked: revoke the whole session so neither the thief nor the victim keeps it.
    /// </summary>
    private async Task<AuthTokensResponse> HandleStaleRefreshTokenAsync(Session session, string presentedHash, CancellationToken ct)
    {
        var isPrevious = session.PreviousRefreshTokenHash is { } previous && FixedTimeEquals(presentedHash, previous);
        var justRotated = session.RefreshRotatedAt is { } rotatedAt
            && Now - rotatedAt < TimeSpan.FromSeconds(_opt.RefreshGraceSeconds);

        if (isPrevious && justRotated)
            return await WaitForGraceAsync(presentedHash, ct) ?? throw InvalidRefreshToken();

        audit.Record(AuditActions.RefreshTokenReused, null, session.UserId, new { sessionId = session.Id });
        await uow.ExecuteInTransactionAsync(async t =>
        {
            await sessions.RevokeAsync(session.Id, Now, RevocationReason.RefreshTokenReused, t);
            await uow.SaveChangesAsync(t);
        }, ct);
        await sessionCache.InvalidateUserAsync(session.UserId, ct);
        logger.LogWarning("Refresh token reuse detected for session {SessionId} of user {UserId}; session revoked",
            session.Id, session.UserId);
        metrics.Refresh("reused");
        throw new UnauthorizedException("Refresh token reuse detected, session revoked", "REFRESH_TOKEN_REUSED");
    }

    /// <summary>The winner of a refresh race publishes its pair right after rotating; give it a moment.</summary>
    private async Task<AuthTokensResponse?> WaitForGraceAsync(string presentedHash, CancellationToken ct)
    {
        for (var i = 0; i < 10; i++)
        {
            if (await graceStore.GetAsync(presentedHash, ct) is { } cached) return cached;
            await Task.Delay(TimeSpan.FromMilliseconds(100), clock, ct);
        }
        return null;
    }

    private async Task<AuthTokensResponse> CreateSessionAsync(
        User user, LoginMethod method, ClientMeta meta, string? clientId, CancellationToken ct)
    {
        var absolute = Now.AddDays(Math.Max(_opt.SessionAbsoluteDays, 1));
        var session = new Session
        {
            UserId = user.Id,
            LoginMethod = method,
            ClientId = clientId,
            IpAddress = meta.IpAddress,
            UserAgent = Truncate(meta.UserAgent, 512),
            AbsoluteExpiresAt = absolute,
            ExpiresAt = Session.SlidingExpiry(Now, TimeSpan.FromDays(_opt.RefreshTokenDays), absolute),
        };
        var refreshToken = tokens.GenerateRefreshToken(session.Id);
        session.RefreshTokenHash = tokens.Hash(refreshToken);

        await sessions.AddAsync(session, ct);
        await uow.SaveChangesAsync(ct);

        var (accessToken, accessExpiresAt) = await CreateAccessTokenAsync(user.Id, session.Id, user.Email, method, clientId, ct);
        return new AuthTokensResponse(accessToken, refreshToken, accessExpiresAt, session.ExpiresAt);
    }

    private async Task<(string Token, DateTime ExpiresAt)> CreateAccessTokenAsync(
        Guid userId, Guid sessionId, string email, LoginMethod method, string? clientId, CancellationToken ct)
    {
        var access = await users.GetAccessAsync(userId, ct);
        string[] amr = method == LoginMethod.EmailMfa ? ["pwd", "mfa"] : ["pwd"];
        return tokens.CreateAccessToken(new AccessTokenRequest(
            userId, sessionId, email, access.Roles, access.Permissions, amr, clients.Find(clientId)?.Audience));
    }

    private static UnauthorizedException MfaInvalid() => new("The verification code is invalid or the login expired", "MFA_INVALID");

    private async Task<bool> FailDummyAsync(string password, CancellationToken ct)
    {
        await passwordHasher.VerifyDummyAsync(password, ct);
        return false;
    }

    /// <summary>New code, or null while the resend cooldown is active or the hourly send cap is reached.</summary>
    private string? TryIssueVerificationCode(User user)
    {
        EnsureVerificationWindow(user);
        var inCooldown = user.EmailVerificationSentAt is { } sentAt
            && Now - sentAt < TimeSpan.FromSeconds(_opt.VerificationResendCooldownSeconds);
        if (inCooldown || user.EmailVerificationSendsInWindow >= _opt.VerificationMaxSendsPerWindow)
            return null;

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        user.EmailVerificationCodeHash = tokens.Hash(code);
        user.EmailVerificationExpiresAt = Now.AddMinutes(_opt.VerificationCodeMinutes);
        user.EmailVerificationSentAt = Now;
        user.EmailVerificationSendsInWindow++;
        return code;
    }

    /// <summary>Starts a new budget of sends and attempts once the previous window is over.</summary>
    private void EnsureVerificationWindow(User user)
    {
        if (user.EmailVerificationWindowStartedAt is { } start && Now - start < TimeSpan.FromMinutes(_opt.VerificationWindowMinutes))
            return;

        user.EmailVerificationWindowStartedAt = Now;
        user.EmailVerificationSendsInWindow = 0;
        user.EmailVerificationAttempts = 0;
    }

    private TimeSpan VerificationWindowRemaining(User user) =>
        user.EmailVerificationWindowStartedAt!.Value.AddMinutes(_opt.VerificationWindowMinutes) - Now;

    private static void ClearVerificationCode(User user)
    {
        user.EmailVerificationCodeHash = null;
        user.EmailVerificationExpiresAt = null;
        user.EmailVerificationAttempts = 0;
    }

    private static void ClearPasswordReset(User user)
    {
        user.PasswordResetTokenHash = null;
        user.PasswordResetExpiresAt = null;
    }

    private string? BuildResetLink(string email, string token)
    {
        if (string.IsNullOrWhiteSpace(_opt.PasswordResetUrl)) return null;
        var separator = _opt.PasswordResetUrl.Contains('?') ? '&' : '?';
        return $"{_opt.PasswordResetUrl}{separator}email={Uri.EscapeDataString(email)}&token={Uri.EscapeDataString(token)}";
    }

    private UnauthorizedException InvalidRefreshToken()
    {
        metrics.Refresh("invalid");
        return new("Invalid or expired refresh token", "INVALID_REFRESH_TOKEN");
    }

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
