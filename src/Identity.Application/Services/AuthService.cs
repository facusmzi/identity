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
    IEmailSender emailSender,
    TimeProvider clock,
    IOptions<AuthOptions> options,
    ILogger<AuthService> logger)
{
    private readonly AuthOptions _opt = options.Value;

    private DateTime Now => clock.GetUtcNow().UtcDateTime;

    /// <summary>
    /// Behaves the same whether or not the email is taken (same response, same Argon2 cost, emails sent in the
    /// background), so it cannot be used to find out who has an account.
    /// Re-registering an unverified account replaces its password: together with verify-email requiring the
    /// password, someone who pre-registers another person's email can never end up owning a verified account.
    /// </summary>
    public async Task RegisterAsync(RegisterRequest req, CancellationToken ct = default)
    {
        var email = NormalizeEmail(req.Email);
        var passwordHash = await passwordHasher.HashAsync(req.Password, ct);

        var existing = await users.GetByEmailAsync(email, ct);
        if (existing is not null)
        {
            // Verified: the owner can log in or reset the password; say nothing.
            if (existing.EmailVerified) return;

            if (TryIssueVerificationCode(existing) is not { } newCode) return;
            existing.PasswordHash = passwordHash;
            await uow.SaveChangesAsync(ct);
            await emailSender.SendVerificationCodeAsync(existing.Email, newCode, ct);
            return;
        }

        var defaultRole = await roles.GetByNameAsync(Role.User, ct)
            ?? throw new InvalidOperationException($"Role '{Role.User}' is not seeded");

        var user = new User { Email = email, PasswordHash = passwordHash };
        user.UserRoles.Add(new UserRole { User = user, Role = defaultRole });
        var code = TryIssueVerificationCode(user)!;

        await users.AddAsync(user, ct);
        await uow.SaveChangesAsync(ct);
        await emailSender.SendVerificationCodeAsync(user.Email, code, ct);
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
        await uow.SaveChangesAsync(ct);
    }

    /// <summary>Silently does nothing for unknown or verified emails, during the cooldown or past the hourly cap.</summary>
    public async Task ResendVerificationAsync(ResendVerificationRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        if (user is not { EmailVerified: false }) return;
        if (TryIssueVerificationCode(user) is not { } code) return;

        await uow.SaveChangesAsync(ct);
        await emailSender.SendVerificationCodeAsync(user.Email, code, ct);
    }

    public async Task<AuthTokensResponse> LoginAsync(LoginRequest req, ClientMeta meta, CancellationToken ct = default)
    {
        var email = NormalizeEmail(req.Email);
        if (await loginThrottle.GetLockoutAsync(email, ct) is { } remaining)
            throw new TooManyRequestsException("Too many failed logins, account temporarily locked", "ACCOUNT_LOCKED", remaining);

        var user = await users.GetByEmailAsync(email, ct);
        var valid = user?.PasswordHash is null
            ? await FailDummyAsync(req.Password, ct)
            : await passwordHasher.VerifyAsync(req.Password, user.PasswordHash, ct);

        if (!valid)
        {
            await loginThrottle.RegisterFailureAsync(email, ct);
            throw new UnauthorizedException("Invalid credentials", "INVALID_CREDENTIALS");
        }

        await loginThrottle.ResetAsync(email, ct);

        if (!user!.EmailVerified)
            throw new ForbiddenException("Email not verified", "EMAIL_NOT_VERIFIED");

        return await CreateSessionAsync(user, LoginMethod.Email, meta, ct);
    }

    public async Task<AuthTokensResponse> RefreshAsync(RefreshRequest req, ClientMeta meta, CancellationToken ct = default)
    {
        var presentedHash = tokens.Hash(req.RefreshToken);

        if (await graceStore.GetAsync(presentedHash, ct) is { } cached)
            return cached;

        if (!tokens.TryGetSessionId(req.RefreshToken, out var sessionId))
            throw InvalidRefreshToken();

        var session = await sessions.GetWithUserAsync(sessionId, ct);
        if (session is null || !session.IsActive(Now))
            throw InvalidRefreshToken();

        if (!FixedTimeEquals(presentedHash, session.RefreshTokenHash))
            return await HandleStaleRefreshTokenAsync(session, presentedHash, ct);

        var refreshToken = tokens.GenerateRefreshToken(session.Id);
        var refreshExpiresAt = Now.AddDays(_opt.RefreshTokenDays);

        var rotated = await sessions.TryRotateRefreshTokenAsync(
            session.Id, presentedHash, tokens.Hash(refreshToken), refreshExpiresAt,
            meta.IpAddress ?? session.IpAddress, Truncate(meta.UserAgent, 512) ?? session.UserAgent, Now, ct);

        // Lost the race against a concurrent refresh with the same token: return the winner's pair.
        if (!rotated)
            return await WaitForGraceAsync(presentedHash, ct) ?? throw InvalidRefreshToken();

        var (accessToken, accessExpiresAt) = tokens.CreateAccessToken(session.UserId, session.Id, session.User.Email);
        var result = new AuthTokensResponse(accessToken, refreshToken, accessExpiresAt, refreshExpiresAt);

        await graceStore.SetAsync(presentedHash, result, TimeSpan.FromSeconds(_opt.RefreshGraceSeconds), ct);
        return result;
    }

    public async Task LogoutAsync(Guid sessionId, CancellationToken ct = default) =>
        await sessions.RevokeAsync(sessionId, Now, ct);

    public async Task LogoutAllAsync(Guid userId, CancellationToken ct = default) =>
        await sessions.RevokeAllForUserAsync(userId, Now, ct: ct);

    public async Task ChangePasswordAsync(Guid userId, Guid currentSessionId, ChangePasswordRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByIdAsync(userId, ct) ?? throw new NotFoundException("User not found");
        if (user.PasswordHash is null) throw new BadRequestException("User has no password set");

        if (!await passwordHasher.VerifyAsync(req.OldPassword, user.PasswordHash, ct))
            throw new UnauthorizedException("Old password is incorrect", "INVALID_PASSWORD");

        user.PasswordHash = await passwordHasher.HashAsync(req.NewPassword, ct);
        ClearPasswordReset(user);

        await uow.ExecuteInTransactionAsync(async t =>
        {
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(userId, Now, exceptSessionId: currentSessionId, t);
        }, ct);
    }

    /// <summary>
    /// Always succeeds from the caller's point of view (unknown emails, deleted accounts and cooldowns
    /// are silently ignored) so the endpoint cannot be used to find out which emails are registered.
    /// </summary>
    public async Task ForgotPasswordAsync(ForgotPasswordRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        if (user is null) return;

        if (user.PasswordResetSentAt is { } sentAt
            && Now - sentAt < TimeSpan.FromSeconds(_opt.PasswordResetCooldownSeconds))
            return;

        var token = tokens.GenerateOpaqueToken();
        user.PasswordResetTokenHash = tokens.Hash(token);
        user.PasswordResetExpiresAt = Now.AddMinutes(_opt.PasswordResetMinutes);
        user.PasswordResetSentAt = Now;
        await uow.SaveChangesAsync(ct);

        await emailSender.SendPasswordResetAsync(user.Email, token, BuildResetLink(user.Email, token), ct);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest req, CancellationToken ct = default)
    {
        var user = await users.GetByEmailAsync(NormalizeEmail(req.Email), ct);
        if (user?.PasswordResetTokenHash is null || user.PasswordResetExpiresAt is null || user.PasswordResetExpiresAt < Now
            || !FixedTimeEquals(tokens.Hash(req.Token), user.PasswordResetTokenHash))
            throw new BadRequestException("Invalid or expired reset token", "INVALID_RESET_TOKEN");

        user.PasswordHash = await passwordHasher.HashAsync(req.NewPassword, ct);
        ClearPasswordReset(user);
        // Receiving the reset email proves ownership of the address. This also lets the real owner
        // take back an email that someone else registered first but never verified.
        user.EmailVerified = true;
        ClearVerificationCode(user);

        await uow.ExecuteInTransactionAsync(async t =>
        {
            await uow.SaveChangesAsync(t);
            await sessions.RevokeAllForUserAsync(user.Id, Now, ct: t);
        }, ct);
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
        var user = await users.GetByIdAsync(userId, ct) ?? throw new NotFoundException("User not found");
        if (user.PasswordHash is null || !await passwordHasher.VerifyAsync(req.Password, user.PasswordHash, ct))
            throw new UnauthorizedException("Password is incorrect", "INVALID_PASSWORD");

        await uow.ExecuteInTransactionAsync(async t =>
        {
            await sessions.RevokeAllForUserAsync(userId, Now, ct: t);
            users.Remove(user);
            await uow.SaveChangesAsync(t);
        }, ct);
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

        await sessions.RevokeAsync(session.Id, Now, ct);
        logger.LogWarning("Refresh token reuse detected for session {SessionId} of user {UserId}; session revoked",
            session.Id, session.UserId);
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

    private async Task<AuthTokensResponse> CreateSessionAsync(User user, LoginMethod method, ClientMeta meta, CancellationToken ct)
    {
        var session = new Session
        {
            UserId = user.Id,
            LoginMethod = method,
            IpAddress = meta.IpAddress,
            UserAgent = Truncate(meta.UserAgent, 512),
            ExpiresAt = Now.AddDays(_opt.RefreshTokenDays),
        };
        var refreshToken = tokens.GenerateRefreshToken(session.Id);
        session.RefreshTokenHash = tokens.Hash(refreshToken);

        await sessions.AddAsync(session, ct);
        await uow.SaveChangesAsync(ct);

        var (accessToken, accessExpiresAt) = tokens.CreateAccessToken(user.Id, session.Id, user.Email);
        return new AuthTokensResponse(accessToken, refreshToken, accessExpiresAt, session.ExpiresAt);
    }

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

    private static UnauthorizedException InvalidRefreshToken() =>
        new("Invalid or expired refresh token", "INVALID_REFRESH_TOKEN");

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];
}
