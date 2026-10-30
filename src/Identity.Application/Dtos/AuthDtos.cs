using System.ComponentModel.DataAnnotations;

namespace Identity.Application.Dtos;

public static class PasswordRules
{
    public const int MaxLength = 128;
    public const string Pattern = @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$";
    public const string Message = "Password must be 8-128 chars and contain a lowercase, an uppercase letter and a digit.";
}

// Every password field is capped: Argon2 over an unbounded input is a cheap DoS vector.

public sealed record RegisterRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, RegularExpression(PasswordRules.Pattern, ErrorMessage = PasswordRules.Message)] string Password);

public sealed record VerifyEmailRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, StringLength(6, MinimumLength = 6)] string Code,
    [Required, MaxLength(PasswordRules.MaxLength)] string Password);

public sealed record ResendVerificationRequest([Required, EmailAddress, MaxLength(254)] string Email);

public sealed record LoginRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, MaxLength(PasswordRules.MaxLength)] string Password,
    bool UseCookies = false,
    [MaxLength(64)] string? ClientId = null);

/// <summary>The refresh token goes in the body (bearer clients) or comes from the session cookie (browsers).</summary>
public sealed record RefreshRequest([MaxLength(256)] string? RefreshToken);

public sealed record ChangePasswordRequest(
    [Required, MaxLength(PasswordRules.MaxLength)] string OldPassword,
    [Required, RegularExpression(PasswordRules.Pattern, ErrorMessage = PasswordRules.Message)] string NewPassword);

public sealed record DeleteAccountRequest([Required, MaxLength(PasswordRules.MaxLength)] string Password);

public sealed record ForgotPasswordRequest([Required, EmailAddress, MaxLength(254)] string Email);

public sealed record ResetPasswordRequest(
    [Required, EmailAddress, MaxLength(254)] string Email,
    [Required, MaxLength(256)] string Token,
    [Required, RegularExpression(PasswordRules.Pattern, ErrorMessage = PasswordRules.Message)] string NewPassword);


public sealed record AuthTokensResponse(
    string AccessToken,
    string RefreshToken,
    DateTime AccessExpiresAt,
    DateTime RefreshExpiresAt);

/// <summary>
/// Login result. Without MFA it carries the tokens (same shape as <see cref="AuthTokensResponse"/>). With MFA the
/// tokens are null, <see cref="MfaRequired"/> is true and <see cref="MfaToken"/> goes to POST /auth/login/mfa.
/// </summary>
public sealed record LoginResponse(
    string? AccessToken,
    string? RefreshToken,
    DateTime? AccessExpiresAt,
    DateTime? RefreshExpiresAt,
    bool MfaRequired,
    string? MfaToken)
{
    public static LoginResponse From(AuthTokensResponse t) =>
        new(t.AccessToken, t.RefreshToken, t.AccessExpiresAt, t.RefreshExpiresAt, false, null);

    public static LoginResponse Mfa(string mfaToken) => new(null, null, null, null, true, mfaToken);
}

/// <summary>Second login step: the TOTP code from the app, or one of the recovery codes.</summary>
public sealed record MfaLoginRequest(
    [Required, MaxLength(256)] string MfaToken,
    [MaxLength(16)] string? Code,
    [MaxLength(32)] string? RecoveryCode,
    bool UseCookies = false);

public sealed record MfaStatusResponse(bool Enabled, int RecoveryCodesLeft);

/// <summary>The secret is shown once, to type it or to scan <see cref="OtpAuthUri"/> as a QR code.</summary>
public sealed record MfaSetupResponse(string Secret, string OtpAuthUri);

public sealed record MfaCodeRequest([Required, MaxLength(16)] string Code);

public sealed record MfaDisableRequest(
    [Required, MaxLength(PasswordRules.MaxLength)] string Password,
    [MaxLength(16)] string? Code,
    [MaxLength(32)] string? RecoveryCode);

/// <summary>Shown once; only their hashes are stored.</summary>
public sealed record RecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes);

public sealed record UserResponse(
    Guid Id,
    string Email,
    bool EmailVerified,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    bool MfaEnabled,
    DateTime CreatedAt);
