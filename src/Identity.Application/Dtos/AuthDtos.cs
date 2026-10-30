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
    [Required, MaxLength(PasswordRules.MaxLength)] string Password);

public sealed record RefreshRequest([Required, MaxLength(256)] string RefreshToken);

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

public sealed record UserResponse(
    Guid Id,
    string Email,
    bool EmailVerified,
    IReadOnlyList<string> Roles,
    DateTime CreatedAt);
