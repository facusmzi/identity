using Identity.Domain.Common;

namespace Identity.Domain.Entities;

public class User : BaseEntity
{
    public required string Email { get; set; }
    public string? PasswordHash { get; set; }

    public bool EmailVerified { get; set; }
    public string? EmailVerificationCodeHash { get; set; }
    public DateTime? EmailVerificationExpiresAt { get; set; }
    public DateTime? EmailVerificationSentAt { get; set; }
    public int EmailVerificationAttempts { get; set; }
    public DateTime? EmailVerificationWindowStartedAt { get; set; }
    public int EmailVerificationSendsInWindow { get; set; }

    public string? PasswordResetTokenHash { get; set; }
    public DateTime? PasswordResetExpiresAt { get; set; }
    public DateTime? PasswordResetSentAt { get; set; }

    public ICollection<Session> Sessions { get; set; } = [];
    public ICollection<UserRole> UserRoles { get; set; } = [];
}
