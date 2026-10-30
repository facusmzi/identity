using Identity.Domain.Common;

namespace Identity.Domain.Entities;

/// <summary>Single-use backup code. Only its SHA-256 is stored; the user sees the code once.</summary>
public class MfaRecoveryCode : BaseEntity
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    public required string CodeHash { get; set; }
    public DateTime? UsedAt { get; set; }
}
