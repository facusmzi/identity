using Identity.Domain.Common;
using Identity.Domain.Enums;

namespace Identity.Domain.Entities;

public class Session : BaseEntity
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;

    public string RefreshTokenHash { get; set; } = "";

    /// <summary>Hash of the token replaced by the last rotation; lets concurrent refreshes be told apart from reuse.</summary>
    public string? PreviousRefreshTokenHash { get; set; }
    public DateTime? RefreshRotatedAt { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public LoginMethod LoginMethod { get; set; } = LoginMethod.Email;

    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }

    public bool IsActive(DateTime now) => RevokedAt is null && ExpiresAt > now;
}
