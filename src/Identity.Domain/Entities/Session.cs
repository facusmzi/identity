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

    /// <summary>Sliding expiry: every refresh pushes it forward, but never past <see cref="AbsoluteExpiresAt"/>.</summary>
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Hard limit set at login. However often the session is refreshed, after this the user must log in again,
    /// so a stolen refresh token cannot be kept alive forever.
    /// </summary>
    public DateTime AbsoluteExpiresAt { get; set; }

    public DateTime? RevokedAt { get; set; }
    public RevocationReason? RevokedReason { get; set; }

    public bool IsActive(DateTime now) => RevokedAt is null && ExpiresAt > now && AbsoluteExpiresAt > now;

    public static DateTime SlidingExpiry(DateTime now, TimeSpan sliding, DateTime absoluteExpiresAt) =>
        now + sliding < absoluteExpiresAt ? now + sliding : absoluteExpiresAt;
}
