namespace Identity.Domain.Entities;

/// <summary>
/// The intermediate "password OK, second factor pending" step of a login. Short-lived, single-use and with a
/// small attempt budget. Not a BaseEntity: it is ephemeral and purged physically by the retention job.
/// </summary>
public class MfaChallenge
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid UserId { get; set; }

    /// <summary>SHA-256 of the opaque token handed to the client.</summary>
    public required string TokenHash { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
    public int FailedAttempts { get; set; }

    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? ClientId { get; set; }
}
