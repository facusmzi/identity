namespace Identity.Application.Abstractions.Security;

/// <summary>
/// Counts failed logins per account (not per IP), shared across API instances, so a password cannot be
/// brute-forced from many IPs. Unknown emails are counted too, so the lockout does not reveal which exist.
/// </summary>
public interface ILoginThrottle
{
    /// <summary>Remaining lockout time, or null if the account may try to log in.</summary>
    Task<TimeSpan?> GetLockoutAsync(string email, CancellationToken ct = default);

    Task RegisterFailureAsync(string email, CancellationToken ct = default);

    Task ResetAsync(string email, CancellationToken ct = default);
}
