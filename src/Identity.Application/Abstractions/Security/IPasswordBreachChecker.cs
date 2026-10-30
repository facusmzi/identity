namespace Identity.Application.Abstractions.Security;

public enum BreachCheckStatus
{
    NotBreached,
    Breached,

    /// <summary>The breach service could not be reached; the policy decides (fail-open or fail-closed).</summary>
    Unavailable,
}

/// <summary>Checks a password against known data breaches without revealing it (k-anonymity).</summary>
public interface IPasswordBreachChecker
{
    Task<BreachCheckStatus> CheckAsync(string password, CancellationToken ct = default);
}
