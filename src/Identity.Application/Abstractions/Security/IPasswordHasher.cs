namespace Identity.Application.Abstractions.Security;

/// <summary>
/// Hashing is memory-hard on purpose, so implementations cap how many run at once and throw
/// <see cref="Common.ServiceUnavailableException"/> when the queue is full instead of exhausting RAM.
/// </summary>
public interface IPasswordHasher
{
    Task<string> HashAsync(string password, CancellationToken ct = default);
    Task<bool> VerifyAsync(string password, string hash, CancellationToken ct = default);

    /// <summary>Burns the same CPU time as a real verify, to avoid user enumeration by timing.</summary>
    Task VerifyDummyAsync(string password, CancellationToken ct = default);
}
