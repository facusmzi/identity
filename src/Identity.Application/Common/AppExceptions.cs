namespace Identity.Application.Common;

/// <summary>Base for expected business errors; the API maps each subtype to an HTTP status.</summary>
public abstract class AppException(string message, string? code = null) : Exception(message)
{
    public string? Code { get; } = code;
}

public sealed class BadRequestException(string message, string? code = null) : AppException(message, code);
public sealed class UnauthorizedException(string message, string? code = null) : AppException(message, code);
public sealed class ForbiddenException(string message, string? code = null) : AppException(message, code);
public sealed class NotFoundException(string message, string? code = null) : AppException(message, code);
public sealed class ConflictException(string message, string? code = null) : AppException(message, code);

/// <summary>429: the caller must wait <see cref="RetryAfter"/> before trying again.</summary>
public sealed class TooManyRequestsException(string message, string? code = null, TimeSpan? retryAfter = null)
    : AppException(message, code)
{
    public TimeSpan? RetryAfter { get; } = retryAfter;
}

/// <summary>503: the server is temporarily saturated (e.g. too many password hashes in flight).</summary>
public sealed class ServiceUnavailableException(string message, string? code = null, TimeSpan? retryAfter = null)
    : AppException(message, code)
{
    public TimeSpan? RetryAfter { get; } = retryAfter;
}
