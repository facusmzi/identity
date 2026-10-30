namespace Identity.Application.Dtos;

public sealed record SessionResponse(
    Guid Id,
    string? IpAddress,
    string? UserAgent,
    string LoginMethod,
    DateTime ExpiresAt,
    DateTime CreatedAt,
    bool Current);
