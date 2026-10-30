using Identity.Application.Dtos;

namespace Identity.Application.Abstractions.Security;

/// <summary>
/// Short-lived cache of the token pair issued when a refresh token was rotated, so that
/// concurrent refreshes with the same (now old) token get the same new pair instead of a 401.
/// </summary>
public interface IRefreshGraceStore
{
    Task<AuthTokensResponse?> GetAsync(string oldRefreshTokenHash, CancellationToken ct = default);
    Task SetAsync(string oldRefreshTokenHash, AuthTokensResponse tokens, TimeSpan ttl, CancellationToken ct = default);
}
