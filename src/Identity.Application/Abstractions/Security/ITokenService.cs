namespace Identity.Application.Abstractions.Security;

/// <summary>
/// What goes into an access token. Roles and permissions are included for OTHER services (they cannot ask
/// this one on every request); this service itself always re-reads them, so here they are never stale.
/// </summary>
public sealed record AccessTokenRequest(
    Guid UserId,
    Guid SessionId,
    string Email,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Permissions,
    IReadOnlyList<string> AuthenticationMethods,
    string? Audience = null);

/// <summary>What a valid access token says (signature, issuer, lifetime and audience already checked).</summary>
public sealed record AccessTokenClaims(Guid UserId, Guid SessionId, string Audience, DateTime ExpiresAt, IReadOnlyList<string> AuthenticationMethods);

public interface ITokenService
{
    (string Token, DateTime ExpiresAt) CreateAccessToken(AccessTokenRequest request);

    /// <summary>Null when the token is not one of ours or is expired/tampered (any configured audience is accepted).</summary>
    Task<AccessTokenClaims?> ReadAccessTokenAsync(string token);

    /// <summary>
    /// Opaque refresh token "{sessionId}.{random}". Carrying the session id lets a reused (already rotated)
    /// token be traced back to its session so the whole session can be revoked.
    /// </summary>
    string GenerateRefreshToken(Guid sessionId);

    bool TryGetSessionId(string refreshToken, out Guid sessionId);

    /// <summary>Cryptographically random URL-safe token (e.g. for password reset links).</summary>
    string GenerateOpaqueToken();

    /// <summary>SHA-256 hex digest; only the hash of refresh tokens and codes is stored.</summary>
    string Hash(string value);
}
