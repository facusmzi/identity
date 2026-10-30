namespace Identity.Application.Abstractions.Security;

public interface ITokenService
{
    (string Token, DateTime ExpiresAt) CreateAccessToken(Guid userId, Guid sessionId, string email);

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
