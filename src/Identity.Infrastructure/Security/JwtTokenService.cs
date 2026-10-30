using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Identity.Application.Abstractions.Security;

namespace Identity.Infrastructure.Security;

public sealed class JwtOptions
{
    public const string Section = "Jwt";

    /// <summary>In production use the public base URL, so other services can discover the JWKS from it.</summary>
    public string Issuer { get; set; } = "identity";
    public string Audience { get; set; } = "identity";
    public int AccessTokenMinutes { get; set; } = 15;

    /// <summary>
    /// RSA private keys (PEM, 2048+ bits). The first one signs new tokens; all of them are published in the
    /// JWKS and accepted for validation, which is how keys are rotated without logging everyone out.
    /// </summary>
    public List<SigningKeyOptions> SigningKeys { get; set; } = [];

    /// <summary>Development only: where the auto-generated key is kept (relative to the content root).</summary>
    public string DevKeyPath { get; set; } = ".keys/dev-signing-key.pem";
}

public sealed class SigningKeyOptions
{
    public string? KeyId { get; set; }
    public string? PrivateKeyPem { get; set; }
    public string? PrivateKeyPath { get; set; }
}

/// <summary>RS256 access tokens signed with the active key from <see cref="SigningKeyProvider"/>.</summary>
public sealed class JwtTokenService(IOptions<JwtOptions> options, SigningKeyProvider keys, TimeProvider clock) : ITokenService
{
    private readonly JwtOptions _opt = options.Value;
    private readonly JsonWebTokenHandler _handler = new();
    private readonly SigningCredentials _credentials = new(keys.Active, SecurityAlgorithms.RsaSha256);

    public (string Token, DateTime ExpiresAt) CreateAccessToken(Guid userId, Guid sessionId, string email)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var expires = now.AddMinutes(_opt.AccessTokenMinutes);

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _opt.Issuer,
            Audience = _opt.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, userId.ToString()),
                new Claim(JwtRegisteredClaimNames.Sid, sessionId.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("typ", "access"),
            ]),
            SigningCredentials = _credentials,
        });

        return (token, expires);
    }

    public string GenerateRefreshToken(Guid sessionId) => $"{sessionId:N}.{GenerateOpaqueToken()}";

    public bool TryGetSessionId(string refreshToken, out Guid sessionId)
    {
        var dot = refreshToken.IndexOf('.');
        sessionId = Guid.Empty;
        return dot > 0 && Guid.TryParseExact(refreshToken.AsSpan(0, dot), "N", out sessionId);
    }

    public string GenerateOpaqueToken() => Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(48));

    public string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
