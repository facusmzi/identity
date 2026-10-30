using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Identity.Application.Abstractions.Security;
using Identity.Application.Services;

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

public static class AccessClaims
{
    public const string Role = "role";
    public const string Permission = "perm";
}

public sealed class SigningKeyOptions
{
    public string? KeyId { get; set; }
    public string? PrivateKeyPem { get; set; }
    public string? PrivateKeyPath { get; set; }
}

/// <summary>RS256 access tokens signed with the active key from <see cref="SigningKeyProvider"/>.</summary>
public sealed class JwtTokenService(IOptions<JwtOptions> options, SigningKeyProvider keys, ClientRegistry clients, TimeProvider clock) : ITokenService
{
    private readonly JwtOptions _opt = options.Value;
    private readonly JsonWebTokenHandler _handler = new();
    private readonly SigningCredentials _credentials = new(keys.Active, SecurityAlgorithms.RsaSha256);

    /// <summary>
    /// Claims: sub, sid, email, email_verified, jti, typ, plus <c>role</c>, <c>perm</c> and <c>amr</c> (arrays) so other
    /// services can authorize on their own. They reflect the moment of issue (stale for at most AccessTokenMinutes).
    /// </summary>
    public (string Token, DateTime ExpiresAt) CreateAccessToken(AccessTokenRequest request)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var expires = now.AddMinutes(_opt.AccessTokenMinutes);

        List<Claim> claims =
        [
            new(JwtRegisteredClaimNames.Sub, request.UserId.ToString()),
            new(JwtRegisteredClaimNames.Sid, request.SessionId.ToString()),
            new(JwtRegisteredClaimNames.Email, request.Email),
            new("email_verified", "true", ClaimValueTypes.Boolean),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("typ", "access"),
        ];
        claims.AddRange(request.Roles.Select(r => new Claim(AccessClaims.Role, r)));
        claims.AddRange(request.Permissions.Select(p => new Claim(AccessClaims.Permission, p)));
        claims.AddRange(request.AuthenticationMethods.Select(m => new Claim(JwtRegisteredClaimNames.Amr, m)));

        var token = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _opt.Issuer,
            Audience = request.Audience ?? _opt.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expires,
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = _credentials,
        });

        return (token, expires);
    }

    public async Task<AccessTokenClaims?> ReadAccessTokenAsync(string token)
    {
        var result = await _handler.ValidateTokenAsync(token, ValidationParameters());
        if (!result.IsValid || result.ClaimsIdentity.FindFirst("typ")?.Value != "access") return null;

        var identity = result.ClaimsIdentity;
        if (!Guid.TryParse(identity.FindFirst(JwtRegisteredClaimNames.Sub)?.Value, out var userId)
            || !Guid.TryParse(identity.FindFirst(JwtRegisteredClaimNames.Sid)?.Value, out var sessionId)
            || result.SecurityToken is not JsonWebToken jwt)
            return null;

        return new AccessTokenClaims(userId, sessionId, jwt.Audiences.FirstOrDefault() ?? "", jwt.ValidTo,
            identity.FindAll(JwtRegisteredClaimNames.Amr).Select(c => c.Value).ToList());
    }

    /// <summary>Same rules the API's JwtBearer applies: our keys, our issuer, RS256 only, any known audience.</summary>
    public TokenValidationParameters ValidationParameters() => new()
    {
        ValidIssuer = _opt.Issuer,
        ValidAudiences = [_opt.Audience, .. clients.Audiences],
        IssuerSigningKeys = keys.Keys,
        ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        ClockSkew = TimeSpan.FromSeconds(30),
        NameClaimType = JwtRegisteredClaimNames.Sub,
        RoleClaimType = AccessClaims.Role,
        LifetimeValidator = (notBefore, expires, _, p) =>
        {
            var now = clock.GetUtcNow().UtcDateTime;
            return (notBefore is null || notBefore <= now + p.ClockSkew) && expires is not null && expires > now - p.ClockSkew;
        },
    };

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
