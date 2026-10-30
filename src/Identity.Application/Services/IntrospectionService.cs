using Identity.Application.Abstractions.Security;
using Identity.Application.Common;

namespace Identity.Application.Services;

/// <summary>RFC 7662-style answer. Inactive tokens get only <c>active: false</c>, never a reason.</summary>
public sealed record IntrospectionResponse(
    bool Active,
    string? Sub = null,
    string? Sid = null,
    string? Aud = null,
    long? Exp = null,
    IReadOnlyList<string>? Roles = null,
    IReadOnlyList<string>? Permissions = null,
    IReadOnlyList<string>? Amr = null)
{
    public static readonly IntrospectionResponse Inactive = new(false);
}

/// <summary>
/// Lets a backend (e.g. the store's checkout) ask "is this access token still good right now?". Validating the JWT
/// locally cannot see a logout or a lock that happened after it was issued; this checks the live session.
/// Roles and permissions in the answer are the current ones, not the ones frozen in the token.
/// </summary>
public sealed class IntrospectionService(ClientRegistry clients, ITokenService tokens, SessionService sessions, IdentityMetrics metrics)
{
    public async Task<IntrospectionResponse> IntrospectAsync(string clientId, string clientSecret, string token, CancellationToken ct = default)
    {
        var client = clients.Authenticate(clientId, clientSecret)
            ?? throw new UnauthorizedException("Invalid client credentials", "INVALID_CLIENT");

        var claims = await tokens.ReadAccessTokenAsync(token);
        // A client only gets answers about tokens issued for it.
        if (claims is null || claims.Audience != client.Audience) return Inactive();

        var session = await sessions.ValidateAsync(claims.SessionId, claims.UserId, ct);
        if (session is null) return Inactive();
        metrics.Introspection(active: true);

        return new IntrospectionResponse(true, claims.UserId.ToString(), claims.SessionId.ToString(), claims.Audience,
            new DateTimeOffset(claims.ExpiresAt, TimeSpan.Zero).ToUnixTimeSeconds(), session.Roles, session.Permissions, claims.AuthenticationMethods);
    }

    private IntrospectionResponse Inactive()
    {
        metrics.Introspection(active: false);
        return IntrospectionResponse.Inactive;
    }
}
