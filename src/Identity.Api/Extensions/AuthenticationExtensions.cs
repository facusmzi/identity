using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Identity.Application.Services;
using Identity.Infrastructure.Security;

namespace Identity.Api.Extensions;

public static class AuthenticationExtensions
{
    public const string RoleClaim = "role";

    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();

        // Configured from DI so it uses the same keys that sign the tokens (and that the JWKS publishes).
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<SigningKeyProvider, IOptions<JwtOptions>>((options, keys, jwtOptions) =>
            {
                var jwt = jwtOptions.Value;
                options.MapInboundClaims = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = jwt.Issuer,
                    ValidAudience = jwt.Audience,
                    IssuerSigningKeys = keys.Keys,
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = JwtRegisteredClaimNames.Sub,
                    RoleClaimType = RoleClaim,
                };
                options.Events = new JwtBearerEvents { OnTokenValidated = ValidateSessionAsync };
            });

        services.AddAuthorization();
        return services;
    }

    /// <summary>
    /// A valid signature is not enough: the session must not be revoked/expired and the user
    /// must not be (logically) deleted. Roles are loaded from the DB so changes apply immediately.
    /// </summary>
    private static async Task ValidateSessionAsync(TokenValidatedContext context)
    {
        var principal = context.Principal!;
        if (principal.FindFirstValue("typ") != "access"
            || !Guid.TryParse(principal.FindFirstValue(JwtRegisteredClaimNames.Sub), out var userId)
            || !Guid.TryParse(principal.FindFirstValue(JwtRegisteredClaimNames.Sid), out var sessionId))
        {
            context.Fail("Invalid token claims");
            return;
        }

        var sessions = context.HttpContext.RequestServices.GetRequiredService<SessionService>();
        var session = await sessions.ValidateAsync(sessionId, userId, context.HttpContext.RequestAborted);
        if (session is null)
        {
            context.Fail("Session expired or revoked");
            return;
        }

        var identity = (ClaimsIdentity)principal.Identity!;
        foreach (var role in session.Roles) identity.AddClaim(new Claim(RoleClaim, role));
    }

    public static Guid GetUserId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(JwtRegisteredClaimNames.Sub)!);

    public static Guid GetSessionId(this ClaimsPrincipal user) =>
        Guid.Parse(user.FindFirstValue(JwtRegisteredClaimNames.Sid)!);
}
