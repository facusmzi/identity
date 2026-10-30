using Scalar.AspNetCore;
using Identity.Api.Extensions;
using Identity.Application;
using Identity.Application.Abstractions;
using Identity.Infrastructure;
using Identity.Infrastructure.Persistence;
using Identity.Infrastructure.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.ValidateSecurityConfiguration(builder.Environment);
builder.Logging.AddStructuredLogging(builder.Environment);

builder.Services
    .AddApplication(builder.Configuration)
    .AddInfrastructure(builder.Configuration)
    .AddJwtAuthentication()
    .AddAuthRateLimiting(builder.Configuration)
    .AddTrustedProxies(builder.Configuration)
    .AddFrontendCors(builder.Configuration)
    .AddIdentityHealthChecks()
    .AddIdentityTelemetry(builder.Configuration);

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IRequestContext, HttpRequestContext>();
builder.Services.AddControllers(o => o.Filters.Add<CsrfFilter>());
builder.Services.AddResponseCaching();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<AppExceptionHandler>();
builder.Services.AddOpenApi();
builder.Services.AddStrictTransportSecurity();

var app = builder.Build();

// Load the keys now: a missing or unreadable key must stop the startup, not fail every request later.
app.Services.GetRequiredService<SigningKeyProvider>();
app.Services.GetRequiredService<Identity.Application.Abstractions.Security.ISecretProtector>();
// Start connecting to Redis now, so shared limits and the session cache are live by the first request.
app.Services.GetRequiredService<StackExchange.Redis.IConnectionMultiplexer>();
await DbInitializer.InitializeAsync(app.Services);

// `dotnet Identity.Api.dll seed-admin <email>` (password from IDENTITY_ADMIN_PASSWORD or stdin): creates or
// promotes an admin without leaving the password in any configuration file. Runs and exits.
if (args is ["seed-admin", ..])
    return await AdminCommand.SeedAdminAsync(app.Services, args);

// Must run first so the rate limiter, sessions and the audit log see the real client address.
if (builder.Configuration.HasTrustedProxies())
    app.UseForwardedHeaders();

app.UseExceptionHandler();
app.UseSecurityHeaders(app.Environment);
if (!app.Environment.IsDevelopment())
    app.UseHsts();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi().AllowAnonymous();
    app.MapScalarApiReference().AllowAnonymous();
}

app.UseCors(OperationsExtensions.CorsPolicy);
app.UseResponseCaching();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapIdentityHealthChecks();

app.Run();
return 0;

public partial class Program;
