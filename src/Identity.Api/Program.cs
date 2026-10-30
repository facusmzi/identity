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
    .AddIdentityHealthChecks();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IRequestContext, HttpRequestContext>();
builder.Services.AddControllers();
builder.Services.AddResponseCaching();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<AppExceptionHandler>();
builder.Services.AddOpenApi();

var app = builder.Build();

// Load the keys now: a missing or unreadable key must stop the startup, not fail every request later.
app.Services.GetRequiredService<SigningKeyProvider>();
app.Services.GetRequiredService<Identity.Application.Abstractions.Security.ISecretProtector>();
await DbInitializer.InitializeAsync(app.Services);

// Must run first so the rate limiter, sessions and the audit log see the real client address.
if (builder.Configuration.HasTrustedProxies())
    app.UseForwardedHeaders();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseCors(OperationsExtensions.CorsPolicy);
app.UseResponseCaching();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapIdentityHealthChecks();

app.Run();

public partial class Program;
