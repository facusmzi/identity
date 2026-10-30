using Scalar.AspNetCore;
using Identity.Api.Extensions;
using Identity.Application;
using Identity.Infrastructure;
using Identity.Infrastructure.Persistence;

var builder = WebApplication.CreateBuilder(args);

builder.Configuration.ValidateSecurityConfiguration(builder.Environment);

builder.Services
    .AddApplication(builder.Configuration)
    .AddInfrastructure(builder.Configuration)
    .AddJwtAuthentication(builder.Configuration)
    .AddAuthRateLimiting(builder.Configuration)
    .AddTrustedProxies(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<AppExceptionHandler>();
builder.Services.AddOpenApi();

var app = builder.Build();

await DbInitializer.InitializeAsync(app.Services);

// Must run first so the rate limiter and the stored session IP see the real client address.
if (builder.Configuration.HasTrustedProxies())
    app.UseForwardedHeaders();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program;
