using Npgsql;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Identity.Application.Services;

namespace Identity.Api.Extensions;

public static class TelemetryExtensions
{
    /// <summary>
    /// Metrics and traces over OTLP to any OpenTelemetry collector (Grafana, Prometheus via the collector, Jaeger,
    /// Datadog...). Enabled only when an endpoint is configured (Telemetry:OtlpEndpoint or the standard
    /// OTEL_EXPORTER_OTLP_ENDPOINT); otherwise nothing is collected.
    /// <list type="bullet">
    /// <item>Metrics: the "Identity" meter (logins, MFA, refreshes, lockouts, breach checks, introspections, Argon2
    /// duration, outbox backlog) plus HTTP server/client and .NET runtime.</item>
    /// <item>Traces: incoming requests (health checks excluded), outgoing HTTP (HIBP, webhooks) and Postgres.</item>
    /// </list>
    /// </summary>
    public static IServiceCollection AddIdentityTelemetry(this IServiceCollection services, IConfiguration config)
    {
        var endpoint = config["Telemetry:OtlpEndpoint"] ?? config["OTEL_EXPORTER_OTLP_ENDPOINT"];
        if (string.IsNullOrWhiteSpace(endpoint)) return services;

        services.AddOpenTelemetry()
            .ConfigureResource(r => r.AddService(config["Telemetry:ServiceName"] ?? "identity"))
            .WithMetrics(m => m
                .AddMeter(IdentityMetrics.MeterName)
                .AddAspNetCoreInstrumentation()
                .AddHttpClientInstrumentation()
                .AddRuntimeInstrumentation()
                .AddOtlpExporter(o => o.Endpoint = new Uri(endpoint)))
            .WithTracing(t => t
                .AddAspNetCoreInstrumentation(o => o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/health"))
                .AddHttpClientInstrumentation()
                .AddNpgsql()
                .AddOtlpExporter(o => o.Endpoint = new Uri(endpoint)));
        return services;
    }
}
