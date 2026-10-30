using System.Diagnostics.Metrics;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;
using Identity.Application.Services;
using Identity.Infrastructure.Messaging;
using Identity.Infrastructure.Persistence;

namespace Identity.Tests;

public sealed class MetricsTests(IdentityFactory factory) : IClassFixture<IdentityFactory>
{
    private static string NewEmail() => $"metrics-{Guid.NewGuid():N}@test.local";

    private MetricCollector<T> Collect<T>(string instrument) where T : struct =>
        new(factory.Services.GetRequiredService<IMeterFactory>(), IdentityMetrics.MeterName, instrument);

    private static long Count(MetricCollector<long> collector, string tag, object value) =>
        collector.GetMeasurementSnapshot().Where(m => Equals(m.Tags[tag], value)).Sum(m => m.Value);

    [Fact]
    public async Task Login_outcomes_are_counted_by_result()
    {
        var email = NewEmail();
        await factory.CreateVerifiedUserAsync(email);
        using var logins = Collect<long>("identity.logins");
        var client = factory.CreateClient();

        await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" });
        await client.PostAsJsonAsync("/auth/login", new { email, password = "Wrong123x" });
        await client.PostAsJsonAsync("/auth/login", new { email, password = "Passw0rd!" });

        Assert.Equal(2, Count(logins, "result", "invalid_credentials"));
        Assert.Equal(1, Count(logins, "result", "success"));
    }

    [Fact]
    public async Task Breach_checks_registrations_and_hash_timing_are_recorded()
    {
        using var breaches = Collect<long>("identity.password.breach_checks");
        using var registrations = Collect<long>("identity.registrations");
        using var hashing = Collect<double>("identity.password_hash.duration");
        var client = factory.CreateClient();

        await client.PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "Password123" }); // breached
        await client.PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "Passw0rd!" });

        Assert.Equal(1, Count(breaches, "result", "breached"));
        Assert.Equal(1, Count(breaches, "result", "not_breached"));
        Assert.Equal(1, Count(registrations, "outcome", "created"));
        Assert.NotEmpty(hashing.GetMeasurementSnapshot());
        Assert.All(hashing.GetMeasurementSnapshot(), m => Assert.True(m.Value > 0));
    }

    [Fact]
    public async Task The_outbox_backlog_gauge_reflects_pending_messages()
    {
        using var pending = Collect<long>("identity.outbox.pending");
        await factory.CreateClient().PostAsJsonAsync("/auth/register", new { email = NewEmail(), password = "Passw0rd!" });

        await using (var scope = factory.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<OutboxBacklog>().RefreshAsync(scope.ServiceProvider.GetRequiredService<AppDbContext>(), default);
        pending.RecordObservableInstruments();
        Assert.True(pending.GetMeasurementSnapshot().Last(m => Equals(m.Tags["kind"], "email")).Value >= 1);

        await factory.DispatchEmailsAsync();
        await using (var scope = factory.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<OutboxBacklog>().RefreshAsync(scope.ServiceProvider.GetRequiredService<AppDbContext>(), default);
        pending.RecordObservableInstruments();
        Assert.Equal(0, pending.GetMeasurementSnapshot().Last(m => Equals(m.Tags["kind"], "email")).Value);
    }
}
