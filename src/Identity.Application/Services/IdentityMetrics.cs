using System.Diagnostics.Metrics;

namespace Identity.Application.Services;

/// <summary>
/// Business metrics (meter "Identity"), plain System.Diagnostics.Metrics so this layer does not depend on any
/// telemetry SDK; the API exports them with OpenTelemetry. Tags are low-cardinality results, never emails or ids.
/// </summary>
public sealed class IdentityMetrics
{
    public const string MeterName = "Identity";

    private readonly Counter<long> _logins;
    private readonly Counter<long> _mfa;
    private readonly Counter<long> _refreshes;
    private readonly Counter<long> _registrations;
    private readonly Counter<long> _lockouts;
    private readonly Counter<long> _breachChecks;
    private readonly Counter<long> _introspections;

    public IdentityMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName);
        _logins = meter.CreateCounter<long>("identity.logins", description: "Password login attempts by result");
        _mfa = meter.CreateCounter<long>("identity.mfa.verifications", description: "Second-factor checks at login by result");
        _refreshes = meter.CreateCounter<long>("identity.token.refreshes", description: "Refresh attempts by result");
        _registrations = meter.CreateCounter<long>("identity.registrations", description: "Registration requests by outcome");
        _lockouts = meter.CreateCounter<long>("identity.account.lockouts", description: "Accounts locked by too many failures");
        _breachChecks = meter.CreateCounter<long>("identity.password.breach_checks", description: "HIBP checks by result");
        _introspections = meter.CreateCounter<long>("identity.introspections", description: "Introspection answers by activity");
    }

    /// <param name="result">success | mfa_required | invalid_credentials | locked | disabled | unverified</param>
    public void Login(string result) => _logins.Add(1, new KeyValuePair<string, object?>("result", result));

    /// <param name="result">totp | recovery_code | failure</param>
    public void Mfa(string result) => _mfa.Add(1, new KeyValuePair<string, object?>("result", result));

    /// <param name="result">success | grace | invalid | reused</param>
    public void Refresh(string result) => _refreshes.Add(1, new KeyValuePair<string, object?>("result", result));

    /// <param name="outcome">created | existing | rejected_password</param>
    public void Registration(string outcome) => _registrations.Add(1, new KeyValuePair<string, object?>("outcome", outcome));

    public void Lockout() => _lockouts.Add(1);

    /// <param name="result">not_breached | breached | unavailable</param>
    public void BreachCheck(string result) => _breachChecks.Add(1, new KeyValuePair<string, object?>("result", result));

    public void Introspection(bool active) => _introspections.Add(1, new KeyValuePair<string, object?>("active", active));
}
