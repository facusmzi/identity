namespace Identity.Application.Options;

public sealed class AuthOptions
{
    public const string Section = "Auth";

    /// <summary>Sliding lifetime of a session: each refresh extends it by this much (up to the absolute limit).</summary>
    public int RefreshTokenDays { get; set; } = 30;

    /// <summary>Absolute lifetime: after this many days from login the user must log in again, refreshed or not.</summary>
    public int SessionAbsoluteDays { get; set; } = 90;

    /// <summary>Long enough for client retries and parallel requests; every second is also a window for a stolen token.</summary>
    public int RefreshGraceSeconds { get; set; } = 5;

    /// <summary>
    /// How long a validated session is served from cache (0 disables it). Revocations still apply immediately;
    /// this only bounds how stale things get if an invalidation is lost (e.g. Redis down at that moment).
    /// </summary>
    public int SessionCacheSeconds { get; set; } = 30;

    public int VerificationCodeMinutes { get; set; } = 15;
    public int VerificationResendCooldownSeconds { get; set; } = 60;

    /// <summary>
    /// Sends and wrong attempts are budgeted per window and are NOT reset by asking for a new code,
    /// so resending cannot be used to brute-force the 6-digit code.
    /// </summary>
    public int VerificationWindowMinutes { get; set; } = 60;
    public int VerificationMaxSendsPerWindow { get; set; } = 5;
    public int VerificationMaxAttempts { get; set; } = 10;

    public int PasswordResetMinutes { get; set; } = 30;
    public int PasswordResetCooldownSeconds { get; set; } = 60;

    /// <summary>Frontend page that receives ?email=..&amp;token=.. (optional; without it the email only shows the token).</summary>
    public string? PasswordResetUrl { get; set; }

    public int LoginMaxFailures { get; set; } = 10;
    public int LoginFailureWindowMinutes { get; set; } = 15;
    public int LoginLockoutMinutes { get; set; } = 15;
}
