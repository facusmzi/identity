namespace Identity.Application.Options;

public sealed class MfaOptions
{
    public const string Section = "Mfa";

    /// <summary>Name shown in the authenticator app.</summary>
    public string Issuer { get; set; } = "Identity";
    public int RecoveryCodes { get; set; } = 10;
    public int ChallengeMinutes { get; set; } = 5;

    /// <summary>Wrong codes allowed per login challenge; failures also count towards the account lockout.</summary>
    public int ChallengeMaxAttempts { get; set; } = 5;
}

public sealed class BreachCheckOptions
{
    public const string Section = "Hibp";

    public bool Enabled { get; set; } = true;

    /// <summary>When the breach service is down: true accepts the password (audited), false rejects it.</summary>
    public bool FailOpen { get; set; } = true;
}
