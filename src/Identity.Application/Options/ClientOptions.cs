namespace Identity.Application.Options;

/// <summary>
/// An application that uses this service (the store's web app, a mobile app, an admin panel...).
/// Configured, not stored: clients change with deployments, not at runtime.
/// </summary>
public sealed class ClientOptions
{
    /// <summary>Sent by the app at login (<c>clientId</c>); stored with the session so refreshes keep it.</summary>
    public string Id { get; set; } = "";

    /// <summary>The <c>aud</c> of its access tokens: what that app's backend validates.</summary>
    public string Audience { get; set; } = "";

    /// <summary>Only for confidential clients (backends): enables token introspection. 32+ random chars.</summary>
    public string? Secret { get; set; }

    /// <summary>Optional: where account events (user deleted/locked/...) are POSTed, signed with WebhookSecret.</summary>
    public string? WebhookUrl { get; set; }
    public string? WebhookSecret { get; set; }
}

public sealed class ClientsOptions
{
    public const string Section = "Clients";

    public List<ClientOptions> Clients { get; set; } = [];
}
