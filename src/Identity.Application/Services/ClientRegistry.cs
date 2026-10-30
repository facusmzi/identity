using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Identity.Application.Common;
using Identity.Application.Options;

namespace Identity.Application.Services;

/// <summary>The configured clients (section <c>Clients</c>, a list).</summary>
public sealed class ClientRegistry
{
    private readonly Dictionary<string, ClientOptions> _byId;

    public ClientRegistry(IConfiguration config)
    {
        var clients = config.GetSection(ClientsOptions.Section).Get<List<ClientOptions>>() ?? [];
        foreach (var c in clients)
        {
            if (string.IsNullOrWhiteSpace(c.Id) || string.IsNullOrWhiteSpace(c.Audience))
                throw new InvalidOperationException("Every entry in Clients needs an Id and an Audience.");
            if (!string.IsNullOrEmpty(c.WebhookUrl) && string.IsNullOrEmpty(c.WebhookSecret))
                throw new InvalidOperationException($"Client '{c.Id}' has a WebhookUrl but no WebhookSecret to sign the calls.");
        }
        if (clients.GroupBy(c => c.Id).FirstOrDefault(g => g.Count() > 1) is { } dup)
            throw new InvalidOperationException($"Client '{dup.Key}' is configured twice.");

        _byId = clients.ToDictionary(c => c.Id, StringComparer.Ordinal);
    }

    public IReadOnlyCollection<ClientOptions> All => _byId.Values;

    public IReadOnlyList<string> Audiences => _byId.Values.Select(c => c.Audience).Where(a => a.Length > 0).Distinct().ToList();

    /// <summary>Null id = no client (default audience). Unknown id = 400, so typos are caught at login.</summary>
    public ClientOptions? Resolve(string? clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId)) return null;
        return _byId.GetValueOrDefault(clientId) ?? throw new BadRequestException($"Unknown client '{clientId}'", "UNKNOWN_CLIENT");
    }

    public ClientOptions? Find(string? clientId) =>
        clientId is null ? null : _byId.GetValueOrDefault(clientId);

    /// <summary>Confidential clients only; constant-time secret comparison.</summary>
    public ClientOptions? Authenticate(string clientId, string secret)
    {
        if (Find(clientId) is not { Secret: { Length: > 0 } expected } client) return null;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(secret)) ? client : null;
    }
}
