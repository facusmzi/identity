using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Identity.Application.Abstractions.Security;

namespace Identity.Infrastructure.Security;

public sealed class HibpClientOptions
{
    public const string Section = "Hibp";

    public string BaseUrl { get; set; } = "https://api.pwnedpasswords.com/";
    public int TimeoutSeconds { get; set; } = 3;

    /// <summary>How many appearances in breaches make a password unacceptable.</summary>
    public int MinBreachCount { get; set; } = 1;
}

/// <summary>
/// Pwned Passwords range API. Only the first 5 hex chars of the SHA-1 leave the server (k-anonymity), and padding
/// is requested so the response size does not leak anything either.
/// </summary>
public sealed class HibpPasswordBreachChecker(HttpClient http, IOptions<HibpClientOptions> options, ILogger<HibpPasswordBreachChecker> logger)
    : IPasswordBreachChecker
{
    public async Task<BreachCheckStatus> CheckAsync(string password, CancellationToken ct = default)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var prefix = hash[..5];
        var suffix = hash[5..];

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"range/{prefix}");
            request.Headers.Add("Add-Padding", "true");
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("HIBP returned status {StatusCode}", (int)response.StatusCode);
                return BreachCheckStatus.Unavailable;
            }

            var body = await response.Content.ReadAsStringAsync(ct);
            return IsBreached(body, suffix, options.Value.MinBreachCount) ? BreachCheckStatus.Breached : BreachCheckStatus.NotBreached;
        }
        catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or TaskCanceledException or TimeoutException
                                       or Polly.Timeout.TimeoutRejectedException or Polly.CircuitBreaker.BrokenCircuitException)
        {
            logger.LogWarning("HIBP request failed: {ExceptionType}", ex.GetType().Name);
            return BreachCheckStatus.Unavailable;
        }
    }

    public static bool IsBreached(string body, string suffix, int minCount)
    {
        foreach (var line in body.AsSpan().EnumerateLines())
        {
            var separator = line.IndexOf(':');
            if (separator <= 0 || !line[..separator].Equals(suffix, StringComparison.OrdinalIgnoreCase)) continue;

            // Padding entries have a count of 0.
            return int.TryParse(line[(separator + 1)..].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var count)
                   && count >= minCount;
        }
        return false;
    }
}
